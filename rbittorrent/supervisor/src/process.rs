//! PID-1 duties and the rtbit child process.
//!
//! * Every child we spawn is registered, so the orphan reaper (SIGCHLD +
//!   `waitid(WNOWAIT)` peek) only collects processes nobody else waits for and
//!   never steals an exit status from tokio.
//! * rtbit runs with a reduced capability bounding set (no `CAP_NET_ADMIN`,
//!   `CAP_NET_RAW`, ...) and `no_new_privs`, so even a compromised torrent
//!   client cannot touch the kill-switch, routes or the WireGuard device.
//! * The Ingress proxy child runs as uid/gid 65534 with no capabilities at
//!   all; its configuration (with the Web UI password) goes through a pipe.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::{LogLevel, Secret};

// ---------------------------------------------------------------------------
// Child registry + orphan reaping
// ---------------------------------------------------------------------------

static REGISTRY: LazyLock<Mutex<HashSet<u32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn registry() -> MutexGuard<'static, HashSet<u32>> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A child process whose PID is protected from the orphan reaper until it has
/// been waited for (or dropped).
#[derive(Debug)]
pub struct TrackedChild {
    child: Option<Child>,
    pid: Option<u32>,
}

/// Spawns `cmd` and registers its PID atomically with respect to the reaper.
pub fn spawn_tracked(cmd: &mut Command) -> io::Result<TrackedChild> {
    let mut reg = registry();
    let child = cmd.spawn()?;
    let pid = child.id();
    if let Some(p) = pid {
        reg.insert(p);
    }
    Ok(TrackedChild {
        child: Some(child),
        pid,
    })
}

impl TrackedChild {
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Access to the underlying tokio child (e.g. its stdin pipe).
    ///
    /// # Panics
    /// Never: `child` is only `None` after `wait_with_output` consumed `self`.
    pub fn inner_mut(&mut self) -> &mut Child {
        match self.child.as_mut() {
            Some(c) => c,
            None => unreachable_child(),
        }
    }

    fn untrack(&mut self) {
        if let Some(p) = self.pid.take() {
            registry().remove(&p);
        }
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        let Some(child) = self.child.as_mut() else {
            return Err(io::Error::other("child already reaped"));
        };
        let status = child.wait().await;
        self.untrack();
        status
    }

    pub async fn wait_with_output(mut self) -> io::Result<Output> {
        let Some(child) = self.child.take() else {
            return Err(io::Error::other("child already reaped"));
        };
        let out = child.wait_with_output().await;
        self.untrack();
        out
    }

    /// Sends a signal (e.g. SIGTERM) to the child.
    pub fn signal(&self, sig: libc::c_int) -> io::Result<()> {
        let Some(pid) = self.pid.and_then(|p| libc::pid_t::try_from(p).ok()) else {
            return Ok(());
        };
        // SAFETY: plain syscall on a PID we own and still track (not yet reaped,
        // so it cannot have been recycled).
        let rc = unsafe { libc::kill(pid, sig) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn start_kill(&mut self) -> io::Result<()> {
        match self.child.as_mut() {
            Some(c) => c.start_kill(),
            None => Ok(()),
        }
    }
}

#[cold]
fn unreachable_child() -> ! {
    // `inner_mut` is only called on live children; abort loudly if not.
    std::process::abort()
}

impl Drop for TrackedChild {
    fn drop(&mut self) {
        self.untrack();
    }
}

/// Reaps exited processes that are not ours to wait for (orphans re-parented
/// to PID 1). Returns how many were collected.
pub fn reap_orphans() -> usize {
    let reg = registry();
    let mut reaped = 0;
    loop {
        // SAFETY: siginfo_t is plain old data; zero is a valid bit pattern.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: valid out-pointer; WNOWAIT leaves the zombie in place so we
        // can decide whether it is ours to reap.
        let rc = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            break; // ECHILD: no children at all.
        }
        // SAFETY: waitid filled `info` for a CLD_* event.
        let pid = unsafe { info.si_pid() };
        if pid <= 0 {
            break; // Children exist but none has exited.
        }
        if u32::try_from(pid).is_ok_and(|p| reg.contains(&p)) {
            // A tracked child: tokio will collect it; try again on the next SIGCHLD.
            break;
        }
        let mut status: libc::c_int = 0;
        // SAFETY: reaping a specific zombie PID we just observed.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r != pid {
            break;
        }
        reaped += 1;
        debug!(pid, status, "reaped orphaned process");
    }
    reaped
}

/// When not PID 1 (e.g. `docker run --init`), become a child subreaper so
/// grandchildren are still re-parented to us.
pub fn become_subreaper_if_needed() {
    if std::process::id() == 1 {
        return;
    }
    // SAFETY: simple prctl with integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc != 0 {
        debug!(
            "PR_SET_CHILD_SUBREAPER failed: {}",
            io::Error::last_os_error()
        );
    }
}

// ---------------------------------------------------------------------------
// Capability sandbox for rtbit
// ---------------------------------------------------------------------------

/// Capabilities rtbit keeps: enough for root to manage files on shared
/// storage written by other apps, nothing network-administrative.
pub const KEEP_CAPS: [u32; 4] = [
    0, // CAP_CHOWN
    1, // CAP_DAC_OVERRIDE
    3, // CAP_FOWNER
    4, // CAP_FSETID
];
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_ADMIN: u32 = 21;

fn last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40)
        .min(63)
}

/// Every capability number up to the kernel's last one, minus [`KEEP_CAPS`].
pub fn caps_to_drop(last: u32) -> Vec<u32> {
    (0..=last.min(63))
        .filter(|c| !KEEP_CAPS.contains(c))
        .collect()
}

/// Parses a `CapEff:`/`CapBnd:` line from `/proc/<pid>/status`.
pub fn parse_cap_mask(status: &str, field: &str) -> Option<u64> {
    status.lines().find_map(|l| {
        let rest = l.strip_prefix(field)?.strip_prefix(':')?;
        u64::from_str_radix(rest.trim(), 16).ok()
    })
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Runs in the forked child right before `execve`: async-signal-safe syscalls
/// only, no allocation.
fn drop_privileges(drop: &[u32]) -> io::Result<()> {
    // 1. Clear ambient capabilities (EINVAL on pre-4.3 kernels is fine).
    // SAFETY: prctl with integer args.
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
        return Err(io::Error::last_os_error());
    }

    // 2. Clear the inheritable set: for uid 0, execve() grants
    //    permitted = inheritable | bounding, so both must be reduced.
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header + two data structs as the v3 ABI requires.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    for d in &mut data {
        d.inheritable = 0;
    }
    // SAFETY: as above; lowering the inheritable set needs no privilege.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &mut hdr, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // 3. Shrink the bounding set (needs CAP_SETPCAP, present by default).
    for &cap in drop {
        // SAFETY: prctl with integer args.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) };
        if rc != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return Err(io::Error::last_os_error());
        }
    }

    // 4. Never regain privileges through setuid/file capabilities.
    // SAFETY: prctl with integer args.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// uid/gid of the unprivileged Ingress proxy (`nobody` on Alpine).
pub const NOBODY: u32 = 65534;

/// Like [`drop_privileges`], then switches to uid/gid 65534, which clears
/// every remaining capability. Async-signal-safe syscalls only.
fn drop_to_nobody(all_caps: &[u32]) -> io::Result<()> {
    drop_privileges(all_caps)?;
    // SAFETY: plain syscalls with integer args / a null list.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setgid(NOBODY) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(NOBODY) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Parses the real uid from `/proc/<pid>/status` (`Uid: r e s f`).
pub fn parse_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|u| u.parse().ok())
}

// ---------------------------------------------------------------------------
// Ingress proxy child
// ---------------------------------------------------------------------------

/// `<exe> ingress-proxy`, unprivileged. stdin carries the config and the
/// supervisor's messages, stdout the proxy's requests (benchmark); its log
/// goes to stderr.
pub fn ingress_command(exe: &Path, sandbox: bool) -> Command {
    let mut cmd = Command::new(exe);
    cmd.arg("ingress-proxy")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    if let Ok(tz) = std::env::var("TZ") {
        cmd.env("TZ", tz);
    }
    if sandbox {
        let all: Vec<u32> = (0..=last_cap()).collect();
        // SAFETY: async-signal-safe syscalls on pre-allocated data only.
        unsafe {
            cmd.pre_exec(move || drop_to_nobody(&all));
        }
    }
    cmd
}

/// The Ingress proxy's pipes: heartbeats/replies go in, requests come out.
#[derive(Debug)]
pub struct IngressPipes {
    pub stdin: tokio::process::ChildStdin,
    pub stdout: tokio::process::ChildStdout,
}

/// Starts the Ingress proxy and sends it its configuration line.
pub async fn spawn_ingress(
    exe: &Path,
    config_line: &str,
    sandbox: bool,
) -> Result<(TrackedChild, IngressPipes)> {
    let mut cmd = ingress_command(exe, sandbox);
    let mut child = spawn_tracked(&mut cmd)
        .with_context(|| format!("cannot start {} ingress-proxy", exe.display()))?;
    let mut stdin = child
        .inner_mut()
        .stdin
        .take()
        .context("the Ingress proxy has no stdin pipe")?;
    let stdout = child
        .inner_mut()
        .stdout
        .take()
        .context("the Ingress proxy has no stdout pipe")?;
    stdin
        .write_all(format!("{config_line}\n").as_bytes())
        .await
        .context("cannot send the Ingress proxy its configuration")?;
    if sandbox && let Some(pid) = child.pid() {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let uid = parse_uid(&status);
        let eff = parse_cap_mask(&status, "CapEff");
        if !status.is_empty() && (uid != Some(NOBODY) || eff != Some(0)) {
            child.start_kill().ok();
            bail!(
                "the Ingress proxy is not sandboxed (uid {uid:?}, CapEff {eff:?}); refusing to run it"
            );
        }
        info!(pid, "Ingress proxy started (uid {NOBODY}, no capabilities)");
    }
    Ok((child, IngressPipes { stdin, stdout }))
}

// ---------------------------------------------------------------------------
// rtbit
// ---------------------------------------------------------------------------

/// Static description of how to run rtbit.
#[derive(Debug, Clone)]
pub struct RtbitSpec {
    pub binary: PathBuf,
    pub home: PathBuf,
    pub data_home: PathBuf,
    pub cache_home: PathBuf,
    pub download_dir: PathBuf,
    pub completed_dir: PathBuf,
    pub webui_port: u16,
    /// `Some("wg0")` in VPN mode; `None` on a direct connection.
    pub bind_device: Option<String>,
    /// The tunnel address in VPN mode; `None` listens on every address.
    pub listen_ip: Option<std::net::Ipv4Addr>,
    pub log_level: LogLevel,
    /// DHT on (the default) or off (`RTBIT_DHT_DISABLE`).
    pub dht: bool,
    /// Passed as RTBIT_SHUTDOWN_TIMEOUT; keep below the supervisor's grace.
    pub shutdown_timeout: Duration,
    /// Drop network-admin capabilities before exec (always on in production).
    pub sandbox: bool,
}

impl RtbitSpec {
    /// Environment for rtbit. Only env vars are used (never flags) because clap
    /// ignores unknown env vars, which keeps the app compatible across rtbit
    /// releases (e.g. `RTBIT_IGNORE_SAVED_NETWORK` only exists since 0.2.0-beta.5).
    pub fn env(&self, listen_port: u16) -> Vec<(String, String)> {
        let path = |p: &PathBuf| p.to_string_lossy().into_owned();
        let mut env: Vec<(String, String)> = vec![
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), path(&self.home)),
            ("XDG_DATA_HOME".into(), path(&self.data_home)),
            ("XDG_CONFIG_HOME".into(), path(&self.data_home)),
            ("XDG_CACHE_HOME".into(), path(&self.cache_home)),
            (
                "RTBIT_HTTP_API_LISTEN_ADDR".into(),
                format!("0.0.0.0:{}", self.webui_port),
            ),
            ("RTBIT_LISTEN_PORT".into(), listen_port.to_string()),
            (
                "RTBIT_LISTEN_IP".into(),
                self.listen_ip
                    .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)
                    .to_string(),
            ),
            ("RTBIT_IPV4_ONLY".into(), "true".into()),
            // Port mapping is the supervisor's job (NAT-PMP inside the tunnel).
            ("RTBIT_UPNP_PORT_FORWARD_DISABLE".into(), "true".into()),
            // No LAN multicast: Local Service Discovery and the UPnP media server.
            ("RTBIT_LSD_DISABLE".into(), "true".into()),
            ("RTBIT_UPNP_SERVER_ENABLE".into(), "false".into()),
            // Web UI network settings must not override the supervisor's port.
            ("RTBIT_IGNORE_SAVED_NETWORK".into(), "true".into()),
            ("RTBIT_DOWNLOAD_FOLDER".into(), path(&self.download_dir)),
            ("RTBIT_COMPLETED_FOLDER".into(), path(&self.completed_dir)),
            ("RTBIT_FASTRESUME".into(), "true".into()),
            (
                "RTBIT_SHUTDOWN_TIMEOUT".into(),
                format!("{}s", self.shutdown_timeout.as_secs().max(1)),
            ),
            (
                "RTBIT_LOG_LEVEL_CONSOLE".into(),
                self.log_level.as_str().into(),
            ),
        ];
        if let Some(dev) = &self.bind_device {
            env.push(("RTBIT_BIND_DEVICE".into(), dev.clone()));
        }
        if let Some(filter) = rust_log(self.log_level) {
            env.push(("RUST_LOG".into(), filter.into()));
        }
        if !self.dht {
            env.push(("RTBIT_DHT_DISABLE".into(), "true".into()));
        }
        if let Ok(tz) = std::env::var("TZ") {
            env.push(("TZ".into(), tz));
        }
        env
    }

    pub fn args(&self) -> Vec<String> {
        vec![
            "server".into(),
            "start".into(),
            self.download_dir.to_string_lossy().into_owned(),
        ]
    }

    pub fn command(&self, listen_port: u16) -> Command {
        let mut cmd = self.base_command(listen_port);
        cmd.args(self.args()).stdin(std::process::Stdio::null());
        cmd
    }

    /// `rtbit auth reset-password -u <user>`; the password goes to stdin.
    pub fn reset_password_command(&self, username: &str) -> Command {
        let mut cmd = self.base_command(0);
        cmd.args(["auth", "reset-password", "-u", username])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        cmd
    }

    /// Stores the Web UI account in rtbit's credential store (before the
    /// first start, so the API is never open and setup is never required).
    pub async fn set_credentials(&self, username: &str, password: &Secret) -> Result<()> {
        let mut cmd = self.reset_password_command(username);
        let mut child = spawn_tracked(&mut cmd)
            .with_context(|| format!("cannot run {} auth", self.binary.display()))?;
        let mut stdin = child
            .inner_mut()
            .stdin
            .take()
            .context("rtbit auth has no stdin pipe")?;
        stdin
            .write_all(format!("{}\n", password.expose()).as_bytes())
            .await
            .context("cannot pass the password to rtbit auth")?;
        drop(stdin);
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .context("rtbit auth reset-password did not finish within 60s")?
            .context("rtbit auth reset-password failed")?;
        if !out.status.success() {
            bail!(
                "rtbit auth reset-password failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn base_command(&self, listen_port: u16) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .envs(self.env(listen_port))
            .current_dir(&self.home)
            // Own process group: terminal ^C goes to us, we stop rtbit in order.
            .process_group(0)
            .kill_on_drop(true);
        if self.sandbox {
            let drop = caps_to_drop(last_cap());
            // SAFETY: the closure only performs async-signal-safe syscalls on
            // pre-allocated data (see `drop_privileges`).
            unsafe {
                cmd.pre_exec(move || drop_privileges(&drop));
            }
        }
        cmd
    }
}

/// rtbit's console filter. At `info`, the engine's per-peer/DHT chatter is
/// cut to warnings (less log I/O on SD cards and fast swarms); rtbit's own
/// Web UI log view still shows everything at info. `RUST_LOG` replaces
/// rtbit's default filter, so its uTP buffer-size notice stays quiet too.
pub fn rust_log(level: LogLevel) -> Option<&'static str> {
    match level {
        LogLevel::Info => Some("info,librtbit=warn,librtbit_dht=warn,librqbit_utp::socket=error"),
        _ => None,
    }
}

/// Exponential backoff for respawns and retries.
#[derive(Debug, Clone)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            next: min,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let d = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        d
    }

    pub fn reset(&mut self) {
        self.next = self.min;
    }
}

/// The running rtbit instance (at most one).
#[derive(Debug)]
pub struct Rtbit {
    spec: RtbitSpec,
    child: Option<TrackedChild>,
    port: Option<u16>,
    started: Option<Instant>,
}

impl Rtbit {
    pub fn new(spec: RtbitSpec) -> Self {
        Self {
            spec,
            child: None,
            port: None,
            started: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    pub fn uptime(&self) -> Option<Duration> {
        self.started.map(|s| s.elapsed())
    }

    pub fn spawn(&mut self, listen_port: u16) -> Result<()> {
        if self.child.is_some() {
            bail!("rtbit is already running");
        }
        let mut cmd = self.spec.command(listen_port);
        let child = spawn_tracked(&mut cmd).with_context(|| {
            format!(
                "cannot start {} (capability sandbox needs CAP_SETPCAP)",
                self.spec.binary.display()
            )
        })?;
        let pid = child.pid();
        self.child = Some(child);
        self.port = Some(listen_port);
        self.started = Some(Instant::now());
        if self.spec.sandbox {
            self.verify_sandbox()?;
        }
        info!(pid, listen_port, "rtbit started");
        Ok(())
    }

    /// Confirms from /proc that rtbit really lost CAP_NET_ADMIN/CAP_NET_RAW.
    fn verify_sandbox(&mut self) -> Result<()> {
        let Some(pid) = self.child.as_ref().and_then(TrackedChild::pid) else {
            return Ok(());
        };
        let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(s) => s,
            Err(e) => {
                // Already exited: the exit path will report it.
                debug!("cannot read rtbit status: {e}");
                return Ok(());
            }
        };
        let eff = parse_cap_mask(&status, "CapEff").unwrap_or(u64::MAX);
        let bnd = parse_cap_mask(&status, "CapBnd").unwrap_or(u64::MAX);
        let forbidden = (1u64 << CAP_NET_ADMIN) | (1u64 << CAP_NET_RAW) | (1u64 << CAP_SYS_ADMIN);
        if (eff | bnd) & forbidden != 0 {
            if let Some(c) = self.child.as_mut() {
                c.start_kill().ok();
            }
            bail!(
                "rtbit still holds network-admin capabilities (CapEff={eff:#x} CapBnd={bnd:#x}); refusing to run it"
            );
        }
        info!("rtbit sandbox active: CapEff={eff:#x}, no NET_ADMIN/NET_RAW, no_new_privs");
        Ok(())
    }

    /// Resolves when rtbit exits; pending forever when it is not running.
    pub async fn exited(&mut self) -> io::Result<ExitStatus> {
        match self.child.as_mut() {
            Some(c) => {
                let status = c.wait().await;
                self.child = None;
                self.started = None;
                status
            }
            None => std::future::pending().await,
        }
    }

    /// SIGTERM, wait up to `grace`, then SIGKILL. Returns the exit status.
    pub async fn stop(&mut self, grace: Duration) -> Option<ExitStatus> {
        let mut child = self.child.take()?;
        self.started = None;
        if let Err(e) = child.signal(libc::SIGTERM) {
            warn!("cannot send SIGTERM to rtbit: {e}");
        }
        match tokio::time::timeout(grace, child.wait()).await {
            Ok(Ok(status)) => {
                info!(%status, "rtbit stopped");
                Some(status)
            }
            Ok(Err(e)) => {
                warn!("waiting for rtbit failed: {e}");
                None
            }
            Err(_) => {
                warn!(
                    "rtbit did not stop within {}s, sending SIGKILL",
                    grace.as_secs()
                );
                child.start_kill().ok();
                child.wait().await.ok()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn spec(binary: &str) -> RtbitSpec {
        RtbitSpec {
            binary: binary.into(),
            home: "/tmp".into(),
            data_home: "/config/db".into(),
            cache_home: "/config/cache".into(),
            download_dir: "/media/rbittorrent/downloads".into(),
            completed_dir: "/media/rbittorrent/completed".into(),
            webui_port: 8080,
            bind_device: Some("wg0".into()),
            listen_ip: Some(Ipv4Addr::new(10, 2, 0, 2)),
            log_level: LogLevel::Info,
            dht: true,
            shutdown_timeout: Duration::from_secs(12),
            sandbox: false,
        }
    }

    #[test]
    fn dht_and_log_filter_env() {
        let mut sp = spec("x");
        let env = sp.env(1);
        let get = |e: &[(String, String)], k: &str| {
            e.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        };
        assert_eq!(get(&env, "RTBIT_DHT_DISABLE"), None);
        assert_eq!(
            get(&env, "RUST_LOG").as_deref(),
            Some("info,librtbit=warn,librtbit_dht=warn,librqbit_utp::socket=error")
        );
        assert_eq!(
            get(&env, "RTBIT_LOG_LEVEL_CONSOLE").as_deref(),
            Some("info")
        );
        sp.dht = false;
        sp.log_level = LogLevel::Debug;
        let env = sp.env(1);
        assert_eq!(get(&env, "RTBIT_DHT_DISABLE").as_deref(), Some("true"));
        assert_eq!(get(&env, "RUST_LOG"), None, "debug shows everything");
        assert_eq!(
            get(&env, "RTBIT_LOG_LEVEL_CONSOLE").as_deref(),
            Some("debug")
        );
    }

    #[tokio::test]
    async fn credentials_go_to_stdin_never_argv() {
        let dir = std::env::temp_dir().join(format!("vpn-sup-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-rtbit");
        let record = dir.join("record");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" > {r}.argv\nread -r pw\necho \"$pw\" > {r}.stdin\n",
                r = record.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut sp = spec(script.to_str().unwrap());
        sp.home = dir.clone();
        sp.set_credentials("admin", &Secret::new("s3cret pass".into()))
            .await
            .unwrap();
        let argv = std::fs::read_to_string(dir.join("record.argv")).unwrap();
        assert_eq!(argv.trim(), "auth reset-password -u admin");
        assert_eq!(
            std::fs::read_to_string(dir.join("record.stdin"))
                .unwrap()
                .trim(),
            "s3cret pass"
        );

        std::fs::write(&script, "#!/bin/sh\necho broken >&2\nexit 3\n").unwrap();
        let err = format!(
            "{:#}",
            sp.set_credentials("admin", &Secret::new("x".into()))
                .await
                .unwrap_err()
        );
        assert!(err.contains("broken") && !err.contains("s3cret"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn uid_is_parsed_from_proc_status() {
        assert_eq!(
            parse_uid("Name:\tx\nUid:\t65534\t65534\t65534\t65534\n"),
            Some(65534)
        );
        assert_eq!(parse_uid("Name:\tx\n"), None);
    }

    #[test]
    fn rtbit_environment_is_locked_to_the_tunnel() {
        let env = spec("/usr/local/bin/rtbit").env(51234);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("RTBIT_LISTEN_PORT"), Some("51234"));
        assert_eq!(get("RTBIT_LISTEN_IP"), Some("10.2.0.2"));
        assert_eq!(get("RTBIT_BIND_DEVICE"), Some("wg0"));
        assert_eq!(get("RTBIT_IPV4_ONLY"), Some("true"));
        assert_eq!(get("RTBIT_UPNP_PORT_FORWARD_DISABLE"), Some("true"));
        assert_eq!(get("RTBIT_LSD_DISABLE"), Some("true"));
        assert_eq!(get("RTBIT_UPNP_SERVER_ENABLE"), Some("false"));
        assert_eq!(get("RTBIT_IGNORE_SAVED_NETWORK"), Some("true"));
        assert_eq!(get("RTBIT_HTTP_API_LISTEN_ADDR"), Some("0.0.0.0:8080"));
        assert_eq!(get("XDG_DATA_HOME"), Some("/config/db"));
        assert_eq!(get("XDG_CACHE_HOME"), Some("/config/cache"));
        assert_eq!(
            get("RTBIT_DOWNLOAD_FOLDER"),
            Some("/media/rbittorrent/downloads")
        );
        assert_eq!(
            get("RTBIT_COMPLETED_FOLDER"),
            Some("/media/rbittorrent/completed")
        );
        assert_eq!(get("RTBIT_SHUTDOWN_TIMEOUT"), Some("12s"));
        // Boolean env values must be literal true/false for clap.
        for (k, v) in &env {
            if k.starts_with("RTBIT_") && (v == "1" || v == "yes") {
                panic!("{k}={v}");
            }
        }
        assert_eq!(
            spec("x").args(),
            vec!["server", "start", "/media/rbittorrent/downloads"]
        );
    }

    #[test]
    fn direct_mode_environment_has_no_tunnel_binding() {
        let mut sp = spec("x");
        sp.bind_device = None;
        sp.listen_ip = None;
        let env = sp.env(4240);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("RTBIT_BIND_DEVICE"), None);
        assert_eq!(get("RTBIT_LISTEN_IP"), Some("0.0.0.0"));
        assert_eq!(get("RTBIT_LISTEN_PORT"), Some("4240"));
        // Still no UPnP/LSD/IPv6 on a direct connection.
        assert_eq!(get("RTBIT_UPNP_PORT_FORWARD_DISABLE"), Some("true"));
        assert_eq!(get("RTBIT_LSD_DISABLE"), Some("true"));
        assert_eq!(get("RTBIT_IPV4_ONLY"), Some("true"));
    }

    #[test]
    fn capability_drop_list() {
        let drop = caps_to_drop(40);
        assert!(drop.contains(&CAP_NET_ADMIN));
        assert!(drop.contains(&CAP_NET_RAW));
        assert!(drop.contains(&CAP_SYS_ADMIN));
        for keep in KEEP_CAPS {
            assert!(!drop.contains(&keep));
        }
        assert_eq!(drop.len(), 41 - KEEP_CAPS.len());
        assert_eq!(caps_to_drop(200).last(), Some(&63));
    }

    #[test]
    fn parses_proc_status_capabilities() {
        let status = "Name:\trtbit\nCapInh:\t0000000000000000\nCapEff:\t000000000000001b\nCapBnd:\t000000000000001b\n";
        assert_eq!(parse_cap_mask(status, "CapEff"), Some(0x1b));
        assert_eq!(parse_cap_mask(status, "CapBnd"), Some(0x1b));
        assert_eq!(parse_cap_mask(status, "CapAmb"), None);
        let keep_mask: u64 = KEEP_CAPS.iter().map(|c| 1u64 << c).sum();
        assert_eq!(keep_mask, 0x1b);
    }

    #[test]
    fn backoff_doubles_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(2), Duration::from_secs(10));
        let seq: Vec<u64> = (0..5).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(seq, vec![2, 4, 8, 10, 10]);
        b.reset();
        assert_eq!(b.next_delay().as_secs(), 2);
    }

    #[tokio::test]
    async fn spawn_stop_and_crash_detection() {
        // `sleep` ignores no signals: SIGTERM stops it promptly.
        let mut sp = spec("/bin/sleep");
        sp.home = std::env::temp_dir();
        let mut rt = Rtbit::new(sp);
        // RtbitSpec::args() appends "server start <dir>", which sleep rejects:
        // that is a quick "crash", exercising the exit path.
        rt.spawn(1).unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), rt.exited())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        assert!(!rt.is_running());
        assert!(rt.stop(Duration::from_secs(1)).await.is_none());
    }

    #[tokio::test]
    async fn tracked_children_are_not_stolen_by_the_reaper() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 7"]);
        let mut child = spawn_tracked(&mut cmd).unwrap();
        // Give it time to become a zombie, then run the reaper.
        tokio::time::sleep(Duration::from_millis(200)).await;
        reap_orphans();
        let status = child.wait().await.unwrap();
        assert_eq!(status.code(), Some(7));
    }
}
