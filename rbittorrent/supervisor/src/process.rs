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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::config::{LogLevel, Secret};
use crate::landlock::{self, FsPolicy, Ruleset};

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
    /// The PID stays registered until the child is really reaped. Untracking
    /// a live child first would let the orphan reaper collect it and the
    /// kernel hand its PID to a new child, while tokio's own orphan queue
    /// still waits on that number and could steal the new child's status.
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            self.untrack();
            return;
        };
        let _ = child.start_kill();
        if matches!(child.try_wait(), Ok(Some(_))) {
            self.untrack();
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            // No runtime left (process exit): nothing will reuse the PID.
            return;
        };
        let pid = self.pid.take();
        rt.spawn(async move {
            let _ = child.wait().await;
            if let Some(p) = pid {
                registry().remove(&p);
            }
        });
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
/// only, no allocation. [`set_no_new_privs`] must follow.
fn drop_capabilities(drop: &[u32]) -> io::Result<()> {
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

    Ok(())
}

/// Never regain privileges through setuid binaries or file capabilities.
/// Also required by Landlock. After it, AppArmor refuses to change the
/// profile, so [`enter_apparmor_child`] comes first. One syscall.
fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: prctl with integer args.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// uid/gid of the unprivileged Ingress proxy (`nobody` on Alpine).
pub const NOBODY: u32 = 65534;

/// Switches to uid/gid 65534, which clears every remaining capability.
/// Async-signal-safe syscalls only.
fn become_nobody() -> io::Result<()> {
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
// Filesystem sandbox (AppArmor child profiles, Landlock)
// ---------------------------------------------------------------------------

static RTBIT_FS_ANNOUNCED: AtomicBool = AtomicBool::new(false);
static PROXY_FS_ANNOUNCED: AtomicBool = AtomicBool::new(false);
/// Set only by [`check_fs_sandbox`] when the user allowed running without
/// any sandbox (`allow_unsandboxed`). Until then every sandboxed child
/// refuses to start without one.
static FS_SANDBOX_OPTIONAL: AtomicBool = AtomicBool::new(false);
/// The app's AppArmor profile, when it confines this process: the children
/// must then run in its child profiles (checked after each start).
static APPARMOR_PROFILE: OnceLock<String> = OnceLock::new();

/// What a child can reach without a sandbox, for the refusal and the warning.
const UNSANDBOXED_RISK: &str = "rtbit runs as root with CAP_DAC_OVERRIDE, so without a sandbox \
    it could read the Web UI password, /data/options.json, every other app's folder in \
    /app_configs and, with the VPN on, /config/wg0.conf";

/// Checks, before any child starts, that the children can be confined: by
/// the app's AppArmor profile (`apparmor.txt`, loaded by the Supervisor;
/// the only option on Home Assistant OS, whose kernels have no Landlock)
/// and/or by Landlock (ABI 2+). Neither is a fatal error unless the user set
/// `allow_unsandboxed`. Returns whether a sandbox is active.
pub fn check_fs_sandbox(policy: &FsPolicy, allow_unsandboxed: bool) -> Result<bool> {
    let landlock = landlock::build(policy).map(|rs| rs.abi);
    let apparmor = crate::apparmor::own_profile();
    if let (Err(aa), Err(ll)) = (&apparmor, &landlock) {
        if !allow_unsandboxed {
            bail!(
                "the filesystem sandbox is not available: {aa}, and {ll}. {UNSANDBOXED_RISK}. \
                 Keep AppArmor on for the app (Home Assistant loads its profile, \
                 apparmor.txt) or run a kernel with Landlock (Linux 5.19 or newer). Refusing \
                 to start; set `allow_unsandboxed: true` (Configuration, show unused optional \
                 options) to run without it at your own risk"
            );
        }
        FS_SANDBOX_OPTIONAL.store(true, Ordering::Relaxed);
        warn!(
            "the filesystem sandbox is not available ({aa}; {ll}); running without it because \
             `allow_unsandboxed` is on. {UNSANDBOXED_RISK}"
        );
        return Ok(false);
    }
    FS_SANDBOX_OPTIONAL.store(false, Ordering::Relaxed);
    if let Ok(profile) = apparmor {
        info!(
            "AppArmor profile `{profile}` confines the app; rtbit and the Ingress proxy start \
             in its child profiles"
        );
        // Set once per process; a second check finds the same profile.
        let _ = APPARMOR_PROFILE.set(profile);
    }
    if let Err(why) = landlock {
        info!("Landlock is not available ({why}); AppArmor is the filesystem sandbox");
    }
    Ok(true)
}

/// A child's sandbox, decided before `fork`.
enum FsSandbox {
    /// The AppArmor child profile (changed to before `no_new_privs`,
    /// verified after the start) and/or Landlock (applied after
    /// `no_new_privs`), both before `execve`.
    Confined {
        apparmor: Option<crate::apparmor::ProfileSwitch>,
        landlock: Option<Arc<Ruleset>>,
    },
    /// No sandbox at all, and [`check_fs_sandbox`] allowed that.
    Allowed,
    /// No sandbox, not allowed: the child must never run.
    Refused,
}

/// The sandbox for a child. Without one, the child runs only when
/// [`check_fs_sandbox`] allowed that; otherwise it refuses to `execve` (see
/// [`apply_fs_sandbox`]).
fn fs_sandbox(who: &str, child: &str, policy: &FsPolicy, announced: &AtomicBool) -> FsSandbox {
    let apparmor = APPARMOR_PROFILE.get();
    let switch = apparmor.map(|p| crate::apparmor::ProfileSwitch::new(p, child));
    let first = !announced.swap(true, Ordering::Relaxed);
    match (landlock::build(policy), apparmor) {
        (Ok(rs), aa) => {
            if first {
                let aa = aa.map_or_else(String::new, |p| format!("AppArmor `{p}//{child}` + "));
                info!(
                    "{who} filesystem sandbox active ({aa}Landlock ABI {}): {}; everything \
                     else, including /data, /app_configs and the secrets in /config, is out of \
                     reach",
                    rs.abi,
                    policy.describe()
                );
            }
            FsSandbox::Confined {
                apparmor: switch,
                landlock: Some(Arc::new(rs)),
            }
        }
        (Err(_), Some(p)) => {
            if first {
                info!(
                    "{who} filesystem sandbox active (AppArmor `{p}//{child}`): /data, \
                     /app_configs and the secrets in /config are out of reach"
                );
            }
            FsSandbox::Confined {
                apparmor: switch,
                landlock: None,
            }
        }
        (Err(why), None) if FS_SANDBOX_OPTIONAL.load(Ordering::Relaxed) => {
            if first {
                warn!("{who} runs without a filesystem sandbox: {why}");
            }
            FsSandbox::Allowed
        }
        (Err(why), None) => {
            error!("{who} cannot be sandboxed ({why}); refusing to start it");
            FsSandbox::Refused
        }
    }
}

/// Runs in the forked child before [`set_no_new_privs`]: moves it to its
/// AppArmor child profile, where its binary then runs (`ix`). An exec
/// transition would come after `no_new_privs`, and AppArmor refuses those.
/// Async-signal-safe (see [`crate::apparmor::ProfileSwitch::apply`]).
fn enter_apparmor_child(fs: &FsSandbox) -> io::Result<()> {
    match fs {
        FsSandbox::Confined {
            apparmor: Some(switch),
            ..
        } => switch.apply(),
        _ => Ok(()),
    }
}

/// Runs in the forked child right before `execve`, after
/// [`set_no_new_privs`] (async-signal-safe: one syscall, or an error built
/// from an errno without allocating).
fn apply_fs_sandbox(fs: &FsSandbox) -> io::Result<()> {
    match fs {
        FsSandbox::Confined {
            landlock: Some(rs), ..
        } => rs.restrict_self(),
        FsSandbox::Confined { landlock: None, .. } | FsSandbox::Allowed => Ok(()),
        FsSandbox::Refused => Err(io::Error::from_raw_os_error(libc::EPERM)),
    }
}

/// When the app's AppArmor profile is active: whether the running child
/// `pid` is in the child profile `child`. `Ok(None)` without AppArmor.
fn verify_apparmor_child(pid: u32, child: &str) -> std::result::Result<Option<String>, String> {
    let Some(profile) = APPARMOR_PROFILE.get() else {
        return Ok(None);
    };
    match crate::apparmor::label_of(Path::new(&format!("/proc/{pid}"))) {
        Some(l) if crate::apparmor::is_child(&l, profile, child) => Ok(Some(l.to_string())),
        Some(l) => Err(format!(
            "it runs under the AppArmor label `{l}`, not `{profile}//{child} (enforce)`"
        )),
        None => Err("its AppArmor label cannot be read".to_owned()),
    }
}

/// What the Ingress proxy may touch: its own binary and system files to
/// start, `/etc` for name resolution, nothing writable.
pub fn ingress_fs_policy(exe: &Path) -> FsPolicy {
    let mut read_exec = landlock::system_read_exec();
    read_exec.push(exe.to_path_buf());
    FsPolicy {
        read_exec,
        read_only: vec![PathBuf::from("/etc")],
        read_write: Vec::new(),
    }
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
        let fs = fs_sandbox(
            "Ingress proxy",
            crate::apparmor::INGRESS_CHILD,
            &ingress_fs_policy(exe),
            &PROXY_FS_ANNOUNCED,
        );
        // SAFETY: async-signal-safe syscalls on pre-allocated data only.
        unsafe {
            cmd.pre_exec(move || {
                drop_capabilities(&all)?;
                become_nobody()?;
                enter_apparmor_child(&fs)?;
                set_no_new_privs()?;
                apply_fs_sandbox(&fs)
            });
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
        // Fail closed: a status that cannot be read is not proof either.
        let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(s) => s,
            Err(e) => {
                child.start_kill().ok();
                bail!("cannot verify the Ingress proxy's sandbox ({e}); refusing to run it");
            }
        };
        let uid = parse_uid(&status);
        let eff = parse_cap_mask(&status, "CapEff");
        if uid != Some(NOBODY) || eff != Some(0) {
            child.start_kill().ok();
            bail!(
                "the Ingress proxy is not sandboxed (uid {uid:?}, CapEff {eff:?}); refusing to run it"
            );
        }
        let profile = match verify_apparmor_child(pid, crate::apparmor::INGRESS_CHILD) {
            Ok(p) => p.map_or_else(String::new, |p| format!(", AppArmor `{p}`")),
            Err(why) => {
                child.start_kill().ok();
                bail!("the Ingress proxy is not confined: {why}; refusing to run it");
            }
        };
        info!(
            pid,
            "Ingress proxy started (uid {NOBODY}, no capabilities{profile})"
        );
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
    /// `RTBIT_COMPLETED_FOLDER`; `None` leaves finished torrents in place.
    pub completed_dir: Option<PathBuf>,
    pub webui_port: u16,
    /// `Some("wg0")` in VPN mode; `None` on a direct connection.
    pub bind_device: Option<String>,
    /// The port announced to trackers and the DHT when peers reach rtbit on
    /// another port than it listens on (a direct connection whose host port
    /// differs from `listen_port`). `None`: the listen port.
    pub announce_port: Option<u16>,
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
            // Temporary files stay inside the sandbox's writable folders.
            ("TMPDIR".into(), path(&self.cache_home)),
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
            // Saved network settings must not override the supervisor's port.
            // The pinned 0.2.0-beta.4 never saves any (its network endpoint
            // refuses every change), so this only matters from beta.5 on.
            ("RTBIT_IGNORE_SAVED_NETWORK".into(), "true".into()),
            ("RTBIT_DOWNLOAD_FOLDER".into(), path(&self.download_dir)),
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
        if let Some(done) = &self.completed_dir {
            env.push(("RTBIT_COMPLETED_FOLDER".into(), path(done)));
        }
        if let Some(port) = self.announce_port {
            env.push(("RTBIT_ANNOUNCE_PORT".into(), port.to_string()));
        }
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        env.extend(low_end_tuning(cores));
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

    /// `rtbit auth reset-password --username=<user>`; the password goes to
    /// stdin. The `--username=` form keeps a user name from ever being parsed
    /// as an option (the name is also validated: no leading `-`).
    pub fn reset_password_command(&self, username: &str) -> Command {
        let mut cmd = self.base_command(0);
        cmd.args(["auth", "reset-password", &format!("--username={username}")])
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
        // Fail closed: exit 0 alone is not proof (clap's help also exits 0).
        // rtbit confirms with "stored new credentials for <user> in <file>".
        let said = String::from_utf8_lossy(&out.stdout);
        if !said.contains(&format!("stored new credentials for {username}")) {
            bail!(
                "rtbit auth reset-password did not confirm storing the Web UI login; \
                 refusing to start rtbit without authentication"
            );
        }
        Ok(())
    }

    /// What rtbit may touch: shared storage (/media, /share), its download
    /// and completed folders, its database and cache; system folders and its
    /// own binary to start; /etc, /proc, /sys and /dev read-only. Not
    /// /data, not /app_configs, not the rest of /config.
    pub fn fs_policy(&self) -> FsPolicy {
        let mut read_exec = landlock::system_read_exec();
        read_exec.push(self.binary.clone());
        let mut read_write =
            crate::config::writable_roots(&self.download_dir, self.completed_dir.as_deref());
        read_write.push(PathBuf::from("/dev/null"));
        for p in [&self.data_home, &self.cache_home] {
            if !read_write.iter().any(|r| p.starts_with(r)) {
                read_write.push(p.clone());
            }
        }
        FsPolicy {
            read_exec,
            read_only: ["/etc", "/proc", "/sys", "/dev"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            read_write,
        }
    }

    fn base_command(&self, listen_port: u16) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .envs(self.env(listen_port))
            .current_dir(&self.home)
            // Own process group: terminal ^C goes to us, we stop rtbit in order.
            .process_group(0)
            .kill_on_drop(true);
        // SAFETY: two plain syscalls on the calling process, no allocation.
        unsafe {
            cmd.pre_exec(|| {
                lower_priority();
                Ok(())
            });
        }
        if self.sandbox {
            let drop = caps_to_drop(last_cap());
            let fs = fs_sandbox(
                "rtbit",
                crate::apparmor::RTBIT_CHILD,
                &self.fs_policy(),
                &RTBIT_FS_ANNOUNCED,
            );
            // SAFETY: the closure only performs async-signal-safe syscalls on
            // pre-allocated data (see `drop_capabilities`). The AppArmor
            // profile changes before `no_new_privs`, Landlock comes after it.
            unsafe {
                cmd.pre_exec(move || {
                    drop_capabilities(&drop)?;
                    enter_apparmor_child(&fs)?;
                    set_no_new_privs()?;
                    apply_fs_sandbox(&fs)
                });
            }
        }
        cmd
    }
}

/// Limits for small boards (Raspberry Pi, Home Assistant Green), sized by
/// the number of CPU cores:
/// - the DHT routing table is saved every 15 minutes, not every minute
///   (1,440 writes a day to the SD card otherwise);
/// - at most `cores / 2` torrents (1 to 5) re-hash at once after a restart
///   or an import, instead of 5 on any machine;
/// - `2 * cores` disk threads (4 to 8, rtbit's default is 8);
/// - 100 peers per torrent, qBittorrent's default (rtbit's is 200).
pub fn low_end_tuning(cores: usize) -> Vec<(String, String)> {
    vec![
        ("RTBIT_DHT_DUMP_INTERVAL".into(), "15m".into()),
        (
            "RTBIT_CONCURRENT_INIT_LIMIT".into(),
            (cores / 2).clamp(1, 5).to_string(),
        ),
        (
            "RTBIT_RUNTIME_MAX_BLOCKING_THREADS".into(),
            (cores * 2).clamp(4, 8).to_string(),
        ),
        ("RTBIT_PEER_LIMIT".into(), "100".into()),
    ]
}

/// rtbit's CPU niceness: below Home Assistant Core and the supervisor.
pub const RTBIT_NICE: libc::c_int = 10;
const IOPRIO_WHO_PROCESS: libc::c_int = 1;
/// `IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 7)`: best effort, lowest level.
const IOPRIO_BE_LOWEST: libc::c_int = (2 << 13) | 7;

/// Runs in rtbit's child before `execve`: rtbit yields the CPU (nice 10)
/// and the disk (lowest best-effort I/O priority) to Home Assistant on a
/// small board, e.g. while it re-hashes torrents on an SD card. Lowering
/// one's own priority needs no capability, and a failure changes nothing
/// else, so errors are ignored (async-signal-safe: two syscalls).
fn lower_priority() {
    // SAFETY: plain syscalls on the calling process.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, RTBIT_NICE);
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0,
            IOPRIO_BE_LOWEST,
        );
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
                let exited = self
                    .child
                    .as_mut()
                    .is_some_and(|c| matches!(c.inner_mut().try_wait(), Ok(Some(_))));
                if exited {
                    // The exit path reports why it stopped.
                    debug!("rtbit exited before its sandbox could be checked: {e}");
                    return Ok(());
                }
                // Fail closed: still running, but nothing proves the sandbox.
                if let Some(c) = self.child.as_mut() {
                    c.start_kill().ok();
                }
                bail!("cannot verify rtbit's sandbox ({e}); refusing to run it");
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
        let profile = match verify_apparmor_child(pid, crate::apparmor::RTBIT_CHILD) {
            Ok(p) => p.map_or_else(String::new, |p| format!(", AppArmor `{p}`")),
            Err(why) => {
                if let Some(c) = self.child.as_mut() {
                    c.start_kill().ok();
                }
                bail!("rtbit is not confined: {why}; refusing to run it");
            }
        };
        info!(
            "rtbit privileges dropped: CapEff={eff:#x}, no NET_ADMIN/NET_RAW, no_new_privs{profile}"
        );
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

    #[test]
    fn a_child_without_its_required_sandbox_never_runs() {
        use std::os::unix::process::CommandExt as _;
        let marker = std::env::temp_dir().join(format!("rbt-refused-{}", std::process::id()));
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("touch {}", marker.display()));
        let fs = FsSandbox::Refused;
        // SAFETY: apply_fs_sandbox only builds an io::Error from an errno.
        unsafe {
            cmd.pre_exec(move || apply_fs_sandbox(&fs));
        }
        let err = cmd
            .status()
            .expect_err("a refused sandbox must stop the exec");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
        assert!(!marker.exists(), "the child ran");

        let mut ok = std::process::Command::new("/bin/true");
        let allowed = FsSandbox::Allowed;
        // SAFETY: as above.
        unsafe {
            ok.pre_exec(move || apply_fs_sandbox(&allowed));
        }
        assert!(ok.status().expect("allowed runs").success());
    }

    fn spec(binary: &str) -> RtbitSpec {
        RtbitSpec {
            binary: binary.into(),
            home: "/tmp".into(),
            data_home: "/config/db".into(),
            cache_home: "/config/cache".into(),
            download_dir: "/media/rbittorrent/downloads".into(),
            completed_dir: Some("/media/rbittorrent/completed".into()),
            webui_port: 8080,
            bind_device: Some("wg0".into()),
            announce_port: None,
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
        assert_eq!(get(&env, "RTBIT_ANNOUNCE_PORT"), None);
        assert_eq!(get(&env, "RTBIT_DHT_DUMP_INTERVAL").as_deref(), Some("15m"));
        assert_eq!(get(&env, "RTBIT_PEER_LIMIT").as_deref(), Some("100"));
        sp.dht = false;
        sp.log_level = LogLevel::Debug;
        sp.announce_port = Some(51413);
        let env = sp.env(1);
        assert_eq!(get(&env, "RTBIT_ANNOUNCE_PORT").as_deref(), Some("51413"));
        assert_eq!(get(&env, "RTBIT_DHT_DISABLE").as_deref(), Some("true"));
        assert_eq!(get(&env, "RUST_LOG"), None, "debug shows everything");
        assert_eq!(
            get(&env, "RTBIT_LOG_LEVEL_CONSOLE").as_deref(),
            Some("debug")
        );
    }

    #[test]
    fn small_boards_get_smaller_limits() {
        let get = |cores: usize, k: &str| {
            low_end_tuning(cores)
                .into_iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v)
                .unwrap()
        };
        // Pi 3/4/5 and HA Green have 4 cores; HA Yellow's CM4 too.
        assert_eq!(get(4, "RTBIT_CONCURRENT_INIT_LIMIT"), "2");
        assert_eq!(get(4, "RTBIT_RUNTIME_MAX_BLOCKING_THREADS"), "8");
        assert_eq!(get(1, "RTBIT_CONCURRENT_INIT_LIMIT"), "1");
        assert_eq!(get(1, "RTBIT_RUNTIME_MAX_BLOCKING_THREADS"), "4");
        assert_eq!(get(2, "RTBIT_RUNTIME_MAX_BLOCKING_THREADS"), "4");
        assert_eq!(get(16, "RTBIT_CONCURRENT_INIT_LIMIT"), "5");
        assert_eq!(get(16, "RTBIT_RUNTIME_MAX_BLOCKING_THREADS"), "8");
    }

    #[test]
    fn rtbit_runs_at_a_lower_priority() {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "cut -d' ' -f19 /proc/self/stat"]);
        // SAFETY: as in `base_command`.
        unsafe {
            cmd.pre_exec(|| {
                lower_priority();
                Ok(())
            });
        }
        let out = cmd.output().expect("sh runs");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            RTBIT_NICE.to_string()
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
                "#!/bin/sh\necho \"$@\" > {r}.argv\nread -r pw\necho \"$pw\" > {r}.stdin\n\
                 echo \"stored new credentials for admin in /x/credentials.json\"\n",
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
        assert_eq!(argv.trim(), "auth reset-password --username=admin");
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

        // Exit 0 without rtbit's confirmation (e.g. clap printing help) is a
        // failure: rtbit must never start without a stored login.
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'Usage: rtbit auth reset-password'\nexit 0\n",
        )
        .unwrap();
        let err = format!(
            "{:#}",
            sp.set_credentials("admin", &Secret::new("x".into()))
                .await
                .unwrap_err()
        );
        assert!(err.contains("did not confirm"), "{err}");
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
