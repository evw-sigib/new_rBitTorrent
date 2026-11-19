//! `rbittorrent-supervisor`: PID 1 of the rbittorrent Home Assistant app.
//!
//! Startup is strictly ordered and fail-closed:
//!
//! 1. read + validate `/data/options.json` (and the pasted WireGuard `.conf`)
//! 2. resolve the WireGuard endpoint once, while normal DNS still works
//! 3. load the nftables kill-switch atomically (drop-by-default, no IPv6;
//!    a static `listen_port` is opened on `wg0` right away when NAT-PMP is
//!    off)
//! 4. point `/etc/resolv.conf` at the in-tunnel DNS
//! 5. create `wg0`, add split-return routes, wait for the first handshake
//! 6. lease a port with NAT-PMP inside the tunnel, open it in the firewall
//! 7. only then start rtbit (sandboxed, bound to `wg0`)
//!
//! VPN mode is on as soon as `vpn_enabled` is set or any WireGuard input
//! exists (`/config/wg0.conf`, `wireguard_conf`, a `wg_*` field); an
//! incomplete configuration is then an error, never a fallback. Without any
//! of these (a fresh install) the app runs on a direct connection: steps 2-6
//! are skipped, a loud warning says the traffic is unprotected, and rtbit
//! listens on `listen_port`.
//!
//! The Web UI account is written into rtbit's credential store before rtbit
//! ever starts, and the unprivileged Ingress proxy (port 8099: sidebar +
//! watchdog) starts right after the kill-switch.
//!
//! Afterwards it renews the lease every 45 s, restarts rtbit only when the
//! forwarded port really changes, respawns rtbit after crashes, reaps orphans
//! and shuts everything down in order on SIGTERM/SIGINT.
//!
//! The control plane is deliberately single-threaded (`current_thread`
//! runtime): it idles in a couple of MiB and never competes with rtbit, which
//! sizes its own multi-threaded runtime to all available cores.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{Instant, sleep, sleep_until};
use tracing::{debug, error, info, warn};

use rbittorrent_supervisor::config::{Options, Paths, Secret, Settings, VpnSettings};
use rbittorrent_supervisor::exec::{Runner, SystemRunner};
use rbittorrent_supervisor::firewall::{DirectSpec, RulesetSpec};
use rbittorrent_supervisor::host::{self, PortState};
use rbittorrent_supervisor::ingress::{self, Health};
use rbittorrent_supervisor::migration::{self, SeedJob};
use rbittorrent_supervisor::natpmp::{Client, NatPmpError, PortDecision, PortForwarder};
use rbittorrent_supervisor::process::{Backoff, Rtbit, RtbitSpec};
use rbittorrent_supervisor::wireguard::{TunnelPlan, WG_FWMARK, WG_IFACE};
use rbittorrent_supervisor::{
    benchmark, config, firewall, ha_supervisor, init_logging, natpmp, process, wireguard,
};

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEFAULT_OPTIONS_PATH: &str = "/data/options.json";
const DEFAULT_RTBIT_BINARY: &str = "/usr/local/bin/rtbit";
const DEFAULT_RESOLV_CONF: &str = "/etc/resolv.conf";

/// Per-attempt limit for the first WireGuard handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// WireGuard's REJECT_AFTER_TIME: older sessions cannot carry traffic.
const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(180);
const STALE_ESCALATE_AFTER: Duration = Duration::from_secs(600);
const HEALTH_INTERVAL: Duration = Duration::from_secs(30);
/// Grace period when restarting rtbit for a new forwarded port: longer than
/// rtbit's own shutdown budget, so its fast-resume flush is never cut short.
const RTBIT_RESTART_GRACE: Duration = Duration::from_secs(15);
/// Grace period on app shutdown (config.yaml `timeout: 30`).
const RTBIT_SHUTDOWN_GRACE: Duration = Duration::from_secs(15);
/// rtbit's own graceful-shutdown budget (flushes the session/fast-resume DB).
const RTBIT_INTERNAL_SHUTDOWN: Duration = Duration::from_secs(12);
const _: () = assert!(
    RTBIT_RESTART_GRACE.as_secs() > RTBIT_INTERNAL_SHUTDOWN.as_secs()
        && RTBIT_SHUTDOWN_GRACE.as_secs() > RTBIT_INTERNAL_SHUTDOWN.as_secs()
);
/// An rtbit that ran this long without crashing resets the respawn backoff.
const RTBIT_STABLE_AFTER: Duration = Duration::from_secs(300);
const REAP_INTERVAL: Duration = Duration::from_secs(30);
const PMP_HINT_EVERY: Duration = Duration::from_secs(1800);
/// The free-space check runs at most this often; its banner at most hourly.
const DISK_CHECK_EVERY: Duration = Duration::from_secs(600);
const DISK_WARN_EVERY: Duration = Duration::from_secs(3600);
const INGRESS_STOP_GRACE: Duration = Duration::from_secs(3);
/// A proxy that does not take a status line within this time is stuck (or
/// hostile) and is restarted, so PID 1 never blocks on its pipe.
const INGRESS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Requests from the proxy are tiny JSON lines; anything longer ends the
/// request channel instead of growing PID 1's memory.
const MAX_PROXY_REQUEST_LINE: u64 = 4 << 10;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("--version" | "-V") => {
            println!("rbittorrent-supervisor {VERSION}");
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some("healthcheck") => return healthcheck(),
        Some("ingress-proxy") => return ingress::main_from_stdin(),
        Some(other) => {
            eprintln!("rbittorrent-supervisor: unknown argument `{other}` (try --help)");
            return ExitCode::from(2);
        }
    }

    // PID 1's secrets: the Supervisor token leaves the environment block,
    // and the process is not dumpable, so no other process without
    // CAP_SYS_PTRACE (rtbit runs as uid 0 without it) can open
    // /proc/1/environ or /proc/1/mem.
    ha_supervisor::take_token_from_env();
    // SAFETY: plain prctl, no pointers.
    let undumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    if !undumpable {
        eprintln!(
            "rbittorrent-supervisor: cannot clear the dumpable flag: {}",
            std::io::Error::last_os_error()
        );
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("rbittorrent-supervisor: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run())
}

fn print_help() {
    println!(
        "rbittorrent-supervisor {VERSION}
rBittorrent: PID-1 supervisor running rustTorrent (rtbit) behind a fail-closed WireGuard kill-switch
(or on a direct connection while no VPN is configured).

USAGE:
    rbittorrent-supervisor              run as the app's init process
    rbittorrent-supervisor healthcheck  exit 0 when http://127.0.0.1:8099/__health reports healthy
                                (rtbit running, fresh WireGuard handshake in VPN mode, Web UI answering)
    rbittorrent-supervisor ingress-proxy
                                internal: the Home Assistant Ingress proxy, started by the
                                supervisor itself (configuration arrives on stdin)
    rbittorrent-supervisor --version    print the version
    rbittorrent-supervisor --help       print this help

ENVIRONMENT (development/testing only):
    RBITTORRENT_OPTIONS      options file        (default {DEFAULT_OPTIONS_PATH})
    RBITTORRENT_CONFIG_ROOT  app config folder   (default /config)
    RBITTORRENT_RTBIT        rtbit binary        (default {DEFAULT_RTBIT_BINARY})
    RBITTORRENT_RESOLV_CONF  resolver file       (default {DEFAULT_RESOLV_CONF})"
    );
}

/// Docker HEALTHCHECK: the same verdict as Home Assistant's watchdog.
fn healthcheck() -> ExitCode {
    use std::io::{Read, Write};
    let addr = SocketAddr::from(([127, 0, 0, 1], config::INGRESS_PORT));
    let result = (|| -> std::io::Result<String> {
        let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
        s.set_read_timeout(Some(Duration::from_secs(8)))?;
        write!(
            s,
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            ingress::HEALTH_PATH
        )?;
        let mut reply = String::new();
        s.take(8192).read_to_string(&mut reply)?;
        Ok(reply)
    })();
    match result {
        Ok(reply) if reply.starts_with("HTTP/1.1 200") => ExitCode::SUCCESS,
        Ok(reply) => {
            let body = reply.split("\r\n\r\n").nth(1).unwrap_or("").trim();
            eprintln!("unhealthy: {body}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("unhealthy: the Ingress proxy is not answering on {addr}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn env_path(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

async fn run() -> ExitCode {
    let options_path = env_path("RBITTORRENT_OPTIONS", DEFAULT_OPTIONS_PATH);
    let options = Options::load(&options_path);
    init_logging(options.as_ref().map(|o| o.log_level).unwrap_or_default());
    info!(
        "rbittorrent supervisor {VERSION} starting (pid {})",
        std::process::id()
    );
    process::become_subreaper_if_needed();

    let mut options = match options {
        Ok(o) => o,
        Err(e) => {
            error!("{e:#}");
            return ExitCode::FAILURE;
        }
    };
    let paths = Paths {
        config_root: env_path("RBITTORRENT_CONFIG_ROOT", "/config"),
    };
    // Before validation: may provide /config/wg0.conf and the folders.
    let migration = migration::prepare(&mut options, &migration::Roots::new(&paths.config_root));
    let settings = match Settings::from_options(&options, &paths) {
        Ok(s) => s,
        Err(e) => {
            error!("configuration error: {e:#}");
            error!("fix the app configuration in Home Assistant and start the app again");
            return ExitCode::FAILURE;
        }
    };
    for note in &settings.notes {
        warn!("config: {note}");
    }
    match &settings.vpn {
        Some(v) => info!(
            "VPN mode ({}): WireGuard configuration from {}, {}",
            v.reason,
            v.source,
            if v.nat_pmp.is_some() {
                "NAT-PMP port forwarding".to_owned()
            } else {
                format!(
                    "static port {} (NAT-PMP off)",
                    settings.fallback_listen_port
                )
            }
        ),
        None => warn!(
            "{}",
            host::direct_mode_banner(settings.fallback_listen_port)
        ),
    }

    let shutdown = match spawn_signal_handlers() {
        Ok(rx) => rx,
        Err(e) => {
            error!("cannot install signal handlers: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    spawn_reaper();

    match supervise(&settings, migration, shutdown).await {
        Ok(()) => {
            info!("shutdown complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("fatal: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// SIGTERM/SIGINT flip the shutdown flag; a second signal exits immediately.
fn spawn_signal_handlers() -> Result<watch::Receiver<bool>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("SIGTERM")?;
    let mut int = signal(SignalKind::interrupt()).context("SIGINT")?;
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let name = tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = int.recv() => "SIGINT",
        };
        info!("{name} received: stopping rtbit, then the tunnel");
        let _ = tx.send(true);
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
        warn!("second signal received: exiting immediately");
        std::process::exit(130);
    });
    Ok(rx)
}

/// PID-1 duty: reap re-parented orphans on SIGCHLD (and periodically).
fn spawn_reaper() {
    use tokio::signal::unix::{SignalKind, signal};
    let sigchld = signal(SignalKind::child());
    tokio::spawn(async move {
        let mut sigchld = match sigchld {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("cannot watch SIGCHLD ({e}); reaping orphans periodically only");
                None
            }
        };
        loop {
            match sigchld.as_mut() {
                Some(s) => {
                    tokio::select! {
                        _ = s.recv() => {},
                        _ = sleep(REAP_INTERVAL) => {},
                    }
                }
                None => sleep(REAP_INTERVAL).await,
            }
            // Let tokio collect its own children first.
            sleep(Duration::from_millis(50)).await;
            process::reap_orphans();
        }
    });
}

fn shutting_down(rx: &watch::Receiver<bool>) -> bool {
    *rx.borrow()
}

/// Runs `fut` unless shutdown is requested first (then returns `None`).
async fn unless_shutdown<T>(
    rx: &mut watch::Receiver<bool>,
    fut: impl std::future::Future<Output = T>,
) -> Option<T> {
    if shutting_down(rx) {
        return None;
    }
    tokio::select! {
        v = fut => Some(v),
        _ = rx.wait_for(|v| *v) => None,
    }
}

async fn preflight(runner: &impl Runner, vpn: bool) -> Result<()> {
    if !vpn {
        // Direct mode needs no tunnel tools.
        return Ok(());
    }
    let ip = runner
        .run("ip", &["-V"], None)
        .await
        .context("`ip` from iproute2 is required")?;
    let ip_version = format!("{}{}", ip.stdout, ip.stderr);
    if !ip_version.contains("iproute2") {
        anyhow::bail!(
            "`ip` is not iproute2 ({}); BusyBox ip cannot create WireGuard links",
            ip_version.trim()
        );
    }
    let wg = runner
        .run("wg", &["--version"], None)
        .await
        .context("`wg` from wireguard-tools is required")?;
    let nft = runner
        .run("nft", &["--version"], None)
        .await
        .context("`nft` from nftables is required")?;
    info!(
        "tools: {} | {} | {}",
        ip_version.trim(),
        wg.stdout.trim(),
        nft.stdout.trim()
    );
    Ok(())
}

fn prepare_dirs(s: &Settings) -> Result<()> {
    for dir in [&s.data_home, &s.cache_home, &s.download_dir]
        .into_iter()
        .chain(&s.completed_dir)
    {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    info!(
        db = %s.data_home.display(),
        cache = %s.cache_home.display(),
        downloads = %s.download_dir.display(),
        completed = %s
            .completed_dir
            .as_deref()
            .map_or_else(|| "none (finished torrents stay in place)".into(), |p| p.display().to_string()),
        "storage ready"
    );
    Ok(())
}

async fn resolve_with_retry(endpoint: &config::Endpoint) -> Result<SocketAddrV4> {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
    let mut attempt = 1;
    loop {
        match wireguard::resolve_endpoint(endpoint).await {
            Ok(addr) => {
                info!("WireGuard endpoint {endpoint} -> {addr}");
                return Ok(addr);
            }
            Err(e) if attempt < 6 => {
                let d = backoff.next_delay();
                warn!("{e:#}; retrying in {}s", d.as_secs());
                sleep(d).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Phase 2 of the qBittorrent import plus the banner line.
struct MigrationRun {
    status: String,
    job: Option<SeedJob>,
}

async fn supervise(
    s: &Settings,
    migration: migration::Migration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let runner = SystemRunner;
    preflight(&runner, s.vpn.is_some()).await?;
    prepare_dirs(s)?;
    // Before the first rtbit command (even `auth`): no child runs without
    // a sandbox (AppArmor or Landlock) unless that was allowed here.
    let mut rtbit_spec = rtbit_spec(s);
    let sandboxed = process::check_fs_sandbox(&rtbit_spec.fs_policy(), s.allow_unsandboxed)?;
    FS_SANDBOX_ACTIVE.store(sandboxed, Ordering::Relaxed);
    host::raise_udp_buffer_limits();
    // Supervisor API: before the kill-switch (it uses the normal network).
    let bt_host_port = supervisor_checks(s).await;
    if s.vpn.is_none() {
        rtbit_spec.announce_port = direct_announce_port(bt_host_port, s.fallback_listen_port);
    }

    // The Web UI account goes into rtbit's credential store before rtbit
    // ever runs: port 8080 is never open and never waits for first-run setup.
    let (password, generated) = s.resolve_webui_password()?;
    rtbit_spec
        .set_credentials(&s.webui_username, &password)
        .await
        .context("cannot store the Web UI account in rtbit")?;
    if generated {
        warn!(
            "`webui_password` is empty: generated a random password for Web UI user `{}` and \
             saved it in /config/{} (this app's own config folder on the Samba/SSH \
             share). The Home Assistant sidebar signs in automatically; use this password for \
             LAN access and Sonarr/Radarr, or set `webui_password` yourself.",
            s.webui_username,
            config::GENERATED_PASSWORD_FILE
        );
    } else {
        info!(
            "Web UI account `{}` ready (sidebar signs in automatically, port {} needs the password)",
            s.webui_username, s.webui_port
        );
    }

    let migration = MigrationRun {
        status: migration.status.clone(),
        job: migration.has_work().then(|| SeedJob {
            api: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, s.webui_port)),
            username: s.webui_username.clone(),
            password: password.clone(),
            config_root: s.config_root.clone(),
            data_roots: config::writable_roots(&s.download_dir, s.completed_dir.as_deref()),
            migration,
        }),
    };

    let ingress_line = ingress_config_line(s, &password)?;
    drop(password);
    let Some(vpn) = s.vpn.as_ref() else {
        return supervise_direct(s, &runner, rtbit_spec, migration, ingress_line, shutdown).await;
    };

    // A. Endpoint resolution happens before DNS is locked down.
    let Some(endpoint) =
        unless_shutdown(&mut shutdown, resolve_with_retry(&vpn.wireguard.endpoint)).await
    else {
        return Ok(());
    };
    let endpoint = endpoint?;
    let (lan, connected) = wireguard::detect_lan(&runner).await?;
    info!(gateway = %lan.gateway, dev = %lan.dev, "uplink detected");

    // B. Fail-closed kill-switch before anything else talks to the network.
    // Static port mode opens `listen_port` in the very first ruleset.
    let ruleset = RulesetSpec {
        lan_iface: lan.dev.clone(),
        wg_iface: WG_IFACE.to_owned(),
        lan_cidrs: s.local_allow_cidrs.clone(),
        webui_port: s.webui_port,
        ingress_port: s.ingress_port,
        ingress_sources: config::HASSIO_NETWORK,
        endpoint,
        wg_fwmark: WG_FWMARK,
        bt_ports: s.static_bt_ports(),
        dns_servers: vpn.wireguard.dns.clone(),
    };
    firewall::install(&runner, &ruleset).await?;
    let cidrs: Vec<String> = s
        .local_allow_cidrs
        .iter()
        .map(ToString::to_string)
        .collect();
    info!(
        "kill-switch active: IPv6 dropped, LAN [{}] may only reach port {} (replies only), \
         Home Assistant {} may reach Ingress port {}, everything else must use {WG_IFACE}",
        cidrs.join(", "),
        s.webui_port,
        config::HASSIO_NETWORK,
        s.ingress_port
    );
    if let [port] = ruleset.bt_ports.as_slice() {
        info!(
            "static port mode: TCP+UDP {port} opened on {WG_IFACE} (forward this port at your VPN provider)"
        );
    }
    let resolv = env_path("RBITTORRENT_RESOLV_CONF", DEFAULT_RESOLV_CONF);
    wireguard::lock_resolv_conf(&resolv, &vpn.wireguard.dns)?;
    info!("DNS locked to {:?} via the tunnel", vpn.wireguard.dns);

    // The Ingress proxy (sidebar + watchdog) runs from here on, so the panel
    // shows a "starting" page instead of an error while the tunnel comes up.
    let (health, health_rx) = watch::channel(Health {
        detail: "connecting the WireGuard tunnel".into(),
        ..health_base()
    });
    let (stop_ingress, stop_rx) = watch::channel(false);
    let ingress_task = tokio::spawn(supervise_ingress(
        ingress_line,
        s.download_dir.clone(),
        health_rx,
        stop_rx,
    ));

    let result = run_tunnel(
        s,
        vpn,
        &runner,
        TunnelInputs {
            lan,
            connected,
            endpoint,
        },
        rtbit_spec,
        migration,
        &health,
        &mut shutdown,
    )
    .await;
    stop_ingress_task(stop_ingress, ingress_task).await;
    result
}

/// Direct connection (no VPN configured): no kill-switch, no tunnel, no
/// NAT-PMP; rtbit listens on `listen_port` on the normal network.
async fn supervise_direct(
    s: &Settings,
    runner: &SystemRunner,
    rtbit_spec: RtbitSpec,
    migration: MigrationRun,
    ingress_line: String,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // Fail closed: without these rules the Web UI would be open to anyone
    // who can reach the container, so rtbit does not start.
    let rules = DirectSpec {
        lan_cidrs: s.local_allow_cidrs.clone(),
        webui_port: s.webui_port,
        ingress_port: s.ingress_port,
        ingress_sources: config::HASSIO_NETWORK,
        published_bt_port: config::DEFAULT_LISTEN_PORT,
        listen_port: s.fallback_listen_port,
    };
    firewall::install_direct(runner, &rules).await?;
    let cidrs: Vec<String> = s
        .local_allow_cidrs
        .iter()
        .map(ToString::to_string)
        .collect();
    info!(
        "direct connection: LAN [{}] may reach port {}, Home Assistant {} may reach Ingress port {}",
        cidrs.join(", "),
        s.webui_port,
        config::HASSIO_NETWORK,
        s.ingress_port
    );
    if rules.listen_port != rules.published_bt_port {
        info!(
            "direct connection: container port {} (TCP+UDP) is redirected to listen_port {}",
            rules.published_bt_port, rules.listen_port
        );
    }
    let (health, health_rx) = watch::channel(Health {
        direct: true,
        port: Some(s.fallback_listen_port),
        detail: "starting rtbit on a direct connection (VPN off)".into(),
        ..health_base()
    });
    let (stop_ingress, stop_rx) = watch::channel(false);
    let ingress_task = tokio::spawn(supervise_ingress(
        ingress_line,
        s.download_dir.clone(),
        health_rx,
        stop_rx,
    ));
    let result = run_session(
        s,
        None,
        runner,
        rtbit_spec,
        migration,
        &health,
        &mut shutdown,
    )
    .await;
    stop_ingress_task(stop_ingress, ingress_task).await;
    result
}

async fn stop_ingress_task(stop: watch::Sender<bool>, mut task: tokio::task::JoinHandle<()>) {
    let _ = stop.send(true);
    if tokio::time::timeout(INGRESS_STOP_GRACE * 2, &mut task)
        .await
        .is_err()
    {
        warn!("the Ingress proxy did not stop in time; stopping it");
        // Dropping the task drops the child, which kills it.
        task.abort();
        let _ = task.await;
    }
}

/// What the tunnel needs from the uplink detection.
struct TunnelInputs {
    lan: wireguard::LanRoute,
    connected: Vec<rbittorrent_supervisor::cidr::Ipv4Cidr>,
    endpoint: SocketAddrV4,
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    s: &Settings,
    vpn: &VpnSettings,
    runner: &SystemRunner,
    uplink: TunnelInputs,
    rtbit_spec: RtbitSpec,
    migration: MigrationRun,
    health: &watch::Sender<Health>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    // C. Tunnel, retried until it works (rtbit never starts without it).
    let nat_pmp_gateway = vpn.nat_pmp.as_ref().map(|n| n.gateway);
    let plan = TunnelPlan {
        lan: uplink.lan,
        endpoint: uplink.endpoint,
        lan_routes: wireguard::plan_lan_routes(&s.local_allow_cidrs, &uplink.connected),
        tunnel_hosts: wireguard::tunnel_hosts(&vpn.wireguard.dns, nat_pmp_gateway),
    };
    let probe_ip = nat_pmp_gateway
        .or_else(|| vpn.wireguard.dns.first().copied())
        .unwrap_or(config::PROTON_GATEWAY);
    let probe = SocketAddrV4::new(probe_ip, natpmp::NATPMP_PORT);
    let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(300));
    loop {
        let attempt = async {
            wireguard::bring_up(runner, &vpn.wireguard, &plan).await?;
            wireguard::wait_for_handshake(runner, &vpn.wireguard, probe, HANDSHAKE_TIMEOUT).await
        };
        match unless_shutdown(shutdown, attempt).await {
            None => {
                wireguard::tear_down(runner).await;
                return Ok(());
            }
            Some(Ok(())) => break,
            Some(Err(e)) => {
                error!("tunnel setup failed: {e:#}");
                wireguard::tear_down(runner).await;
                let d = backoff.next_delay();
                warn!(
                    "retrying the tunnel in {}s (rtbit stays stopped)",
                    d.as_secs()
                );
                let _ = health.send(Health {
                    detail: format!(
                        "WireGuard tunnel setup failed; retrying in {}s",
                        d.as_secs()
                    ),
                    ..health_base()
                });
                if unless_shutdown(shutdown, sleep(d)).await.is_none() {
                    return Ok(());
                }
            }
        }
    }

    // D. Port forwarding + rtbit.
    let result = run_session(
        s,
        Some(vpn),
        runner,
        rtbit_spec,
        migration,
        health,
        shutdown,
    )
    .await;
    wireguard::tear_down(runner).await;
    result
}

/// Port-conflict guard and discovery through the Supervisor API. Best
/// effort: nothing here can stop the app. Returns the host port Home
/// Assistant publishes the BitTorrent port on, when it could be read.
async fn supervisor_checks(s: &Settings) -> Option<ha_supervisor::HostPort> {
    let Some(api) = ha_supervisor::SupervisorApi::from_env().await else {
        debug!(
            "no SUPERVISOR_TOKEN (not running under Home Assistant): skipping Supervisor checks"
        );
        return None;
    };
    let slugs: Vec<String> = migration::candidate_roots(&migration::Roots::new(&s.config_root))
        .into_iter()
        .filter_map(|(_, slug)| slug)
        .collect();
    let apps = api.qbittorrent_apps(&slugs).await;
    if let Some(banner) = ha_supervisor::conflict_banner(&apps, s.webui_port) {
        warn!("{banner}");
    } else if !apps.is_empty() {
        let names: Vec<&str> = apps.iter().map(|a| a.slug.as_str()).collect();
        info!(
            "qBittorrent app(s) installed but not running: {}",
            names.join(", ")
        );
    }
    let config = match ha_supervisor::own_hostname() {
        Some(host) => serde_json::json!({ "host": host, "port": s.webui_port, "ssl": false }),
        None => serde_json::json!({ "port": s.webui_port, "ssl": false }),
    };
    match api.announce("qbittorrent", config).await {
        Ok(_) => info!(
            "offered the qBittorrent API (port {}) to Home Assistant's discovery",
            s.webui_port
        ),
        Err(e) => debug!("Home Assistant discovery not available: {e:#}"),
    }
    let bt = format!("{}/tcp", config::DEFAULT_LISTEN_PORT);
    match api.own_host_port(&bt).await {
        Ok(p) => p,
        Err(e) => {
            debug!("cannot read the app's port mapping: {e:#}");
            None
        }
    }
}

/// On a direct connection peers reach rtbit through the host port Home
/// Assistant maps to container port 4240 (redirected to `listen_port`
/// inside), so that is the port to announce when it differs.
fn direct_announce_port(mapped: Option<ha_supervisor::HostPort>, listen_port: u16) -> Option<u16> {
    use ha_supervisor::HostPort;
    let published = config::DEFAULT_LISTEN_PORT;
    match mapped {
        Some(HostPort::Mapped(p)) if p != listen_port => {
            info!(
                "direct connection: Home Assistant publishes container port {published} on host \
                 port {p}; rtbit announces port {p} to trackers and the DHT"
            );
            Some(p)
        }
        Some(HostPort::Mapped(_)) | None => None,
        Some(HostPort::Unmapped) => {
            info!(
                "direct connection: container port {published} is not published (the app's \
                 Network settings): peers cannot connect to you, only you to them"
            );
            None
        }
    }
}

/// Whether rtbit's Landlock sandbox is active (set once at startup).
static FS_SANDBOX_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The parts of [`Health`] that never change after startup.
fn health_base() -> Health {
    Health {
        unsandboxed: !FS_SANDBOX_ACTIVE.load(Ordering::Relaxed),
        ..Health::default()
    }
}

fn rtbit_spec(s: &Settings) -> RtbitSpec {
    RtbitSpec {
        binary: env_path("RBITTORRENT_RTBIT", DEFAULT_RTBIT_BINARY),
        // Inside the sandbox's writable folders (with Landlock, /config
        // itself is out of reach).
        home: s.data_home.clone(),
        data_home: s.data_home.clone(),
        cache_home: s.cache_home.clone(),
        download_dir: s.download_dir.clone(),
        completed_dir: s.completed_dir.clone(),
        webui_port: s.webui_port,
        // VPN mode: bound to wg0 and its address; direct mode: any interface.
        bind_device: s.vpn.as_ref().map(|_| WG_IFACE.to_owned()),
        // Set from Home Assistant's port mapping on a direct connection.
        announce_port: None,
        listen_ip: s.vpn.as_ref().map(|v| v.wireguard.address.addr()),
        log_level: s.log_level,
        dht: s.enable_dht,
        shutdown_timeout: RTBIT_INTERNAL_SHUTDOWN,
        sandbox: true,
    }
}

fn ingress_config_line(s: &Settings, password: &Secret) -> Result<String> {
    let cfg = ingress::ProxyConfig {
        listen: SocketAddr::from(([0, 0, 0, 0], s.ingress_port)),
        upstream: SocketAddr::from(([127, 0, 0, 1], s.webui_port)),
        // Ingress and the watchdog always come from the Supervisor. Other apps
        // on 172.30.32.0/23 pass the firewall but are refused here: they must
        // never inherit the automatic sign-in. Loopback (the Docker
        // HEALTHCHECK) may only read /__health: rtbit shares this network
        // namespace.
        allowed_peers: vec![format!("{}/32", ingress::SUPERVISOR_IP)],
        health_only_peers: vec!["127.0.0.1/32".to_owned()],
        username: s.webui_username.clone(),
        password: password.expose().to_owned(),
        log_level: s.log_level,
        speed_target: None,
        peering: None,
    };
    serde_json::to_string(&cfg).context("cannot encode the Ingress configuration")
}

/// Keeps the Ingress proxy child running, feeds it health heartbeats and
/// answers its requests (the disk half of the speed test).
async fn supervise_ingress(
    config_line: String,
    download_dir: PathBuf,
    mut health: watch::Receiver<Health>,
    mut stop: watch::Receiver<bool>,
) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            error!("cannot locate the supervisor binary for the Ingress proxy: {e}");
            return;
        }
    };
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    let mut health_open = true;
    loop {
        if *stop.borrow() {
            return;
        }
        let started = Instant::now();
        let (mut child, pipes) = match process::spawn_ingress(&exe, &config_line, true).await {
            Ok(x) => x,
            Err(e) => {
                error!("{e:#}");
                if unless_shutdown(&mut stop, sleep(backoff.next_delay()))
                    .await
                    .is_none()
                {
                    return;
                }
                continue;
            }
        };
        let process::IngressPipes { mut stdin, stdout } = pipes;
        let (request_tx, mut requests) = tokio::sync::mpsc::channel::<String>(4);
        let reader = tokio::spawn(read_proxy_requests(stdout, request_tx));
        let mut requests_open = true;
        let mut hardware_job: Option<(u64, tokio::task::JoinHandle<benchmark::HardwareResult>)> =
            None;
        let current = health.borrow_and_update().clone();
        let mut stuck = !send_line(&mut stdin, &health_line(&current)).await;
        let status = loop {
            if stuck {
                warn!("the Ingress proxy stopped reading its status pipe; restarting it");
                child.start_kill().ok();
                stuck = false;
            }
            tokio::select! {
                status = child.wait() => break Some(status),
                changed = health.changed(), if health_open => {
                    if changed.is_err() {
                        health_open = false;
                        continue;
                    }
                    let h = health.borrow_and_update().clone();
                    stuck = !send_line(&mut stdin, &health_line(&h)).await;
                }
                line = requests.recv(), if requests_open => match line {
                    Some(line) => match serde_json::from_str::<ingress::ProxyRequest>(&line) {
                        Ok(ingress::ProxyRequest::Hardware { id }) if hardware_job.is_none() => {
                            let dir = download_dir.clone();
                            hardware_job = Some((id, tokio::task::spawn_blocking(move || {
                                benchmark::run_hardware(&dir, host::cpu_cores())
                            })));
                        }
                        Ok(ingress::ProxyRequest::Hardware { id }) => {
                            // An earlier test (one the proxy gave up on, e.g.
                            // on a stalled network disk) still runs: answer
                            // now instead of letting this one wait for it.
                            let busy = benchmark::HardwareResult {
                                disk_error: Some(
                                    "the disk test from an earlier run has not finished (a slow \
                                     or stalled disk?); try again later"
                                        .to_owned(),
                                ),
                                cpu_cores: host::cpu_cores(),
                                ..benchmark::HardwareResult::default()
                            };
                            stuck = !send_line(&mut stdin, &ingress::hardware_line(&busy, id)).await;
                        }
                        Err(e) => debug!("ignoring an unknown request from the Ingress proxy: {e}"),
                    },
                    None => requests_open = false,
                },
                (id, result) = async {
                    match hardware_job.as_mut() {
                        Some((id, job)) => (*id, job.await),
                        None => std::future::pending().await,
                    }
                }, if hardware_job.is_some() => {
                    hardware_job = None;
                    match result {
                        Ok(r) => {
                            if let Some(e) = &r.disk_error {
                                warn!("speed test: {e}");
                            }
                            stuck = !send_line(&mut stdin, &ingress::hardware_line(&r, id)).await;
                        }
                        Err(e) => warn!("speed test: the disk test failed: {e}"),
                    }
                }
                () = stop_requested(&mut stop) => break None,
            }
        };
        reader.abort();
        let Some(status) = status else {
            // EOF on its stdin makes the proxy exit by itself.
            drop(stdin);
            if tokio::time::timeout(INGRESS_STOP_GRACE, child.wait())
                .await
                .is_err()
            {
                child.start_kill().ok();
                let _ = child.wait().await;
            }
            return;
        };
        match status {
            Ok(st) => warn!("the Ingress proxy exited ({st}); restarting it"),
            Err(e) => warn!("waiting for the Ingress proxy failed: {e}"),
        }
        if started.elapsed() >= Duration::from_secs(60) {
            backoff.reset();
        }
        if unless_shutdown(&mut stop, sleep(backoff.next_delay()))
            .await
            .is_none()
        {
            return;
        }
    }
}

async fn stop_requested(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

fn health_line(h: &Health) -> String {
    serde_json::to_string(h).unwrap_or_default()
}

/// Sends one line to the proxy. `false` when the proxy did not take it in
/// time (a pipe it no longer reads): the caller restarts it.
async fn send_line(stdin: &mut tokio::process::ChildStdin, line: &str) -> bool {
    if line.is_empty() {
        return true;
    }
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    match tokio::time::timeout(INGRESS_SEND_TIMEOUT, stdin.write_all(&buf)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            // The proxy exited; `child.wait()` reports it.
            debug!("cannot send a line to the Ingress proxy: {e}");
            true
        }
        Err(_) => false,
    }
}

/// Reads the proxy's request lines, each at most [`MAX_PROXY_REQUEST_LINE`]
/// bytes. A longer line, or the end of the pipe, ends the channel.
async fn read_proxy_requests(
    stdout: tokio::process::ChildStdout,
    tx: tokio::sync::mpsc::Sender<String>,
) {
    use tokio::io::AsyncReadExt as _;
    let mut reader = tokio::io::BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_PROXY_REQUEST_LINE)
            .read_line(&mut line)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(_) if !line.ends_with('\n') => {
                warn!(
                    "the Ingress proxy sent an over-long request; ignoring its requests until it restarts"
                );
                return;
            }
            Ok(_) => {
                if tx.send(line.trim_end().to_owned()).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// NAT-PMP failure bookkeeping, so logs stay informative but not noisy.
#[derive(Debug, Default)]
struct PmpHealth {
    failures: u32,
    ever_succeeded: bool,
    last_hint: Option<Instant>,
}

impl PmpHealth {
    fn success(&mut self) {
        if self.failures > 0 && self.ever_succeeded {
            info!("NAT-PMP port forwarding recovered");
        }
        self.failures = 0;
        self.ever_succeeded = true;
    }

    fn failure(&mut self, e: &NatPmpError, fallback_port: u16) {
        self.failures += 1;
        let hint_due = self.last_hint.is_none_or(|t| t.elapsed() >= PMP_HINT_EVERY);
        if e.needs_pmp_hint() && !self.ever_succeeded && hint_due {
            warn!("NAT-PMP: {e}");
            warn!("{}", natpmp::PMP_HINT);
            warn!(
                "continuing without a forwarded port (rtbit listens on {fallback_port}, \
                 downloads work, but peers cannot connect to you); retrying in the background"
            );
            self.last_hint = Some(Instant::now());
        } else if self.failures == 1 {
            warn!("NAT-PMP renewal failed: {e}; retrying shortly");
        } else {
            debug!(failures = self.failures, "NAT-PMP still failing: {e}");
        }
    }
}

struct Session<'a, R: Runner> {
    runner: &'a R,
    rtbit: Rtbit,
    respawn: Backoff,
    respawn_at: Option<Instant>,
    /// Port rtbit is (or should be) listening on.
    listen_port: u16,
    /// Last NAT-PMP port applied to firewall + rtbit (None = fallback port).
    applied_lease: Option<u16>,
    /// The TCP and UDP ports currently in the kill-switch's `@bt_port` set
    /// (NAT-PMP mode).
    applied_ports: Vec<u16>,
    /// When the gateway drops the current mappings unless they are renewed.
    lease_expires: Option<Instant>,
    tunnel_healthy: bool,
    /// Direct connection: no tunnel, no kill-switch.
    direct: bool,
    nat_pmp: bool,
    public_ip: Option<Ipv4Addr>,
    download_dir: PathBuf,
    disk_checked: Option<Instant>,
    disk_warned: Option<Instant>,
    /// The startup banner was logged; later port changes log it again.
    announced: bool,
    /// qBittorrent import, for the banner.
    migration_status: String,
    health: &'a watch::Sender<Health>,
    /// rtbit starts so far ([`Health::generation`]).
    rtbit_starts: u64,
}

impl<R: Runner> Session<'_, R> {
    fn start_rtbit(&mut self) {
        if self.rtbit.is_running() {
            return;
        }
        self.check_disk(true);
        match self.rtbit.spawn(self.listen_port) {
            Ok(()) => {
                self.respawn_at = None;
                // The proxy drops its rtbit sessions when this changes.
                self.rtbit_starts += 1;
            }
            Err(e) => {
                error!("{e:#}");
                self.schedule_respawn();
            }
        }
        self.publish();
    }

    /// Sends the current state to the Ingress proxy (`/__health`).
    fn publish(&self) {
        let detail = if !self.direct && !self.tunnel_healthy {
            "the WireGuard tunnel has no recent handshake"
        } else if !self.rtbit.is_running() {
            "rtbit is not running (restarting)"
        } else if self.direct {
            "rtbit is running on a direct connection (VPN off)"
        } else {
            "rtbit is running behind the VPN"
        };
        // Only a port peers can actually reach: none while NAT-PMP has no
        // (or an expired) lease.
        let port = match self.port_state() {
            PortState::Pending(_) => None,
            PortState::Forwarded(p) | PortState::Static(p) | PortState::Direct(p) => Some(p),
        };
        let _ = self.health.send(Health {
            rtbit: self.rtbit.is_running(),
            tunnel: !self.direct && self.tunnel_healthy,
            port,
            detail: detail.into(),
            direct: self.direct,
            public_ip: self.public_ip,
            generation: self.rtbit_starts,
            unsandboxed: !FS_SANDBOX_ACTIVE.load(Ordering::Relaxed),
        });
    }

    /// Free-space guard for the download folder (a USB disk that is not
    /// mounted makes /media fall back to Home Assistant's own disk).
    fn check_disk(&mut self, force: bool) {
        let now = Instant::now();
        if !force
            && self
                .disk_checked
                .is_some_and(|t| now - t < DISK_CHECK_EVERY)
        {
            return;
        }
        self.disk_checked = Some(now);
        let low = host::available_bytes(&self.download_dir).is_ok_and(|b| b < host::LOW_DISK_BYTES);
        if !low {
            self.disk_warned = None;
        } else if self.disk_warned.is_none_or(|t| now - t >= DISK_WARN_EVERY) {
            host::warn_if_low_disk(&self.download_dir);
            self.disk_warned = Some(now);
        }
    }

    fn port_state(&self) -> PortState {
        if self.direct {
            return PortState::Direct(self.listen_port);
        }
        match (self.nat_pmp, self.applied_lease) {
            (false, _) => PortState::Static(self.listen_port),
            (true, Some(p)) => PortState::Forwarded(p),
            (true, None) => PortState::Pending(self.listen_port),
        }
    }

    fn log_banner(&mut self) {
        self.announced = true;
        info!(
            "{}",
            host::status_banner(
                self.public_ip,
                self.port_state(),
                &self.migration_status,
                host::cpu_cores(),
                &host::storage_summary(&self.download_dir),
            )
        );
    }

    fn schedule_respawn(&mut self) {
        let d = self.respawn.next_delay();
        warn!("restarting rtbit in {}s", d.as_secs());
        self.respawn_at = Some(Instant::now() + d);
    }

    /// Applies a freshly leased port: firewall first (TCP and UDP), then
    /// rtbit, and only what actually changed.
    async fn apply_lease(&mut self, lease: &natpmp::Lease) {
        let ports = lease.firewall_ports();
        if ports != self.applied_ports {
            if let Err(e) = firewall::set_bt_ports(self.runner, &ports).await {
                error!("{e:#}; keeping the previous port for now");
                return;
            }
            self.applied_ports = ports;
        }
        self.lease_expires =
            Some(Instant::now() + Duration::from_secs(u64::from(lease.lifetime.max(1))));
        match natpmp::decide(self.applied_lease, lease.port) {
            PortDecision::Unchanged => {
                debug!(
                    port = lease.port,
                    udp = lease.udp_port,
                    lifetime = lease.lifetime,
                    "NAT-PMP lease renewed"
                );
            }
            PortDecision::Changed { old, new } => {
                match old {
                    None => info!(
                        port = new,
                        "NAT-PMP forwarded port {new} (TCP+UDP) opened on {WG_IFACE}"
                    ),
                    Some(o) => {
                        info!("NAT-PMP forwarded port changed {o} -> {new}; restarting rtbit")
                    }
                }
                self.applied_lease = Some(new);
                if self.listen_port != new {
                    self.listen_port = new;
                    if self.rtbit.is_running() {
                        self.rtbit.stop(RTBIT_RESTART_GRACE).await;
                    }
                    self.restart_when_ready();
                }
                if self.announced {
                    self.log_banner();
                }
                self.publish();
            }
        }
    }

    /// Starts rtbit now if nothing stands in the way; otherwise the respawn
    /// timer starts it (crash backoff, or a tunnel without a handshake).
    fn restart_when_ready(&mut self) {
        if self.respawn_at.is_some() {
            return;
        }
        if self.tunnel_healthy {
            self.start_rtbit();
        } else {
            info!(
                "rtbit starts on port {} once the tunnel is healthy again",
                self.listen_port
            );
            self.respawn_at = Some(Instant::now());
            self.publish();
        }
    }

    /// Renewals failed for longer than the lease lifetime: the gateway has
    /// dropped the mapping, so the port is closed again and the status bar
    /// stops showing it. The next successful lease opens it again.
    async fn expire_lease_if_stale(&mut self) {
        if self.applied_lease.is_none() || self.lease_expires.is_none_or(|t| Instant::now() < t) {
            return;
        }
        warn!(
            "the NAT-PMP lease on port {} expired without a renewal; inbound peers cannot reach \
             rtbit until a new port is leased",
            self.listen_port
        );
        match firewall::set_bt_ports(self.runner, &[]).await {
            Ok(()) => self.applied_ports.clear(),
            Err(e) => error!("{e:#}"),
        }
        self.applied_lease = None;
        self.lease_expires = None;
        self.publish();
    }
}

/// Asks the gateway for the VPN exit address; keeps the old one on errors.
async fn refresh_public_ip<R: Runner>(f: &PortForwarder, session: &mut Session<'_, R>) {
    match f.client().external_address().await {
        Ok(ext) if wireguard::is_public(ext.ip.into()) => {
            if session.public_ip.is_some_and(|ip| ip != ext.ip) {
                info!("VPN exit address is now {}", ext.ip);
            }
            session.public_ip = Some(ext.ip);
        }
        Ok(ext) => warn!("NAT-PMP reports a non-public address {}", ext.ip),
        Err(e) => debug!("NAT-PMP external address: {e}"),
    }
}

async fn run_session(
    s: &Settings,
    vpn: Option<&VpnSettings>,
    runner: &impl Runner,
    rtbit_spec: RtbitSpec,
    migration: MigrationRun,
    health: &watch::Sender<Health>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut session = Session {
        runner,
        rtbit: Rtbit::new(rtbit_spec),
        respawn: Backoff::new(Duration::from_secs(2), Duration::from_secs(120)),
        respawn_at: None,
        listen_port: s.fallback_listen_port,
        applied_lease: None,
        applied_ports: Vec::new(),
        lease_expires: None,
        tunnel_healthy: true,
        direct: vpn.is_none(),
        nat_pmp: vpn.is_some_and(|v| v.nat_pmp.is_some()),
        public_ip: None,
        download_dir: s.download_dir.clone(),
        disk_checked: None,
        disk_warned: None,
        announced: false,
        migration_status: migration.status,
        health,
        rtbit_starts: 0,
    };
    let _ = health.send(Health {
        tunnel: vpn.is_some(),
        direct: vpn.is_none(),
        detail: if vpn.is_some() {
            "tunnel up; leasing a port and starting rtbit".into()
        } else {
            "starting rtbit on a direct connection (VPN off)".into()
        },
        ..health_base()
    });

    // NAT-PMP: verify the public IP through the tunnel, then lease a port.
    let mut forwarder = match vpn.and_then(|v| v.nat_pmp.as_ref().map(|n| (v, n))) {
        Some((v, n)) => {
            let gw = SocketAddrV4::new(n.gateway, natpmp::NATPMP_PORT);
            let client = Client::connect(v.wireguard.address.addr(), gw)
                .await
                .with_context(|| format!("cannot open the NAT-PMP socket towards {gw}"))?;
            Some(PortForwarder::new(client))
        }
        None => None,
    };
    let mut pmp = PmpHealth::default();
    let mut pmp_retry = Backoff::new(Duration::from_secs(10), Duration::from_secs(300));
    let mut next_pmp = Instant::now() + natpmp::RENEW_INTERVAL;

    if let Some(f) = forwarder.as_mut() {
        match f.client().external_address().await {
            Ok(ext) => {
                if wireguard::is_public(ext.ip.into()) {
                    info!(
                        "VPN exit verified: public IPv4 {} (NAT-PMP epoch {})",
                        ext.ip, ext.epoch
                    );
                    session.public_ip = Some(ext.ip);
                } else {
                    warn!("NAT-PMP reports a non-public address {}", ext.ip);
                }
            }
            Err(e) => debug!("NAT-PMP external address: {e}"),
        }
        match f.lease().await {
            Ok(lease) => {
                pmp.success();
                session.apply_lease(&lease).await;
                next_pmp = Instant::now() + natpmp::renew_after(lease.lifetime);
            }
            Err(e) => {
                pmp.failure(&e, s.fallback_listen_port);
                next_pmp = Instant::now() + pmp_retry.next_delay();
            }
        }
    } else if vpn.is_some() {
        // Static port mode: the kill-switch opened the port at install time.
        info!(
            "NAT-PMP disabled: rtbit listens on the static port {} on {WG_IFACE}",
            s.fallback_listen_port
        );
    } else {
        info!(
            "direct connection: rtbit listens on port {} (TCP+UDP) on the normal network",
            s.fallback_listen_port
        );
    }
    session.start_rtbit();
    session.log_banner();
    // qBittorrent categories/torrents go in through rtbit's own API.
    let mut seeding = migration.job.map(|job| tokio::spawn(migration::seed(job)));

    let mut health = tokio::time::interval(HEALTH_INTERVAL);
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    health.tick().await; // the first tick fires immediately
    let mut stale_since: Option<Instant> = None;
    let mut handshakes = wireguard::HandshakeClock::default();
    let mut stale_escalated = false;

    loop {
        tokio::select! {
            _ = shutdown.wait_for(|v| *v) => break,

            res = async {
                match seeding.as_mut() {
                    Some(task) => task.await,
                    None => std::future::pending().await,
                }
            }, if seeding.is_some() => {
                seeding = None;
                match res {
                    Ok(Ok(report)) => {
                        migration::log_report(&report);
                        session.migration_status =
                            format!("{}; {}", session.migration_status, report.summary());
                    }
                    Ok(Err(e)) => warn!("qBittorrent import: {e:#} (tried again at the next start)"),
                    Err(e) => warn!("qBittorrent import task failed: {e}"),
                }
            }

            status = session.rtbit.exited() => {
                match status {
                    Ok(st) => error!("rtbit exited unexpectedly ({st})"),
                    Err(e) => error!("rtbit wait failed: {e}"),
                }
                session.publish();
                session.schedule_respawn();
            }

            _ = sleep_until(session.respawn_at.unwrap_or_else(Instant::now)), if session.respawn_at.is_some() => {
                if session.tunnel_healthy {
                    session.respawn_at = None;
                    session.start_rtbit();
                } else {
                    debug!("tunnel unhealthy; delaying rtbit restart");
                    session.respawn_at = Some(Instant::now() + Duration::from_secs(10));
                }
            }

            _ = sleep_until(next_pmp), if forwarder.is_some() => {
                if let Some(f) = forwarder.as_mut() {
                    match f.lease().await {
                        Ok(lease) => {
                            pmp.success();
                            pmp_retry.reset();
                            if lease.gateway_restarted {
                                warn!("NAT-PMP gateway restarted (epoch went backwards); mappings were re-created");
                            }
                            // A restarted gateway may come back with another exit address.
                            if session.public_ip.is_none() || lease.gateway_restarted {
                                refresh_public_ip(f, &mut session).await;
                            }
                            session.apply_lease(&lease).await;
                            next_pmp = Instant::now() + natpmp::renew_after(lease.lifetime);
                        }
                        Err(e) => {
                            pmp.failure(&e, s.fallback_listen_port);
                            next_pmp = Instant::now() + pmp_retry.next_delay();
                            session.expire_lease_if_stale().await;
                        }
                    }
                }
            }

            _ = health.tick() => {
                if session.rtbit.uptime().is_some_and(|u| u >= RTBIT_STABLE_AFTER) {
                    session.respawn.reset();
                }
                let Some(vpn) = vpn else {
                    session.check_disk(false);
                    session.publish();
                    continue;
                };
                let age = wireguard::handshake_timestamp(runner, &vpn.wireguard)
                    .await
                    .map(|ts| {
                        ts.map(|ts| {
                            handshakes.age(ts, wireguard::wall_secs(), std::time::Instant::now())
                        })
                    });
                let fresh = matches!(age, Ok(Some(a)) if a <= HANDSHAKE_STALE_AFTER);
                if fresh {
                    if !session.tunnel_healthy {
                        info!("WireGuard tunnel healthy again");
                    }
                    session.tunnel_healthy = true;
                    stale_since = None;
                    stale_escalated = false;
                } else {
                    if session.tunnel_healthy {
                        warn!(
                            "no WireGuard handshake for over {}s ({age:?}); all torrent traffic is \
                             blocked by the kill-switch until the tunnel recovers",
                            HANDSHAKE_STALE_AFTER.as_secs()
                        );
                        stale_since = Some(Instant::now());
                    }
                    session.tunnel_healthy = false;
                    if !stale_escalated && stale_since.is_some_and(|t| t.elapsed() >= STALE_ESCALATE_AFTER) {
                        error!(
                            "the VPN server {} has not answered for 10 minutes; restart the app \
                             (re-resolves the endpoint) or generate a config for another Proton server",
                            vpn.wireguard.endpoint
                        );
                        stale_escalated = true;
                    }
                }
                session.expire_lease_if_stale().await;
                session.check_disk(false);
                session.publish();
            }
        }
    }

    if let Some(task) = seeding {
        task.abort();
    }
    // Orderly shutdown: rtbit flushes its session DB, then mappings go, then wg0.
    session.rtbit.stop(RTBIT_SHUTDOWN_GRACE).await;
    if let Some(f) = forwarder.as_mut() {
        f.release().await;
    }
    Ok(())
}
