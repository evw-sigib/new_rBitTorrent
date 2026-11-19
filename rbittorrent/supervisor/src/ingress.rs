//! Home Assistant Ingress reverse proxy (`rbittorrent-supervisor ingress-proxy`).
//!
//! The Supervisor forwards `https://<ha>/api/hassio_ingress/<token>/...` to
//! this proxy on port 8099 with the prefix stripped and announced in the
//! `X-Ingress-Path` header. The proxy:
//!
//! * accepts connections only from the allowed peers (Home Assistant's
//!   Supervisor, plus loopback); everyone else gets `403` before any HTTP is
//!   parsed,
//! * forwards HTTP, streaming bodies (SSE, uploads) and WebSocket upgrades to
//!   rtbit on `127.0.0.1:8080`,
//! * signs in to rtbit with the configured Web UI account and injects that
//!   session into every request (`Authorization: Bearer` for rtbit's API, the
//!   `SID` cookie for the qBittorrent-compatible `/api/v2`), so the sidebar
//!   needs no second login while port 8080 stays password-protected,
//! * keeps the single-page app inside the Ingress path: absolute redirects and
//!   cookie paths get the prefix, and HTML pages get a `<base href>` plus a
//!   small script that prefixes root-relative `fetch`/`XMLHttpRequest`/
//!   `WebSocket`/`EventSource`/link URLs,
//! * answers with a self-refreshing "starting" page while rtbit is down
//!   (waiting for the VPN, port change), never with a blank page,
//! * serves `GET /__health` for Home Assistant's watchdog: `200` only while
//!   rtbit runs, the WireGuard handshake is fresh (VPN mode) and rtbit
//!   answers,
//! * adds a status bar to the web UI: a dismissible "Direct Connection
//!   (Unprotected)" notice with setup links while the VPN is off, a green
//!   "VPN Protected" pill while it is on, both with a speed-test button,
//! * serves `POST /__benchmark`, the on-demand speed test (see
//!   [`crate::benchmark`]): nothing of it exists until the button is pressed.
//!
//! It runs as its own process with uid/gid 65534 and no capabilities. Its
//! stdin is a pipe from the supervisor: the first line is the configuration
//! (including the password), every further line a [`Health`] heartbeat or
//! the answer to a request. Its stdout is a pipe the other way, for requests
//! ([`ProxyRequest`]: the disk half of the speed test needs the supervisor's
//! access to the download folder); its log goes to stderr.

use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::{Body as _, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::benchmark::{self, HardwareResult, PeeringTarget, SpeedTarget};
use crate::cidr::Ipv4Cidr;
use crate::config::LogLevel;

/// Home Assistant's Supervisor: the only source of Ingress traffic.
pub const SUPERVISOR_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 32, 2);
/// What the Supervisor puts in front of every Ingress URL.
pub const INGRESS_PATH_PREFIX: &str = "/api/hassio_ingress/";

const MAX_CONNECTIONS: usize = 128;
/// Connections from health-only peers (the Docker HEALTHCHECK) have their
/// own small pool, so Ingress traffic can never starve the watchdog.
const MAX_HEALTH_ONLY_CONNECTIONS: usize = 8;
/// Also the idle keep-alive limit: hyper starts this timer whenever the
/// connection waits for the next request head.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Handshake plus response headers from rtbit (a streamed body may then
/// take as long as it needs).
const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// A whole sign-in or token refresh, body included.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on a token lifetime rtbit announces.
const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// `POST /__benchmark` takes no input; anything bigger is refused.
const MAX_BENCHMARK_BODY: usize = 16 << 10;
/// Upper bound for an HTML page that gets the base/shim injected.
const MAX_REWRITE_BYTES: usize = 4 << 20;
/// Upper bound for rtbit's login responses.
const MAX_AUTH_BODY: usize = 64 << 10;
/// Renew an access token this long before it expires.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(300);
/// rtbit drops idle qBittorrent sessions after an hour; renew well before.
const SID_LIFETIME: Duration = Duration::from_secs(30 * 60);
/// After rtbit rejected the configured account, wait before trying again
/// (rtbit rate-limits failed logins).
const LOGIN_RETRY_AFTER: Duration = Duration::from_secs(30);
const LOGIN_WARN_EVERY: Duration = Duration::from_secs(600);
const REJECT_LOG_EVERY: Duration = Duration::from_secs(60);
const MAX_CONFIG_BYTES: u64 = 64 << 10;
/// The supervisor reports every 30 s; older news means it is stuck.
const HEALTH_STALE_AFTER: Duration = Duration::from_secs(90);
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Path of the watchdog endpoint (`watchdog:` in config.yaml).
pub const HEALTH_PATH: &str = "/__health";
/// Path of the on-demand speed test.
pub const BENCHMARK_PATH: &str = "/__benchmark";
/// After a speed test, wait this long before the next one.
const BENCHMARK_COOLDOWN: Duration = Duration::from_secs(10);
/// How long the supervisor may take for the disk/SHA-1 half.
const HARDWARE_TIMEOUT: Duration = Duration::from_secs(20);
/// The setup guides the status bar links to.
pub const DOCS_URL: &str =
    "https://github.com/evw-sigib/new_rbittorrent/blob/main/rbittorrent/DOCS.md";

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Body type used for every request and response the proxy produces.
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What the supervisor hands to `rbittorrent-supervisor ingress-proxy` on stdin.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    /// Peers that may use the proxy, as CIDRs (`172.30.32.2/32`).
    pub allowed_peers: Vec<String>,
    /// Peers that may only read `/__health` (`127.0.0.1/32` for the Docker
    /// HEALTHCHECK): rtbit shares the network namespace, so loopback must
    /// never reach the signed-in proxy or the speed test.
    #[serde(default)]
    pub health_only_peers: Vec<String>,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub log_level: LogLevel,
    /// Speed-test server; `None` is Cloudflare (only tests change it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_target: Option<SpeedTarget>,
    /// Regional peering targets; `None` is [`benchmark::default_peering`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peering: Option<Vec<PeeringTarget>>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("listen", &self.listen)
            .field("upstream", &self.upstream)
            .field("allowed_peers", &self.allowed_peers)
            .field("health_only_peers", &self.health_only_peers)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// What the supervisor knows about the data plane, sent to the proxy as one
/// JSON line per heartbeat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// The rtbit child process is running.
    pub rtbit: bool,
    /// `wg0` has a WireGuard handshake younger than 180 s.
    pub tunnel: bool,
    /// The NAT-PMP (or static) port rtbit listens on.
    #[serde(default)]
    pub port: Option<u16>,
    /// Human-readable state, e.g. "waiting for the WireGuard handshake".
    #[serde(default)]
    pub detail: String,
    /// Direct connection: the VPN is off (no tunnel to check).
    #[serde(default)]
    pub direct: bool,
    /// The VPN exit address NAT-PMP reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<Ipv4Addr>,
    /// Counts rtbit starts. A new value means rtbit restarted and every
    /// session the proxy holds is gone.
    #[serde(default)]
    pub generation: u64,
}

/// A request from the proxy to the supervisor (one JSON line on stdout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum ProxyRequest {
    /// Run [`benchmark::run_hardware`] and answer with [`hardware_line`].
    Hardware,
}

/// A line from the supervisor after the configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum SupervisorLine {
    Hardware { hardware: HardwareResult },
    Health(Health),
}

/// The supervisor's answer to [`ProxyRequest::Hardware`].
pub fn hardware_line(r: &HardwareResult) -> String {
    serde_json::json!({ "hardware": r }).to_string()
}

/// Entry point of `rbittorrent-supervisor ingress-proxy`.
pub fn main_from_stdin() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ingress-proxy: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run_from_stdin())
}

/// stdin as a non-blocking pipe (it always is one: the supervisor spawns
/// this process with a piped stdin), so no helper thread is needed.
fn stdin_pipe() -> std::io::Result<tokio::net::unix::pipe::Receiver> {
    use std::os::fd::AsFd;
    std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .and_then(tokio::net::unix::pipe::Receiver::from_owned_fd)
}

async fn run_from_stdin() -> ExitCode {
    let mut stdin = match stdin_pipe() {
        Ok(p) => tokio::io::BufReader::new(p),
        Err(e) => {
            eprintln!(
                "ingress-proxy: stdin must be a pipe from rbittorrent-supervisor ({e}); \
                 this command is started by the supervisor, not by hand"
            );
            return ExitCode::from(2);
        }
    };
    let mut line = String::new();
    if let Err(e) = (&mut stdin)
        .take(MAX_CONFIG_BYTES)
        .read_line(&mut line)
        .await
    {
        eprintln!("ingress-proxy: cannot read the configuration from stdin: {e}");
        return ExitCode::from(2);
    }
    let cfg: ProxyConfig = match serde_json::from_str(line.trim()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ingress-proxy: invalid configuration on stdin: {e}");
            return ExitCode::from(2);
        }
    };
    line.clear();
    // stdout belongs to the request channel.
    crate::init_logging_stderr(cfg.log_level);
    match run(cfg, stdin).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("Ingress proxy: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg: ProxyConfig, mut status: impl tokio::io::AsyncBufRead + Unpin) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let proxy = Proxy::new(&cfg)?;
    match stdout_pipe() {
        Ok(mut out) => {
            let (tx, mut rx) = mpsc::unbounded_channel::<String>();
            proxy.connect_supervisor(tx);
            tokio::spawn(async move {
                while let Some(mut line) = rx.recv().await {
                    line.push('\n');
                    if let Err(e) = out.write_all(line.as_bytes()).await {
                        debug!("request pipe to the supervisor: {e}");
                        return;
                    }
                }
            });
        }
        Err(e) => debug!("no request pipe to the supervisor ({e}); the disk speed test is off"),
    }
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("cannot listen on {}", cfg.listen))?;
    info!(
        "Ingress proxy listening on {} (accepting {}; /__health only: {}), forwarding to rtbit on {}",
        cfg.listen,
        cfg.allowed_peers.join(", "),
        if cfg.health_only_peers.is_empty() {
            "none".to_owned()
        } else {
            cfg.health_only_peers.join(", ")
        },
        cfg.upstream
    );
    let heartbeats = async {
        let mut line = String::new();
        loop {
            line.clear();
            match (&mut status)
                .take(MAX_CONFIG_BYTES)
                .read_line(&mut line)
                .await
            {
                Ok(0) => return "the supervisor closed the status pipe",
                Ok(_) => match serde_json::from_str::<SupervisorLine>(line.trim()) {
                    Ok(SupervisorLine::Health(h)) => proxy.set_health(h),
                    Ok(SupervisorLine::Hardware { hardware }) => proxy.deliver_hardware(hardware),
                    Err(e) => debug!("ignoring a malformed status line: {e}"),
                },
                Err(e) => {
                    debug!("status pipe: {e}");
                    return "the status pipe failed";
                }
            }
        }
    };
    tokio::select! {
        r = serve(listener, proxy.clone()) => r,
        why = heartbeats => {
            debug!("Ingress proxy stopping: {why}");
            Ok(())
        }
        _ = term.recv() => {
            debug!("Ingress proxy: SIGTERM");
            Ok(())
        }
    }
}

/// stdout as a non-blocking pipe for requests to the supervisor.
fn stdout_pipe() -> std::io::Result<tokio::net::unix::pipe::Sender> {
    use std::os::fd::AsFd;
    std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .and_then(tokio::net::unix::pipe::Sender::from_owned_fd)
}

// ---------------------------------------------------------------------------
// Proxy state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BearerState {
    /// The rtbit start the tokens belong to ([`Health::generation`]).
    generation: u64,
    access: Option<String>,
    refresh: Option<String>,
    expires: Option<Instant>,
    retry_after: Option<Instant>,
    last_warning: Option<Instant>,
    announced: bool,
}

#[derive(Default)]
struct SidState {
    generation: u64,
    sid: Option<String>,
    obtained: Option<Instant>,
    retry_after: Option<Instant>,
}

/// Which upstream session a request was sent with.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cred {
    Bearer(String),
    Sid(String),
}

#[derive(Debug)]
enum LoginError {
    /// rtbit is not listening (starting, waiting for the VPN, restarting).
    Unreachable(anyhow::Error),
    /// rtbit answered but refused the account.
    Rejected(StatusCode),
    Malformed(anyhow::Error),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Unreachable(e) => write!(f, "rtbit is not reachable: {e:#}"),
            LoginError::Rejected(s) => write!(f, "rtbit refused the Web UI account (HTTP {s})"),
            LoginError::Malformed(e) => write!(f, "unexpected login response: {e:#}"),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// The running proxy.
pub struct Proxy {
    upstream: SocketAddr,
    upstream_host: HeaderValue,
    allowed: Vec<Ipv4Cidr>,
    health_only: Vec<Ipv4Cidr>,
    username: String,
    password: String,
    bearer: Mutex<BearerState>,
    sid: Mutex<SidState>,
    rejected: AtomicU64,
    last_reject_log: std::sync::Mutex<Option<Instant>>,
    health: std::sync::Mutex<Option<(Health, Instant)>>,
    rtbit_generation: AtomicU64,
    speed_target: SpeedTarget,
    peering: Vec<PeeringTarget>,
    supervisor_tx: std::sync::Mutex<Option<mpsc::UnboundedSender<String>>>,
    hardware_waiter: std::sync::Mutex<Option<oneshot::Sender<HardwareResult>>>,
    benchmark_busy: AtomicBool,
    benchmark_done: std::sync::Mutex<Option<Instant>>,
}

/// What a peer may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Full,
    HealthOnly,
    Denied,
}

/// Clears the "speed test running" flag however the test ends. It lives in
/// the spawned test task, so a client that disconnects mid-test cannot
/// release the lock (or skip the cooldown) while the test still runs.
struct BusyGuard(Arc<Proxy>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.benchmark_busy.store(false, Ordering::Release);
    }
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("upstream", &self.upstream)
            .field("allowed", &self.allowed)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    pub fn new(cfg: &ProxyConfig) -> Result<Arc<Self>> {
        if cfg.allowed_peers.is_empty() {
            bail!("the Ingress proxy needs at least one allowed peer");
        }
        let parse = |list: &[String]| {
            list.iter()
                .map(|p| {
                    p.parse::<Ipv4Cidr>()
                        .map_err(|e| anyhow::anyhow!("invalid allowed peer `{p}`: {e}"))
                })
                .collect::<Result<Vec<_>>>()
        };
        let allowed = parse(&cfg.allowed_peers)?;
        let health_only = parse(&cfg.health_only_peers)?;
        let upstream_host =
            HeaderValue::from_str(&cfg.upstream.to_string()).context("invalid upstream address")?;
        Ok(Arc::new(Self {
            upstream: cfg.upstream,
            upstream_host,
            allowed,
            health_only,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            bearer: Mutex::new(BearerState::default()),
            sid: Mutex::new(SidState::default()),
            rejected: AtomicU64::new(0),
            last_reject_log: std::sync::Mutex::new(None),
            health: std::sync::Mutex::new(None),
            rtbit_generation: AtomicU64::new(0),
            speed_target: cfg.speed_target.clone().unwrap_or_default(),
            peering: cfg
                .peering
                .clone()
                .unwrap_or_else(benchmark::default_peering),
            supervisor_tx: std::sync::Mutex::new(None),
            hardware_waiter: std::sync::Mutex::new(None),
            benchmark_busy: AtomicBool::new(false),
            benchmark_done: std::sync::Mutex::new(None),
        }))
    }

    /// Where requests to the supervisor go (see [`ProxyRequest`]).
    pub fn connect_supervisor(&self, tx: mpsc::UnboundedSender<String>) {
        *lock(&self.supervisor_tx) = Some(tx);
    }

    /// The supervisor's answer to [`ProxyRequest::Hardware`].
    pub fn deliver_hardware(&self, r: HardwareResult) {
        if let Some(waiter) = lock(&self.hardware_waiter).take() {
            let _ = waiter.send(r);
        }
    }

    async fn request_hardware(&self) -> Result<HardwareResult, String> {
        let tx = lock(&self.supervisor_tx)
            .clone()
            .ok_or_else(|| "not connected to the supervisor".to_owned())?;
        let (waiter, answer) = oneshot::channel();
        *lock(&self.hardware_waiter) = Some(waiter);
        let line = serde_json::to_string(&ProxyRequest::Hardware).map_err(|e| e.to_string())?;
        tx.send(line)
            .map_err(|_| "the link to the supervisor is closed".to_owned())?;
        match tokio::time::timeout(HARDWARE_TIMEOUT, answer).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => Err("the supervisor did not answer".to_owned()),
            Err(_) => Err(format!(
                "the disk test took longer than {}s",
                HARDWARE_TIMEOUT.as_secs()
            )),
        }
    }

    /// `POST /__benchmark`: one test at a time, JSON-only (a plain form or
    /// link from another site cannot trigger it), with a short cooldown. The
    /// test runs in its own task: a client that goes away does not stop it,
    /// and the lock and cooldown hold until it really ends.
    async fn benchmark_response(self: &Arc<Self>, req: Request<Incoming>) -> Response<ProxyBody> {
        let (parts, body) = req.into_parts();
        let h = &parts.headers;
        let is_json = h
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("application/json")
            });
        if !is_json {
            return json_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "send the request with Content-Type: application/json",
            );
        }
        if let Some(site) = h.get("sec-fetch-site").and_then(|v| v.to_str().ok())
            && !matches!(site, "same-origin" | "none")
        {
            return json_error(StatusCode::FORBIDDEN, "cross-site requests are refused");
        }
        // Read (and ignore) the body, so the connection stays usable.
        if collect_limited(body, MAX_BENCHMARK_BODY).await.is_err() {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the speed test takes no request body",
            );
        }
        if self.benchmark_busy.swap(true, Ordering::AcqRel) {
            return too_many("a speed test is already running", 10);
        }
        let busy = BusyGuard(self.clone());
        if let Some(done) = *lock(&self.benchmark_done) {
            let wait = BENCHMARK_COOLDOWN.saturating_sub(done.elapsed());
            if !wait.is_zero() {
                return too_many(
                    "please wait a few seconds between tests",
                    wait.as_secs().max(1),
                );
            }
        }
        let proxy = self.clone();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _busy = busy;
            let body = proxy.run_benchmark().await;
            let _ = tx.send(body);
        });
        match rx.await {
            Ok(body) => json(StatusCode::OK, &body),
            Err(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the speed test stopped unexpectedly",
            ),
        }
    }

    /// The speed test itself; returns the JSON answer.
    async fn run_benchmark(&self) -> String {
        let health = self.current_health().map(|(h, _)| h);
        let direct = health.as_ref().is_some_and(|h| h.direct);
        let route = if direct { "eth0" } else { "wg0" };
        info!("speed test started (route {route})");
        let started = Instant::now();
        // Disk and SHA-1 first (well under a second), so they never compete
        // with the download for the CPU.
        let (hardware, hardware_error) = match self.request_hardware().await {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e)),
        };
        let network = if !direct && !health.as_ref().is_some_and(|h| h.tunnel) {
            benchmark::NetworkResult {
                error: Some(
                    "the VPN tunnel is down, so the kill-switch blocks all traffic; \
                     try again once it is connected"
                        .to_owned(),
                ),
                ..benchmark::NetworkResult::default()
            }
        } else {
            let peering = if direct {
                self.peering.clone()
            } else {
                Vec::new()
            };
            benchmark::run_network(self.speed_target.clone(), peering).await
        };
        *lock(&self.benchmark_done) = Some(Instant::now());
        info!(
            "speed test finished in {:.1}s: download {} Mbit/s, disk {} MB/s, SHA-1 {} MB/s",
            started.elapsed().as_secs_f64(),
            opt_num(network.download_mbps),
            opt_num(hardware.as_ref().and_then(|h| h.disk_write_mb_s)),
            opt_num(hardware.as_ref().and_then(|h| h.sha1_mb_s)),
        );
        serde_json::json!({
            "mode": if direct { "direct" } else { "vpn" },
            "route": route,
            "network": network,
            "hardware": hardware,
            "hardware_error": hardware_error,
            "seconds": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        })
        .to_string()
    }

    /// Records the supervisor's latest view of rtbit and the tunnel.
    pub fn set_health(&self, h: Health) {
        self.rtbit_generation.store(h.generation, Ordering::Release);
        *self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((h, Instant::now()));
    }

    fn current_health(&self) -> Option<(Health, Duration)> {
        self.health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(h, at)| (h.clone(), at.elapsed()))
    }

    /// `GET /__health`: 200 only when rtbit runs, the tunnel is fresh (VPN
    /// mode), the supervisor is alive and rtbit's own `/healthz` answers.
    async fn health_response(&self) -> Response<ProxyBody> {
        let (health, age) = match self.current_health() {
            Some(x) => x,
            None => return health_json(false, "no status from the supervisor yet", None),
        };
        let problem = if age > HEALTH_STALE_AFTER {
            Some(format!(
                "no status from the supervisor for {}s",
                age.as_secs()
            ))
        } else if !health.direct && !health.tunnel {
            Some(non_empty(
                &health.detail,
                "the WireGuard tunnel has no recent handshake",
            ))
        } else if !health.rtbit {
            Some(non_empty(&health.detail, "rtbit is not running"))
        } else {
            self.probe_rtbit().await.err()
        };
        match problem {
            Some(p) => health_json(false, &p, Some(&health)),
            None if health.direct => health_json(
                true,
                "rtbit is running on a direct connection (VPN off)",
                Some(&health),
            ),
            None => health_json(true, "rtbit is running behind the VPN", Some(&health)),
        }
    }

    async fn probe_rtbit(&self) -> Result<(), String> {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/healthz")
            .body(empty())
            .map_err(|e| e.to_string())?;
        req.headers_mut()
            .insert(header::HOST, self.upstream_host.clone());
        match tokio::time::timeout(HEALTH_PROBE_TIMEOUT, self.send(req)).await {
            Ok(Ok(r)) if r.status().is_success() => Ok(()),
            Ok(Ok(r)) => Err(format!("rtbit /healthz answered HTTP {}", r.status())),
            Ok(Err(e)) => Err(format!("rtbit does not answer: {e:#}")),
            Err(_) => Err("rtbit did not answer within 3s".to_owned()),
        }
    }

    /// Health-only peers are matched first, so a peer on both lists is
    /// still limited to `/__health`.
    pub fn peer_access(&self, ip: IpAddr) -> Access {
        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => return Access::Denied,
            },
        };
        if self.health_only.iter().any(|c| c.contains_addr(v4)) {
            Access::HealthOnly
        } else if self.allowed.iter().any(|c| c.contains_addr(v4)) {
            Access::Full
        } else {
            Access::Denied
        }
    }

    fn log_rejection(&self, peer: SocketAddr) {
        let total = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self
            .last_reject_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_none_or(|t| t.elapsed() >= REJECT_LOG_EVERY) {
            warn!(
                %peer,
                total,
                "refused an Ingress connection that did not come from Home Assistant's Supervisor"
            );
            *last = Some(Instant::now());
        } else {
            debug!(%peer, total, "refused Ingress connection");
        }
    }

    // -- upstream sessions ---------------------------------------------------

    /// A valid rtbit access token, signing in or refreshing as needed.
    async fn bearer(&self) -> Option<String> {
        let mut st = self.bearer.lock().await;
        let generation = self.rtbit_generation.load(Ordering::Acquire);
        if st.generation != generation {
            // rtbit restarted: its tokens are gone.
            st.access = None;
            st.refresh = None;
            st.expires = None;
            st.retry_after = None;
            st.generation = generation;
        }
        let now = Instant::now();
        if let (Some(token), Some(expires)) = (&st.access, st.expires)
            && expires > now + TOKEN_REFRESH_MARGIN
        {
            return Some(token.clone());
        }
        if st.retry_after.is_some_and(|t| t > now) {
            return None;
        }
        if let Some(refresh) = st.refresh.take() {
            let body = serde_json::json!({ "refresh_token": refresh }).to_string();
            match self.token_request("/auth/refresh", body).await {
                Ok(t) => return Some(store_tokens(&mut st, t)),
                Err(e) => debug!("Ingress token refresh failed: {e}"),
            }
        }
        let body =
            serde_json::json!({ "username": self.username, "password": self.password }).to_string();
        match self.token_request("/auth/login", body).await {
            Ok(t) => {
                if !st.announced {
                    info!(
                        "Ingress auto-login active: the Home Assistant sidebar is signed in as `{}`",
                        self.username
                    );
                    st.announced = true;
                }
                st.retry_after = None;
                Some(store_tokens(&mut st, t))
            }
            Err(e) => {
                st.access = None;
                st.expires = None;
                match e {
                    LoginError::Unreachable(_) => debug!("Ingress auto-login: {e}"),
                    _ => {
                        st.retry_after = Some(now + LOGIN_RETRY_AFTER);
                        if st
                            .last_warning
                            .is_none_or(|t| t.elapsed() >= LOGIN_WARN_EVERY)
                        {
                            warn!(
                                "Ingress auto-login failed: {e}; the sidebar shows rtbit's own \
                                 sign-in page until `webui_username`/`webui_password` match"
                            );
                            st.last_warning = Some(now);
                        }
                    }
                }
                None
            }
        }
    }

    /// A valid qBittorrent-API session cookie value.
    async fn sid(&self) -> Option<String> {
        let mut st = self.sid.lock().await;
        let generation = self.rtbit_generation.load(Ordering::Acquire);
        if st.generation != generation {
            st.sid = None;
            st.obtained = None;
            st.retry_after = None;
            st.generation = generation;
        }
        let now = Instant::now();
        if let (Some(sid), Some(at)) = (&st.sid, st.obtained)
            && at.elapsed() < SID_LIFETIME
        {
            return Some(sid.clone());
        }
        if st.retry_after.is_some_and(|t| t > now) {
            return None;
        }
        match self.sid_login().await {
            Ok(sid) => {
                st.sid = Some(sid.clone());
                st.obtained = Some(now);
                st.retry_after = None;
                Some(sid)
            }
            Err(e) => {
                st.sid = None;
                if !matches!(e, LoginError::Unreachable(_)) {
                    st.retry_after = Some(now + LOGIN_RETRY_AFTER);
                }
                debug!("Ingress qBittorrent-API login: {e}");
                None
            }
        }
    }

    async fn invalidate(&self, used: &Cred) {
        match used {
            Cred::Bearer(token) => {
                let mut st = self.bearer.lock().await;
                if st.access.as_deref() == Some(token.as_str()) {
                    st.access = None;
                    st.expires = None;
                }
            }
            Cred::Sid(sid) => {
                let mut st = self.sid.lock().await;
                if st.sid.as_deref() == Some(sid.as_str()) {
                    st.sid = None;
                    st.obtained = None;
                }
            }
        }
    }

    async fn token_request(&self, path: &str, json: String) -> Result<TokenResponse, LoginError> {
        tokio::time::timeout(AUTH_TIMEOUT, self.token_request_inner(path, json))
            .await
            .unwrap_or_else(|_| {
                Err(LoginError::Unreachable(anyhow::anyhow!(
                    "no answer to {path} within {}s",
                    AUTH_TIMEOUT.as_secs()
                )))
            })
    }

    async fn token_request_inner(
        &self,
        path: &str,
        json: String,
    ) -> Result<TokenResponse, LoginError> {
        let resp = self
            .post(path, "application/json", json)
            .await
            .map_err(LoginError::Unreachable)?;
        let status = resp.status();
        let body = collect_limited(resp.into_body(), MAX_AUTH_BODY)
            .await
            .map_err(LoginError::Unreachable)?;
        if !status.is_success() {
            return Err(LoginError::Rejected(status));
        }
        serde_json::from_slice(&body).map_err(|e| LoginError::Malformed(e.into()))
    }

    async fn sid_login(&self) -> Result<String, LoginError> {
        tokio::time::timeout(AUTH_TIMEOUT, self.sid_login_inner())
            .await
            .unwrap_or_else(|_| {
                Err(LoginError::Unreachable(anyhow::anyhow!(
                    "no answer to the qBittorrent-API login within {}s",
                    AUTH_TIMEOUT.as_secs()
                )))
            })
    }

    async fn sid_login_inner(&self) -> Result<String, LoginError> {
        let form = format!(
            "username={}&password={}",
            form_encode(&self.username),
            form_encode(&self.password)
        );
        let resp = self
            .post(
                "/api/v2/auth/login",
                "application/x-www-form-urlencoded",
                form,
            )
            .await
            .map_err(LoginError::Unreachable)?;
        let status = resp.status();
        let sid = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| {
                c.split(';')
                    .next()
                    .and_then(|kv| kv.trim().strip_prefix("SID="))
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
            });
        match sid {
            Some(sid) if status.is_success() => Ok(sid),
            _ if status.is_success() => Err(LoginError::Rejected(StatusCode::UNAUTHORIZED)),
            _ => Err(LoginError::Rejected(status)),
        }
    }

    async fn post(
        &self,
        path: &str,
        content_type: &'static str,
        body: String,
    ) -> Result<Response<Incoming>> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(full(Bytes::from(body)))
            .context("cannot build the login request")?;
        let h = req.headers_mut();
        h.insert(header::HOST, self.upstream_host.clone());
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        self.send(req).await
    }

    async fn send(&self, req: Request<ProxyBody>) -> Result<Response<Incoming>> {
        let exchange = async {
            let stream =
                tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(self.upstream))
                    .await
                    .context("connection timed out")?
                    .with_context(|| format!("cannot connect to {}", self.upstream))?;
            let _ = stream.set_nodelay(true);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .context("HTTP handshake with rtbit failed")?;
            tokio::spawn(async move {
                if let Err(e) = conn.with_upgrades().await {
                    debug!("rtbit connection ended: {e}");
                }
            });
            sender
                .send_request(req)
                .await
                .context("rtbit closed the connection")
        };
        tokio::time::timeout(UPSTREAM_RESPONSE_TIMEOUT, exchange)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "rtbit did not answer within {}s",
                    UPSTREAM_RESPONSE_TIMEOUT.as_secs()
                )
            })?
    }

    // -- request handling ----------------------------------------------------

    /// One request. `access` comes from [`Proxy::peer_access`]; `permit` is
    /// the connection's slot, kept by a WebSocket tunnel for as long as it
    /// runs.
    pub async fn handle(
        self: &Arc<Self>,
        mut req: Request<Incoming>,
        access: Access,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Response<ProxyBody> {
        let prefix = ingress_prefix(req.headers());
        let Some(pq) = req.uri().path_and_query().cloned() else {
            return text(StatusCode::BAD_REQUEST, "bad request");
        };
        let path = pq.path().to_owned();
        if !path.starts_with('/') || req.method() == Method::CONNECT {
            return text(StatusCode::BAD_REQUEST, "bad request");
        }
        let navigation = wants_html(req.headers());
        let method = req.method().clone();

        let health = path == HEALTH_PATH && matches!(method, Method::GET | Method::HEAD);
        if access != Access::Full && !health {
            return text(
                StatusCode::FORBIDDEN,
                "Forbidden: this address may only read /__health.\n",
            );
        }
        if health {
            return self.health_response().await;
        }
        if path == BENCHMARK_PATH {
            if method != Method::POST {
                let mut r = json_error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
                r.headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static("POST"));
                return r;
            }
            return self.benchmark_response(req).await;
        }

        // The sidebar is already signed in: tell the web UI that no login is needed.
        if method == Method::GET && path == "/auth/status" && self.bearer().await.is_some() {
            return json(
                StatusCode::OK,
                r#"{"auth_enabled":false,"setup_required":false}"#,
            );
        }

        let qbit = path == "/api/v2" || path.starts_with("/api/v2/");
        let upgrade = is_upgrade(req.headers());
        let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
        let (parts, body) = req.into_parts();
        let plain = navigation || !keeps_encoding(&path);
        let base_headers = forward_headers(&parts.headers, upgrade, plain, &self.upstream_host);
        let replayable = body.is_end_stream();
        let mut body = Some(body);

        let mut attempt = 0;
        loop {
            attempt += 1;
            let cred = if qbit {
                self.sid().await.map(Cred::Sid)
            } else {
                self.bearer().await.map(Cred::Bearer)
            };
            let mut headers = base_headers.clone();
            apply_cred(&mut headers, cred.as_ref(), &parts.headers);
            let upstream_body = match body.take() {
                Some(b) if !replayable => b.map_err(BoxError::from).boxed_unsync(),
                _ => empty(),
            };
            let mut up = match Request::builder()
                .method(method.clone())
                .uri(pq.as_str())
                .body(upstream_body)
            {
                Ok(r) => r,
                Err(_) => return text(StatusCode::BAD_REQUEST, "bad request"),
            };
            *up.headers_mut() = headers;

            let resp = match self.send(up).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("rtbit unavailable for {method} {path}: {e:#}");
                    return unavailable(navigation);
                }
            };
            let refused = if qbit {
                resp.status() == StatusCode::FORBIDDEN
            } else {
                resp.status() == StatusCode::UNAUTHORIZED
            };
            if refused && let Some(c) = &cred {
                self.invalidate(c).await;
                if attempt == 1 && replayable {
                    debug!("rtbit refused the cached session for {path}; signing in again");
                    continue;
                }
            }
            return self
                .finish(resp, &method, &prefix, &path, client_upgrade, permit)
                .await;
        }
    }

    async fn finish(
        &self,
        mut resp: Response<Incoming>,
        method: &Method,
        prefix: &str,
        path: &str,
        client_upgrade: Option<hyper::upgrade::OnUpgrade>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Response<ProxyBody> {
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(client) = client_upgrade else {
                return text(StatusCode::BAD_GATEWAY, "unexpected protocol switch");
            };
            let upstream = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                // The tunnel counts against MAX_CONNECTIONS until it closes.
                let _permit = permit;
                match tokio::try_join!(client, upstream) {
                    Ok((c, u)) => {
                        let mut c = TokioIo::new(c);
                        let mut u = TokioIo::new(u);
                        if let Err(e) = tokio::io::copy_bidirectional(&mut c, &mut u).await {
                            debug!("WebSocket tunnel closed: {e}");
                        }
                    }
                    Err(e) => debug!("WebSocket upgrade failed: {e}"),
                }
            });
            let (parts, _) = resp.into_parts();
            return Response::from_parts(parts, empty());
        }

        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers, false);
        rewrite_location(&mut parts.headers, prefix, &self.upstream);
        rewrite_set_cookie(&mut parts.headers, prefix);
        // Inside Home Assistant the page is always framed, and a browser
        // Basic-auth dialog would only confuse.
        parts.headers.remove(header::X_FRAME_OPTIONS);
        parts.headers.remove(header::WWW_AUTHENTICATE);

        if !prefix.is_empty() && *method == Method::HEAD && is_plain_html(&parts.headers) {
            // Match what GET sends: the page is rewritten, so rtbit's
            // validators and length do not apply.
            for h in [
                header::CONTENT_LENGTH,
                header::ETAG,
                header::LAST_MODIFIED,
                header::CACHE_CONTROL,
            ] {
                parts.headers.remove(h);
            }
            parts
                .headers
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        let rewrite = !prefix.is_empty()
            && *method != Method::HEAD
            && !matches!(
                parts.status,
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
            )
            && is_plain_html(&parts.headers)
            && content_length(&parts.headers).is_none_or(|l| l <= MAX_REWRITE_BYTES);
        if !rewrite {
            return Response::from_parts(parts, body.map_err(BoxError::from).boxed_unsync());
        }
        let html = match collect_limited(body, MAX_REWRITE_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                warn!("cannot rewrite {path} for Ingress: {e:#}");
                return text(StatusCode::BAD_GATEWAY, "rtbit sent an unreadable page");
            }
        };
        let out = Bytes::from(rewrite_page(&html, prefix, base_dir(path), is_web_ui(path)));
        for h in [
            header::CONTENT_LENGTH,
            header::ETAG,
            header::LAST_MODIFIED,
            header::CACHE_CONTROL,
        ] {
            parts.headers.remove(h);
        }
        parts
            .headers
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(out.len()));
        Response::from_parts(parts, full(out))
    }
}

fn store_tokens(st: &mut BearerState, t: TokenResponse) -> String {
    let lifetime = t.expires_in.map_or(DEFAULT_TOKEN_LIFETIME, |s| {
        Duration::from_secs(s.min(MAX_TOKEN_LIFETIME.as_secs()))
    });
    let now = Instant::now();
    st.expires = Some(
        now.checked_add(lifetime)
            .unwrap_or_else(|| now + DEFAULT_TOKEN_LIFETIME),
    );
    st.refresh = t.refresh_token;
    st.access = Some(t.access_token.clone());
    t.access_token
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Serves Ingress connections on `listener` until the task is dropped. A
/// connection beyond the limit is closed at once instead of queueing, and
/// health-only peers draw from their own pool.
pub async fn serve(listener: TcpListener, proxy: Arc<Proxy>) -> Result<()> {
    let ingress = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let health_only = Arc::new(Semaphore::new(MAX_HEALTH_ONLY_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("Ingress accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let access = proxy.peer_access(peer.ip());
        let pool = if access == Access::HealthOnly {
            &health_only
        } else {
            &ingress
        };
        let Ok(permit) = pool.clone().try_acquire_owned() else {
            debug!(%peer, "too many Ingress connections; closing this one");
            drop(stream);
            continue;
        };
        let proxy = proxy.clone();
        tokio::spawn(handle_connection(
            proxy,
            stream,
            peer,
            access,
            Arc::new(permit),
        ));
    }
}

async fn handle_connection(
    proxy: Arc<Proxy>,
    mut stream: TcpStream,
    peer: SocketAddr,
    access: Access,
    permit: Arc<OwnedSemaphorePermit>,
) {
    if access == Access::Denied {
        proxy.log_rejection(peer);
        const BODY: &str = "Forbidden: this port only serves Home Assistant Ingress.\n";
        let reply = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        })
        .await;
        return;
    }
    let _ = stream.set_nodelay(true);
    let service_proxy = proxy.clone();
    let service = hyper::service::service_fn(move |req| {
        let proxy = service_proxy.clone();
        let permit = permit.clone();
        async move { Ok::<_, Infallible>(proxy.handle(req, access, permit).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    if let Err(e) = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
    {
        debug!(%peer, "Ingress connection ended: {e}");
    }
}

// ---------------------------------------------------------------------------
// Header handling
// ---------------------------------------------------------------------------

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// Removes hop-by-hop headers (and the ones `Connection` names).
fn strip_hop_by_hop(h: &mut HeaderMap, keep_upgrade: bool) {
    let named: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .filter(|n| !(keep_upgrade && *n == header::UPGRADE))
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(n);
    }
    if !keep_upgrade {
        h.remove(header::UPGRADE);
    }
}

/// Requests that may keep `Accept-Encoding`: rtbit's APIs and static assets
/// that are never HTML. Anything else might answer with a page that has to
/// be rewritten, whatever the browser's `Accept` says (`*/*` included).
fn keeps_encoding(path: &str) -> bool {
    const ASSETS: [&str; 10] = [
        ".js", ".mjs", ".css", ".json", ".wasm", ".svg", ".map", ".woff", ".woff2", ".ico",
    ];
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/api/") || ASSETS.iter().any(|ext| lower.ends_with(ext))
}

fn is_upgrade(h: &HeaderMap) -> bool {
    let connection_upgrade = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    connection_upgrade && h.contains_key(header::UPGRADE)
}

/// A browser page load (as opposed to an API call).
fn wants_html(h: &HeaderMap) -> bool {
    let accept_html = h
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"));
    let document = h
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| matches!(v, "document" | "iframe"));
    accept_html || document
}

/// The validated `X-Ingress-Path` (`/api/hassio_ingress/<token>`), or "".
pub fn ingress_prefix(h: &HeaderMap) -> String {
    let Some(value) = h.get("x-ingress-path").and_then(|v| v.to_str().ok()) else {
        return String::new();
    };
    let value = value.trim().trim_end_matches('/');
    let valid = value
        .strip_prefix(INGRESS_PATH_PREFIX)
        .is_some_and(|token| {
            (1..=256).contains(&token.len())
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if valid {
        value.to_owned()
    } else {
        debug!("ignoring a malformed X-Ingress-Path header");
        String::new()
    }
}

/// Headers sent to rtbit: hop-by-hop, browser identity (cookies, origin,
/// credentials) and Home Assistant's own headers are not forwarded.
/// `plain`: ask for an uncompressed answer (HTML must arrive uncompressed so
/// the base and shim can be injected).
fn forward_headers(
    src: &HeaderMap,
    upgrade: bool,
    plain: bool,
    upstream_host: &HeaderValue,
) -> HeaderMap {
    let mut h = src.clone();
    strip_hop_by_hop(&mut h, upgrade);
    for n in [
        header::HOST,
        header::AUTHORIZATION,
        header::COOKIE,
        header::ORIGIN,
        header::REFERER,
    ] {
        h.remove(n);
    }
    let ha_specific: Vec<HeaderName> = h
        .keys()
        .filter(|k| {
            let k = k.as_str();
            k == "x-ingress-path" || k.starts_with("x-hass-") || k.starts_with("x-remote-user-")
        })
        .cloned()
        .collect();
    for k in ha_specific {
        h.remove(k);
    }
    if plain {
        h.remove(header::ACCEPT_ENCODING);
    }
    if upgrade {
        h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
    h.insert(header::HOST, upstream_host.clone());
    h
}

/// Puts the proxy's own session on the request; without one (rtbit refused
/// the account), the browser's own rtbit login is passed through instead.
fn apply_cred(h: &mut HeaderMap, cred: Option<&Cred>, original: &HeaderMap) {
    match cred {
        Some(Cred::Bearer(token)) => {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                h.insert(header::AUTHORIZATION, v);
            }
        }
        Some(Cred::Sid(sid)) => {
            if let Ok(v) = HeaderValue::from_str(&format!("SID={sid}")) {
                h.insert(header::COOKIE, v);
            }
        }
        None => {
            if let Some(auth) = original.get(header::AUTHORIZATION) {
                h.insert(header::AUTHORIZATION, auth.clone());
            }
            // Only rtbit's own cookie, never Home Assistant's.
            let sid: Vec<&str> = original
                .get_all(header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(';'))
                .map(str::trim)
                .filter(|c| c.starts_with("SID="))
                .collect();
            if !sid.is_empty()
                && let Ok(v) = HeaderValue::from_str(&sid.join("; "))
            {
                h.insert(header::COOKIE, v);
            }
        }
    }
}

fn already_prefixed(value: &[u8], prefix: &[u8]) -> bool {
    value.starts_with(prefix)
        && matches!(
            value.get(prefix.len()),
            None | Some(b'/' | b'?' | b'#' | b'"' | b'\'')
        )
}

/// Keeps redirects inside the Ingress path (`/web/` -> `<prefix>/web/`).
fn rewrite_location(h: &mut HeaderMap, prefix: &str, upstream: &SocketAddr) {
    let Some(loc) = h.get(header::LOCATION).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let origin = format!("http://{upstream}");
    let path = match loc.strip_prefix(&origin) {
        Some("") => "/",
        Some(rest) if rest.starts_with('/') => rest,
        _ => loc,
    };
    let new = if path.starts_with('/')
        && !path.starts_with("//")
        && !prefix.is_empty()
        && !already_prefixed(path.as_bytes(), prefix.as_bytes())
    {
        format!("{prefix}{path}")
    } else {
        path.to_owned()
    };
    if new != loc
        && let Ok(v) = HeaderValue::from_str(&new)
    {
        h.insert(header::LOCATION, v);
    }
}

/// Scopes rtbit's cookies to the Ingress path: `Path=/x` becomes
/// `Path=<prefix>/x`, and a cookie without `Path` gets `Path=<prefix>` (the
/// browser's default could be `/api/hassio_ingress`, shared by every app).
/// The first element is the cookie's own `name=value`, never an attribute.
fn rewrite_set_cookie(h: &mut HeaderMap, prefix: &str) {
    if prefix.is_empty() || !h.contains_key(header::SET_COOKIE) {
        return;
    }
    let cookies: Vec<HeaderValue> = h
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| HeaderValue::from_str(&scope_cookie(s, prefix)).ok())
                .unwrap_or_else(|| v.clone())
        })
        .collect();
    h.remove(header::SET_COOKIE);
    for c in cookies {
        h.append(header::SET_COOKIE, c);
    }
}

fn scope_cookie(cookie: &str, prefix: &str) -> String {
    let mut parts = cookie.split(';');
    let mut out = vec![parts.next().unwrap_or_default().trim().to_owned()];
    let mut has_path = false;
    for attr in parts {
        let t = attr.trim();
        if t.is_empty() {
            continue;
        }
        match t.split_once('=') {
            Some((k, p)) if k.trim().eq_ignore_ascii_case("path") => {
                has_path = true;
                let p = p.trim();
                if p.starts_with('/') && !already_prefixed(p.as_bytes(), prefix.as_bytes()) {
                    out.push(format!("Path={prefix}{p}"));
                } else if p.starts_with('/') {
                    out.push(format!("Path={p}"));
                } else {
                    // Not a valid path: the browser would use its default.
                    out.push(format!("Path={prefix}"));
                }
            }
            _ => out.push(t.to_owned()),
        }
    }
    if !has_path {
        out.push(format!("Path={prefix}"));
    }
    out.join("; ")
}

fn is_plain_html(h: &HeaderMap) -> bool {
    let html = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("text/html"));
    let encoded = h
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("identity"));
    html && !encoded
}

fn content_length(h: &HeaderMap) -> Option<usize> {
    h.get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

// ---------------------------------------------------------------------------
// HTML rewriting
// ---------------------------------------------------------------------------

/// Prefixes root-relative URLs at runtime. The rtbit web UI already derives
/// its API base from `location.pathname`, so this mainly catches absolute
/// links (`/swagger/`), Swagger UI's `/api-docs/openapi.json`, and any future
/// root-relative call; URLs that already carry the prefix are left alone.
const SHIM: &str = r##"(function(){var P=__INGRESS_PATH__;if(!P)return;var O=location.origin;
function fix(u){if(typeof u!=="string")return u;if(u.indexOf(O+"/")===0)return O+fix(u.slice(O.length));
if(u.charAt(0)!=="/"||u.charAt(1)==="/")return u;if(u===P||u.indexOf(P+"/")===0||u.indexOf(P+"?")===0||u.indexOf(P+"#")===0)return u;return P+u;}
function fixAny(u){if(typeof URL!=="undefined"&&u instanceof URL){if(u.origin===O){var p=fix(u.pathname);if(p!==u.pathname){u=new URL(u.href);u.pathname=p;}}return u;}return fix(u);}
function wsUrl(u){if(typeof URL!=="undefined"&&u instanceof URL)u=u.href;if(typeof u==="string"){var m=/^(wss?:)\/\/([^\/?#]*)(.*)$/i.exec(u);if(m){if(m[2]!==location.host)return u;var r=m[3]||"/";return m[1]+"//"+m[2]+fix(r.charAt(0)==="/"?r:"/"+r);}}
u=fixAny(u);if(typeof u==="string"&&u.charAt(0)==="/")return(location.protocol==="https:"?"wss://":"ws://")+location.host+u;return u;}
var F=window.fetch;if(F)window.fetch=function(i,o){if(typeof Request!=="undefined"&&i instanceof Request){var r=new URL(i.url);if(r.origin===O){var p=fix(r.pathname);if(p!==r.pathname){r.pathname=p;i=new Request(r.href,i);}}}else{i=fixAny(i);}return F.call(this,i,o);};
var X=window.XMLHttpRequest&&XMLHttpRequest.prototype.open;if(X)XMLHttpRequest.prototype.open=function(){var a=Array.prototype.slice.call(arguments);a[1]=fixAny(a[1]);return X.apply(this,a);};
function wrap(n,c){var C=window[n];if(!C||typeof Proxy==="undefined"||typeof Reflect==="undefined")return;window[n]=new Proxy(C,{construct:function(t,a,nt){a=Array.prototype.slice.call(a);if(a.length)a[0]=c(a[0]);return Reflect.construct(t,a,nt);}});}
wrap("WebSocket",wsUrl);wrap("EventSource",fixAny);
["pushState","replaceState"].forEach(function(m){var H=history[m];if(H)history[m]=function(s,t,u){return u===undefined||u===null?H.call(this,s,t):H.call(this,s,t,fixAny(u));};});
var W=window.open;if(W)window.open=function(){var a=Array.prototype.slice.call(arguments);a[0]=fixAny(a[0]);return W.apply(this,a);};
function nav(e){var a=e.target&&e.target.closest?e.target.closest("a[href],area[href]"):null;if(!a)return;var h=a.getAttribute("href"),n=fix(h);if(n!==h)a.setAttribute("href",n);}
document.addEventListener("click",nav,true);document.addEventListener("auxclick",nav,true);
document.addEventListener("submit",function(e){var f=e.target;if(!f||!f.getAttribute)return;var a=f.getAttribute("action"),n=fix(a);if(a&&n!==a)f.setAttribute("action",n);},true);})();"##;

/// The status bar on top of the web UI (Ingress only). It polls
/// `/__health`, shows the VPN state and opens the speed-test dialog. All
/// text is set with `textContent`, styles live in a shadow root so neither
/// the bar nor rtbit's UI can restyle the other, and the "Dismiss" choice is
/// kept per browser in `localStorage`. ASCII only (emoji as `\u` escapes).
const STATUS_BAR: &str = r##"(function(){var P=__INGRESS_PATH__,D=__DOCS__,K="rbittorrent.directBarDismissed";
if(!document.head)return;
function store(v){try{if(v===undefined)return localStorage.getItem(K);localStorage.setItem(K,v);}catch(e){}return null;}
var g=document.createElement("style");g.textContent="html.rbt-bar body{padding-top:var(--rbt-bar-h)!important;box-sizing:border-box}html.rbt-bar .h-dvh,html.rbt-bar .h-screen{height:calc(100dvh - var(--rbt-bar-h))!important}";document.head.appendChild(g);
var CSS=":host{all:initial}*{box-sizing:border-box;font:13px/1.25 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}"+
".bar{display:flex;align-items:center;gap:8px;padding:0 12px;overflow-x:auto;white-space:nowrap;scrollbar-width:none}.bar::-webkit-scrollbar{display:none}"+
".direct{height:36px;background:#fff4e5;color:#5c3400;border-bottom:1px solid #ffb74d}.vpn{height:32px;background:#f1f8f2;color:#1b5e20;border-bottom:1px solid #c8e6c9}"+
".label{font-weight:600;flex:none}.pill{flex:none;font-weight:600;color:#fff;background:#2e7d32;border-radius:999px;padding:3px 10px}.pill.down{background:#a15c00}"+
".b{flex:none;font-weight:500;color:inherit;background:transparent;border:1px solid currentColor;border-radius:6px;padding:4px 10px;cursor:pointer;text-decoration:none}"+
".b:hover{background:rgba(127,127,127,.12)}.b:focus-visible,.l:focus-visible{outline:2px solid #1565c0;outline-offset:2px}"+
".primary{background:#1565c0;border-color:#1565c0;color:#fff}.primary:hover{background:#0d47a1}.l{flex:none;color:inherit;text-decoration:underline}.x{margin-left:auto}"+
".overlay{position:fixed;inset:0;z-index:2147483001;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(0,0,0,.45)}"+
".modal{width:100%;max-width:440px;max-height:90vh;overflow:auto;background:#fff;color:#212121;border-radius:12px;padding:16px 18px;box-shadow:0 10px 40px rgba(0,0,0,.3)}"+
".modal h2{font-size:16px;font-weight:700;margin:0 0 10px}.modal h3{font-size:13px;font-weight:700;margin:14px 0 4px}"+
".row{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid rgba(127,127,127,.2)}.k{color:#666}.v{font-weight:600;text-align:right;white-space:normal}"+
".muted{color:#666;white-space:normal}.err{color:#c62828;white-space:normal}.foot{display:flex;justify-content:flex-end;margin-top:14px}.modal .b{border-color:rgba(127,127,127,.6)}"+
".spin{width:26px;height:26px;margin:12px auto;border:3px solid rgba(127,127,127,.3);border-top-color:#1565c0;border-radius:50%;animation:s 1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}"+
"@media (prefers-color-scheme:dark){.direct{background:#2b1d00;color:#ffcc80;border-color:#7a4f00}.vpn{background:#0f2214;color:#a5d6a7;border-color:#1e4620}"+
".modal{background:#1e1e1e;color:#e6e6e6}.k,.muted{color:#aaa}.err{color:#ef9a9a}}";
var host=null,root=null,bar=null,modal=null,state="",last=null;
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e;}
function btn(c,x,f){var b=el("button",c,x);b.type="button";b.addEventListener("click",f);return b;}
function link(c,x,h){var a=el("a",c,x);a.href=h;a.target="_blank";a.rel="noopener noreferrer";return a;}
function offset(px){var d=document.documentElement;if(px){d.style.setProperty("--rbt-bar-h",px+"px");d.classList.add("rbt-bar");}else d.classList.remove("rbt-bar");}
function ensure(){if(host)return true;if(!document.body)return false;host=el("div");host.id="rbittorrent-status-bar";host.style.cssText="position:fixed;top:0;left:0;right:0;z-index:2147483000";
root=host.attachShadow?host.attachShadow({mode:"open"}):host;var s=el("style");s.textContent=CSS;root.appendChild(s);bar=el("div","bar");root.appendChild(bar);document.body.appendChild(host);return true;}
function render(h){var key="";
if(h&&h.vpn===false)key=store()==="1"?"":"direct";else if(h&&h.vpn===true)key=h.tunnel?"vpn|"+(h.public_ip||"")+"|"+(h.port||""):"down";
if(key===state&&(!key||host))return;if(key&&!ensure())return;state=key;
if(!key){if(host)host.style.display="none";offset(0);return;}
host.style.display="";bar.textContent="";
if(key==="direct"){bar.className="bar direct";bar.setAttribute("role","status");
bar.appendChild(el("span","label","\uD83D\uDD13 Direct Connection (Unprotected)"));
bar.appendChild(btn("b","\u26A1 Speed Test",speed));
bar.appendChild(link("b primary","\uD83D\uDCD8 Proton VPN Setup",D+"#proton-vpn-setup"));
bar.appendChild(link("l","Custom / Static WireGuard",D+"#other-wireguard-providers-static-port"));
var x=btn("b x","\u2715 Dismiss",function(){store("1");render(last);});x.title="Hide this notice for good in this browser";bar.appendChild(x);offset(36);}
else{bar.className="bar vpn";bar.setAttribute("role","status");var p=el("span",key==="down"?"pill down":"pill");
if(key==="down")p.textContent="\uD83D\uDD12 VPN reconnecting (kill-switch on)";
else{var d=[];if(h.public_ip)d.push(h.public_ip);if(h.port)d.push("Port "+h.port);p.textContent="\uD83D\uDD12 VPN Protected"+(d.length?" ("+d.join(" \u2022 ")+")":"");}
bar.appendChild(p);if(key!=="down")bar.appendChild(btn("b","\u26A1 Test VPN Speed",speed));offset(32);}}
function row(t,k,v){var r=el("div","row");r.appendChild(el("span","k",k));r.appendChild(el("span","v",v));t.appendChild(r);}
function num(v,u){return typeof v==="number"?v.toLocaleString(undefined,{maximumFractionDigits:1})+" "+u:"\u2014";}
function shut(){if(modal){root.removeChild(modal);modal=null;document.removeEventListener("keydown",esc,true);}}
function esc(e){if(e.key==="Escape")shut();}
function show(b,st,j){b.textContent="";if(st!==200||!j){b.appendChild(el("p","err",(j&&j.error)||("The test could not run (HTTP "+st+").")));return;}
var n=j.network||{},hw=j.hardware,t=el("div");
row(t,"Route",j.route==="wg0"?"wg0 (VPN tunnel)":"eth0 (direct)");
row(t,"Download",num(n.download_mbps,"Mbit/s"));
row(t,"Latency",typeof n.latency_ms==="number"?num(n.latency_ms,"ms")+(n.colo?" ("+n.colo+(n.country?", "+n.country:"")+")":""):"\u2014");
row(t,"Public IP",n.public_ip||"\u2014");
if(hw){row(t,"Disk write",typeof hw.disk_write_mb_s==="number"?num(hw.disk_write_mb_s,"MB/s"):(hw.disk_error||"\u2014"));row(t,"SHA-1 hashing",num(hw.sha1_mb_s,"MB/s")+" ("+hw.cpu_cores+" cores)");}
else row(t,"Disk / CPU",j.hardware_error||"\u2014");
b.appendChild(t);
if(n.peering&&n.peering.length){b.appendChild(el("h3",null,"Regional peering"));var q=el("div");n.peering.forEach(function(x){row(q,x.name+" ("+x.address+")",typeof x.ms==="number"?num(x.ms,"ms"):"no answer");});b.appendChild(q);}
if(n.error)b.appendChild(el("p","err",n.error));
b.appendChild(el("p","muted",j.route==="wg0"?"Measured through the VPN tunnel with Cloudflare's speed test.":"Measured on your normal connection with Cloudflare's speed test. With the VPN on, the test runs through the tunnel."));}
function speed(){if(modal||!ensure())return;modal=el("div","overlay");var box=el("div","modal");box.setAttribute("role","dialog");box.setAttribute("aria-modal","true");box.setAttribute("aria-label","Speed test");
box.appendChild(el("h2",null,"\u26A1 Speed test"));var b=el("div");b.appendChild(el("p","muted","Measuring download, latency, disk and hashing speed (about 10 seconds)\u2026"));b.appendChild(el("div","spin"));box.appendChild(b);
var f=el("div","foot"),c=btn("b","Close",shut);f.appendChild(c);box.appendChild(f);modal.appendChild(box);
modal.addEventListener("click",function(e){if(e.target===modal)shut();});document.addEventListener("keydown",esc,true);root.appendChild(modal);c.focus();
fetch(P+"/__benchmark",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",cache:"no-store",credentials:"same-origin"})
.then(function(r){return r.json().then(function(j){return[r.status,j];},function(){return[r.status,null];});})
.then(function(x){show(b,x[0],x[1]);},function(e){b.textContent="";b.appendChild(el("p","err","The test could not run: "+e));});}
function poll(){fetch(P+"/__health",{cache:"no-store",credentials:"same-origin"}).then(function(r){return r.json();}).then(function(h){last=h;render(h);},function(){})
.then(function(){setTimeout(poll,document.hidden?60000:15000);});}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",poll);else poll();})();"##;

/// Directory of a request path (`/web/index.html` -> `/web/`).
fn base_dir(path: &str) -> &str {
    // rtbit serves the web UI at `/web` as well as `/web/`.
    if path == "/web" {
        return "/web/";
    }
    path.rfind('/').and_then(|i| path.get(..=i)).unwrap_or("/")
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn find_ci(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
        .map(|p| p + from)
}

/// Offset just after the `>` closing the first `<tag ...>` (not `<tagx`).
fn after_open_tag(html: &[u8], tag: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(i) = find_ci(html, tag, at) {
        let next = html.get(i + tag.len()).copied();
        if matches!(next, Some(b'>' | b'/') | Some(b' ' | b'\t' | b'\n' | b'\r')) {
            let close = html.get(i..)?.iter().position(|&b| b == b'>')?;
            return Some(i + close + 1);
        }
        at = i + 1;
    }
    None
}

/// Where the `<base>` + shim go: after `<meta charset>` (which must stay in
/// the first 1024 bytes) or else right after `<head>`.
fn injection_point(html: &[u8]) -> usize {
    let Some(head) = after_open_tag(html, b"<head", 0) else {
        return after_open_tag(html, b"<html", 0).unwrap_or(0);
    };
    let head_close = find_ci(html, b"</head", head).unwrap_or(html.len());
    find_ci(html, b"<meta charset", head)
        .filter(|&m| m < head_close)
        .and_then(|m| {
            html.get(m..)?
                .iter()
                .position(|&b| b == b'>')
                .map(|p| m + p + 1)
        })
        .unwrap_or(head)
}

const URL_ATTRS: [&[u8]; 5] = [b"href=", b"src=", b"action=", b"formaction=", b"poster="];

/// Prefixes root-relative URL attributes (`href="/x"` -> `href="<prefix>/x"`).
fn prefix_root_relative_attrs(html: &[u8], prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(html.len() + 256);
    let mut copied = 0;
    let mut i = 0;
    // Inline script and style bodies are code, not markup: `href="/x"` in a
    // JavaScript string is left alone (the shim handles it at runtime).
    let mut skip: Option<(usize, usize)> = None;
    while i < html.len() {
        if let Some((from, to)) = skip
            && i >= from
        {
            i = to.max(i + 1);
            skip = None;
            continue;
        }
        if skip.is_none() && html.get(i) == Some(&b'<') {
            for tag in [&b"<script"[..], &b"<style"[..]] {
                let opens = html
                    .get(i..i + tag.len())
                    .is_some_and(|w| w.eq_ignore_ascii_case(tag))
                    && matches!(
                        html.get(i + tag.len()),
                        Some(b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/')
                    );
                if opens {
                    // Attributes of the opening tag are still rewritten.
                    let body = html
                        .get(i..)
                        .and_then(|r| r.iter().position(|&b| b == b'>'))
                        .map_or(html.len(), |p| i + p + 1);
                    let close: Vec<u8> = [&b"</"[..], tag.get(1..).unwrap_or_default()].concat();
                    let end = find_ci(html, &close, body).unwrap_or(html.len());
                    skip = Some((body, end));
                    break;
                }
            }
        }
        if html.get(i).is_some_and(u8::is_ascii_whitespace) {
            let rest = html.get(i + 1..).unwrap_or_default();
            let attr = URL_ATTRS.iter().find(|a| {
                rest.get(..a.len())
                    .is_some_and(|w| w.eq_ignore_ascii_case(a))
            });
            if let Some(attr) = attr {
                let quote_at = i + 1 + attr.len();
                if matches!(html.get(quote_at), Some(b'"' | b'\'')) {
                    let value = html.get(quote_at + 1..).unwrap_or_default();
                    if value.first() == Some(&b'/')
                        && value.get(1) != Some(&b'/')
                        && !already_prefixed(value, prefix)
                    {
                        out.extend_from_slice(html.get(copied..=quote_at).unwrap_or_default());
                        out.extend_from_slice(prefix);
                        copied = quote_at + 1;
                        i = quote_at + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out.extend_from_slice(html.get(copied..).unwrap_or_default());
    out
}

/// Injects `<base href>` and the URL shim and prefixes root-relative
/// attributes. `prefix` must come from [`ingress_prefix`].
pub fn rewrite_html(html: &[u8], prefix: &str, dir: &str) -> Vec<u8> {
    rewrite_page(html, prefix, dir, false)
}

/// The web UI itself (not Swagger or other pages): gets the status bar.
fn is_web_ui(path: &str) -> bool {
    path == "/web" || path.starts_with("/web/")
}

/// [`rewrite_html`], plus the status bar when `status_bar` is set.
pub fn rewrite_page(html: &[u8], prefix: &str, dir: &str, status_bar: bool) -> Vec<u8> {
    let body = prefix_root_relative_attrs(html, prefix.as_bytes());
    let at = injection_point(&body);
    let prefix_js = serde_json::to_string(prefix).unwrap_or_else(|_| "\"\"".to_owned());
    let mut snippet = format!(
        "<base href=\"{}\"><script>{}</script>",
        html_escape(&format!("{prefix}{dir}")),
        SHIM.replace("__INGRESS_PATH__", &prefix_js)
    );
    if status_bar {
        let docs_js = serde_json::to_string(DOCS_URL).unwrap_or_else(|_| "\"\"".to_owned());
        snippet.push_str("<script>");
        snippet.push_str(
            &STATUS_BAR
                .replace("__INGRESS_PATH__", &prefix_js)
                .replace("__DOCS__", &docs_js),
        );
        snippet.push_str("</script>");
    }
    let mut out = Vec::with_capacity(body.len() + snippet.len());
    out.extend_from_slice(body.get(..at).unwrap_or_default());
    out.extend_from_slice(snippet.as_bytes());
    out.extend_from_slice(body.get(at..).unwrap_or_default());
    out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn full(b: Bytes) -> ProxyBody {
    Full::new(b).map_err(|never| match never {}).boxed_unsync()
}

fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn respond(status: StatusCode, content_type: &'static str, body: &str) -> Response<ProxyBody> {
    let mut r = Response::new(full(Bytes::copy_from_slice(body.as_bytes())));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn non_empty(detail: &str, fallback: &str) -> String {
    if detail.is_empty() {
        fallback.to_owned()
    } else {
        detail.to_owned()
    }
}

fn health_json(ok: bool, message: &str, h: Option<&Health>) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "status": if ok { "ok" } else { "unhealthy" },
        "message": message,
        "rtbit": h.is_some_and(|h| h.rtbit),
        "tunnel": h.is_some_and(|h| h.tunnel),
        "port": h.and_then(|h| h.port),
        // Unknown (null) until the supervisor's first heartbeat.
        "vpn": h.map(|h| !h.direct),
        "public_ip": h.and_then(|h| h.public_ip),
    })
    .to_string();
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json(status, &body)
}

fn text(status: StatusCode, body: &str) -> Response<ProxyBody> {
    respond(status, "text/plain; charset=utf-8", body)
}

fn json(status: StatusCode, body: &str) -> Response<ProxyBody> {
    respond(status, "application/json", body)
}

fn json_error(status: StatusCode, message: &str) -> Response<ProxyBody> {
    json(status, &serde_json::json!({ "error": message }).to_string())
}

fn too_many(message: &str, retry_after_secs: u64) -> Response<ProxyBody> {
    let mut r = json_error(StatusCode::TOO_MANY_REQUESTS, message);
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    r
}

fn opt_num(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_owned(), |v| format!("{v:.1}"))
}

const STARTING_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rBittorrent is starting</title>
<style>
:root{color-scheme:light dark;--bg:#fafafa;--fg:#212121;--muted:#616161}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#e1e1e1;--muted:#9e9e9e}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:36rem;margin:12vh auto;padding:0 16px}
p{color:var(--muted)}
</style></head><body><main>
<h1>rBittorrent is starting&hellip;</h1>
<p>The torrent engine is not reachable yet. With the VPN on, it only starts
once the WireGuard tunnel is up and the kill-switch is active, and it restarts
for a few seconds when the forwarded port changes.</p>
<p>This page reloads every 5 seconds. If it stays here, open the app's
<strong>Log</strong> tab in Home Assistant.</p>
</main></body></html>
"#;

/// rtbit is down: a self-refreshing page for browsers, a 503 for API calls.
fn unavailable(navigation: bool) -> Response<ProxyBody> {
    let mut r = if navigation {
        respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/html; charset=utf-8",
            STARTING_PAGE,
        )
    } else {
        text(
            StatusCode::SERVICE_UNAVAILABLE,
            "rtbit is not reachable yet (starting, or waiting for the VPN tunnel)\n",
        )
    };
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    r
}

async fn collect_limited<B>(body: B, limit: usize) -> Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    Limited::new(body, limit)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// `application/x-www-form-urlencoded` value encoding.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "/api/hassio_ingress/AbC-123_x";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn ingress_path_is_validated() {
        assert_eq!(ingress_prefix(&headers(&[("x-ingress-path", P)])), P);
        assert_eq!(
            ingress_prefix(&headers(&[("x-ingress-path", &format!("{P}/"))])),
            P
        );
        for bad in [
            "/api/hassio_ingress/",
            "/api/hassio_ingress/a\"><script>",
            "/api/hassio_ingress/a/b",
            "/somewhere/else",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                ingress_prefix(&headers(&[("x-ingress-path", bad)])),
                "",
                "{bad}"
            );
        }
        assert_eq!(ingress_prefix(&HeaderMap::new()), "");
    }

    #[test]
    fn html_gets_base_and_shim_after_meta_charset() {
        let html = b"<!doctype html><html><HEAD>\n<meta charset=\"UTF-8\" />\n<title>t</title>\
            <script type=\"module\" src=\"assets/index.js\"></script></head>\
            <body><a href=\"/swagger/\">api</a><img src='/x.png'><a href=\"//cdn/x\">c</a>\
            <a href=\"/api/hassio_ingress/AbC-123_x/web/\">self</a></body></html>";
        let out = String::from_utf8(rewrite_html(html, P, "/web/")).unwrap();
        let meta_end = out.find("/>").unwrap() + 2;
        let base = out
            .find("<base href=\"/api/hassio_ingress/AbC-123_x/web/\">")
            .unwrap();
        assert_eq!(base, meta_end, "{out}");
        assert!(out.contains("var P=\"/api/hassio_ingress/AbC-123_x\";"));
        assert!(
            out.contains("src=\"assets/index.js\""),
            "relative assets untouched"
        );
        assert!(out.contains("href=\"/api/hassio_ingress/AbC-123_x/swagger/\""));
        assert!(out.contains("src='/api/hassio_ingress/AbC-123_x/x.png'"));
        assert!(
            out.contains("href=\"//cdn/x\""),
            "protocol-relative untouched"
        );
        assert!(
            out.contains("href=\"/api/hassio_ingress/AbC-123_x/web/\">self"),
            "no double prefix"
        );
        assert!(!out.contains("__INGRESS_PATH__"));
    }

    #[test]
    fn html_without_head_still_gets_the_base() {
        let out = String::from_utf8(rewrite_html(b"<html><body>x</body></html>", P, "/")).unwrap();
        assert!(out.starts_with("<html><base href=\"/api/hassio_ingress/AbC-123_x/\">"));
        let out = String::from_utf8(rewrite_html(b"<header>x</header>", P, "/")).unwrap();
        assert!(
            out.starts_with("<base href="),
            "<header> is not <head>: {out}"
        );
    }

    #[test]
    fn redirects_stay_inside_ingress() {
        let up: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        for (loc, want) in [
            ("/web/", format!("{P}/web/")),
            ("./web/", "./web/".to_owned()),
            ("http://127.0.0.1:8080/web/", format!("{P}/web/")),
            ("http://127.0.0.1:8080", format!("{P}/")),
            (&format!("{P}/web/"), format!("{P}/web/")),
            ("https://example.com/x", "https://example.com/x".to_owned()),
        ] {
            let mut h = headers(&[("location", loc)]);
            rewrite_location(&mut h, P, &up);
            assert_eq!(h["location"], want.as_str(), "{loc}");
        }
        let mut h = headers(&[("location", "/web/")]);
        rewrite_location(&mut h, "", &up);
        assert_eq!(h["location"], "/web/");
    }

    #[test]
    fn cookie_paths_are_scoped_to_the_ingress_path() {
        let mut h = headers(&[
            ("set-cookie", "SID=abc; Path=/; HttpOnly; SameSite=Strict"),
            ("set-cookie", "other=1; path=/api/v2"),
            ("set-cookie", "x=1"),
            // A cookie *named* path is not a Path attribute.
            (
                "set-cookie",
                "path=/x;Secure;  Path=/api/hassio_ingress/AbC-123_x/web",
            ),
            ("set-cookie", "y=2; Path=relative"),
        ]);
        rewrite_set_cookie(&mut h, P);
        let all: Vec<&str> = h
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            all,
            vec![
                "SID=abc; Path=/api/hassio_ingress/AbC-123_x/; HttpOnly; SameSite=Strict",
                "other=1; Path=/api/hassio_ingress/AbC-123_x/api/v2",
                "x=1; Path=/api/hassio_ingress/AbC-123_x",
                "path=/x; Secure; Path=/api/hassio_ingress/AbC-123_x/web",
                "y=2; Path=/api/hassio_ingress/AbC-123_x",
            ]
        );
    }

    #[test]
    fn only_html_capable_requests_lose_accept_encoding() {
        for p in [
            "/api/v2/torrents/info",
            "/web/assets/index-abc.js",
            "/web/a.CSS",
        ] {
            assert!(keeps_encoding(p), "{p}");
        }
        for p in [
            "/web/",
            "/web",
            "/swagger/",
            "/",
            "/torrents",
            "/web/index.html",
        ] {
            assert!(!keeps_encoding(p), "{p}");
        }
    }

    #[test]
    fn inline_scripts_and_styles_are_not_rewritten() {
        let html = br#"<script src="/a.js"></script><script>var u = ' href="/x"';</script><STYLE>a{x: ' src="/y"'}</STYLE><a href="/z">z</a>"#;
        let out = String::from_utf8(prefix_root_relative_attrs(html, P.as_bytes())).unwrap();
        assert!(
            out.contains(&format!(r#"<script src="{P}/a.js">"#)),
            "{out}"
        );
        assert!(out.contains(r#"' href="/x"'"#), "{out}");
        assert!(out.contains(r#"' src="/y"'"#), "{out}");
        assert!(out.contains(&format!(r#"<a href="{P}/z">"#)), "{out}");
        // An unclosed script swallows the rest instead of rewriting it.
        let open = br#"<script> x=' href="/q"'"#;
        assert_eq!(
            prefix_root_relative_attrs(open, P.as_bytes()),
            open.to_vec()
        );
    }

    #[test]
    fn token_lifetimes_are_capped() {
        let mut st = BearerState::default();
        let token = store_tokens(
            &mut st,
            TokenResponse {
                access_token: "t".into(),
                refresh_token: None,
                expires_in: Some(u64::MAX),
            },
        );
        assert_eq!(token, "t");
        let left = st.expires.unwrap() - Instant::now();
        assert!(left <= MAX_TOKEN_LIFETIME, "{left:?}");
    }

    #[test]
    fn forwarded_headers_drop_browser_identity() {
        let host = HeaderValue::from_static("127.0.0.1:8080");
        let src = headers(&[
            ("host", "ha.example"),
            ("authorization", "Bearer browser"),
            ("cookie", "ingress_session=s3cret; SID=old"),
            ("origin", "https://ha.example"),
            ("referer", "https://ha.example/x"),
            ("x-ingress-path", P),
            ("x-hass-source", "core.ingress"),
            ("x-remote-user-name", "me"),
            ("connection", "keep-alive, x-drop-me"),
            ("x-drop-me", "1"),
            ("accept-encoding", "gzip"),
            ("accept", "text/html"),
            ("x-forwarded-for", "10.0.0.5"),
        ]);
        let h = forward_headers(&src, false, true, &host);
        let names: Vec<&str> = h.keys().map(HeaderName::as_str).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert_eq!(h["host"], "127.0.0.1:8080");
        assert!(h.contains_key("accept") && h.contains_key("x-forwarded-for"));

        let mut with = h.clone();
        apply_cred(&mut with, Some(&Cred::Bearer("tok".into())), &src);
        assert_eq!(with["authorization"], "Bearer tok");
        let mut without = h.clone();
        apply_cred(&mut without, None, &src);
        assert_eq!(without["authorization"], "Bearer browser");
        assert_eq!(
            without["cookie"], "SID=old",
            "Home Assistant cookies never leak"
        );

        let ws = headers(&[("connection", "Upgrade"), ("upgrade", "websocket")]);
        assert!(is_upgrade(&ws));
        let h = forward_headers(&ws, true, false, &host);
        assert_eq!(h["connection"], "upgrade");
        assert_eq!(h["upgrade"], "websocket");
    }

    #[test]
    fn peers_are_matched_against_the_allowlist() {
        let cfg = ProxyConfig {
            listen: "0.0.0.0:8099".parse().unwrap(),
            upstream: "127.0.0.1:8080".parse().unwrap(),
            allowed_peers: vec!["172.30.32.2/32".into()],
            health_only_peers: vec!["127.0.0.1/32".into()],
            username: "admin".into(),
            password: "pw".into(),
            log_level: LogLevel::Info,
            speed_target: None,
            peering: None,
        };
        assert!(!format!("{cfg:?}").contains("pw\""));
        let p = Proxy::new(&cfg).unwrap();
        for (ip, access) in [
            ("172.30.32.2", Access::Full),
            ("::ffff:172.30.32.2", Access::Full),
            ("127.0.0.1", Access::HealthOnly),
            ("::ffff:127.0.0.1", Access::HealthOnly),
            ("172.30.32.3", Access::Denied),
            ("172.30.33.1", Access::Denied),
            ("127.0.0.2", Access::Denied),
            ("192.168.1.10", Access::Denied),
            ("::1", Access::Denied),
        ] {
            assert_eq!(p.peer_access(ip.parse().unwrap()), access, "{ip}");
        }
        // A peer on both lists stays health-only.
        let mut both = cfg.clone();
        both.allowed_peers.push("127.0.0.1/32".into());
        let p = Proxy::new(&both).unwrap();
        assert_eq!(
            p.peer_access("127.0.0.1".parse().unwrap()),
            Access::HealthOnly
        );
        let mut bad = cfg.clone();
        bad.allowed_peers = vec!["nope".into()];
        assert!(Proxy::new(&bad).is_err());
        bad.allowed_peers.clear();
        assert!(Proxy::new(&bad).is_err());
    }

    #[test]
    fn form_values_are_percent_encoded() {
        assert_eq!(form_encode("p@ss w&rd=1"), "p%40ss%20w%26rd%3D1");
        assert_eq!(form_encode("a-b.c_d~"), "a-b.c_d~");
    }

    #[test]
    fn status_bar_only_on_the_web_ui() {
        for (path, bar) in [
            ("/web", true),
            ("/web/", true),
            ("/web/index.html", true),
            ("/swagger/", false),
            ("/", false),
            ("/webx", false),
        ] {
            assert_eq!(is_web_ui(path), bar, "{path}");
        }
        let html = b"<html><head><meta charset=\"UTF-8\"></head><body></body></html>";
        let with = String::from_utf8(rewrite_page(html, P, "/web/", true)).unwrap();
        let without = String::from_utf8(rewrite_page(html, P, "/web/", false)).unwrap();
        assert_eq!(
            without,
            String::from_utf8(rewrite_html(html, P, "/web/")).unwrap()
        );
        for needle in [
            "rbittorrent-status-bar",
            "#proton-vpn-setup",
            "#other-wireguard-providers-static-port",
            "Custom / Static WireGuard",
            "Test VPN Speed",
            "/__benchmark",
            "localStorage",
        ] {
            assert!(with.contains(needle), "{needle}");
            assert!(!without.contains(needle), "{needle}");
        }
        assert!(with.contains(&format!("D=\"{DOCS_URL}\"")));
        assert!(!with.contains("__DOCS__") && !with.contains("__INGRESS_PATH__"));
        assert!(with.is_ascii());
        assert!(
            !STATUS_BAR.contains("innerHTML"),
            "text only via textContent"
        );
        assert!(
            !STATUS_BAR.contains("</script"),
            "cannot break out of its tag"
        );
    }

    #[test]
    fn supervisor_lines_and_requests() {
        let h: SupervisorLine =
            serde_json::from_str(r#"{"rtbit":true,"tunnel":true,"port":5,"detail":""}"#).unwrap();
        assert_eq!(
            h,
            SupervisorLine::Health(Health {
                rtbit: true,
                tunnel: true,
                port: Some(5),
                ..Health::default()
            }),
            "lines from before the direct mode still parse"
        );
        let hw = HardwareResult {
            disk_write_mb_s: Some(12.5),
            disk_path: "/media/x".into(),
            sha1_mb_s: Some(900.0),
            cpu_cores: 4,
            ..HardwareResult::default()
        };
        let line = hardware_line(&hw);
        assert_eq!(
            serde_json::from_str::<SupervisorLine>(&line).unwrap(),
            SupervisorLine::Hardware { hardware: hw }
        );
        assert_eq!(
            serde_json::to_string(&ProxyRequest::Hardware).unwrap(),
            r#"{"request":"hardware"}"#
        );
        let direct = Health {
            direct: true,
            public_ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ..Health::default()
        };
        let back: Health = serde_json::from_str(&serde_json::to_string(&direct).unwrap()).unwrap();
        assert_eq!(back, direct);
    }

    #[test]
    fn base_dir_of_paths() {
        assert_eq!(base_dir("/web/"), "/web/");
        assert_eq!(base_dir("/web/index.html"), "/web/");
        assert_eq!(base_dir("/swagger/"), "/swagger/");
        assert_eq!(base_dir("/"), "/");
        assert_eq!(base_dir("/web"), "/web/");
    }
}
