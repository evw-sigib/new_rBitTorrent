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
//!   rtbit runs, the WireGuard handshake is fresh and rtbit answers.
//!
//! It runs as its own process with uid/gid 65534 and no capabilities. Its
//! stdin is a pipe from the supervisor: the first line is the configuration
//! (including the password), every further line a [`Health`] heartbeat.

use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};

use crate::cidr::Ipv4Cidr;
use crate::config::LogLevel;

/// Home Assistant's Supervisor: the only source of Ingress traffic.
pub const SUPERVISOR_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 32, 2);
/// What the Supervisor puts in front of every Ingress URL.
pub const INGRESS_PATH_PREFIX: &str = "/api/hassio_ingress/";

const MAX_CONNECTIONS: usize = 128;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
    /// Peers that may connect, as CIDRs (`172.30.32.2/32`, `127.0.0.1/32`).
    pub allowed_peers: Vec<String>,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub log_level: LogLevel,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("listen", &self.listen)
            .field("upstream", &self.upstream)
            .field("allowed_peers", &self.allowed_peers)
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
    crate::init_logging(cfg.log_level);
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
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("cannot listen on {}", cfg.listen))?;
    info!(
        "Ingress proxy listening on {} (accepting {}), forwarding to rtbit on {}",
        cfg.listen,
        cfg.allowed_peers.join(", "),
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
                Ok(_) => match serde_json::from_str::<Health>(line.trim()) {
                    Ok(h) => proxy.set_health(h),
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

// ---------------------------------------------------------------------------
// Proxy state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BearerState {
    access: Option<String>,
    refresh: Option<String>,
    expires: Option<Instant>,
    retry_after: Option<Instant>,
    last_warning: Option<Instant>,
    announced: bool,
}

#[derive(Default)]
struct SidState {
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
    username: String,
    password: String,
    bearer: Mutex<BearerState>,
    sid: Mutex<SidState>,
    rejected: AtomicU64,
    last_reject_log: std::sync::Mutex<Option<Instant>>,
    health: std::sync::Mutex<Option<(Health, Instant)>>,
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
        let allowed = cfg
            .allowed_peers
            .iter()
            .map(|p| {
                p.parse::<Ipv4Cidr>()
                    .map_err(|e| anyhow::anyhow!("invalid allowed peer `{p}`: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let upstream_host =
            HeaderValue::from_str(&cfg.upstream.to_string()).context("invalid upstream address")?;
        Ok(Arc::new(Self {
            upstream: cfg.upstream,
            upstream_host,
            allowed,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            bearer: Mutex::new(BearerState::default()),
            sid: Mutex::new(SidState::default()),
            rejected: AtomicU64::new(0),
            last_reject_log: std::sync::Mutex::new(None),
            health: std::sync::Mutex::new(None),
        }))
    }

    /// Records the supervisor's latest view of rtbit and the tunnel.
    pub fn set_health(&self, h: Health) {
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

    /// `GET /__health`: 200 only when rtbit runs, the tunnel is fresh, the
    /// supervisor is alive and rtbit's own `/healthz` answers.
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
        } else if !health.tunnel {
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

    fn peer_allowed(&self, ip: IpAddr) -> bool {
        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => return false,
            },
        };
        self.allowed.iter().any(|c| c.contains_addr(v4))
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
    }

    // -- request handling ----------------------------------------------------

    async fn handle(&self, mut req: Request<Incoming>) -> Response<ProxyBody> {
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

        if path == HEALTH_PATH && matches!(method, Method::GET | Method::HEAD) {
            return self.health_response().await;
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
        let base_headers =
            forward_headers(&parts.headers, upgrade, navigation, &self.upstream_host);
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
                .finish(resp, &method, &prefix, &path, client_upgrade)
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
    ) -> Response<ProxyBody> {
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(client) = client_upgrade else {
                return text(StatusCode::BAD_GATEWAY, "unexpected protocol switch");
            };
            let upstream = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
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
        let out = Bytes::from(rewrite_html(&html, prefix, base_dir(path)));
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
    let lifetime = t
        .expires_in
        .map_or(DEFAULT_TOKEN_LIFETIME, Duration::from_secs);
    st.expires = Some(Instant::now() + lifetime);
    st.refresh = t.refresh_token;
    st.access = Some(t.access_token.clone());
    t.access_token
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Serves Ingress connections on `listener` until the task is dropped.
pub async fn serve(listener: TcpListener, proxy: Arc<Proxy>) -> Result<()> {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .context("connection limiter closed")?;
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("Ingress accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(proxy, stream, peer).await;
        });
    }
}

async fn handle_connection(proxy: Arc<Proxy>, mut stream: TcpStream, peer: SocketAddr) {
    if !proxy.peer_allowed(peer.ip()) {
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
        async move { Ok::<_, Infallible>(proxy.handle(req).await) }
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
fn forward_headers(
    src: &HeaderMap,
    upgrade: bool,
    navigation: bool,
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
    if navigation {
        // HTML must arrive uncompressed so the base/shim can be injected.
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

/// `Path=/` cookies from rtbit would land on Home Assistant's own origin root.
fn rewrite_set_cookie(h: &mut HeaderMap, prefix: &str) {
    if prefix.is_empty() || !h.contains_key(header::SET_COOKIE) {
        return;
    }
    let cookies: Vec<HeaderValue> = h
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| {
            let Ok(s) = v.to_str() else {
                return v.clone();
            };
            let rewritten: Vec<String> = s
                .split(';')
                .map(|attr| {
                    let t = attr.trim();
                    match t.split_once('=') {
                        Some((k, p))
                            if k.trim().eq_ignore_ascii_case("path")
                                && p.starts_with('/')
                                && !already_prefixed(p.as_bytes(), prefix.as_bytes()) =>
                        {
                            format!(" Path={prefix}{p}")
                        }
                        _ => attr.to_owned(),
                    }
                })
                .collect();
            HeaderValue::from_str(&rewritten.join(";")).unwrap_or_else(|_| v.clone())
        })
        .collect();
    h.remove(header::SET_COOKIE);
    for c in cookies {
        h.append(header::SET_COOKIE, c);
    }
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
function wsUrl(u){u=fixAny(u);if(typeof u==="string"&&u.charAt(0)==="/")return(location.protocol==="https:"?"wss://":"ws://")+location.host+u;return u;}
var F=window.fetch;if(F)window.fetch=function(i,o){if(typeof Request!=="undefined"&&i instanceof Request){var r=new URL(i.url);if(r.origin===O){var p=fix(r.pathname);if(p!==r.pathname){r.pathname=p;i=new Request(r.href,i);}}}else{i=fixAny(i);}return F.call(this,i,o);};
var X=window.XMLHttpRequest&&XMLHttpRequest.prototype.open;if(X)XMLHttpRequest.prototype.open=function(){var a=Array.prototype.slice.call(arguments);a[1]=fixAny(a[1]);return X.apply(this,a);};
function wrap(n,c){var C=window[n];if(!C||typeof Proxy==="undefined"||typeof Reflect==="undefined")return;window[n]=new Proxy(C,{construct:function(t,a,nt){a=Array.prototype.slice.call(a);if(a.length)a[0]=c(a[0]);return Reflect.construct(t,a,nt);}});}
wrap("WebSocket",wsUrl);wrap("EventSource",fixAny);
["pushState","replaceState"].forEach(function(m){var H=history[m];if(H)history[m]=function(s,t,u){return u===undefined||u===null?H.call(this,s,t):H.call(this,s,t,fixAny(u));};});
var W=window.open;if(W)window.open=function(){var a=Array.prototype.slice.call(arguments);a[0]=fixAny(a[0]);return W.apply(this,a);};
function nav(e){var a=e.target&&e.target.closest?e.target.closest("a[href],area[href]"):null;if(!a)return;var h=a.getAttribute("href"),n=fix(h);if(n!==h)a.setAttribute("href",n);}
document.addEventListener("click",nav,true);document.addEventListener("auxclick",nav,true);
document.addEventListener("submit",function(e){var f=e.target;if(!f||!f.getAttribute)return;var a=f.getAttribute("action"),n=fix(a);if(a&&n!==a)f.setAttribute("action",n);},true);})();"##;

/// Directory of a request path (`/web/index.html` -> `/web/`).
fn base_dir(path: &str) -> &str {
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
    while i < html.len() {
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
    let body = prefix_root_relative_attrs(html, prefix.as_bytes());
    let at = injection_point(&body);
    let prefix_js = serde_json::to_string(prefix).unwrap_or_else(|_| "\"\"".to_owned());
    let snippet = format!(
        "<base href=\"{}\"><script>{}</script>",
        html_escape(&format!("{prefix}{dir}")),
        SHIM.replace("__INGRESS_PATH__", &prefix_js)
    );
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
<p>The torrent engine is not reachable yet. It only starts once the Proton VPN
tunnel is up and the kill-switch is active, and it restarts for a few seconds
when the forwarded port changes.</p>
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
                "x=1",
            ]
        );
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
            allowed_peers: vec!["172.30.32.2/32".into(), "127.0.0.1/32".into()],
            username: "admin".into(),
            password: "pw".into(),
            log_level: LogLevel::Info,
        };
        assert!(!format!("{cfg:?}").contains("pw\""));
        let p = Proxy::new(&cfg).unwrap();
        for (ip, ok) in [
            ("172.30.32.2", true),
            ("127.0.0.1", true),
            ("::ffff:172.30.32.2", true),
            ("172.30.32.3", false),
            ("172.30.33.1", false),
            ("127.0.0.2", false),
            ("192.168.1.10", false),
            ("::1", false),
        ] {
            assert_eq!(p.peer_allowed(ip.parse().unwrap()), ok, "{ip}");
        }
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
    fn base_dir_of_paths() {
        assert_eq!(base_dir("/web/"), "/web/");
        assert_eq!(base_dir("/web/index.html"), "/web/");
        assert_eq!(base_dir("/swagger/"), "/swagger/");
        assert_eq!(base_dir("/"), "/");
    }
}
