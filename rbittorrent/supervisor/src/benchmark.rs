//! On-demand speed and hardware test (`POST /__benchmark`, sidebar only).
//!
//! Nothing here runs, allocates or listens until someone presses the
//! sidebar's speed-test button; afterwards every buffer and thread is gone
//! again (0 MB idle). Two halves:
//!
//! * [`run_network`], in the unprivileged Ingress proxy: download speed
//!   from Cloudflare's speed-test endpoint over TLS (6 s cap, parallel
//!   streams, on whatever route is active: `wg0` with the VPN, `eth0`
//!   without), the latency to the Cloudflare PoP that answers, and on a direct
//!   connection the connect latency to three anycast networks (regional
//!   peering).
//! * [`run_hardware`], in the supervisor (which may write to the download
//!   folder): sequential write speed of a 4 MiB file in `download_dir`,
//!   fsynced and deleted at once, and SHA-1 hashing speed (ring's assembly,
//!   ARMv8 SHA / SHA-NI when the CPU has them), the hash BitTorrent pieces use.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tracing::debug;

/// Cloudflare's public speed-test service (what speed.cloudflare.com uses).
pub const DEFAULT_HOST: &str = "speed.cloudflare.com";
/// Download measurement window.
pub const DOWNLOAD_WINDOW: Duration = Duration::from_secs(6);
/// Parallel download connections (one TCP stream rarely fills a fast line).
pub const STREAMS: usize = 4;
/// Size of each download request; streams repeat requests until the window ends.
pub const CHUNK_BYTES: u64 = 25_000_000;
/// The write test: one 4 MiB file, deleted straight away.
pub const DISK_TEST_BYTES: usize = 4 << 20;
/// SHA-1 test: 16 passes over the 4 MiB buffer.
pub const HASH_PASSES: usize = 16;
const LATENCY_SAMPLES: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const PEERING_TIMEOUT: Duration = Duration::from_secs(2);
/// All peering targets together (they are probed in parallel).
const PEERING_BUDGET: Duration = Duration::from_millis(6500);
/// The trace and the latency samples together.
const PROBE_BUDGET: Duration = Duration::from_secs(6);
/// How long the download streams may take to deliver their first byte
/// (connect, TLS and the first request). The window starts there.
pub const FIRST_BYTE_LIMIT: Duration = Duration::from_secs(6);
/// A shorter measurement says more about the handshake than the line.
pub const MIN_MEASUREMENT: Duration = Duration::from_secs(1);
/// How often the download window is checked.
const WINDOW_TICK: Duration = Duration::from_millis(25);
/// Hard cap for the whole network half.
pub const NETWORK_DEADLINE: Duration = Duration::from_secs(25);
const USER_AGENT: &str = concat!("rBittorrent-speedtest/", env!("CARGO_PKG_VERSION"));

/// Anycast networks whose nearest point of presence shows how well the
/// connection peers regionally (direct mode only).
pub fn default_peering() -> Vec<PeeringTarget> {
    [
        ("Cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
        ("Google", Ipv4Addr::new(8, 8, 8, 8)),
        ("Quad9", Ipv4Addr::new(9, 9, 9, 9)),
    ]
    .into_iter()
    .map(|(name, ip)| PeeringTarget {
        name: name.to_owned(),
        addr: SocketAddr::V4(SocketAddrV4::new(ip, 443)),
    })
    .collect()
}

/// Where the download test goes. Always Cloudflare over TLS in the app; the
/// plain-HTTP variant exists for the test suite's local mock server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedTarget {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// Resolve `host` to this address instead of using DNS (tests).
    #[serde(default)]
    pub connect_to: Option<SocketAddr>,
}

impl Default for SpeedTarget {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_owned(),
            port: 443,
            tls: true,
            connect_to: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeeringTarget {
    pub name: String,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PeeringResult {
    pub name: String,
    pub address: String,
    pub ms: Option<f64>,
}

/// The network half's result. Every part is optional: a failing step is
/// reported in `error` and the others still run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkResult {
    pub download_mbps: Option<f64>,
    pub downloaded_bytes: u64,
    pub seconds: f64,
    pub streams: usize,
    /// Median time for a tiny request to the speed-test server.
    pub latency_ms: Option<f64>,
    /// Cloudflare data centre (IATA code) and country that answered.
    pub colo: Option<String>,
    pub country: Option<String>,
    /// The address Cloudflare saw: the VPN exit with the VPN on.
    pub public_ip: Option<String>,
    pub peering: Vec<PeeringResult>,
    pub error: Option<String>,
}

/// The supervisor's half.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HardwareResult {
    pub disk_write_mb_s: Option<f64>,
    pub disk_path: String,
    pub disk_error: Option<String>,
    pub sha1_mb_s: Option<f64>,
    pub cpu_cores: usize,
}

/// One decimal place for display.
fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Megabits per second for `bytes` in `elapsed`.
pub fn mbps(bytes: u64, elapsed: Duration) -> Option<f64> {
    let secs = elapsed.as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    (secs > 0.0 && bytes > 0).then(|| round1(bytes as f64 * 8.0 / secs / 1e6))
}

/// Megabytes (10^6) per second.
pub fn mb_per_s(bytes: usize, elapsed: Duration) -> Option<f64> {
    let secs = elapsed.as_secs_f64().max(1e-6);
    #[allow(clippy::cast_precision_loss)]
    (bytes > 0).then(|| round1(bytes as f64 / secs / 1e6))
}

/// The median of `samples` in milliseconds.
pub fn median_ms(samples: &mut [Duration]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    samples
        .get(samples.len() / 2)
        .map(|d| round1(d.as_secs_f64() * 1000.0))
}

/// `key=value` lines of `/cdn-cgi/trace`.
pub fn parse_trace(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// Network half (Ingress proxy)
// ---------------------------------------------------------------------------

/// Runs the network test on its own short-lived multi-threaded runtime, so
/// TLS decryption of several streams can use every core and the proxy's own
/// single-threaded runtime keeps serving the sidebar meanwhile.
pub async fn run_network(target: SpeedTarget, peering: Vec<PeeringTarget>) -> NetworkResult {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("rbt-benchmark".into())
        .spawn(move || {
            let workers = std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .clamp(1, STREAMS);
            let result = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(async {
                    match tokio::time::timeout(NETWORK_DEADLINE, network(&target, &peering)).await {
                        Ok(r) => r,
                        Err(_) => NetworkResult {
                            error: Some(format!(
                                "the test did not finish within {}s",
                                NETWORK_DEADLINE.as_secs()
                            )),
                            ..NetworkResult::default()
                        },
                    }
                }),
                Err(e) => NetworkResult {
                    error: Some(format!("cannot start the test runtime: {e}")),
                    ..NetworkResult::default()
                },
            };
            let _ = tx.send(result);
        });
    if let Err(e) = spawned {
        return NetworkResult {
            error: Some(format!("cannot start the test thread: {e}")),
            ..NetworkResult::default()
        };
    }
    rx.await.unwrap_or_else(|_| NetworkResult {
        error: Some("the test thread stopped unexpectedly".to_owned()),
        ..NetworkResult::default()
    })
}

async fn network(target: &SpeedTarget, peering: &[PeeringTarget]) -> NetworkResult {
    let mut out = NetworkResult {
        streams: STREAMS,
        ..NetworkResult::default()
    };
    let client = match Client::new(target).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            out.error = Some(format!("{e:#}"));
            out.peering = peering_test(peering).await;
            return out;
        }
    };
    let mut errors = Vec::new();

    // Where we come out and how far away that is, while the peering targets
    // are probed (in parallel, so the whole test stays within its deadline).
    let mut probe_out = Probe::default();
    let (probed, peering_results) = tokio::join!(
        tokio::time::timeout(PROBE_BUDGET, probe(&client, &mut probe_out)),
        peering_test(peering),
    );
    out.peering = peering_results;
    out.public_ip = probe_out.public_ip;
    out.colo = probe_out.colo;
    out.country = probe_out.country;
    out.latency_ms = median_ms(&mut probe_out.samples);
    errors.extend(probe_out.errors);
    if probed.is_err() && out.latency_ms.is_none() {
        errors.push(format!("{} did not answer in time", target.host));
    }

    let dl = download_window(&client).await;
    out.downloaded_bytes = dl.bytes;
    match dl.measured {
        Some(d) => {
            out.seconds = round1(d.as_secs_f64());
            if d >= MIN_MEASUREMENT {
                out.download_mbps = mbps(dl.bytes, d);
            } else {
                errors.push(format!(
                    "the download stopped after {:.1}s, too early to measure",
                    d.as_secs_f64()
                ));
            }
        }
        None if dl.errors.is_empty() => errors.push(format!(
            "no data from {} within {}s",
            target.host,
            FIRST_BYTE_LIMIT.as_secs()
        )),
        None => {}
    }
    if out.download_mbps.is_none() {
        let mut stream_errors = dl.errors;
        stream_errors.dedup();
        errors.extend(stream_errors.into_iter().take(1));
    }
    out.error = (!errors.is_empty()).then(|| errors.join("; "));
    out
}

#[derive(Default)]
struct Probe {
    public_ip: Option<String>,
    colo: Option<String>,
    country: Option<String>,
    samples: Vec<Duration>,
    errors: Vec<String>,
}

/// `/cdn-cgi/trace` and the latency samples on one connection. Results land
/// in `p` as they come, so a timeout keeps what was measured.
async fn probe(client: &Client, p: &mut Probe) {
    let mut conn = match client.connect().await {
        Ok(c) => c,
        Err(e) => {
            p.errors.push(format!("{e:#}"));
            return;
        }
    };
    match client.get_text(&mut conn, "/cdn-cgi/trace").await {
        Ok(text) => {
            for (k, v) in parse_trace(&text) {
                match k.as_str() {
                    "ip" => p.public_ip = Some(v),
                    "colo" => p.colo = Some(v),
                    "loc" => p.country = Some(v),
                    _ => {}
                }
            }
        }
        Err(e) => {
            debug!("speed test trace: {e:#}");
            // A failed request can leave the connection unusable.
            conn = match client.connect().await {
                Ok(c) => c,
                Err(e) => {
                    p.errors.push(format!("{e:#}"));
                    return;
                }
            };
        }
    }
    for _ in 0..LATENCY_SAMPLES {
        let t = Instant::now();
        match client.get_text(&mut conn, "/__down?bytes=0").await {
            Ok(_) => p.samples.push(t.elapsed()),
            Err(e) => {
                p.errors.push(format!("latency: {e:#}"));
                break;
            }
        }
    }
}

struct Download {
    bytes: u64,
    /// From the first byte to the end of the window; `None` without data.
    measured: Option<Duration>,
    errors: Vec<String>,
}

/// Parallel streams for [`DOWNLOAD_WINDOW`], counted from the first byte any
/// of them receives, so a slow handshake cannot shrink the window.
async fn download_window(client: &Arc<Client>) -> Download {
    let counter = Arc::new(AtomicU64::new(0));
    let first_byte = Arc::new(std::sync::OnceLock::<Instant>::new());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let started = Instant::now();
    let mut streams = tokio::task::JoinSet::new();
    for _ in 0..STREAMS {
        let client = client.clone();
        let counter = counter.clone();
        let first_byte = first_byte.clone();
        let mut stop = stop_rx.clone();
        streams.spawn(async move {
            tokio::select! {
                r = client.download(&counter, &first_byte) => r,
                _ = stop.changed() => Ok(()),
            }
        });
    }
    let mut errors = Vec::new();
    let window = loop {
        let now = Instant::now();
        match first_byte.get() {
            Some(fb) if now >= *fb + DOWNLOAD_WINDOW => break Some((*fb, now)),
            None if now >= started + FIRST_BYTE_LIMIT => break None,
            _ => {}
        }
        tokio::select! {
            joined = streams.join_next() => match joined {
                Some(r) => record_stream(&mut errors, r),
                // Every stream ended before the window closed.
                None => break first_byte.get().map(|fb| (*fb, Instant::now())),
            },
            () = tokio::time::sleep(WINDOW_TICK) => {}
        }
    };
    let bytes = counter.load(Ordering::Relaxed);
    let _ = stop_tx.send(true);
    while let Some(r) = streams.join_next().await {
        record_stream(&mut errors, r);
    }
    Download {
        bytes,
        measured: window.map(|(from, to)| to.saturating_duration_since(from)),
        errors,
    }
}

fn record_stream(errors: &mut Vec<String>, r: Result<Result<()>, tokio::task::JoinError>) {
    match r {
        Ok(Ok(())) => {}
        Ok(Err(e)) => errors.push(format!("{e:#}")),
        Err(e) => errors.push(format!("download task: {e}")),
    }
}

/// TCP connect time to each target (best of three), all targets at once.
async fn peering_test(targets: &[PeeringTarget]) -> Vec<PeeringResult> {
    let mut tasks: Vec<_> = targets
        .iter()
        .map(|t| tokio::spawn(best_connect(t.addr)))
        .collect();
    let deadline = tokio::time::Instant::now() + PEERING_BUDGET;
    let mut out = Vec::with_capacity(targets.len());
    for (t, task) in targets.iter().zip(tasks.iter_mut()) {
        let best = match tokio::time::timeout_at(deadline, &mut *task).await {
            Ok(Ok(best)) => best,
            Ok(Err(_)) => None,
            Err(_) => {
                task.abort();
                None
            }
        };
        out.push(PeeringResult {
            name: t.name.clone(),
            address: t.addr.ip().to_string(),
            ms: best.map(|d| round1(d.as_secs_f64() * 1000.0)),
        });
    }
    out
}

async fn best_connect(addr: SocketAddr) -> Option<Duration> {
    let mut best: Option<Duration> = None;
    for _ in 0..3 {
        let start = Instant::now();
        if let Ok(Ok(_)) = tokio::time::timeout(PEERING_TIMEOUT, TcpStream::connect(addr)).await {
            let d = start.elapsed();
            best = Some(best.map_or(d, |b| b.min(d)));
        }
    }
    best
}

/// A tiny HTTP/1.1 client for the speed-test server (TLS in production).
struct Client {
    target: SpeedTarget,
    addr: SocketAddr,
    host: HeaderValue,
    tls: Option<tokio_rustls::TlsConnector>,
}

type Sender = SendRequest<Empty<Bytes>>;

impl Client {
    async fn new(target: &SpeedTarget) -> Result<Self> {
        let addr = match target.connect_to {
            Some(a) => a,
            None => {
                let addrs = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio::net::lookup_host((target.host.as_str(), target.port)),
                )
                .await
                .map_err(|_| anyhow!("DNS lookup of {} timed out", target.host))?
                .with_context(|| format!("cannot resolve {}", target.host))?;
                // IPv6 is dropped by the kill-switch (and often absent).
                addrs
                    .into_iter()
                    .find(SocketAddr::is_ipv4)
                    .ok_or_else(|| anyhow!("{} has no IPv4 address", target.host))?
            }
        };
        let host = HeaderValue::from_str(&target.host).context("invalid speed-test host")?;
        let tls = target.tls.then(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let provider = Arc::new(tls_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map(|b| b.with_root_certificates(roots).with_no_client_auth());
            config.map(|c| tokio_rustls::TlsConnector::from(Arc::new(c)))
        });
        let tls = match tls {
            Some(Ok(c)) => Some(c),
            Some(Err(e)) => bail!("TLS setup failed: {e}"),
            None => None,
        };
        Ok(Self {
            target: target.clone(),
            addr,
            host,
            tls,
        })
    }

    async fn connect(&self) -> Result<Sender> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| anyhow!("connecting to {} timed out", self.target.host))?
            .with_context(|| format!("cannot connect to {} ({})", self.target.host, self.addr))?;
        let _ = stream.set_nodelay(true);
        match &self.tls {
            Some(tls) => {
                let name = rustls::pki_types::ServerName::try_from(self.target.host.clone())
                    .context("invalid TLS server name")?;
                let tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, tls.connect(name, stream))
                    .await
                    .map_err(|_| anyhow!("TLS handshake with {} timed out", self.target.host))?
                    .with_context(|| format!("TLS handshake with {} failed", self.target.host))?;
                handshake(TokioIo::new(tls_stream)).await
            }
            None => handshake(TokioIo::new(stream)).await,
        }
    }

    fn request(&self, path: &str) -> Result<Request<Empty<Bytes>>> {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Empty::new())
            .context("cannot build the speed-test request")?;
        let h = req.headers_mut();
        h.insert(header::HOST, self.host.clone());
        h.insert(header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        Ok(req)
    }

    async fn get_text(&self, conn: &mut Sender, path: &str) -> Result<String> {
        let req = self.request(path)?;
        let fut = async {
            conn.ready().await.context("connection closed")?;
            let resp = conn.send_request(req).await.context("request failed")?;
            let status = resp.status();
            let body = Limited::new(resp.into_body(), 64 << 10)
                .collect()
                .await
                .map_err(|e| anyhow!("cannot read the answer: {e}"))?
                .to_bytes();
            if !status.is_success() {
                bail!("{} answered HTTP {status}", self.target.host);
            }
            Ok(String::from_utf8_lossy(&body).into_owned())
        };
        tokio::time::timeout(REQUEST_TIMEOUT, fut)
            .await
            .map_err(|_| anyhow!("{} did not answer in time", self.target.host))?
    }

    /// One stream: repeated large requests, counting bytes until it is
    /// stopped. A connection the server closes after some data (keep-alive
    /// limits) is replaced; one that fails before any data ends the stream.
    async fn download(
        &self,
        counter: &AtomicU64,
        first_byte: &std::sync::OnceLock<Instant>,
    ) -> Result<()> {
        let mut conn = self.connect().await?;
        let mut delivered = false;
        loop {
            let mut got = 0u64;
            let r = self
                .download_chunk(&mut conn, counter, first_byte, &mut got)
                .await;
            delivered |= got > 0;
            match r {
                Ok(()) if got == 0 => bail!("{} sent an empty download", self.target.host),
                Ok(()) => {}
                Err(e) if !delivered => return Err(e),
                Err(e) => {
                    debug!("speed test: new connection after: {e:#}");
                    conn = self.connect().await?;
                    delivered = false;
                }
            }
        }
    }

    async fn download_chunk(
        &self,
        conn: &mut Sender,
        counter: &AtomicU64,
        first_byte: &std::sync::OnceLock<Instant>,
        got: &mut u64,
    ) -> Result<()> {
        conn.ready().await.context("connection closed")?;
        let req = self.request(&format!("/__down?bytes={CHUNK_BYTES}"))?;
        let resp = conn
            .send_request(req)
            .await
            .context("download request failed")?;
        if !resp.status().is_success() {
            bail!(
                "{} refused the download (HTTP {})",
                self.target.host,
                resp.status()
            );
        }
        let mut body = resp.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.context("download interrupted")?;
            if let Some(data) = frame.data_ref() {
                first_byte.get_or_init(Instant::now);
                let n = data.len() as u64;
                *got += n;
                counter.fetch_add(n, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}

async fn handshake<T>(io: T) -> Result<Sender>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP handshake failed")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("speed-test connection ended: {e}");
        }
    });
    Ok(sender)
}

/// ring's TLS provider; ChaCha20 first on CPUs without AES instructions (Pi 4
/// and older), where it is several times faster than software AES.
fn tls_provider() -> rustls::crypto::CryptoProvider {
    let mut p = rustls::crypto::ring::default_provider();
    if !has_aes_instructions() {
        p.cipher_suites.sort_by_key(|s| {
            !matches!(
                s.suite(),
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            )
        });
    }
    p
}

fn has_aes_instructions() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Hardware half (supervisor)
// ---------------------------------------------------------------------------

/// Deterministic, incompressible test data (xorshift), so compressing file
/// systems cannot cheat the write test.
pub fn test_buffer(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Writes `data` to a new hidden file in `dir`, fsyncs, closes and deletes
/// it. The folder is opened once without following a symlink, and the file
/// is created and removed relative to that handle, so a folder swapped for a
/// symlink meanwhile cannot redirect this root process. The file is closed
/// before it is deleted: SMB/CIFS shares refuse to delete open files.
pub fn disk_write_test(dir: &Path, data: &[u8]) -> Result<Duration> {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    let context = || format!("cannot create a test file in {}", dir.display());
    let folder = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| {
            // O_NOFOLLOW: ELOOP or (with O_DIRECTORY) ENOTDIR on a symlink.
            if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
                anyhow!("the folder is a symbolic link")
            } else {
                anyhow::Error::from(e)
            }
        })
        .with_context(context)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let name = CString::new(format!(
        ".rbittorrent-speedtest-{}-{nanos}.tmp",
        std::process::id()
    ))
    .context("invalid test file name")?;
    let start = Instant::now();
    // SAFETY: a valid folder descriptor and a NUL-terminated name.
    let raw = unsafe {
        libc::openat(
            folder.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw < 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error())).with_context(context);
    }
    // SAFETY: `openat` just returned this descriptor to us.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    let written = file
        .write_all(data)
        .context("write failed")
        .and_then(|()| file.sync_all().context("fsync failed"))
        .map(|()| start.elapsed());
    drop(file);
    // SAFETY: the same folder descriptor and name as above.
    if unsafe { libc::unlinkat(folder.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(anyhow!(
            "cannot remove the test file {}: {e}",
            dir.join(name.to_string_lossy().as_ref()).display()
        ));
    }
    written
}

/// SHA-1 over `passes` copies of `data`.
pub fn sha1_test(data: &[u8], passes: usize) -> Duration {
    let start = Instant::now();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    for _ in 0..passes {
        ctx.update(data);
    }
    std::hint::black_box(ctx.finish());
    start.elapsed()
}

/// The supervisor's half (blocking: run it on a blocking thread).
pub fn run_hardware(download_dir: &Path, cpu_cores: usize) -> HardwareResult {
    let data = test_buffer(DISK_TEST_BYTES);
    let mut out = HardwareResult {
        disk_path: download_dir.display().to_string(),
        cpu_cores,
        ..HardwareResult::default()
    };
    match disk_write_test(download_dir, &data) {
        Ok(d) => out.disk_write_mb_s = mb_per_s(data.len(), d),
        Err(e) => out.disk_error = Some(format!("{e:#}")),
    }
    let d = sha1_test(&data, HASH_PASSES);
    out.sha1_mb_s = mb_per_s(data.len() * HASH_PASSES, d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_and_rounding() {
        assert_eq!(mbps(12_500_000, Duration::from_secs(1)), Some(100.0));
        assert_eq!(mbps(0, Duration::from_secs(1)), None);
        assert_eq!(mbps(1, Duration::ZERO), None);
        assert_eq!(mb_per_s(4_000_000, Duration::from_millis(500)), Some(8.0));
        let mut s = vec![
            Duration::from_millis(30),
            Duration::from_millis(10),
            Duration::from_millis(20),
        ];
        assert_eq!(median_ms(&mut s), Some(20.0));
        assert_eq!(median_ms(&mut []), None);
    }

    #[test]
    fn trace_lines_are_parsed() {
        let t = parse_trace("fl=1\nip=185.159.156.1\ncolo=AMS\nloc=NL\ngarbage\n");
        assert!(t.contains(&("ip".into(), "185.159.156.1".into())));
        assert!(t.contains(&("colo".into(), "AMS".into())));
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn hardware_test_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("rbt-bench-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let r = run_hardware(&dir, 4);
        assert!(r.disk_write_mb_s.is_some_and(|v| v > 0.0), "{r:?}");
        assert!(r.sha1_mb_s.is_some_and(|v| v > 0.0), "{r:?}");
        assert_eq!(r.cpu_cores, 4);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "test file removed"
        );
        let missing = run_hardware(&dir.join("not-mounted"), 1);
        assert!(
            missing
                .disk_error
                .unwrap()
                .contains("cannot create a test file")
        );
        assert!(missing.sha1_mb_s.is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A raw HTTP/1.1 stand-in for the speed-test server: every download
    /// waits until 3 s after the first one was asked for (a slow start) and
    /// closes the connection after 2 MB (a keep-alive limit).
    async fn slow_start_server() -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let gate = Arc::new(std::sync::OnceLock::<tokio::time::Instant>::new());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let gate = gate.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        let head_end = loop {
                            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break i + 4;
                            }
                            let mut chunk = [0u8; 1024];
                            match s.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                        buf.drain(..head_end);
                        let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                        if path == "/cdn-cgi/trace" {
                            let body = "ip=203.0.113.9\ncolo=TST\nloc=BE\n";
                            let r = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            );
                            if s.write_all(r.as_bytes()).await.is_err() {
                                return;
                            }
                            continue;
                        }
                        let n: usize = path
                            .strip_prefix("/__down?bytes=")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        if n == 0 {
                            if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                .await
                                .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                        let at = *gate
                            .get_or_init(|| tokio::time::Instant::now() + Duration::from_secs(3));
                        tokio::time::sleep_until(at).await;
                        let len = n.min(2_000_000);
                        let r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
                        );
                        if s.write_all(r.as_bytes()).await.is_err() {
                            return;
                        }
                        let block = vec![7u8; 64 << 10];
                        let mut left = len;
                        while left > 0 {
                            let take = left.min(block.len());
                            if s.write_all(&block[..take]).await.is_err() {
                                return;
                            }
                            left -= take;
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        return;
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn the_window_starts_at_the_first_byte_and_streams_reconnect() {
        let addr = slow_start_server().await;
        let target = SpeedTarget {
            host: "speed.test".into(),
            port: addr.port(),
            tls: false,
            connect_to: Some(addr),
        };
        let peering = vec![
            PeeringTarget {
                name: "here".into(),
                addr,
            },
            PeeringTarget {
                name: "closed".into(),
                addr: "127.0.0.1:1".parse().unwrap(),
            },
        ];
        let started = Instant::now();
        let r = network(&target, &peering).await;
        let took = started.elapsed();
        assert!(r.error.is_none(), "{r:?}");
        assert_eq!(r.public_ip.as_deref(), Some("203.0.113.9"));
        assert!(r.latency_ms.is_some(), "{r:?}");
        // The full window after the 3 s start, not what was left of it.
        let secs = r.seconds;
        assert!((5.9..7.0).contains(&secs), "{r:?}");
        assert!(took >= Duration::from_secs(9), "{took:?}");
        assert!(took < NETWORK_DEADLINE, "{took:?}");
        // Several 2 MB answers per stream: the streams reconnected.
        assert!(r.downloaded_bytes > (STREAMS as u64) * 2_000_000, "{r:?}");
        let expected = r.downloaded_bytes as f64 * 8.0 / secs / 1e6;
        let got = r.download_mbps.unwrap();
        assert!(
            (got - expected).abs() / expected < 0.05,
            "{got} vs {expected}"
        );
        assert_eq!(r.peering.len(), 2);
        assert!(r.peering[0].ms.is_some(), "{r:?}");
        assert!(r.peering[1].ms.is_none(), "{r:?}");
    }

    #[test]
    fn the_disk_test_does_not_follow_a_symlinked_folder() {
        let base = std::env::temp_dir().join(format!("rbt-bench-link-{}", std::process::id()));
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = disk_write_test(&link, b"data").unwrap_err();
        assert!(format!("{e:#}").contains("symbolic link"), "{e:#}");
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
        assert!(disk_write_test(&real, b"data").is_ok());
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_data_is_not_trivially_compressible() {
        let b = test_buffer(DISK_TEST_BYTES);
        assert_eq!(b.len(), DISK_TEST_BYTES);
        let zeros = b.iter().filter(|&&x| x == 0).count();
        assert!(zeros < b.len() / 100, "{zeros}");
        assert_ne!(b.get(..64), b.get(64..128));
    }

    #[test]
    fn tls_provider_keeps_every_suite() {
        let p = tls_provider();
        assert_eq!(
            p.cipher_suites.len(),
            rustls::crypto::ring::default_provider().cipher_suites.len()
        );
    }
}
