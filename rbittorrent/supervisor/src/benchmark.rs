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
use std::path::{Path, PathBuf};
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

    // Where we come out, and how far away that is.
    match client.connect().await {
        Ok(mut conn) => {
            match client.get_text(&mut conn, "/cdn-cgi/trace").await {
                Ok(text) => {
                    for (k, v) in parse_trace(&text) {
                        match k.as_str() {
                            "ip" => out.public_ip = Some(v),
                            "colo" => out.colo = Some(v),
                            "loc" => out.country = Some(v),
                            _ => {}
                        }
                    }
                }
                Err(e) => debug!("speed test trace: {e:#}"),
            }
            let mut samples = Vec::with_capacity(LATENCY_SAMPLES);
            for _ in 0..LATENCY_SAMPLES {
                let t = Instant::now();
                match client.get_text(&mut conn, "/__down?bytes=0").await {
                    Ok(_) => samples.push(t.elapsed()),
                    Err(e) => {
                        errors.push(format!("latency: {e:#}"));
                        break;
                    }
                }
            }
            out.latency_ms = median_ms(&mut samples);
        }
        Err(e) => errors.push(format!("{e:#}")),
    }

    // Download: parallel streams until the window closes.
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + DOWNLOAD_WINDOW;
    let first_byte = Arc::new(std::sync::OnceLock::<Instant>::new());
    let mut tasks = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        let client = client.clone();
        let counter = counter.clone();
        let first_byte = first_byte.clone();
        tasks.push(tokio::spawn(async move {
            client.download(deadline, &counter, &first_byte).await
        }));
    }
    let mut stream_errors = Vec::new();
    for t in tasks {
        match t.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => stream_errors.push(format!("{e:#}")),
            Err(e) => stream_errors.push(format!("download task: {e}")),
        }
    }
    let end = Instant::now().min(deadline);
    let bytes = counter.load(Ordering::Relaxed);
    let measured_from = first_byte.get().copied().unwrap_or(start);
    out.downloaded_bytes = bytes;
    out.seconds = round1(end.saturating_duration_since(measured_from).as_secs_f64());
    out.download_mbps = mbps(bytes, end.saturating_duration_since(measured_from));
    if bytes == 0 {
        stream_errors.dedup();
        errors.extend(stream_errors.into_iter().take(1));
    }

    out.peering = peering_test(peering).await;
    if out.download_mbps.is_none() || !errors.is_empty() {
        out.error = (!errors.is_empty()).then(|| errors.join("; "));
    }
    out
}

/// TCP connect time to each target (best of three).
async fn peering_test(targets: &[PeeringTarget]) -> Vec<PeeringResult> {
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let mut best: Option<Duration> = None;
        for _ in 0..3 {
            let start = Instant::now();
            if let Ok(Ok(_)) =
                tokio::time::timeout(PEERING_TIMEOUT, TcpStream::connect(t.addr)).await
            {
                let d = start.elapsed();
                best = Some(best.map_or(d, |b| b.min(d)));
            }
        }
        out.push(PeeringResult {
            name: t.name.clone(),
            address: t.addr.ip().to_string(),
            ms: best.map(|d| round1(d.as_secs_f64() * 1000.0)),
        });
    }
    out
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

    /// One stream: repeated large requests, counting bytes until `deadline`.
    async fn download(
        &self,
        deadline: Instant,
        counter: &AtomicU64,
        first_byte: &std::sync::OnceLock<Instant>,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::from_std(deadline);
        let work = async {
            let mut conn = self.connect().await?;
            loop {
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
                        counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
            }
        };
        match tokio::time::timeout_at(deadline, work).await {
            Ok(r) => r,
            Err(_) => Ok(()), // the window closed: the normal end
        }
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

/// Removes the test file however the test ends.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Writes `data` to a new hidden file in `dir`, fsyncs and deletes it.
pub fn disk_write_test(dir: &Path, data: &[u8]) -> Result<Duration> {
    use std::io::Write as _;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let path = dir.join(format!(
        ".rbittorrent-speedtest-{}-{nanos}.tmp",
        std::process::id()
    ));
    let start = Instant::now();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("cannot create a test file in {}", dir.display()))?;
    let _guard = TempFile(path);
    f.write_all(data).context("write failed")?;
    f.sync_all().context("fsync failed")?;
    Ok(start.elapsed())
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
