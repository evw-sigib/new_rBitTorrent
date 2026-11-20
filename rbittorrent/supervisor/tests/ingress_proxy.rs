//! Integration tests: the real Ingress proxy over real sockets, in front of a
//! mock rtbit that implements the endpoints the proxy and the web UI use.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::channel::Channel;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;

use rbittorrent_supervisor::benchmark::{self, PeeringTarget, SpeedTarget};
use rbittorrent_supervisor::config::LogLevel;
use rbittorrent_supervisor::ingress::{self, Health, Proxy, ProxyConfig, ProxyRequest};

const PASSWORD: &str = "p@ss w&rd=1";
const PREFIX: &str = "/api/hassio_ingress/Zx9-tok_en";

type Body = UnsyncBoxBody<Bytes, Infallible>;

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).boxed_unsync()
}

// ---------------------------------------------------------------------------
// Mock rtbit
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Mock {
    logins: AtomicUsize,
    refreshes: AtomicUsize,
    sid_logins: AtomicUsize,
    requests: AtomicUsize,
    tokens: Mutex<HashSet<String>>,
    next: AtomicUsize,
    healthz: AtomicU16,
    gate: Mutex<Option<oneshot::Receiver<()>>>,
}

const INDEX: &str = "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"UTF-8\" />\n    \
    <title>RustTorrent</title>\n    <link rel=\"icon\" href=\"assets/logo.svg\" />\n    \
    <script type=\"module\" crossorigin src=\"assets/index.js\"></script>\n  </head>\n  \
    <body><div id=\"app\"></div><a href=\"/swagger/\">API</a></body>\n</html>\n";

/// Deterministic, non-repeating-looking payload.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 7)) as u8)
        .collect()
}

fn json_resp(status: StatusCode, v: serde_json::Value) -> Response<Body> {
    let mut r = Response::new(full(v.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

fn header_str(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).map(|v| v.to_str().unwrap().to_owned())
}

impl Mock {
    fn issue(&self) -> serde_json::Value {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let token = format!("tok-{n}");
        self.tokens.lock().unwrap().insert(token.clone());
        serde_json::json!({
            "access_token": token,
            "refresh_token": format!("ref-{n}"),
            "token_type": "Bearer",
            "expires_in": 900,
            "role": "admin",
        })
    }

    fn bearer_ok(&self, h: &HeaderMap) -> bool {
        header_str(h, "authorization")
            .and_then(|a| a.strip_prefix("Bearer ").map(str::to_owned))
            .is_some_and(|t| self.tokens.lock().unwrap().contains(&t))
    }

    async fn handle(self: Arc<Self>, mut req: Request<Incoming>) -> Response<Body> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let path = req.uri().path().to_owned();
        let method = req.method().clone();
        match (method, path.as_str()) {
            (Method::POST, "/auth/login") => {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                self.logins.fetch_add(1, Ordering::SeqCst);
                if v["username"] == "admin" && v["password"] == PASSWORD {
                    json_resp(StatusCode::OK, self.issue())
                } else {
                    json_resp(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({"error": "bad"}),
                    )
                }
            }
            (Method::POST, "/auth/refresh") => {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                self.refreshes.fetch_add(1, Ordering::SeqCst);
                if v["refresh_token"]
                    .as_str()
                    .is_some_and(|t| t.starts_with("ref-"))
                {
                    json_resp(StatusCode::OK, self.issue())
                } else {
                    json_resp(StatusCode::UNAUTHORIZED, serde_json::json!({}))
                }
            }
            (Method::GET, "/auth/status") => json_resp(
                StatusCode::OK,
                serde_json::json!({"auth_enabled": true, "setup_required": false}),
            ),
            (Method::GET, "/") => {
                let mut r = Response::new(full("redirect"));
                *r.status_mut() = StatusCode::TEMPORARY_REDIRECT;
                r.headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_static("/web/"));
                r
            }
            (Method::GET, "/web/") => {
                let mut r = Response::new(full(INDEX));
                let h = r.headers_mut();
                h.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                h.insert(header::ETAG, HeaderValue::from_static("\"index-v1\""));
                h.insert(
                    "x-saw-accept-encoding",
                    HeaderValue::from_str(
                        &header_str(req.headers(), "accept-encoding").unwrap_or_default(),
                    )
                    .unwrap(),
                );
                r
            }
            (Method::GET, "/torrents") => {
                if !self.bearer_ok(req.headers()) {
                    let mut r = json_resp(StatusCode::UNAUTHORIZED, serde_json::json!({}));
                    r.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static("Basic realm=\"API\""),
                    );
                    return r;
                }
                let h = req.headers();
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({
                        "torrents": [{"id": 1, "name": "/web/ <b>not html</b>"}],
                        "authorization": header_str(h, "authorization"),
                        "cookie": header_str(h, "cookie"),
                        "origin": header_str(h, "origin"),
                        "referer": header_str(h, "referer"),
                        "host": header_str(h, "host"),
                        "x_ingress_path": header_str(h, "x-ingress-path"),
                    }),
                )
            }
            (Method::POST, "/api/v2/auth/login") => {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let form = String::from_utf8(body.to_vec()).unwrap();
                self.sid_logins.fetch_add(1, Ordering::SeqCst);
                let ok = form == "username=admin&password=p%40ss%20w%26rd%3D1";
                let mut r = Response::new(full(if ok { "Ok." } else { "Fails." }));
                if ok {
                    r.headers_mut().insert(
                        header::SET_COOKIE,
                        HeaderValue::from_static("SID=sid-1; Path=/; HttpOnly; SameSite=Strict"),
                    );
                }
                r
            }
            (Method::GET, "/api/v2/app/version") => {
                let ok = header_str(req.headers(), "cookie").as_deref() == Some("SID=sid-1")
                    && header_str(req.headers(), "authorization").is_none();
                let mut r = Response::new(full(if ok { "v5.0.0" } else { "Forbidden" }));
                if !ok {
                    *r.status_mut() = StatusCode::FORBIDDEN;
                }
                r
            }
            (Method::GET, "/healthz") => {
                let mut r = Response::new(full("ok"));
                *r.status_mut() =
                    StatusCode::from_u16(self.healthz.load(Ordering::SeqCst)).unwrap();
                r
            }
            (Method::GET, "/big") => {
                let (mut tx, body) = Channel::<Bytes, Infallible>::new(4);
                tokio::spawn(async move {
                    let data = pattern(8 << 20);
                    for chunk in data.chunks(64 << 10) {
                        if tx.send_data(Bytes::copy_from_slice(chunk)).await.is_err() {
                            return;
                        }
                    }
                });
                let mut r = Response::new(body.boxed_unsync());
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                r
            }
            (Method::GET, "/gated") => {
                let gate = self.gate.lock().unwrap().take().unwrap();
                let (mut tx, body) = Channel::<Bytes, Infallible>::new(1);
                tokio::spawn(async move {
                    tx.send_data(Bytes::from_static(b"data: first\n\n"))
                        .await
                        .unwrap();
                    let _ = gate.await;
                    let _ = tx.send_data(Bytes::from_static(b"data: second\n\n")).await;
                });
                let mut r = Response::new(body.boxed_unsync());
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/event-stream"),
                );
                r
            }
            (Method::POST, "/torrents") => {
                if !self.bearer_ok(req.headers()) {
                    return json_resp(StatusCode::UNAUTHORIZED, serde_json::json!({}));
                }
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let ok = body.as_ref() == pattern(6 << 20).as_slice();
                json_resp(
                    StatusCode::OK,
                    serde_json::json!({"received": body.len(), "intact": ok}),
                )
            }
            (Method::GET, "/ws") => {
                let upgrade = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    let mut io = TokioIo::new(upgrade.await.unwrap());
                    let mut buf = [0u8; 64];
                    loop {
                        let n = io.read(&mut buf).await.unwrap_or(0);
                        if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
                let mut r = Response::new(full(Bytes::new()));
                *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                let h = r.headers_mut();
                h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                h.insert(
                    "sec-websocket-accept",
                    HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
                );
                r
            }
            _ => {
                let mut r = Response::new(full("not found"));
                *r.status_mut() = StatusCode::NOT_FOUND;
                r
            }
        }
    }
}

async fn start_mock() -> (SocketAddr, Arc<Mock>) {
    let mock = Arc::new(Mock::default());
    mock.healthz.store(200, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let m = mock.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let m = m.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let m = m.clone();
                    async move { Ok::<_, Infallible>(m.handle(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    (addr, mock)
}

async fn start_proxy(upstream: SocketAddr, password: &str) -> (SocketAddr, Arc<Proxy>) {
    start_proxy_with(upstream, password, None, None).await
}

async fn start_proxy_with(
    upstream: SocketAddr,
    password: &str,
    speed_target: Option<SpeedTarget>,
    peering: Option<Vec<PeeringTarget>>,
) -> (SocketAddr, Arc<Proxy>) {
    // These tests drive the proxy from loopback, so it gets full access here;
    // production makes loopback health-only (see the test below).
    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream,
        allowed_peers: vec!["172.30.32.2/32".into(), "127.0.0.1/32".into()],
        health_only_peers: Vec::new(),
        username: "admin".into(),
        password: password.into(),
        log_level: LogLevel::Info,
        speed_target,
        peering,
    };
    start_proxy_cfg(&cfg).await
}

async fn start_proxy_cfg(cfg: &ProxyConfig) -> (SocketAddr, Arc<Proxy>) {
    let proxy = Proxy::new(cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(ingress::serve(listener, proxy.clone()));
    (addr, proxy)
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

async fn send(addr: SocketAddr, req: Request<Body>) -> Response<Incoming> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    sender.send_request(req).await.unwrap()
}

fn get(path: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut r = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(full(Bytes::new()))
        .unwrap();
    r.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("172.30.33.5:8099"));
    r.headers_mut()
        .insert("x-ingress-path", HeaderValue::from_static(PREFIX));
    for (k, v) in headers {
        r.headers_mut().insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    r
}

async fn body_of(resp: Response<Incoming>) -> (StatusCode, HeaderMap, Bytes) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

fn json(body: &Bytes) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn index_html_gets_base_href_and_shim_for_the_ingress_path() {
    let (up, _mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;
    let resp = send(
        proxy,
        get(
            "/web/",
            &[
                ("accept", "text/html,application/xhtml+xml"),
                ("accept-encoding", "gzip, br"),
            ],
        ),
    )
    .await;
    let (status, h, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(
        h["content-length"].to_str().unwrap(),
        body.len().to_string()
    );
    assert_eq!(h["cache-control"], "no-store");
    assert!(
        h.get("etag").is_none(),
        "rewritten pages must not be cached"
    );
    assert_eq!(
        h["x-saw-accept-encoding"], "",
        "HTML is fetched uncompressed"
    );

    let meta = html.find("<meta charset=\"UTF-8\" />").unwrap();
    let base = html
        .find(&format!("<base href=\"{PREFIX}/web/\">"))
        .unwrap_or_else(|| panic!("no base href in {html}"));
    assert!(base > meta && base < html.find("<title>").unwrap());
    assert!(html.contains(&format!("var P=\"{PREFIX}\"")), "{html}");
    for hook in [
        "window.fetch",
        "XMLHttpRequest.prototype.open",
        "\"WebSocket\"",
        "\"EventSource\"",
    ] {
        assert!(html.contains(hook), "shim misses {hook}");
    }
    assert!(
        html.contains("src=\"assets/index.js\""),
        "relative assets untouched"
    );
    assert!(
        html.contains(&format!("href=\"{PREFIX}/swagger/\"")),
        "absolute link prefixed"
    );
    // The status bar comes with the web UI.
    assert!(html.contains("rbittorrent-status-bar"), "{html}");
    assert!(html.contains("Direct Connection (Unprotected)"));
    assert!(html.contains(&format!("D=\"{}\"", ingress::DOCS_URL)));
    assert!(html.is_ascii(), "injected markup is pure ASCII");
}

#[tokio::test]
async fn redirects_stay_inside_ingress_and_api_json_is_untouched() {
    let (up, _mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;

    let (status, h, _) = body_of(send(proxy, get("/", &[("accept", "text/html")])).await).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(h["location"].to_str().unwrap(), format!("{PREFIX}/web/"));

    let (status, h, body) = body_of(send(proxy, get("/torrents", &[])).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["content-type"], "application/json");
    let v = json(&body);
    assert_eq!(
        v["torrents"][0]["name"], "/web/ <b>not html</b>",
        "API bodies pass unmodified"
    );
}

#[tokio::test]
async fn ingress_requests_are_signed_in_automatically() {
    let (up, mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;

    // The web UI asks whether it must show a login page: no.
    let (status, _, body) = body_of(send(proxy, get("/auth/status", &[])).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&body),
        serde_json::json!({"auth_enabled": false, "setup_required": false})
    );

    let browser = [
        ("authorization", "Bearer browser-token"),
        ("cookie", "ingress_session=ha-secret; SID=stale"),
        ("origin", "https://ha.example"),
        ("referer", "https://ha.example/x"),
    ];
    for _ in 0..3 {
        let (status, _, body) = body_of(send(proxy, get("/torrents", &browser)).await).await;
        assert_eq!(status, StatusCode::OK);
        let v = json(&body);
        assert_eq!(v["authorization"], "Bearer tok-1");
        assert_eq!(
            v["cookie"],
            serde_json::Value::Null,
            "HA cookies never reach rtbit"
        );
        assert_eq!(v["origin"], serde_json::Value::Null);
        assert_eq!(v["referer"], serde_json::Value::Null);
        assert_eq!(v["x_ingress_path"], serde_json::Value::Null);
        assert_eq!(v["host"], up.to_string());
    }
    assert_eq!(
        mock.logins.load(Ordering::SeqCst),
        1,
        "one login, then the cached token"
    );

    // rtbit forgot the session (e.g. restarted): the proxy renews it and
    // replays the request transparently.
    mock.tokens.lock().unwrap().clear();
    let (status, _, body) = body_of(send(proxy, get("/torrents", &[])).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["authorization"], "Bearer tok-2");
    assert_eq!(mock.refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn qbittorrent_api_gets_a_sid_cookie() {
    let (up, mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;
    for _ in 0..2 {
        let (status, _, body) =
            body_of(send(proxy, get("/api/v2/app/version", &[("cookie", "SID=evil")])).await).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(body.as_ref(), b"v5.0.0");
    }
    assert_eq!(mock.sid_logins.load(Ordering::SeqCst), 1);

    // A login made through Ingress gets its cookie scoped to the Ingress path.
    let mut login = Request::builder()
        .method(Method::POST)
        .uri("/api/v2/auth/login")
        .body(full("username=admin&password=p%40ss%20w%26rd%3D1"))
        .unwrap();
    login
        .headers_mut()
        .insert("x-ingress-path", HeaderValue::from_static(PREFIX));
    let (_, h, _) = body_of(send(proxy, login).await).await;
    assert_eq!(
        h["set-cookie"].to_str().unwrap(),
        format!("SID=sid-1; Path={PREFIX}/; HttpOnly; SameSite=Strict")
    );
}

#[tokio::test]
async fn wrong_account_falls_back_to_rtbits_own_sign_in() {
    let (up, _mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, "not-the-password").await;
    let (status, _, body) = body_of(send(proxy, get("/auth/status", &[])).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&body)["auth_enabled"],
        true,
        "rtbit's answer passes through"
    );

    // The browser's own token is forwarded; no Basic-auth dialog in the iframe.
    let (status, h, _) = body_of(
        send(
            proxy,
            get("/torrents", &[("authorization", "Bearer browser-token")]),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(h.get("www-authenticate").is_none());
}

#[tokio::test]
async fn websocket_upgrades_are_tunnelled() {
    let (up, _mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!(
            "GET /ws HTTP/1.1\r\nHost: x\r\nX-Ingress-Path: {PREFIX}\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(head.contains("upgrade: websocket"), "{head}");
    for msg in [&b"ping"[..], b"\x81\x05hello"] {
        s.write_all(msg).await.unwrap();
        let mut echo = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo, msg);
    }
}

#[tokio::test]
async fn non_supervisor_peers_are_refused_before_any_http() {
    let (up, mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;
    // Same host, but from 127.0.0.2: neither the Supervisor nor loopback .1.
    let sock = TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut s = sock.connect(proxy).await.unwrap();
    s.write_all(b"GET /auth/status HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut reply = String::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden"), "{reply}");
    assert!(reply.contains("only serves Home Assistant Ingress"));
    assert_eq!(
        mock.requests.load(Ordering::SeqCst),
        0,
        "nothing reached rtbit"
    );
}

#[tokio::test]
async fn large_downloads_and_event_streams_are_streamed_not_buffered() {
    let (up, mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;

    // 8 MiB (twice the HTML rewrite limit) arrives byte-identical.
    let (status, h, body) = body_of(send(proxy, get("/big", &[("accept", "*/*")])).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["content-type"], "application/octet-stream");
    assert_eq!(body.len(), 8 << 20);
    assert!(
        body.as_ref() == pattern(8 << 20).as_slice(),
        "payload corrupted"
    );

    // An event stream's first event is delivered while rtbit still holds
    // the rest back: the proxy forwards frames as they come.
    let (release, gate) = oneshot::channel();
    *mock.gate.lock().unwrap() = Some(gate);
    let resp = send(proxy, get("/gated", &[("accept", "text/event-stream")])).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("first event must arrive before the stream ends")
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap().as_ref(), b"data: first\n\n");
    release.send(()).unwrap();
    let rest = body.collect().await.unwrap().to_bytes();
    assert_eq!(rest.as_ref(), b"data: second\n\n");
}

#[tokio::test]
async fn large_uploads_are_streamed_through() {
    let (up, _mock) = start_mock().await;
    let (proxy, _) = start_proxy(up, PASSWORD).await;
    let (mut tx, body) = Channel::<Bytes, Infallible>::new(2);
    tokio::spawn(async move {
        for chunk in pattern(6 << 20).chunks(100_000) {
            tx.send(Frame::data(Bytes::copy_from_slice(chunk)))
                .await
                .unwrap();
        }
    });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/torrents")
        .body(body.boxed_unsync())
        .unwrap();
    req.headers_mut()
        .insert("x-ingress-path", HeaderValue::from_static(PREFIX));
    let (status, _, body) = body_of(send(proxy, req).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&body),
        serde_json::json!({"received": 6 << 20, "intact": true})
    );
}

#[tokio::test]
async fn health_endpoint_follows_rtbit_and_the_tunnel() {
    let (up, mock) = start_mock().await;
    let (proxy, state) = start_proxy(up, PASSWORD).await;
    let check = || async move {
        let (status, _, body) = body_of(send(proxy, get(ingress::HEALTH_PATH, &[])).await).await;
        (status, json(&body))
    };

    let (status, v) = check().await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["message"], "no status from the supervisor yet");

    state.set_health(Health {
        rtbit: false,
        tunnel: false,
        port: None,
        detail: "connecting the WireGuard tunnel".into(),
        ..Health::default()
    });
    let (status, v) = check().await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["message"], "connecting the WireGuard tunnel");

    state.set_health(Health {
        rtbit: true,
        tunnel: true,
        port: Some(45678),
        detail: String::new(),
        ..Health::default()
    });
    let (status, v) = check().await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["port"], 45678);

    // rtbit alive but not answering properly.
    mock.healthz.store(500, Ordering::SeqCst);
    let (status, v) = check().await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(v["message"].as_str().unwrap().contains("500"), "{v}");
    mock.healthz.store(200, Ordering::SeqCst);

    state.set_health(Health {
        rtbit: true,
        tunnel: false,
        port: Some(45678),
        detail: String::new(),
        ..Health::default()
    });
    let (status, v) = check().await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["message"], "the WireGuard tunnel has no recent handshake");
}

#[tokio::test]
async fn rtbit_down_shows_a_starting_page_never_a_blank_one() {
    // Nothing listens on the upstream port.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = closed.local_addr().unwrap();
    drop(closed);
    let (proxy, _) = start_proxy(up, PASSWORD).await;

    let (status, h, body) =
        body_of(send(proxy, get("/web/", &[("accept", "text/html")])).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(h["retry-after"], "5");
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("rBittorrent is starting"));
    assert!(html.contains("http-equiv=\"refresh\""));

    let (status, h, body) = body_of(send(proxy, get("/torrents", &[])).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        h["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert!(String::from_utf8_lossy(&body).contains("not reachable yet"));
}

#[tokio::test]
async fn health_in_direct_mode_needs_no_tunnel() {
    let (up, mock) = start_mock().await;
    let (proxy, state) = start_proxy(up, PASSWORD).await;
    state.set_health(Health {
        rtbit: true,
        tunnel: false,
        port: Some(4240),
        direct: true,
        ..Health::default()
    });
    let (status, _, body) = body_of(send(proxy, get(ingress::HEALTH_PATH, &[])).await).await;
    let v = json(&body);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["vpn"], false);
    assert_eq!(v["port"], 4240);
    assert_eq!(
        v["message"],
        "rtbit is running on a direct connection (VPN off)"
    );

    // Still unhealthy when rtbit itself is down.
    mock.healthz.store(500, Ordering::SeqCst);
    let (status, _, _) = body_of(send(proxy, get(ingress::HEALTH_PATH, &[])).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // VPN mode reports the exit address for the status bar.
    mock.healthz.store(200, Ordering::SeqCst);
    state.set_health(Health {
        rtbit: true,
        tunnel: true,
        port: Some(45678),
        public_ip: Some("185.159.156.1".parse().unwrap()),
        ..Health::default()
    });
    let (status, _, body) = body_of(send(proxy, get(ingress::HEALTH_PATH, &[])).await).await;
    let v = json(&body);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["vpn"], true);
    assert_eq!(v["public_ip"], "185.159.156.1");
}

/// A plain-HTTP stand-in for Cloudflare's speed-test endpoints.
async fn start_speed_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path().to_owned();
                    let query = req.uri().query().unwrap_or_default().to_owned();
                    let resp: Response<Body> = if path == "/cdn-cgi/trace" {
                        Response::new(full("fl=1\nip=203.0.113.7\ncolo=TST\nloc=BE\n"))
                    } else if path == "/__down" {
                        let n: u64 = query
                            .strip_prefix("bytes=")
                            .and_then(|v| v.parse().ok())
                            .unwrap();
                        let (mut tx, body) = Channel::<Bytes, Infallible>::new(4);
                        tokio::spawn(async move {
                            let chunk = Bytes::from(vec![7u8; 256 << 10]);
                            let mut left = n;
                            while left > 0 {
                                let take = left.min(chunk.len() as u64);
                                let part = chunk.slice(..usize::try_from(take).unwrap());
                                if tx.send(Frame::data(part)).await.is_err() {
                                    return;
                                }
                                left -= take;
                                // ~1 GB/s at most: enough to measure, gentle on CI.
                                tokio::time::sleep(Duration::from_micros(250)).await;
                            }
                        });
                        Response::new(body.boxed_unsync())
                    } else {
                        let mut r = Response::new(full("not found"));
                        *r.status_mut() = StatusCode::NOT_FOUND;
                        r
                    };
                    Ok::<_, Infallible>(resp)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn post_benchmark(headers: &[(&str, &str)]) -> Request<Body> {
    let mut r = Request::builder()
        .method(Method::POST)
        .uri(ingress::BENCHMARK_PATH)
        .body(full("{}"))
        .unwrap();
    r.headers_mut()
        .insert("x-ingress-path", HeaderValue::from_static(PREFIX));
    for (k, v) in headers {
        r.headers_mut().insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn speed_test_measures_network_disk_and_hashing_on_demand() {
    let (up, _mock) = start_mock().await;
    let speed = start_speed_server().await;
    let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = peer_listener.local_addr().unwrap();
    let (proxy, state) = start_proxy_with(
        up,
        PASSWORD,
        Some(SpeedTarget {
            host: "speed.test".into(),
            port: speed.port(),
            tls: false,
            connect_to: Some(speed),
        }),
        Some(vec![PeeringTarget {
            name: "Local".into(),
            addr: peer,
        }]),
    )
    .await;

    // The supervisor's half: a real disk test in a temporary folder.
    let dir = std::env::temp_dir().join(format!("rbt-ingress-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    state.connect_supervisor(tx);
    let link = state.clone();
    let work_dir = dir.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let req: ProxyRequest = serde_json::from_str(&line).unwrap();
            let ProxyRequest::Hardware { id } = req;
            let d = work_dir.clone();
            let r = tokio::task::spawn_blocking(move || benchmark::run_hardware(&d, 2))
                .await
                .unwrap();
            // A stale answer (an older request) is ignored, the right one lands.
            link.deliver_hardware(r.clone(), id.wrapping_sub(1));
            link.deliver_hardware(r, id);
        }
    });

    // Only POST, only JSON, never cross-site.
    let (status, h, _) = body_of(send(proxy, get(ingress::BENCHMARK_PATH, &[])).await).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(h["allow"], "POST");
    let (status, _, _) = body_of(send(proxy, post_benchmark(&[])).await).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (status, _, _) = body_of(
        send(
            proxy,
            post_benchmark(&[
                ("content-type", "application/json"),
                ("sec-fetch-site", "cross-site"),
            ]),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Direct mode: download, latency, public IP, peering, disk and SHA-1.
    state.set_health(Health {
        rtbit: true,
        direct: true,
        port: Some(4240),
        ..Health::default()
    });
    let started = std::time::Instant::now();
    let (status, _, body) = body_of(
        send(
            proxy,
            post_benchmark(&[
                ("content-type", "application/json"),
                ("sec-fetch-site", "same-origin"),
            ]),
        )
        .await,
    )
    .await;
    let v = json(&body);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(
        started.elapsed() >= benchmark::DOWNLOAD_WINDOW,
        "6 s window"
    );
    assert!(started.elapsed() < Duration::from_secs(20), "{v}");
    assert_eq!(v["mode"], "direct");
    assert_eq!(v["route"], "eth0");
    let n = &v["network"];
    assert!(n["download_mbps"].as_f64().unwrap() > 1.0, "{v}");
    assert!(n["downloaded_bytes"].as_u64().unwrap() > 1_000_000, "{v}");
    assert!(n["latency_ms"].as_f64().is_some(), "{v}");
    assert_eq!(n["colo"], "TST");
    assert_eq!(n["country"], "BE");
    assert_eq!(n["public_ip"], "203.0.113.7");
    assert_eq!(n["streams"], benchmark::STREAMS);
    assert!(n["error"].is_null(), "{v}");
    assert_eq!(n["peering"][0]["name"], "Local");
    assert!(n["peering"][0]["ms"].as_f64().is_some(), "{v}");
    let hw = &v["hardware"];
    assert!(hw["disk_write_mb_s"].as_f64().unwrap() > 0.0, "{v}");
    assert!(hw["sha1_mb_s"].as_f64().unwrap() > 0.0, "{v}");
    assert_eq!(hw["cpu_cores"], 2);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "test file deleted"
    );

    // A cooldown between runs.
    let (status, h, _) = body_of(
        send(
            proxy,
            post_benchmark(&[("content-type", "application/json")]),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(h.contains_key("retry-after"));

    // VPN mode with the tunnel down: the kill-switch blocks the network
    // half, the disk half still runs, and peering is never probed.
    tokio::time::sleep(Duration::from_secs(10)).await;
    state.set_health(Health {
        rtbit: false,
        tunnel: false,
        ..Health::default()
    });
    let (status, _, body) = body_of(
        send(
            proxy,
            post_benchmark(&[("content-type", "application/json")]),
        )
        .await,
    )
    .await;
    let v = json(&body);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["route"], "wg0");
    assert!(
        v["network"]["error"]
            .as_str()
            .unwrap()
            .contains("kill-switch"),
        "{v}"
    );
    assert!(v["network"]["peering"].as_array().unwrap().is_empty());
    assert!(v["hardware"]["sha1_mb_s"].as_f64().is_some());
    drop(peer_listener);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn speed_test_without_the_supervisor_link_reports_why() {
    let (up, _mock) = start_mock().await;
    let (proxy, state) = start_proxy(up, PASSWORD).await;
    state.set_health(Health {
        rtbit: false,
        tunnel: false,
        ..Health::default()
    });
    let (status, _, body) = body_of(
        send(
            proxy,
            post_benchmark(&[("content-type", "application/json")]),
        )
        .await,
    )
    .await;
    let v = json(&body);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["hardware"].is_null());
    assert_eq!(v["hardware_error"], "not connected to the supervisor");
}

#[tokio::test]
async fn loopback_may_only_read_health() {
    let (up, mock) = start_mock().await;
    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: up,
        allowed_peers: vec!["172.30.32.2/32".into()],
        health_only_peers: vec!["127.0.0.1/32".into()],
        username: "admin".into(),
        password: PASSWORD.into(),
        log_level: LogLevel::Info,
        speed_target: None,
        peering: None,
    };
    let (proxy, state) = start_proxy_cfg(&cfg).await;
    state.set_health(Health {
        rtbit: true,
        direct: true,
        ..Health::default()
    });
    let (status, _, body) = body_of(send(proxy, get(ingress::HEALTH_PATH, &[])).await).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    for path in ["/web/", "/auth/status", "/torrents", "/api/v2/app/version"] {
        let (status, _, body) = body_of(send(proxy, get(path, &[])).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(String::from_utf8_lossy(&body).contains("/__health"));
    }
    let (status, _, _) = body_of(
        send(
            proxy,
            post_benchmark(&[("content-type", "application/json")]),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no speed test from loopback");
    assert_eq!(mock.logins.load(Ordering::SeqCst), 0, "never signed in");
    assert_eq!(mock.sid_logins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_rtbit_restart_drops_the_cached_sessions() {
    let (up, mock) = start_mock().await;
    let (proxy, state) = start_proxy(up, PASSWORD).await;
    state.set_health(Health {
        rtbit: true,
        direct: true,
        generation: 1,
        ..Health::default()
    });
    let (status, _, body) = body_of(send(proxy, get("/torrents", &[])).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["authorization"], "Bearer tok-1");

    // rtbit restarted (a NAT-PMP port change): its tokens are gone. A POST
    // with a body cannot be replayed, so it must go out with a fresh login.
    mock.tokens.lock().unwrap().clear();
    state.set_health(Health {
        rtbit: true,
        direct: true,
        generation: 2,
        ..Health::default()
    });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/torrents")
        .body(full(pattern(6 << 20)))
        .unwrap();
    req.headers_mut()
        .insert("x-ingress-path", HeaderValue::from_static(PREFIX));
    let (status, _, body) = body_of(send(proxy, req).await).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(json(&body)["intact"], true);
    assert_eq!(mock.logins.load(Ordering::SeqCst), 2, "signed in again");
    assert_eq!(
        mock.refreshes.load(Ordering::SeqCst),
        0,
        "old refresh token dropped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_speed_test_keeps_its_lock_when_the_client_leaves() {
    let (up, _mock) = start_mock().await;
    let (proxy, state) = start_proxy(up, PASSWORD).await;
    // VPN mode with the tunnel down: no network test, only the (slow) disk half.
    state.set_health(Health::default());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    state.connect_supervisor(tx);
    let link = state.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let ProxyRequest::Hardware { id } = serde_json::from_str(&line).unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            link.deliver_hardware(benchmark::HardwareResult::default(), id);
        }
    });

    // Start a test and hang up before it answers.
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!(
            "POST {} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\n\r\n{{}}",
            ingress::BENCHMARK_PATH
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(s);

    let post = || post_benchmark(&[("content-type", "application/json")]);
    let (status, _, body) = body_of(send(proxy, post()).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        String::from_utf8_lossy(&body).contains("already running"),
        "{body:?}"
    );

    // Once the abandoned test ends, the cooldown applies.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    let (status, _, body) = body_of(send(proxy, post()).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(String::from_utf8_lossy(&body).contains("wait"), "{body:?}");
}
