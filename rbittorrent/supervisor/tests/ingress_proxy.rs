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

use rbittorrent_supervisor::config::LogLevel;
use rbittorrent_supervisor::ingress::{self, Health, Proxy, ProxyConfig};

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
    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream,
        allowed_peers: vec!["172.30.32.2/32".into(), "127.0.0.1/32".into()],
        username: "admin".into(),
        password: password.into(),
        log_level: LogLevel::Info,
    };
    let proxy = Proxy::new(&cfg).unwrap();
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
    });
    let (status, v) = check().await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["message"], "connecting the WireGuard tunnel");

    state.set_health(Health {
        rtbit: true,
        tunnel: true,
        port: Some(45678),
        detail: String::new(),
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
