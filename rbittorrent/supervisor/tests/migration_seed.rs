//! Integration tests: the qBittorrent takeover end to end (phase 1 on a
//! fake legacy profile, phase 2 against a mock rtbit qBittorrent API) and
//! the Supervisor API client against a mock Supervisor.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use rbittorrent_supervisor::config::{Options, Secret};
use rbittorrent_supervisor::ha_supervisor::{self, SupervisorApi};
use rbittorrent_supervisor::migration::{self, Roots, SeedJob};

// ---------------------------------------------------------------------------
// tiny mock server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    method: Method,
    path: String,
    headers: hyper::HeaderMap,
    body: Bytes,
}

type Handler =
    Arc<dyn Fn(&Seen) -> (StatusCode, Vec<(&'static str, String)>, String) + Send + Sync>;

async fn serve(handler: Handler) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            let log = log2.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let handler = handler.clone();
                    let log = log.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let seen = Seen {
                            method: parts.method,
                            path: parts.uri.path().to_owned(),
                            headers: parts.headers,
                            body,
                        };
                        let (status, headers, text) = handler(&seen);
                        log.lock().unwrap().push(seen);
                        let mut r = Response::new(Full::new(Bytes::from(text)));
                        *r.status_mut() = status;
                        for (k, v) in headers {
                            r.headers_mut()
                                .append(k, HeaderValue::from_str(&v).unwrap());
                        }
                        Ok::<_, Infallible>(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, log)
}

fn form(body: &[u8]) -> BTreeMap<String, String> {
    url_decode_pairs(std::str::from_utf8(body).unwrap())
}

fn url_decode_pairs(s: &str) -> BTreeMap<String, String> {
    s.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else if b[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// `name -> (filename, value)` of a multipart body.
fn multipart(seen: &Seen) -> BTreeMap<String, (Option<String>, Vec<u8>)> {
    let ct = seen.headers[header::CONTENT_TYPE].to_str().unwrap();
    let boundary = ct.split("boundary=").nth(1).unwrap();
    let delim = format!("--{boundary}");
    let body = &seen.body[..];
    let text = unsafe_split(body, delim.as_bytes());
    let mut out = BTreeMap::new();
    for part in text {
        let Some(pos) = find(part, b"\r\n\r\n") else {
            continue;
        };
        let head = std::str::from_utf8(&part[..pos]).unwrap();
        let mut value = part[pos + 4..].to_vec();
        if value.ends_with(b"\r\n") {
            value.truncate(value.len() - 2);
        }
        let name = head
            .split("name=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let file = head
            .split("filename=\"")
            .nth(1)
            .map(|f| f.split('"').next().unwrap().to_owned());
        out.insert(name.to_owned(), (file, value));
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn unsafe_split<'a>(mut hay: &'a [u8], delim: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    while let Some(p) = find(hay, delim) {
        out.push(&hay[..p]);
        hay = &hay[p + delim.len()..];
    }
    out.push(hay);
    out.into_iter()
        .filter(|p| p.starts_with(b"\r\n"))
        .map(|p| &p[2..])
        .collect()
}

// ---------------------------------------------------------------------------
// mock rtbit (qBittorrent API)
// ---------------------------------------------------------------------------

const USER: &str = "homer";
const PASS: &str = "d'oh & co=1";

fn rtbit_handler(existing_category: &'static str) -> Handler {
    let categories = Arc::new(Mutex::new(vec![existing_category.to_owned()]));
    Arc::new(move |r: &Seen| {
        let authed = r
            .headers
            .get(header::COOKIE)
            .is_some_and(|c| c.to_str().unwrap() == "SID=sid-42");
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/healthz") => (StatusCode::OK, vec![], "ok".into()),
            ("POST", "/api/v2/auth/login") => {
                let f = form(&r.body);
                if f.get("username").map(String::as_str) == Some(USER)
                    && f.get("password").map(String::as_str) == Some(PASS)
                    && r.headers.get(header::ORIGIN).is_none()
                {
                    (
                        StatusCode::OK,
                        vec![("set-cookie", "SID=sid-42; Path=/; HttpOnly".into())],
                        "Ok.".into(),
                    )
                } else {
                    (StatusCode::FORBIDDEN, vec![], "Fails.".into())
                }
            }
            (_, _) if !authed => (StatusCode::FORBIDDEN, vec![], "Forbidden".into()),
            ("POST", "/api/v2/torrents/createCategory") => {
                let f = form(&r.body);
                let name = f["category"].clone();
                let mut cats = categories.lock().unwrap();
                if cats.contains(&name) {
                    (
                        StatusCode::CONFLICT,
                        vec![],
                        "Unable to create category".into(),
                    )
                } else {
                    cats.push(name);
                    (StatusCode::OK, vec![], "Ok.".into())
                }
            }
            ("POST", "/api/v2/torrents/add") => (StatusCode::OK, vec![], "Ok.".into()),
            _ => (StatusCode::NOT_FOUND, vec![], "Not Found".into()),
        }
    })
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rbittorrent-it-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bstr(s: &str) -> String {
    format!("{}:{s}", s.len())
}

/// A legacy alexbelgium-style profile with two torrents (one importable, one
/// whose save path is gone) and three categories (one rtbit already has).
fn legacy_profile(base: &Path, payload: &Path) -> PathBuf {
    let app = base.join("addon_configs/db21ed7f_qbittorrent/qBittorrent");
    let backup = app.join("BT_backup");
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::create_dir_all(base.join("config")).unwrap();
    std::fs::write(
        app.join("qBittorrent.conf"),
        "[BitTorrent]\nSession\\DefaultSavePath=/share/qBittorrent/\nSession\\TempPathEnabled=false\n\
         [Preferences]\nWebUI\\Username=homer\nWebUI\\Port=8080\n",
    )
    .unwrap();
    std::fs::write(
        app.join("categories.json"),
        r#"{"tv-sonarr":{"save_path":"/share/qBittorrent/tv"},"radarr":{"save_path":""},"lidarr":{"save_path":"/media/music"}}"#,
    )
    .unwrap();
    let torrent = format!("d4:infod{}{}ee", bstr("name"), bstr("Show.S01"));
    let ok = payload.display().to_string();
    std::fs::write(backup.join("aaaa.torrent"), &torrent).unwrap();
    std::fs::write(
        backup.join("aaaa.fastresume"),
        format!(
            "d12:auto_managedi1e6:pausedi0e{}{}{}{}e",
            bstr("qBt-category"),
            bstr("tv-sonarr"),
            bstr("save_path"),
            bstr(&ok)
        ),
    )
    .unwrap();
    std::fs::write(backup.join("bbbb.torrent"), &torrent).unwrap();
    let gone = payload.join("missing-disk");
    std::fs::write(
        backup.join("bbbb.fastresume"),
        format!(
            "d{}{}e",
            bstr("save_path"),
            bstr(&gone.display().to_string())
        ),
    )
    .unwrap();
    app
}

#[tokio::test]
async fn qbittorrent_takeover_seeds_categories_and_torrents_once() {
    let base = tmp("takeover");
    let payload = base.join("media/qbt");
    std::fs::create_dir_all(&payload).unwrap();
    legacy_profile(&base, &payload);
    let roots = Roots {
        app_configs: base.join("addon_configs"),
        share: base.join("share"),
        config: base.join("config"),
    };

    // Phase 1.
    let mut o = Options {
        import_active_torrents: true,
        ..Options::default()
    };
    let m = migration::prepare(&mut o, &roots);
    assert!(m.fresh && m.has_work(), "{m:?}");
    assert_eq!(o.webui_username, USER);
    // TempPathEnabled=false: straight into the save path, no completed folder.
    assert_eq!(o.download_dir, "/share/qBittorrent");
    assert_eq!(o.completed_dir, None);

    // Phase 2 against the mock rtbit.
    let (addr, log) = serve(rtbit_handler("radarr")).await;
    let job = SeedJob {
        api: addr,
        username: o.webui_username.clone(),
        password: Secret::new(PASS.into()),
        config_root: roots.config.clone(),
        // The test's own media folder stands in for /media, so the `lidarr`
        // category (/media/music) is outside what rtbit could write.
        data_roots: vec![base.join("media"), PathBuf::from("/share")],
        migration: m,
    };
    let report = migration::seed(job).await.unwrap();
    assert_eq!(report.category_notes.len(), 1, "{report:?}");
    assert!(report.category_notes[0].contains("`lidarr`: /media/music is outside"));
    assert_eq!(report.categories_created, 2, "{report:?}");
    assert_eq!(report.categories_existing, 1);
    assert_eq!(report.torrents_added, 1);
    assert_eq!(report.torrents_skipped.len(), 1, "{report:?}");
    assert!(report.torrents_skipped[0].contains("does not exist"));
    assert!(report.summary().contains("1/2 torrents"));

    let seen = log.lock().unwrap().clone();
    let cats: Vec<BTreeMap<String, String>> = seen
        .iter()
        .filter(|r| r.path == "/api/v2/torrents/createCategory")
        .map(|r| form(&r.body))
        .collect();
    assert_eq!(cats.len(), 3);
    let tv = cats.iter().find(|c| c["category"] == "tv-sonarr").unwrap();
    assert_eq!(tv["savePath"], "/share/qBittorrent/tv");
    let lidarr = cats.iter().find(|c| c["category"] == "lidarr").unwrap();
    assert!(
        lidarr.get("savePath").is_none_or(String::is_empty),
        "{lidarr:?}"
    );
    let adds: Vec<&Seen> = seen
        .iter()
        .filter(|r| r.path == "/api/v2/torrents/add")
        .collect();
    assert_eq!(adds.len(), 1);
    let parts = multipart(adds[0]);
    assert_eq!(parts["torrents"].0.as_deref(), Some("aaaa.torrent"));
    assert!(parts["torrents"].1.starts_with(b"d4:info"));
    assert_eq!(
        parts["savepath"].1,
        payload.display().to_string().as_bytes()
    );
    assert_eq!(parts["category"].1, b"tv-sonarr");
    assert_eq!(parts["contentLayout"].1, b"Original");
    assert_eq!(parts["stopped"].1, b"false");

    // Markers: the record and the torrent import, both private.
    let rec: migration::Record =
        serde_json::from_str(&std::fs::read_to_string(roots.config.join(".migrated")).unwrap())
            .unwrap();
    assert_eq!(rec.source, "db21ed7f_qbittorrent");
    assert_eq!(rec.categories.len(), 3);
    let done: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(roots.config.join(".torrents_migrated")).unwrap(),
    )
    .unwrap();
    assert_eq!(done["added"], 1);
    use std::os::unix::fs::PermissionsExt;
    for f in [".migrated", ".torrents_migrated"] {
        let mode = std::fs::metadata(roots.config.join(f))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{f}");
    }

    // Next start: nothing left to do, the folders and user stay in effect.
    let mut o = Options {
        import_active_torrents: true,
        ..Options::default()
    };
    let m = migration::prepare(&mut o, &roots);
    assert!(!m.has_work(), "{m:?}");
    assert_eq!(o.webui_username, USER);
    assert_eq!(o.download_dir, "/share/qBittorrent");
    assert_eq!(o.completed_dir, None);
    let _ = std::fs::remove_dir_all(base);
}

#[tokio::test]
async fn refused_login_writes_no_marker_so_the_next_start_retries() {
    let base = tmp("refused");
    let payload = base.join("media/qbt");
    std::fs::create_dir_all(&payload).unwrap();
    legacy_profile(&base, &payload);
    let roots = Roots {
        app_configs: base.join("addon_configs"),
        share: base.join("share"),
        config: base.join("config"),
    };
    let mut o = Options::default();
    let m = migration::prepare(&mut o, &roots);
    let (addr, log) = serve(rtbit_handler("x")).await;
    let job = SeedJob {
        api: addr,
        username: USER.into(),
        password: Secret::new("wrong-password".into()),
        config_root: roots.config.clone(),
        data_roots: vec![base.join("media")],
        migration: m,
    };
    let err = migration::seed(job).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("refused the Web UI login"),
        "{err:#}"
    );
    assert!(!roots.config.join(".migrated").exists());
    assert!(
        log.lock()
            .unwrap()
            .iter()
            .all(|r| !r.path.contains("torrents/")),
        "nothing is created without a session"
    );
    assert!(migration::prepare(&mut Options::default(), &roots).fresh);
    let _ = std::fs::remove_dir_all(base);
}

// ---------------------------------------------------------------------------
// mock Supervisor
// ---------------------------------------------------------------------------

fn supervisor_handler(allow_list: bool) -> Handler {
    Arc::new(move |r: &Seen| {
        let ok = |data: serde_json::Value| {
            (
                StatusCode::OK,
                vec![("content-type", "application/json".to_owned())],
                serde_json::json!({ "result": "ok", "data": data }).to_string(),
            )
        };
        if r.headers
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap())
            != Some("Bearer test-token")
        {
            return (StatusCode::UNAUTHORIZED, vec![], "{}".into());
        }
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/addons") if allow_list => ok(serde_json::json!({ "addons": [
                { "slug": "db21ed7f_qbittorrent", "name": "qBittorrent", "state": "started" },
                { "slug": "a0d7b954_sonarr", "name": "Sonarr", "state": "started" },
                { "slug": "local_qbittorrent", "name": "qBit (old)", "state": "stopped" }
            ]})),
            ("GET", "/addons") => (
                StatusCode::FORBIDDEN,
                vec![],
                r#"{"result":"error","message":"Access not allowed"}"#.into(),
            ),
            ("GET", "/addons/db21ed7f_qbittorrent/info") => ok(serde_json::json!({
                "slug": "db21ed7f_qbittorrent", "name": "qBittorrent", "state": "started",
                "network": { "8080/tcp": 8080, "6881/tcp": 6881 }
            })),
            ("POST", "/discovery") => ok(serde_json::json!({ "uuid": "u-1" })),
            ("GET", "/addons/self/info") => ok(serde_json::json!({
                "slug": "local_rbittorrent",
                "network": { "4240/tcp": 51413, "4240/udp": 51413, "8080/tcp": null }
            })),
            _ => (
                StatusCode::NOT_FOUND,
                vec![],
                r#"{"result":"error","message":"not found"}"#.into(),
            ),
        }
    })
}

#[tokio::test]
async fn running_qbittorrent_is_found_even_without_the_app_list_permission() {
    for allow_list in [false, true] {
        let (addr, log) = serve(supervisor_handler(allow_list)).await;
        let api = SupervisorApi::new(addr, "test-token".into());
        assert!(!format!("{api:?}").contains("test-token"), "token redacted");
        let apps = api
            .qbittorrent_apps(&["db21ed7f_qbittorrent".into(), "../etc".into()])
            .await;
        let running: Vec<_> = apps.iter().filter(|a| a.is_running()).collect();
        assert_eq!(running.len(), 1, "{apps:?}");
        assert_eq!(running[0].slug, "db21ed7f_qbittorrent");
        assert!(running[0].host_ports.contains(&8080), "{apps:?}");
        let banner = ha_supervisor::conflict_banner(&apps, 8080).unwrap();
        assert!(banner.contains("holds host port 8080"), "{banner}");
        if allow_list {
            assert!(
                apps.iter()
                    .any(|a| a.slug == "local_qbittorrent" && !a.is_running())
            );
            assert!(!apps.iter().any(|a| a.slug.contains("sonarr")));
        }
        let uuid = api
            .announce(
                "qbittorrent",
                serde_json::json!({ "host": "abc-rbittorrent", "port": 8080 }),
            )
            .await
            .unwrap();
        assert_eq!(uuid, "u-1");
        let seen = log.lock().unwrap().clone();
        assert!(
            seen.iter().all(|r| !r.path.contains("..")),
            "invalid slugs never reach the Supervisor"
        );
        let disc = seen.iter().find(|r| r.path == "/discovery").unwrap();
        let body: serde_json::Value = serde_json::from_slice(&disc.body).unwrap();
        assert_eq!(body["service"], "qbittorrent");
        assert_eq!(body["config"]["port"], 8080);
        // The app's own port mapping (direct mode announces the host port).
        assert_eq!(
            api.own_host_port("4240/tcp").await.unwrap(),
            Some(ha_supervisor::HostPort::Mapped(51413))
        );
        assert_eq!(
            api.own_host_port("8080/tcp").await.unwrap(),
            Some(ha_supervisor::HostPort::Unmapped)
        );
    }

    // A refusing Supervisor is not an error for the app.
    let (addr, _) = serve(Arc::new(|_: &Seen| {
        (
            StatusCode::FORBIDDEN,
            vec![],
            r#"{"result":"error","message":"no"}"#.into(),
        )
    }))
    .await;
    let api = SupervisorApi::new(addr, "test-token".into());
    assert!(api.qbittorrent_apps(&[]).await.is_empty());
    assert!(
        api.announce("qbittorrent", serde_json::json!({}))
            .await
            .is_err()
    );
}
