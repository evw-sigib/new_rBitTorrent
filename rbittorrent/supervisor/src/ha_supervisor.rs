//! Home Assistant Supervisor API (`hassio_api: true`, default role): warns
//! about a qBittorrent app that is still running, and announces rBittorrent
//! to Home Assistant's discovery.
//!
//! The default role may not list all apps (`GET /addons`), but it may read
//! `/addons/<slug>/info`, so the slugs found under `/app_configs` are asked
//! one by one when the list is refused. Every call is best effort: the app
//! never fails because the Supervisor said no. All calls happen before the
//! kill-switch is loaded (they use the container's normal network).

use std::fmt::Write as _;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpStream;
use tracing::debug;

use crate::ingress::SUPERVISOR_IP;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 4 << 20;
/// alexbelgium's qBittorrent app, the most common one on Home Assistant.
pub const KNOWN_QBITTORRENT_SLUGS: [&str; 1] = ["db21ed7f_qbittorrent"];

/// One installed app, as far as the Supervisor tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub slug: String,
    pub name: String,
    pub state: String,
    /// Host ports it publishes (from `network`), when known.
    pub host_ports: Vec<u16>,
}

impl AppInfo {
    pub fn is_running(&self) -> bool {
        self.state == "started"
    }
}

pub struct SupervisorApi {
    addr: SocketAddr,
    token: String,
}

impl std::fmt::Debug for SupervisorApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorApi")
            .field("addr", &self.addr)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl SupervisorApi {
    pub fn new(addr: SocketAddr, token: String) -> Self {
        Self { addr, token }
    }

    /// `SUPERVISOR_TOKEN` is only set inside a Home Assistant app.
    pub async fn from_env() -> Option<Self> {
        let token = std::env::var("SUPERVISOR_TOKEN")
            .or_else(|_| std::env::var("HASSIO_TOKEN"))
            .ok()
            .filter(|t| !t.trim().is_empty())?;
        let addr = match tokio::time::timeout(TIMEOUT, tokio::net::lookup_host(("supervisor", 80)))
            .await
        {
            Ok(Ok(mut addrs)) => addrs.find(SocketAddr::is_ipv4),
            _ => None,
        }
        .unwrap_or_else(default_addr);
        Some(Self::new(addr, token.trim().to_owned()))
    }

    /// Sends one request and returns the `data` member of the answer.
    async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let body = body.map(Value::to_string).unwrap_or_default();
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(Bytes::from(body)))
            .context("cannot build the Supervisor request")?;
        let h = req.headers_mut();
        h.insert(header::HOST, HeaderValue::from_static("supervisor"));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.token))
                .context("SUPERVISOR_TOKEN is not a valid header value")?,
        );
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let fut = async {
            let stream = TcpStream::connect(self.addr)
                .await
                .with_context(|| format!("cannot reach the Supervisor at {}", self.addr))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .context("HTTP handshake with the Supervisor failed")?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Supervisor connection ended: {e}");
                }
            });
            let resp = sender.send_request(req).await?;
            let status = resp.status();
            let body = Limited::new(resp.into_body(), MAX_RESPONSE)
                .collect()
                .await
                .map_err(|e| anyhow!("cannot read the Supervisor's answer: {e}"))?
                .to_bytes();
            if !status.is_success() {
                bail!("{path}: HTTP {status}");
            }
            let v: Value = serde_json::from_slice(&body).context("Supervisor sent invalid JSON")?;
            if v.get("result").and_then(Value::as_str) != Some("ok") {
                bail!(
                    "{path}: {}",
                    v.get("message").and_then(Value::as_str).unwrap_or("error")
                );
            }
            Ok(v.get("data").cloned().unwrap_or(Value::Null))
        };
        tokio::time::timeout(TIMEOUT, fut)
            .await
            .map_err(|_| anyhow!("{path}: the Supervisor did not answer within {TIMEOUT:?}"))?
    }

    /// Installed qBittorrent apps: from `GET /addons` when allowed, otherwise
    /// from `/addons/<slug>/info` for each candidate slug.
    pub async fn qbittorrent_apps(&self, candidate_slugs: &[String]) -> Vec<AppInfo> {
        match self.call(Method::GET, "/addons", None).await {
            Ok(data) => {
                let list = data
                    .get("addons")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut out: Vec<AppInfo> = list
                    .iter()
                    .filter_map(parse_app)
                    .filter(|a| is_qbittorrent(&a.slug))
                    .collect();
                // The list has no port details; fetch them for running ones.
                for app in out.iter_mut().filter(|a| a.is_running()) {
                    if let Ok(info) = self.app_info(&app.slug).await {
                        app.host_ports = info.host_ports;
                    }
                }
                out
            }
            Err(e) => {
                debug!("Supervisor app list unavailable ({e:#}); asking per app");
                let mut slugs: Vec<String> = candidate_slugs
                    .iter()
                    .cloned()
                    .chain(KNOWN_QBITTORRENT_SLUGS.iter().map(|s| (*s).to_owned()))
                    .filter(|s| is_qbittorrent(s) && valid_slug(s))
                    .collect();
                slugs.sort();
                slugs.dedup();
                let mut out = Vec::new();
                for slug in slugs {
                    match self.app_info(&slug).await {
                        Ok(info) => out.push(info),
                        Err(e) => debug!("Supervisor info for {slug}: {e:#}"),
                    }
                }
                out
            }
        }
    }

    async fn app_info(&self, slug: &str) -> Result<AppInfo> {
        let data = self
            .call(Method::GET, &format!("/addons/{slug}/info"), None)
            .await?;
        let mut info = parse_app(&data).ok_or_else(|| anyhow!("unexpected app info"))?;
        if info.slug.is_empty() {
            slug.clone_into(&mut info.slug);
        }
        info.host_ports = data
            .get("network")
            .and_then(Value::as_object)
            .map(|m| {
                m.values()
                    .filter_map(Value::as_u64)
                    .filter_map(|p| u16::try_from(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        Ok(info)
    }

    /// `POST /discovery`: lets Home Assistant offer the qBittorrent
    /// integration for this app. Returns the discovery UUID.
    pub async fn announce(&self, service: &str, config: Value) -> Result<String> {
        let body = serde_json::json!({ "service": service, "config": config });
        let data = self.call(Method::POST, "/discovery", Some(&body)).await?;
        Ok(data
            .get("uuid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }
}

pub fn is_qbittorrent(slug: &str) -> bool {
    slug.to_ascii_lowercase().contains("qbittorrent")
}

/// Supervisor slugs: lowercase letters, digits, `_` and `-` only (also keeps
/// the value safe to put into a request path).
pub fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn parse_app(v: &Value) -> Option<AppInfo> {
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    v.as_object()?;
    Some(AppInfo {
        slug: s("slug"),
        name: s("name"),
        state: s("state"),
        host_ports: Vec::new(),
    })
}

/// The loud warning for running qBittorrent apps, or `None`.
pub fn conflict_banner(apps: &[AppInfo], webui_port: u16) -> Option<String> {
    let running: Vec<&AppInfo> = apps.iter().filter(|a| a.is_running()).collect();
    if running.is_empty() {
        return None;
    }
    let mut s = String::from(
        "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
    );
    for a in &running {
        let name = if a.name.is_empty() { &a.slug } else { &a.name };
        let _ = writeln!(s, "!! qBittorrent is still running: {name} ({})", a.slug);
        if a.host_ports.contains(&webui_port) {
            let _ = writeln!(
                s,
                "!!   it holds host port {webui_port}, the port rBittorrent uses"
            );
        }
    }
    s.push_str(
        "!! Stop it (and turn off its \"Start on boot\") so both apps do not seed\n\
         !! the same files at once and fight over port 8080. Sonarr, Radarr and\n\
         !! the qBittorrent integration then reach rBittorrent on the same port.\n\
         !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    );
    Some(s)
}

/// This container's host name on Home Assistant's network (what other apps
/// and Home Assistant use to reach it), e.g. `1a2b3c4d-rbittorrent`.
pub fn own_hostname() -> Option<String> {
    let h = std::fs::read_to_string("/etc/hostname").ok()?;
    let h = h.trim();
    (!h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
    .then(|| h.to_owned())
}

/// Fallback when the Supervisor cannot be resolved (it is always this IP).
pub fn default_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(SUPERVISOR_IP, 80))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(slug: &str, state: &str, ports: &[u16]) -> AppInfo {
        AppInfo {
            slug: slug.into(),
            name: "qBittorrent".into(),
            state: state.into(),
            host_ports: ports.to_vec(),
        }
    }

    #[test]
    fn banner_only_for_running_apps() {
        assert!(conflict_banner(&[], 8080).is_none());
        assert!(
            conflict_banner(&[app("db21ed7f_qbittorrent", "stopped", &[8080])], 8080).is_none()
        );
        let b = conflict_banner(&[app("db21ed7f_qbittorrent", "started", &[8080])], 8080).unwrap();
        assert!(
            b.contains("still running: qBittorrent (db21ed7f_qbittorrent)"),
            "{b}"
        );
        assert!(b.contains("holds host port 8080"));
        let b = conflict_banner(&[app("x_qbittorrent", "started", &[8081])], 8080).unwrap();
        assert!(!b.contains("holds host port"));
    }

    #[test]
    fn slug_rules() {
        assert!(is_qbittorrent("db21ed7f_qbittorrent"));
        assert!(is_qbittorrent("local_qBittorrent_vpn"));
        assert!(!is_qbittorrent("rbittorrent"));
        assert!(valid_slug("db21ed7f_qbittorrent"));
        assert!(!valid_slug("../core"));
        assert!(!valid_slug("a/b"));
        assert!(!valid_slug(""));
        assert_eq!(default_addr().to_string(), "172.30.32.2:80");
    }
}
