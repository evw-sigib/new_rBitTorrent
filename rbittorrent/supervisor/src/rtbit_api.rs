//! Small client for rtbit's qBittorrent-compatible API on the loopback
//! interface, used to seed migrated categories and torrents.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::Secret;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 1 << 20;
/// How long a call waits for rtbit to come back (a NAT-PMP port change
/// restarts it) before the call counts as failed.
const RECOVER_TIMEOUT: Duration = Duration::from_secs(90);

/// rtbit answered and said no: retrying the same request will not help.
/// Anything else (no connection, timeout, lost session) is transient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Whether `e` is a [`Refused`] answer rather than a transient failure.
pub fn is_refusal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Refused>().is_some()
}

/// What `torrents/createCategory` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryOutcome {
    Created,
    AlreadyExists,
}

/// One `.torrent` for `torrents/add`.
#[derive(Debug, Clone)]
pub struct TorrentUpload<'a> {
    pub file_name: &'a str,
    pub data: &'a [u8],
    pub save_path: &'a str,
    pub category: Option<&'a str>,
    /// `Original`, `Subfolder` or `NoSubfolder`.
    pub content_layout: &'a str,
    pub stopped: bool,
}

pub struct RtbitApi {
    addr: SocketAddr,
    host: HeaderValue,
    sid: Option<String>,
    /// Kept so a call can sign in again after rtbit restarted (its sessions
    /// do not survive a restart).
    credentials: Option<(String, Secret)>,
}

impl std::fmt::Debug for RtbitApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtbitApi")
            .field("addr", &self.addr)
            .field("signed_in", &self.sid.is_some())
            .finish()
    }
}

impl RtbitApi {
    pub fn new(addr: SocketAddr) -> Self {
        let host = HeaderValue::from_str(&addr.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("127.0.0.1"));
        Self {
            addr,
            host,
            sid: None,
            credentials: None,
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: Bytes,
    ) -> Result<(StatusCode, hyper::HeaderMap, Bytes)> {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(body))
            .context("cannot build the request")?;
        let h = req.headers_mut();
        h.insert(header::HOST, self.host.clone());
        if let Some(ct) = content_type {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_str(ct)?);
        }
        if let Some(sid) = &self.sid {
            h.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("SID={sid}"))?,
            );
        }
        let fut = async {
            let stream = TcpStream::connect(self.addr)
                .await
                .with_context(|| format!("cannot connect to rtbit on {}", self.addr))?;
            let _ = stream.set_nodelay(true);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .context("HTTP handshake with rtbit failed")?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("rtbit API connection ended: {e}");
                }
            });
            let resp = sender
                .send_request(req)
                .await
                .context("rtbit closed the connection")?;
            let (parts, body) = resp.into_parts();
            let body = Limited::new(body, MAX_RESPONSE)
                .collect()
                .await
                .map_err(|e| anyhow!("cannot read rtbit's response: {e}"))?
                .to_bytes();
            Ok((parts.status, parts.headers, body))
        };
        tokio::time::timeout(REQUEST_TIMEOUT, fut)
            .await
            .map_err(|_| anyhow!("rtbit did not answer {path} within {REQUEST_TIMEOUT:?}"))?
    }

    /// One authenticated call. A lost session (401/403) signs in again, and a
    /// failed connection waits for rtbit to come back and signs in again;
    /// either way the request is sent once more.
    async fn call(
        &mut self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: Bytes,
    ) -> Result<(StatusCode, hyper::HeaderMap, Bytes)> {
        if self.credentials.is_none() {
            return self.send(method, path, content_type, body).await;
        }
        match self
            .send(method.clone(), path, content_type, body.clone())
            .await
        {
            Ok((s, ..)) if s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN => {
                debug!("rtbit answered {path} with {s}: signing in again");
            }
            Err(e) => {
                debug!("rtbit API call {path} failed ({e:#}): waiting for rtbit");
                self.wait_ready(RECOVER_TIMEOUT)
                    .await
                    .with_context(|| format!("{e:#}"))?;
            }
            Ok(answer) => return Ok(answer),
        }
        self.sign_in().await?;
        self.send(method, path, content_type, body).await
    }

    /// Waits until `GET /healthz` answers 200.
    pub async fn wait_ready(&self, limit: Duration) -> Result<()> {
        let start = tokio::time::Instant::now();
        loop {
            match self.send(Method::GET, "/healthz", None, Bytes::new()).await {
                Ok((s, _, _)) if s.is_success() => return Ok(()),
                Ok((s, _, _)) => debug!("rtbit /healthz: {s}"),
                Err(e) => debug!("rtbit /healthz: {e:#}"),
            }
            if start.elapsed() >= limit {
                bail!(
                    "rtbit's API did not become ready within {}s",
                    limit.as_secs()
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// `auth/login`: keeps the SID cookie (and the credentials, to sign in
    /// again after an rtbit restart) for later calls.
    pub async fn login(&mut self, username: &str, password: &Secret) -> Result<()> {
        self.credentials = Some((username.to_owned(), password.clone()));
        self.sign_in().await
    }

    async fn sign_in(&mut self) -> Result<()> {
        let Some((username, password)) = &self.credentials else {
            bail!("no rtbit credentials");
        };
        let form = format!(
            "username={}&password={}",
            form_encode(username),
            form_encode(password.expose())
        );
        self.sid = None;
        let (status, headers, _) = self
            .send(
                Method::POST,
                "/api/v2/auth/login",
                Some("application/x-www-form-urlencoded"),
                Bytes::from(form),
            )
            .await?;
        match session_cookie(&headers) {
            Some(sid) if status.is_success() => {
                self.sid = Some(sid);
                Ok(())
            }
            _ => bail!("rtbit refused the Web UI login ({status})"),
        }
    }

    /// `torrents/createCategory`.
    pub async fn create_category(
        &mut self,
        name: &str,
        save_path: Option<&str>,
    ) -> Result<CategoryOutcome> {
        let form = format!(
            "category={}&savePath={}",
            form_encode(name),
            form_encode(save_path.unwrap_or(""))
        );
        let (status, _, body) = self
            .call(
                Method::POST,
                "/api/v2/torrents/createCategory",
                Some("application/x-www-form-urlencoded"),
                Bytes::from(form),
            )
            .await?;
        match status {
            s if s.is_success() => Ok(CategoryOutcome::Created),
            StatusCode::CONFLICT => Ok(CategoryOutcome::AlreadyExists),
            s => Err(refusal(&format!("category `{name}`"), s, &body)),
        }
    }

    /// `torrents/add` with one `.torrent` file.
    pub async fn add_torrent(&mut self, t: &TorrentUpload<'_>) -> Result<()> {
        let mut fields: Vec<(&str, Option<&str>, &[u8])> = vec![
            ("torrents", Some(t.file_name), t.data),
            ("savepath", None, t.save_path.as_bytes()),
            // An explicit save path only applies with automatic management off.
            ("autoTMM", None, b"false"),
            ("contentLayout", None, t.content_layout.as_bytes()),
            ("stopped", None, if t.stopped { b"true" } else { b"false" }),
        ];
        if let Some(c) = t.category {
            fields.push(("category", None, c.as_bytes()));
        }
        let boundary = multipart_boundary(&fields)?;
        let body = multipart(&boundary, &fields);
        let (status, _, body) = self
            .call(
                Method::POST,
                "/api/v2/torrents/add",
                Some(&format!("multipart/form-data; boundary={boundary}")),
                Bytes::from(body),
            )
            .await?;
        // qBittorrent answers a rejected torrent with 200 and `Fails.`.
        if !status.is_success() || body.trim_ascii().eq_ignore_ascii_case(b"Fails.") {
            return Err(refusal("the torrent", status, &body));
        }
        Ok(())
    }
}

fn refusal(what: &str, status: StatusCode, body: &[u8]) -> anyhow::Error {
    let text: String = String::from_utf8_lossy(body)
        .trim()
        .chars()
        .take(200)
        .collect();
    anyhow::Error::new(Refused(format!("rtbit refused {what} ({status}: {text})")))
}

/// The `SID` value from a login answer's `Set-Cookie` headers.
fn session_cookie(headers: &hyper::HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.split(';')
                .next()
                .and_then(|kv| kv.trim().strip_prefix("SID="))
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        })
}

/// `application/x-www-form-urlencoded` value encoding.
pub fn form_encode(s: &str) -> String {
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

/// A random boundary (128 bits from the kernel CSPRNG) that occurs in none
/// of the field values.
fn multipart_boundary(fields: &[(&str, Option<&str>, &[u8])]) -> Result<String> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    for _ in 0..4 {
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce)
            .map_err(|_| anyhow!("no randomness for a multipart boundary"))?;
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let boundary = format!("rbittorrent-{hex}");
        let needle = boundary.as_bytes();
        let collides = fields
            .iter()
            .any(|(_, _, v)| v.windows(needle.len()).any(|w| w == needle));
        if !collides {
            return Ok(boundary);
        }
    }
    bail!("cannot find a multipart boundary that is not in the upload")
}

/// `multipart/form-data` body. Field names and file names are ours (ASCII,
/// no quotes); values are raw bytes.
pub fn multipart(boundary: &str, fields: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, file_name, value) in fields {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match file_name {
            Some(f) => {
                let f: String = f
                    .chars()
                    .filter(|c| !matches!(c, '"' | '\r' | '\n' | '\\'))
                    .collect();
                out.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\
                         Content-Type: application/x-bittorrent\r\n\r\n"
                    )
                    .as_bytes(),
                );
            }
            None => out.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_and_multipart_encoding() {
        assert_eq!(form_encode("a b&c=/é"), "a%20b%26c%3D%2F%C3%A9");
        let body = multipart(
            "B",
            &[
                ("torrents", Some("x\"y.torrent"), b"d4:infodee"),
                ("savepath", None, b"/share/tv"),
            ],
        );
        let text = String::from_utf8(body).unwrap();
        assert_eq!(
            text,
            "--B\r\nContent-Disposition: form-data; name=\"torrents\"; filename=\"xy.torrent\"\r\n\
             Content-Type: application/x-bittorrent\r\n\r\nd4:infodee\r\n\
             --B\r\nContent-Disposition: form-data; name=\"savepath\"\r\n\r\n/share/tv\r\n--B--\r\n"
        );
    }

    #[test]
    fn boundaries_are_random_and_never_in_the_body() {
        let fields: [(&str, Option<&str>, &[u8]); 1] = [("torrents", None, b"rbittorrent-")];
        let a = multipart_boundary(&fields).unwrap();
        let b = multipart_boundary(&fields).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), "rbittorrent-".len() + 32);
        assert!(!a.contains(char::is_uppercase));
    }

    #[test]
    fn refusals_are_told_apart_from_transient_failures() {
        let refused = refusal("the torrent", StatusCode::OK, b"Fails.");
        assert!(is_refusal(&refused));
        assert!(refused.to_string().contains("Fails."));
        let wrapped = refused.context("x.torrent");
        assert!(is_refusal(&wrapped));
        assert!(!is_refusal(&anyhow!("cannot connect to rtbit")));
    }

    #[test]
    fn session_cookie_is_found() {
        let mut h = hyper::HeaderMap::new();
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_static("other=1; Path=/"),
        );
        h.append(
            header::SET_COOKIE,
            HeaderValue::from_static("SID=abc; HttpOnly"),
        );
        assert_eq!(session_cookie(&h).as_deref(), Some("abc"));
        let mut empty = hyper::HeaderMap::new();
        empty.append(header::SET_COOKIE, HeaderValue::from_static("SID=; Path=/"));
        assert_eq!(session_cookie(&empty), None);
    }
}
