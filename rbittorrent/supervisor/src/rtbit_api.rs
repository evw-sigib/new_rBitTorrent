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

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 1 << 20;

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
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(StatusCode, hyper::HeaderMap, Bytes)> {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(Bytes::from(body)))
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

    /// Waits until `GET /healthz` answers 200.
    pub async fn wait_ready(&self, limit: Duration) -> Result<()> {
        let start = tokio::time::Instant::now();
        loop {
            match self.send(Method::GET, "/healthz", None, Vec::new()).await {
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

    /// `auth/login`: keeps the SID cookie for later calls.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let form = format!(
            "username={}&password={}",
            form_encode(username),
            form_encode(password)
        );
        let (status, headers, _) = self
            .send(
                Method::POST,
                "/api/v2/auth/login",
                Some("application/x-www-form-urlencoded"),
                form.into_bytes(),
            )
            .await?;
        let sid = headers
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
            Some(sid) if status.is_success() => {
                self.sid = Some(sid);
                Ok(())
            }
            _ => bail!("rtbit refused the Web UI login ({status})"),
        }
    }

    /// `torrents/createCategory`.
    pub async fn create_category(
        &self,
        name: &str,
        save_path: Option<&str>,
    ) -> Result<CategoryOutcome> {
        let form = format!(
            "category={}&savePath={}",
            form_encode(name),
            form_encode(save_path.unwrap_or(""))
        );
        let (status, _, body) = self
            .send(
                Method::POST,
                "/api/v2/torrents/createCategory",
                Some("application/x-www-form-urlencoded"),
                form.into_bytes(),
            )
            .await?;
        match status {
            s if s.is_success() => Ok(CategoryOutcome::Created),
            StatusCode::CONFLICT => Ok(CategoryOutcome::AlreadyExists),
            s => bail!(
                "rtbit refused category `{name}` ({s}: {})",
                String::from_utf8_lossy(&body).trim()
            ),
        }
    }

    /// `torrents/add` with one `.torrent` file.
    pub async fn add_torrent(&self, t: &TorrentUpload<'_>) -> Result<()> {
        let boundary = multipart_boundary();
        let mut fields: Vec<(&str, Option<&str>, &[u8])> = vec![
            ("torrents", Some(t.file_name), t.data),
            ("savepath", None, t.save_path.as_bytes()),
            ("contentLayout", None, t.content_layout.as_bytes()),
            ("stopped", None, if t.stopped { b"true" } else { b"false" }),
        ];
        if let Some(c) = t.category {
            fields.push(("category", None, c.as_bytes()));
        }
        let body = multipart(&boundary, &fields);
        let (status, _, body) = self
            .send(
                Method::POST,
                "/api/v2/torrents/add",
                Some(&format!("multipart/form-data; boundary={boundary}")),
                body,
            )
            .await?;
        if !status.is_success() {
            bail!(
                "rtbit refused the torrent ({status}: {})",
                String::from_utf8_lossy(&body).trim()
            );
        }
        Ok(())
    }
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

fn multipart_boundary() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("rbittorrent-{nanos:x}-{:x}", std::process::id())
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
}
