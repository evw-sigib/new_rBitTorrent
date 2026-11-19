//! One-time takeover of an existing qBittorrent installation, so switching
//! to rBittorrent needs no changes in Sonarr, Radarr, Prowlarr,
//! qBitController or Home Assistant's qBittorrent integration.
//!
//! Phase 1, [`prepare`], before the configuration is validated:
//! * finds qBittorrent profiles in `/app_configs/*qbittorrent*` (the
//!   `all_app_configs` map, read-only; `/addon_configs` on Supervisors from
//!   before 2026.07), `/share/qBittorrent` and `/config/qBittorrent`;
//! * copies the old app's WireGuard file to `/config/wg0.conf` when
//!   rBittorrent has no VPN settings of its own;
//! * takes over the save/incomplete folders and the Web UI user name when
//!   the options still have their defaults, and reads `categories.json`.
//!
//! Phase 2, [`seed`], once rtbit runs: creates the categories through
//! rtbit's qBittorrent API and, if `import_active_torrents` is on, re-adds
//! every torrent from `BT_backup` at its old save path, so rtbit verifies the
//! existing files and keeps seeding instead of downloading again.
//!
//! `/config/.migrated` (a JSON record of what was taken over) and
//! `/config/.torrents_migrated` mark the two phases as done; the record is
//! re-applied on every start, so the imported folders stay in effect while
//! the options keep their defaults.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::bencode;
use crate::config::{self, Options, Secret};
use crate::rtbit_api::{CategoryOutcome, RtbitApi, TorrentUpload};

pub const MIGRATED_MARKER: &str = ".migrated";
pub const TORRENTS_MARKER: &str = ".torrents_migrated";
const RECORD_VERSION: u32 = 1;
const MAX_WALK_DEPTH: usize = 4;
const MAX_WALK_ENTRIES: usize = 20_000;
const MAX_TEXT_FILE: u64 = 1 << 20;
const MAX_TORRENT_FILE: u64 = 32 << 20;
/// Upper bound on imported torrents (a runaway BT_backup must not stall startup).
pub const MAX_TORRENTS: usize = 10_000;
const RTBIT_READY_TIMEOUT: Duration = Duration::from_secs(120);

/// Where to look. Defaults are the app's mounts; tests point elsewhere.
#[derive(Debug, Clone)]
pub struct Roots {
    pub app_configs: PathBuf,
    pub share: PathBuf,
    pub config: PathBuf,
}

impl Roots {
    pub fn new(config: &Path) -> Self {
        let env = |k: &str, d: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(d), PathBuf::from)
        };
        // `all_app_configs` mounts at /app_configs; the legacy
        // `all_addon_configs` name used /addon_configs.
        let default_apps = ["/app_configs", "/addon_configs"]
            .into_iter()
            .find(|p| Path::new(p).is_dir())
            .unwrap_or("/app_configs");
        Self {
            app_configs: env("RBITTORRENT_APP_CONFIGS", default_apps),
            share: env("RBITTORRENT_SHARE", "/share"),
            config: config.to_path_buf(),
        }
    }
}

/// A qBittorrent profile found on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyInstall {
    pub root: PathBuf,
    /// The old app's slug when found under `/app_configs`.
    pub slug: Option<String>,
    pub conf: Option<PathBuf>,
    pub categories: Option<PathBuf>,
    pub bt_backup: Option<PathBuf>,
    pub wireguard: Vec<PathBuf>,
    /// qBittorrent 5's SQLite resume store, which is not supported.
    pub sqlite_resume: bool,
}

impl LegacyInstall {
    fn is_useful(&self) -> bool {
        self.conf.is_some()
            || self.categories.is_some()
            || self.bt_backup.is_some()
            || !self.wireguard.is_empty()
    }

    pub fn label(&self) -> String {
        self.slug
            .clone()
            .unwrap_or_else(|| self.root.display().to_string())
    }
}

/// Folders that may hold a qBittorrent profile, in priority order.
pub fn candidate_roots(roots: &Roots) -> Vec<(PathBuf, Option<String>)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&roots.app_configs) {
        let mut apps: Vec<(PathBuf, String)> = rd
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.to_ascii_lowercase()
                    .contains("qbittorrent")
                    .then(|| (e.path(), name))
            })
            .collect();
        apps.sort();
        out.extend(apps.into_iter().map(|(p, n)| (p, Some(n))));
    }
    let mut named = |dir: &Path| {
        if let Ok(rd) = std::fs::read_dir(dir) {
            let mut found: Vec<PathBuf> = rd
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter(|e| e.file_name().eq_ignore_ascii_case("qbittorrent"))
                .map(|e| e.path())
                .collect();
            found.sort();
            out.extend(found.into_iter().map(|p| (p, None)));
        }
    };
    named(&roots.share);
    named(&roots.config);
    out
}

/// Bounded breadth-first walk of one candidate folder (no symlinks, at most
/// [`MAX_WALK_DEPTH`] levels and [`MAX_WALK_ENTRIES`] entries: the folder
/// may also hold a large download tree).
pub fn scan(root: &Path, slug: Option<String>) -> LegacyInstall {
    let mut found = LegacyInstall {
        root: root.to_path_buf(),
        slug,
        ..LegacyInstall::default()
    };
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut seen = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let in_wireguard_dir = dir
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("wireguard"));
        for e in entries {
            seen += 1;
            if seen > MAX_WALK_ENTRIES {
                debug!(
                    "stopped scanning {} after {MAX_WALK_ENTRIES} entries",
                    root.display()
                );
                return found;
            }
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            let path = e.path();
            if ft.is_dir() {
                if name == "BT_backup" {
                    found.bt_backup.get_or_insert(path);
                } else if depth < MAX_WALK_DEPTH {
                    queue.push_back((path, depth + 1));
                }
            } else if ft.is_file() {
                let lower = name.to_ascii_lowercase();
                if name == "qBittorrent.conf" {
                    found.conf.get_or_insert(path);
                } else if name == "categories.json" {
                    found.categories.get_or_insert(path);
                } else if name == "torrents.db" {
                    found.sqlite_resume = true;
                } else if lower.ends_with(".conf") && (in_wireguard_dir || lower == "wg0.conf") {
                    found.wireguard.push(path);
                }
            }
        }
    }
    found
}

/// All useful qBittorrent profiles.
pub fn discover(roots: &Roots) -> Vec<LegacyInstall> {
    candidate_roots(roots)
        .into_iter()
        .map(|(p, slug)| scan(&p, slug))
        .filter(LegacyInstall::is_useful)
        .collect()
}

// ---------------------------------------------------------------------------
// qBittorrent.conf / categories.json / .fastresume
// ---------------------------------------------------------------------------

/// The settings taken from `qBittorrent.conf`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyConf {
    pub save_path: Option<String>,
    pub temp_path: Option<String>,
    pub temp_enabled: bool,
    pub username: Option<String>,
    pub webui_port: Option<u16>,
}

/// Parses the Qt INI file. `Session\...` (qBittorrent 4.4+) wins over the
/// older `Downloads\...` keys.
pub fn parse_qbittorrent_conf(text: &str) -> LegacyConf {
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#', '[']) {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // Qt writes `\` as `\\` inside quoted values and keys use `\`.
            kv.insert(k.trim().replace("\\\\", "\\"), unquote(v.trim()));
        }
    }
    let get = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| kv.get(*k))
            .filter(|v| !v.is_empty() && !v.starts_with('@'))
            .cloned()
    };
    let bool_of = |keys: &[&str]| get(keys).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    LegacyConf {
        save_path: get(&["Session\\DefaultSavePath", "Downloads\\SavePath"]).map(clean_path),
        temp_path: get(&["Session\\TempPath", "Downloads\\TempPath"]).map(clean_path),
        temp_enabled: bool_of(&["Session\\TempPathEnabled", "Downloads\\TempPathEnabled"]),
        username: get(&["WebUI\\Username"]),
        webui_port: get(&["WebUI\\Port"]).and_then(|p| p.parse().ok()),
    }
}

fn unquote(v: &str) -> String {
    match v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) => inner.replace("\\\"", "\"").replace("\\\\", "\\"),
        None => v.to_owned(),
    }
}

/// Trailing slashes off, `\` to `/` (Windows-style values do not occur on
/// Home Assistant, but an imported profile might have them).
fn clean_path(p: String) -> String {
    let p = p.replace('\\', "/");
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// rtbit's (and qBittorrent's) category name rule.
pub fn valid_category_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.contains("//")
        && !name.chars().any(char::is_control)
}

/// `categories.json`: `{"tv-sonarr": {"save_path": "/share/tv"}}`
/// (qBittorrent 4.4+) or `{"tv-sonarr": "/share/tv"}` (older). An empty
/// path means "the default save path". Relative paths are resolved against
/// `default_save`.
pub fn parse_categories(
    json: &str,
    default_save: Option<&str>,
) -> Result<BTreeMap<String, Option<String>>> {
    let v: serde_json::Value = serde_json::from_str(json).context("invalid categories.json")?;
    let obj = v
        .as_object()
        .context("categories.json is not a JSON object")?;
    let mut out = BTreeMap::new();
    for (name, val) in obj {
        if !valid_category_name(name) {
            continue;
        }
        let path = match val {
            serde_json::Value::String(s) => Some(s.as_str()),
            serde_json::Value::Object(o) => o.get("save_path").and_then(|p| p.as_str()),
            _ => None,
        }
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.starts_with('/') {
                clean_path(p.to_owned())
            } else {
                let base = default_save.unwrap_or("/");
                clean_path(format!("{base}/{p}"))
            }
        });
        out.insert(name.clone(), path);
    }
    Ok(out)
}

/// What a `.fastresume` says about one torrent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResumeInfo {
    pub save_path: Option<String>,
    pub category: Option<String>,
    pub stopped: bool,
    pub content_layout: &'static str,
}

/// Reads libtorrent's `save_path` (where the files are now; while a torrent
/// is incomplete that may be the temp folder) and qBittorrent's extras.
pub fn parse_fastresume(data: &[u8]) -> Result<ResumeInfo> {
    let v = bencode::decode(data).context("not a valid .fastresume file")?;
    let s = |k: &str| {
        v.get(k)
            .and_then(bencode::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let i = |k: &str| v.get(k).and_then(bencode::Value::as_int);
    let save_path = s("save_path").or_else(|| s("qBt-savePath")).map(clean_path);
    let stopped = (i("paused") == Some(1) && i("auto_managed") == Some(0))
        || i("qBt-paused") == Some(1)
        || i("qBt-stopped") == Some(1);
    let content_layout = match s("qBt-contentLayout").as_deref() {
        Some("Subfolder") => "Subfolder",
        Some("NoSubfolder") => "NoSubfolder",
        Some(_) => "Original",
        None if i("qBt-hasRootFolder") == Some(0) => "NoSubfolder",
        None => "Original",
    };
    Ok(ResumeInfo {
        save_path,
        category: s("qBt-category").filter(|c| valid_category_name(c)),
        stopped,
        content_layout,
    })
}

// ---------------------------------------------------------------------------
// WireGuard takeover
// ---------------------------------------------------------------------------

/// rBittorrent has no VPN settings of its own (methods 2 and 3 empty).
pub fn wireguard_options_empty(o: &Options) -> bool {
    [
        &o.wireguard_conf,
        &o.wg_private_key,
        &o.wg_public_key,
        &o.wg_endpoint,
        &o.wg_address,
    ]
    .iter()
    .all(|v| v.as_deref().is_none_or(|s| s.trim().is_empty()))
}

/// The first legacy WireGuard file that is complete (`wg0.conf` first, then
/// by name), with its text.
pub fn pick_wireguard(candidates: &[PathBuf]) -> Option<(PathBuf, String)> {
    let mut sorted: Vec<&PathBuf> = candidates.iter().collect();
    sorted.sort_by_key(|p| {
        let wg0 = p
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("wg0.conf"));
        (!wg0, (*p).clone())
    });
    for p in sorted {
        let Some(text) = read_small(p, MAX_TEXT_FILE) else {
            continue;
        };
        match config::parse_wg_conf(&text) {
            Ok(c)
                if c.private_key.is_some()
                    && c.peer_public_key.is_some()
                    && c.endpoint.is_some() =>
            {
                return Some((p.clone(), text));
            }
            Ok(_) => debug!("{} is not a complete WireGuard config", p.display()),
            Err(e) => debug!("{} is not a WireGuard config: {e:#}", p.display()),
        }
    }
    None
}

fn read_small(p: &Path, limit: u64) -> Option<String> {
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > limit {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

// ---------------------------------------------------------------------------
// The record and phase 1
// ---------------------------------------------------------------------------

/// `/config/.migrated`: what was taken over, re-applied on every start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    pub version: u32,
    pub completed_at: u64,
    pub source: String,
    pub wireguard_from: Option<String>,
    pub download_dir: Option<String>,
    pub completed_dir: Option<String>,
    pub webui_username: Option<String>,
    pub categories: BTreeMap<String, Option<String>>,
    pub bt_backup: Option<String>,
}

/// Work for phase 2 plus the banner line.
#[derive(Debug, Clone, Default)]
pub struct Migration {
    /// The record in effect (from disk, or built now).
    pub record: Option<Record>,
    /// Built this start: `/config/.migrated` is written after phase 2.
    pub fresh: bool,
    /// `BT_backup` to import (phase 2), when asked for and not done yet.
    pub torrents_from: Option<PathBuf>,
    /// One line for the status banner.
    pub status: String,
}

impl Migration {
    pub fn has_work(&self) -> bool {
        self.fresh || self.torrents_from.is_some()
    }
}

fn data_path_ok(p: &str) -> bool {
    config::validate_data_path(p).is_ok()
}

/// The app's data mounts (/media, /share, /config).
pub fn default_data_roots() -> Vec<PathBuf> {
    config::PERMITTED_DATA_ROOTS
        .iter()
        .map(PathBuf::from)
        .collect()
}

/// Absolute, no `..`, strictly below one of `roots`.
pub fn path_allowed(p: &str, roots: &[PathBuf]) -> bool {
    let p = Path::new(p);
    p.is_absolute()
        && !p
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        && roots.iter().any(|r| p.starts_with(r) && p != r)
}

/// Applies a record to options that still have their defaults.
pub fn apply_record(o: &mut Options, rec: &Record) -> Vec<String> {
    let defaults = Options::default();
    let mut applied = Vec::new();
    if let (Some(dl), Some(done)) = (&rec.download_dir, &rec.completed_dir) {
        if o.download_dir == defaults.download_dir && o.completed_dir == defaults.completed_dir {
            o.download_dir.clone_from(dl);
            o.completed_dir.clone_from(done);
            applied.push(format!("folders {done} (incomplete: {dl})"));
        } else {
            debug!("download folders set in the options; the imported ones are not used");
        }
    }
    if let Some(user) = &rec.webui_username
        && o.webui_username == defaults.webui_username
        && *user != o.webui_username
    {
        o.webui_username.clone_from(user);
        applied.push(format!("Web UI user `{user}`"));
    }
    applied
}

/// Builds a record from the profiles found.
pub fn build_record(installs: &[LegacyInstall], now: u64) -> (Record, Vec<String>) {
    let mut notes = Vec::new();
    let mut rec = Record {
        version: RECORD_VERSION,
        completed_at: now,
        ..Record::default()
    };
    let primary = installs
        .iter()
        .find(|i| i.conf.is_some())
        .or_else(|| installs.first());
    let Some(primary) = primary else {
        return (rec, notes);
    };
    rec.source = primary.label();
    let conf = primary
        .conf
        .as_deref()
        .and_then(|p| read_small(p, MAX_TEXT_FILE))
        .map(|t| parse_qbittorrent_conf(&t))
        .unwrap_or_default();
    if let Some(save) = conf.save_path.clone() {
        let temp = conf
            .temp_path
            .clone()
            .filter(|t| conf.temp_enabled && *t != save)
            .unwrap_or_else(|| format!("{save}/incomplete"));
        if data_path_ok(&save) && data_path_ok(&temp) {
            rec.completed_dir = Some(save);
            rec.download_dir = Some(temp);
        } else {
            notes.push(format!(
                "qBittorrent's save path {save} is outside /media, /share and /config; \
                 keeping rBittorrent's download folders"
            ));
        }
    }
    rec.webui_username = conf
        .username
        .filter(|u| !u.trim().is_empty() && u.len() <= 128 && !u.chars().any(char::is_control));
    if let Some(p) = conf.webui_port.filter(|p| *p != config::WEBUI_PORT) {
        notes.push(format!(
            "qBittorrent's Web UI used port {p}; rBittorrent answers on {}: set the host \
             port to {p} in the app's Network settings to keep clients unchanged",
            config::WEBUI_PORT
        ));
    }
    let default_save = rec.completed_dir.clone();
    for install in installs {
        let Some(text) = install
            .categories
            .as_deref()
            .and_then(|p| read_small(p, MAX_TEXT_FILE))
        else {
            continue;
        };
        match parse_categories(&text, default_save.as_deref()) {
            Ok(cats) => {
                for (name, path) in cats {
                    let path = path.filter(|p| {
                        let ok = data_path_ok(p);
                        if !ok {
                            notes.push(format!(
                                "category `{name}`: save path {p} is outside /media, /share \
                                 and /config; it uses the default folder"
                            ));
                        }
                        ok
                    });
                    rec.categories.entry(name).or_insert(path);
                }
            }
            Err(e) => notes.push(format!("{}: {e:#}", install.label())),
        }
    }
    rec.bt_backup = installs
        .iter()
        .find_map(|i| i.bt_backup.as_ref())
        .map(|p| p.display().to_string());
    if installs
        .iter()
        .any(|i| i.sqlite_resume && i.bt_backup.is_none())
    {
        notes.push(
            "qBittorrent keeps its torrents in an SQLite database (torrents.db); only \
             fastresume files can be imported: switch qBittorrent to \"Fastresume files\" \
             (Advanced settings), restart it once, then delete /config/.torrents_migrated"
                .to_owned(),
        );
    }
    (rec, notes)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Phase 1 (synchronous, before the configuration is validated).
pub fn prepare(o: &mut Options, roots: &Roots) -> Migration {
    let marker = roots.config.join(MIGRATED_MARKER);
    let torrents_done = roots.config.join(TORRENTS_MARKER).exists();
    let mut m = Migration::default();

    if marker.exists() {
        let rec = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|t| serde_json::from_str::<Record>(&t).ok());
        match rec {
            Some(rec) => {
                let applied = apply_record(o, &rec);
                if !applied.is_empty() {
                    debug!("qBittorrent import in effect: {}", applied.join(", "));
                }
                if o.import_active_torrents && !torrents_done {
                    m.torrents_from = rec.bt_backup.as_ref().map(PathBuf::from);
                }
                m.status = format!("done earlier (from {})", rec.source);
                m.record = Some(rec);
            }
            None => {
                warn!(
                    "{} is unreadable; delete it to import again",
                    marker.display()
                );
                m.status = "done earlier".to_owned();
            }
        }
        return m;
    }
    if !o.import_from_qbittorrent {
        m.status = "off (import_from_qbittorrent)".to_owned();
        return m;
    }

    let installs = discover(roots);
    if installs.is_empty() {
        info!("qBittorrent import: no qBittorrent installation found");
        m.status = "no qBittorrent installation found".to_owned();
        return m;
    }
    for i in &installs {
        info!(
            "qBittorrent import: found {} (settings: {}, categories: {}, torrents: {}, WireGuard files: {})",
            i.root.display(),
            yes(i.conf.is_some()),
            yes(i.categories.is_some()),
            yes(i.bt_backup.is_some()),
            i.wireguard.len()
        );
    }

    let (mut rec, notes) = build_record(&installs, now_secs());
    for n in notes {
        warn!("qBittorrent import: {n}");
    }

    // WireGuard: only when rBittorrent has nothing of its own.
    let wg0 = roots.config.join(config::WG_CONF_FILE);
    if wireguard_options_empty(o) && !wg0.exists() {
        let all: Vec<PathBuf> = installs.iter().flat_map(|i| i.wireguard.clone()).collect();
        if let Some((src, text)) = pick_wireguard(&all) {
            match config::write_private(&wg0, &text) {
                Ok(()) => {
                    info!(
                        "qBittorrent import: copied the WireGuard config {} to {}",
                        src.display(),
                        wg0.display()
                    );
                    rec.wireguard_from = Some(src.display().to_string());
                }
                Err(e) => warn!("qBittorrent import: cannot write {}: {e:#}", wg0.display()),
            }
        } else if !all.is_empty() {
            warn!(
                "qBittorrent import: {} WireGuard file(s) found, none complete \
                 (PrivateKey, PublicKey and Endpoint)",
                all.len()
            );
        }
    }

    let applied = apply_record(o, &rec);
    if o.import_active_torrents && !torrents_done {
        m.torrents_from = rec.bt_backup.as_ref().map(PathBuf::from);
    }
    let mut parts = Vec::new();
    if rec.wireguard_from.is_some() {
        parts.push("WireGuard".to_owned());
    }
    parts.extend(applied);
    if !rec.categories.is_empty() {
        parts.push(format!("{} categories", rec.categories.len()));
    }
    if m.torrents_from.is_some() {
        parts.push("torrents (after rtbit starts)".to_owned());
    } else if rec.bt_backup.is_some() && !o.import_active_torrents {
        parts.push("torrents not imported (import_active_torrents is off)".to_owned());
    }
    m.status = if parts.is_empty() {
        format!("{}: nothing to take over", rec.source)
    } else {
        format!("from {}: {}", rec.source, parts.join(", "))
    };
    m.record = Some(rec);
    m.fresh = true;
    m
}

fn yes(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

// ---------------------------------------------------------------------------
// Phase 2
// ---------------------------------------------------------------------------

/// What phase 2 did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SeedReport {
    pub categories_created: usize,
    pub categories_existing: usize,
    pub category_errors: Vec<String>,
    pub torrents_added: usize,
    pub torrents_skipped: Vec<String>,
    pub torrents_failed: Vec<String>,
}

impl SeedReport {
    pub fn summary(&self) -> String {
        let mut s = String::new();
        let cats = self.categories_created + self.categories_existing;
        if cats > 0 || !self.category_errors.is_empty() {
            let _ = write!(s, "{} categories ({} new)", cats, self.categories_created);
        }
        let attempted =
            self.torrents_added + self.torrents_skipped.len() + self.torrents_failed.len();
        if attempted > 0 {
            if !s.is_empty() {
                s.push_str(", ");
            }
            let _ = write!(
                s,
                "{}/{attempted} torrents re-added (verifying existing files)",
                self.torrents_added
            );
        }
        if s.is_empty() {
            s.push_str("nothing to seed");
        }
        s
    }
}

/// Everything phase 2 needs (owned, so it can run as its own task).
#[derive(Debug, Clone)]
pub struct SeedJob {
    pub api: SocketAddr,
    pub username: String,
    pub password: Secret,
    pub config_root: PathBuf,
    /// Save paths must lie below one of these ([`default_data_roots`]).
    pub data_roots: Vec<PathBuf>,
    pub migration: Migration,
}

/// Phase 2: categories, then torrents. Markers are written only once rtbit
/// has answered, so an rtbit that never starts means another try next time.
pub async fn seed(job: SeedJob) -> Result<SeedReport> {
    let mut report = SeedReport::default();
    let mut api = RtbitApi::new(job.api);
    api.wait_ready(RTBIT_READY_TIMEOUT).await?;
    api.login(&job.username, job.password.expose())
        .await
        .context("cannot sign in to rtbit's qBittorrent API")?;

    let m = &job.migration;
    if m.fresh
        && let Some(rec) = &m.record
    {
        for (name, path) in &rec.categories {
            match api.create_category(name, path.as_deref()).await {
                Ok(CategoryOutcome::Created) => report.categories_created += 1,
                Ok(CategoryOutcome::AlreadyExists) => report.categories_existing += 1,
                Err(e) => report.category_errors.push(format!("{name}: {e:#}")),
            }
        }
        config::write_private(
            &job.config_root.join(MIGRATED_MARKER),
            &serde_json::to_string_pretty(rec)?,
        )
        .context("cannot write the migration record")?;
    }

    if let Some(dir) = &m.torrents_from {
        import_torrents(&api, dir, &job.data_roots, &mut report).await;
        let done = serde_json::json!({
            "completed_at": now_secs(),
            "from": dir.display().to_string(),
            "added": report.torrents_added,
            "skipped": report.torrents_skipped,
            "failed": report.torrents_failed,
        });
        config::write_private(
            &job.config_root.join(TORRENTS_MARKER),
            &serde_json::to_string_pretty(&done)?,
        )
        .context("cannot write the torrent import marker")?;
    }
    Ok(report)
}

/// `<hash>.torrent` + `<hash>.fastresume` pairs in `BT_backup`, by name.
pub fn list_backup(dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut out: Vec<(PathBuf, PathBuf)> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "torrent"))
        .map(|t| {
            let r = t.with_extension("fastresume");
            (t, r)
        })
        .collect();
    out.sort();
    if out.len() > MAX_TORRENTS {
        warn!(
            "qBittorrent import: {} torrents found, importing the first {MAX_TORRENTS}",
            out.len()
        );
        out.truncate(MAX_TORRENTS);
    }
    Ok(out)
}

/// Checks one torrent and turns it into an upload, or says why not.
pub fn prepare_upload(
    torrent: &Path,
    resume: &Path,
    data_roots: &[PathBuf],
) -> Result<(Vec<u8>, ResumeInfo)> {
    let meta = std::fs::metadata(torrent)?;
    if meta.len() > MAX_TORRENT_FILE {
        bail!("larger than {} MiB", MAX_TORRENT_FILE >> 20);
    }
    let data = std::fs::read(torrent)?;
    bencode::decode(&data).context("not a valid .torrent file")?;
    let resume_meta = std::fs::metadata(resume).context("no .fastresume next to it")?;
    if resume_meta.len() > MAX_TORRENT_FILE {
        bail!(".fastresume larger than {} MiB", MAX_TORRENT_FILE >> 20);
    }
    let info = parse_fastresume(&std::fs::read(resume)?)?;
    let Some(save) = &info.save_path else {
        bail!("no save path in its .fastresume");
    };
    if !path_allowed(save, data_roots) {
        bail!("save path {save} is outside /media, /share and /config");
    }
    if !Path::new(save).is_dir() {
        bail!("save path {save} does not exist (disk not mounted?)");
    }
    Ok((data, info))
}

async fn import_torrents(
    api: &RtbitApi,
    dir: &Path,
    data_roots: &[PathBuf],
    report: &mut SeedReport,
) {
    let pairs = match list_backup(dir) {
        Ok(p) => p,
        Err(e) => {
            report.torrents_failed.push(format!("{e:#}"));
            return;
        }
    };
    for (torrent, resume) in pairs {
        let name = torrent
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (data, info) = match prepare_upload(&torrent, &resume, data_roots) {
            Ok(v) => v,
            Err(e) => {
                report.torrents_skipped.push(format!("{name}: {e:#}"));
                continue;
            }
        };
        let upload = TorrentUpload {
            file_name: &name,
            data: &data,
            save_path: info.save_path.as_deref().unwrap_or_default(),
            category: info.category.as_deref(),
            content_layout: info.content_layout,
            stopped: info.stopped,
        };
        match api.add_torrent(&upload).await {
            Ok(()) => report.torrents_added += 1,
            Err(e) => report.torrents_failed.push(format!("{name}: {e:#}")),
        }
    }
}

/// Logs the outcome of phase 2 in one block.
pub fn log_report(report: &SeedReport) {
    let mut s = format!("qBittorrent import finished: {}", report.summary());
    for e in &report.category_errors {
        let _ = write!(s, "\n  category error: {e}");
    }
    for e in report.torrents_skipped.iter().take(50) {
        let _ = write!(s, "\n  skipped: {e}");
    }
    for e in report.torrents_failed.iter().take(50) {
        let _ = write!(s, "\n  failed: {e}");
    }
    let hidden = report.torrents_skipped.len().saturating_sub(50)
        + report.torrents_failed.len().saturating_sub(50);
    if hidden > 0 {
        let _ = write!(
            s,
            "\n  ... and {hidden} more (see /config/{TORRENTS_MARKER})"
        );
    }
    if report.category_errors.is_empty()
        && report.torrents_skipped.is_empty()
        && report.torrents_failed.is_empty()
    {
        info!("{s}");
    } else {
        warn!("{s}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rbittorrent-migration-{}-{tag}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn qbittorrent_conf_new_and_old_keys() {
        let conf = parse_qbittorrent_conf(
            "[BitTorrent]\n\
             Session\\DefaultSavePath=/share/qBittorrent/\n\
             Session\\TempPath=/share/qBittorrent/temp/\n\
             Session\\TempPathEnabled=true\n\
             [Preferences]\n\
             Downloads\\SavePath=/old/\n\
             WebUI\\Username=homer\n\
             WebUI\\Password_PBKDF2=\"@ByteArray(abc:def)\"\n\
             WebUI\\Port=8081\n",
        );
        assert_eq!(
            conf,
            LegacyConf {
                save_path: Some("/share/qBittorrent".into()),
                temp_path: Some("/share/qBittorrent/temp".into()),
                temp_enabled: true,
                username: Some("homer".into()),
                webui_port: Some(8081),
            }
        );
        let old = parse_qbittorrent_conf(
            "[Preferences]\r\nDownloads\\SavePath=\"/media/My Disk/\"\r\nDownloads\\TempPathEnabled=false\r\n",
        );
        assert_eq!(old.save_path.as_deref(), Some("/media/My Disk"));
        assert!(!old.temp_enabled);
        assert!(old.username.is_none());
    }

    #[test]
    fn categories_both_formats() {
        let new = parse_categories(
            r#"{"tv-sonarr":{"save_path":"/share/tv/"},"radarr":{"save_path":""},
                "lidarr":{"save_path":"music"},"/bad":{"save_path":"/x"}}"#,
            Some("/share/qBittorrent"),
        )
        .unwrap();
        assert_eq!(new.len(), 3);
        assert_eq!(new["tv-sonarr"].as_deref(), Some("/share/tv"));
        assert_eq!(new["radarr"], None);
        assert_eq!(new["lidarr"].as_deref(), Some("/share/qBittorrent/music"));
        let old = parse_categories(r#"{"books":"/media/books","x":""}"#, None).unwrap();
        assert_eq!(old["books"].as_deref(), Some("/media/books"));
        assert_eq!(old["x"], None);
        assert!(parse_categories("[1]", None).is_err());
        assert!(parse_categories("nope", None).is_err());
    }

    #[test]
    fn fastresume_fields() {
        let r = parse_fastresume(
            b"d12:auto_managedi0e6:pausedi1e12:qBt-category9:tv-sonarr\
              17:qBt-contentLayout11:NoSubfolder9:save_path15:/share/tv/Show/e",
        )
        .unwrap();
        assert_eq!(r.save_path.as_deref(), Some("/share/tv/Show"));
        assert_eq!(r.category.as_deref(), Some("tv-sonarr"));
        assert!(r.stopped);
        assert_eq!(r.content_layout, "NoSubfolder");
        let queued = parse_fastresume(
            b"d12:auto_managedi1e6:pausedi1e17:qBt-hasRootFolderi0e12:qBt-savePath7:/media/e",
        )
        .unwrap();
        assert!(!queued.stopped, "queued (auto-managed) is not stopped");
        assert_eq!(queued.save_path.as_deref(), Some("/media"));
        assert_eq!(queued.content_layout, "NoSubfolder");
        assert_eq!(parse_fastresume(b"de").unwrap().content_layout, "Original");
        assert!(parse_fastresume(b"not bencode").is_err());
    }

    const WG: &str = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
        Address = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1\nPostUp = iptables -A x\n\n[Peer]\n\
        PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0, ::/0\n\
        Endpoint = 190.2.131.156:51820\n";

    fn legacy(base: &Path) -> PathBuf {
        let app = base.join("addon_configs/db21ed7f_qbittorrent");
        std::fs::create_dir_all(app.join("qBittorrent/BT_backup")).unwrap();
        std::fs::create_dir_all(app.join("wireguard")).unwrap();
        std::fs::write(
            app.join("qBittorrent/qBittorrent.conf"),
            "[BitTorrent]\nSession\\DefaultSavePath=/share/qBittorrent/\n\
             [Preferences]\nWebUI\\Username=homer\n",
        )
        .unwrap();
        std::fs::write(
            app.join("qBittorrent/categories.json"),
            r#"{"tv-sonarr":{"save_path":"/share/qBittorrent/tv"},"radarr":{"save_path":""}}"#,
        )
        .unwrap();
        std::fs::write(
            app.join("wireguard/broken.conf"),
            "[Interface]\nPrivateKey = x\n",
        )
        .unwrap();
        std::fs::write(app.join("wireguard/proton.conf"), WG).unwrap();
        app
    }

    fn roots(base: &Path) -> Roots {
        std::fs::create_dir_all(base.join("config")).unwrap();
        std::fs::create_dir_all(base.join("share")).unwrap();
        Roots {
            app_configs: base.join("addon_configs"),
            share: base.join("share"),
            config: base.join("config"),
        }
    }

    #[test]
    fn discovery_finds_profiles_in_all_three_places() {
        let base = tmp("discover");
        let r = roots(&base);
        let app = legacy(&base);
        std::fs::create_dir_all(base.join("addon_configs/a0d7b954_sonarr")).unwrap();
        std::fs::create_dir_all(base.join("addon_configs/12345678_rbittorrent/qBittorrent"))
            .unwrap();
        std::fs::create_dir_all(base.join("share/qBittorrent/qBittorrent")).unwrap();
        std::fs::write(
            base.join("share/qBittorrent/qBittorrent/qBittorrent.conf"),
            "",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("config/qBittorrent")).unwrap(); // empty: ignored
        let found = discover(&r);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert_eq!(found[0].slug.as_deref(), Some("db21ed7f_qbittorrent"));
        assert_eq!(
            found[0].conf,
            Some(app.join("qBittorrent/qBittorrent.conf"))
        );
        assert_eq!(found[0].bt_backup, Some(app.join("qBittorrent/BT_backup")));
        assert_eq!(found[0].wireguard.len(), 2);
        assert_eq!(found[1].root, base.join("share/qBittorrent"));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn first_start_takes_over_wireguard_paths_user_and_categories() {
        let base = tmp("prepare");
        let r = roots(&base);
        legacy(&base);
        let mut o = Options {
            import_active_torrents: true,
            ..Options::default()
        };
        let m = prepare(&mut o, &r);
        assert!(m.fresh && m.has_work());
        let wg0 = base.join("config/wg0.conf");
        assert_eq!(
            std::fs::read_to_string(&wg0).unwrap(),
            WG,
            "the complete file wins"
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&wg0).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(o.completed_dir, "/share/qBittorrent");
        assert_eq!(o.download_dir, "/share/qBittorrent/incomplete");
        assert_eq!(o.webui_username, "homer");
        let rec = m.record.clone().unwrap();
        assert_eq!(rec.categories.len(), 2);
        assert!(
            m.torrents_from
                .as_ref()
                .unwrap()
                .ends_with("qBittorrent/BT_backup")
        );
        assert!(
            m.status.contains("WireGuard") && m.status.contains("2 categories"),
            "{}",
            m.status
        );
        // Not marked until phase 2 ran.
        assert!(!base.join("config/.migrated").exists());

        // Next start with the record on disk: applied again, no rescan.
        std::fs::write(
            base.join("config/.migrated"),
            serde_json::to_string(&rec).unwrap(),
        )
        .unwrap();
        let mut o2 = Options::default();
        let m2 = prepare(&mut o2, &r);
        assert!(!m2.fresh && m2.torrents_from.is_none());
        assert_eq!(o2.completed_dir, "/share/qBittorrent");
        assert!(m2.status.starts_with("done earlier"));
        // Turning on the torrent import later still works.
        let mut o3 = Options {
            import_active_torrents: true,
            ..Options::default()
        };
        assert!(prepare(&mut o3, &r).torrents_from.is_some());
        std::fs::write(base.join("config/.torrents_migrated"), "{}").unwrap();
        assert!(prepare(&mut o3, &r).torrents_from.is_none());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn user_settings_always_win() {
        let base = tmp("userwins");
        let r = roots(&base);
        legacy(&base);
        let mut o = Options {
            wireguard_conf: Some(WG.into()),
            download_dir: "/media/dl".into(),
            completed_dir: "/media/done".into(),
            webui_username: "marge".into(),
            ..Options::default()
        };
        let m = prepare(&mut o, &r);
        assert!(
            !base.join("config/wg0.conf").exists(),
            "own WireGuard options: no copy"
        );
        assert_eq!(
            (
                o.download_dir.as_str(),
                o.completed_dir.as_str(),
                o.webui_username.as_str()
            ),
            ("/media/dl", "/media/done", "marge")
        );
        assert!(
            m.torrents_from.is_none(),
            "import_active_torrents defaults to off"
        );
        // An existing wg0.conf is never overwritten either.
        std::fs::write(base.join("config/wg0.conf"), "mine").unwrap();
        let mut o = Options::default();
        prepare(&mut o, &r);
        assert_eq!(
            std::fs::read_to_string(base.join("config/wg0.conf")).unwrap(),
            "mine"
        );
        // Switched off: nothing happens at all.
        let mut o = Options {
            import_from_qbittorrent: false,
            ..Options::default()
        };
        let m = prepare(&mut o, &r);
        assert!(!m.has_work() && m.status.starts_with("off"));
        assert_eq!(o.webui_username, "admin");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn unusable_save_paths_are_not_taken_over() {
        let (rec, notes) = build_record(
            &[LegacyInstall {
                root: "/nonexistent".into(),
                ..LegacyInstall::default()
            }],
            1,
        );
        assert!(rec.completed_dir.is_none() && notes.is_empty());
        let base = tmp("badpath");
        std::fs::write(
            base.join("qBittorrent.conf"),
            "[BitTorrent]\nSession\\DefaultSavePath=/downloads/\n[Preferences]\nWebUI\\Port=8081\n",
        )
        .unwrap();
        let install = scan(&base, None);
        let (rec, notes) = build_record(&[install], 1);
        assert!(rec.completed_dir.is_none());
        assert!(
            notes.iter().any(|n| n.contains("/downloads is outside")),
            "{notes:?}"
        );
        assert!(notes.iter().any(|n| n.contains("port 8081")), "{notes:?}");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn backup_entries_are_checked_before_upload() {
        let base = tmp("backup");
        let save = base.join("data");
        std::fs::create_dir_all(&save).unwrap();
        let t = base.join("aa.torrent");
        std::fs::write(&t, b"d4:infod4:name1:xee").unwrap();
        // No .fastresume.
        assert!(
            prepare_upload(&t, &t.with_extension("fastresume"), &default_data_roots()).is_err()
        );
        // Save path outside the app's folders.
        let resume = |p: &str| format!("d9:save_path{}:{p}e", p.len()).into_bytes();
        std::fs::write(
            t.with_extension("fastresume"),
            resume(&save.display().to_string()),
        )
        .unwrap();
        let err =
            prepare_upload(&t, &t.with_extension("fastresume"), &default_data_roots()).unwrap_err();
        assert!(err.to_string().contains("outside"), "{err}");
        std::fs::write(
            t.with_extension("fastresume"),
            resume("/share/definitely-missing"),
        )
        .unwrap();
        let err =
            prepare_upload(&t, &t.with_extension("fastresume"), &default_data_roots()).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
        assert_eq!(list_backup(&base).unwrap().len(), 1);
        // Inside an allowed root and present: accepted.
        std::fs::write(
            t.with_extension("fastresume"),
            resume(&save.display().to_string()),
        )
        .unwrap();
        let (data, info) = prepare_upload(
            &t,
            &t.with_extension("fastresume"),
            std::slice::from_ref(&base),
        )
        .unwrap();
        assert_eq!(data, b"d4:infod4:name1:xee");
        assert_eq!(info.content_layout, "Original");
        assert!(!path_allowed("/share/../etc", &default_data_roots()));
        assert!(!path_allowed("/share", &default_data_roots()));
        assert!(path_allowed("/share/tv", &default_data_roots()));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn report_summary() {
        let r = SeedReport {
            categories_created: 2,
            categories_existing: 1,
            torrents_added: 3,
            torrents_skipped: vec!["a".into()],
            ..SeedReport::default()
        };
        assert_eq!(
            r.summary(),
            "3 categories (2 new), 3/4 torrents re-added (verifying existing files)"
        );
        assert_eq!(SeedReport::default().summary(), "nothing to seed");
    }
}
