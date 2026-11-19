//! Host facts for the logs: free disk space, CPU cores, UDP buffer limits,
//! and the startup/port-rotation status banner.

use std::fmt::Write as _;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use tracing::{debug, error, info};

/// Below this much free space on the download folder, the log shouts.
pub const LOW_DISK_BYTES: u64 = 1 << 30;

/// Socket buffer limit that lets rtbit's uTP socket and the kernel
/// WireGuard socket absorb multi-gigabit bursts (quic-go/WireGuard guidance).
pub const UDP_BUFFER_TARGET: u64 = 7 * 1024 * 1024;

/// Bytes available to unprivileged writers on the filesystem holding `path`.
pub fn available_bytes(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: statvfs writes into a zeroed, properly sized struct.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string and out-pointer.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::useless_conversion)] // the field widths differ per target
    let bytes = u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize));
    Ok(bytes)
}

/// CPUs this container may use (cgroup quota and affinity aware).
pub fn cpu_cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// `1536` -> `1.5 KiB`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {name}")
    }
}

/// Free space on the download folder for the banner ("412.3 GiB free").
pub fn storage_summary(path: &Path) -> String {
    match available_bytes(path) {
        Ok(b) => format!("{} free on {}", format_bytes(b), path.display()),
        Err(e) => format!("unknown for {} ({e})", path.display()),
    }
}

/// Logs a loud banner when the download folder is nearly full. Returns
/// whether space is low.
pub fn warn_if_low_disk(path: &Path) -> bool {
    match available_bytes(path) {
        Ok(b) if b < LOW_DISK_BYTES => {
            error!(
                "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                 !! LOW DISK SPACE: only {} free on {}\n\
                 !! If downloads should go to a USB/SSD or network disk, check that it\n\
                 !! is still mounted: otherwise they now fill Home Assistant's own disk\n\
                 !! (on a Raspberry Pi usually the SD card). Free space or fix the mount.\n\
                 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                format_bytes(b),
                path.display()
            );
            true
        }
        Ok(_) => false,
        Err(e) => {
            debug!("cannot check free space on {}: {e}", path.display());
            false
        }
    }
}

/// How the BitTorrent port is reachable, for the banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Forwarded(u16),
    /// VPN without NAT-PMP: this port is opened on wg0.
    Static(u16),
    /// No VPN: rtbit listens on this port of the normal connection.
    Direct(u16),
    /// NAT-PMP is enabled but has no lease yet; rtbit uses the fallback port.
    Pending(u16),
}

/// The status box, logged at startup and on port rotation.
pub fn status_banner(
    public_ip: Option<Ipv4Addr>,
    port: PortState,
    migration: &str,
    cores: usize,
    storage: &str,
) -> String {
    let ip = match (port, public_ip) {
        (PortState::Direct(_), _) => {
            "VPN OFF: direct connection, your own IP is visible".to_owned()
        }
        (_, Some(ip)) => format!("{ip} (verified through the tunnel via NAT-PMP)"),
        (_, None) => "not verified (NAT-PMP disabled or not answering)".to_owned(),
    };
    let port = match port {
        PortState::Forwarded(p) => format!("{p} TCP+UDP (NAT-PMP, peers can connect)"),
        PortState::Static(p) => format!("{p} TCP+UDP (static, opened on wg0; NAT-PMP off)"),
        PortState::Direct(p) => {
            format!("{p} (direct; map it in the Network section for inbound peers)")
        }
        PortState::Pending(p) => {
            format!("none yet (NAT-PMP retrying; rtbit listens on {p}, inbound peers blocked)")
        }
    };
    let mut s =
        String::from("\n+------------------------- rBittorrent -------------------------+\n");
    let _ = writeln!(s, "| VPN public IP   {ip}");
    let _ = writeln!(s, "| Forwarded port  {port}");
    let _ = writeln!(s, "| qBittorrent     {migration}");
    let _ = writeln!(s, "| CPU cores       {cores} (all available to rtbit)");
    let _ = writeln!(s, "| Storage         {storage}");
    s.push_str("+---------------------------------------------------------------+");
    s
}

/// The warning logged at every start without the VPN.
pub fn direct_mode_banner(listen_port: u16) -> String {
    let rule = "!".repeat(72);
    format!(
        "\n{rule}\n\
         !! VPN OFF: rBittorrent uses your normal internet connection.\n\
         !! Peers and trackers see your real IP address, and no kill-switch\n\
         !! protects you. rtbit listens on port {listen_port}.\n\
         !! To use Proton VPN, put its WireGuard file in /config/wg0.conf, paste\n\
         !! it into `wireguard_conf` or fill the `wg_*` fields, and restart:\n\
         !! the VPN then turns on by itself (fail-closed, no fallback).\n\
         {rule}"
    )
}

/// Best effort: raise `net.core.{r,w}mem_max` so large UDP buffers are
/// possible. Containers normally mount /proc/sys read-only, and these limits
/// are host-wide, so failure is expected and only logged. Never lowers them.
pub fn raise_udp_buffer_limits() {
    let mut report = Vec::new();
    for name in ["rmem_max", "wmem_max"] {
        let path = Path::new("/proc/sys/net/core").join(name);
        let current = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        match current {
            Some(c) if c >= UDP_BUFFER_TARGET => report.push(format!("{name}={c}")),
            Some(c) => match std::fs::write(&path, UDP_BUFFER_TARGET.to_string()) {
                Ok(()) => report.push(format!("{name}={c}->{UDP_BUFFER_TARGET}")),
                Err(e) => {
                    debug!("cannot raise net.core.{name}: {e}");
                    report.push(format!("{name}={c} (read-only here)"));
                }
            },
            None => report.push(format!("{name}=n/a")),
        }
    }
    info!("UDP socket buffer limits: {}", report.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_human_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(LOW_DISK_BYTES), "1.0 GiB");
        assert_eq!(format_bytes(412 * (1 << 30) + (1 << 29)), "412.5 GiB");
    }

    #[test]
    fn free_space_of_a_real_directory() {
        let b = available_bytes(Path::new("/")).unwrap();
        assert!(b > 0);
        assert!(available_bytes(Path::new("/definitely/not/here")).is_err());
        assert!(storage_summary(Path::new("/")).contains("free on /"));
        assert!(cpu_cores() >= 1);
    }

    #[test]
    fn banner_has_the_five_facts() {
        let b = status_banner(
            Some(Ipv4Addr::new(185, 159, 156, 1)),
            PortState::Forwarded(45678),
            "from db21ed7f_qbittorrent: WireGuard, 3 categories",
            4,
            "412.3 GiB free on /media/rbittorrent/downloads",
        );
        let lines: Vec<&str> = b.lines().filter(|l| l.starts_with("| ")).collect();
        assert_eq!(lines.len(), 5, "{b}");
        assert!(lines[0].contains("185.159.156.1"));
        assert!(lines[1].contains("45678 TCP+UDP"));
        assert!(lines[2].contains("3 categories"));
        assert!(lines[3].contains("4 (all available"));
        assert!(lines[4].contains("412.3 GiB"));
        let b = status_banner(None, PortState::Pending(4240), "off", 1, "x");
        assert!(b.contains("not verified") && b.contains("none yet"));
        assert!(
            status_banner(None, PortState::Static(4240), "off", 1, "x")
                .contains("4240 TCP+UDP (static, opened on wg0")
        );
        let d = status_banner(None, PortState::Direct(4240), "off", 1, "x");
        assert!(d.contains("VPN OFF") && d.contains("4240 (direct"), "{d}");
    }

    #[test]
    fn direct_mode_banner_is_loud_and_explains_the_fix() {
        let b = direct_mode_banner(4240);
        assert!(b.contains("VPN OFF") && b.contains("real IP address"));
        assert!(b.contains("port 4240") && b.contains("/config/wg0.conf"));
        assert!(b.lines().filter(|l| l.starts_with("!!")).count() >= 6);
    }
}
