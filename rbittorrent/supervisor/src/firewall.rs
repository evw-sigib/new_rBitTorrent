//! Fail-closed nftables kill-switch, loaded atomically with `nft -f -`.
//!
//! The ruleset is rendered as text (pure, unit-tested) and piped to `nft` on
//! stdin, so the whole table is replaced in one kernel transaction: there is
//! never a moment with a half-written firewall.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result, bail};

use crate::cidr::Ipv4Cidr;
use crate::exec::Runner;

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "killswitch";
pub const BT_PORT_SET: &str = "bt_port";
pub const LAN_SET: &str = "lan_cidrs";
/// The two TCP ports that may answer on the uplink: Web UI/API + Ingress.
pub const UI_PORT_SET: &str = "ui_ports";

/// Everything the ruleset depends on.
#[derive(Debug, Clone)]
pub struct RulesetSpec {
    /// Container uplink towards Home Assistant / the LAN (default route device).
    pub lan_iface: String,
    /// The WireGuard interface.
    pub wg_iface: String,
    /// LAN ranges allowed to reach the Web UI/API (already collapsed).
    pub lan_cidrs: Vec<Ipv4Cidr>,
    /// rtbit Web UI/API port (8080).
    pub webui_port: u16,
    /// Ingress reverse-proxy port (8099), reachable only from `ingress_sources`.
    pub ingress_port: u16,
    /// Home Assistant's internal network (Supervisor = Ingress).
    pub ingress_sources: Ipv4Cidr,
    /// Resolved WireGuard server.
    pub endpoint: SocketAddrV4,
    /// fwmark the kernel WireGuard device puts on its encrypted UDP packets.
    pub wg_fwmark: u32,
    /// Initially open BitTorrent ports (normally empty until NAT-PMP answers).
    pub bt_ports: Vec<u16>,
    /// The tunnel's DNS servers: the only destinations for port 53.
    pub dns_servers: Vec<Ipv4Addr>,
}

/// Linux interface names: 1-15 bytes, no whitespace, quotes or `/`.
/// Anything else is refused so nothing can be injected into the ruleset.
pub fn valid_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
}

fn port_elements(ports: &[u16]) -> String {
    let mut ports: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders the complete kill-switch table.
///
/// `add table` + `delete table` + full definition is the atomic "replace"
/// idiom: within one transaction the old table (if any) disappears and the new
/// one appears, chains, sets, elements and all.
pub fn render_ruleset(spec: &RulesetSpec) -> Result<String> {
    for name in [&spec.lan_iface, &spec.wg_iface] {
        if !valid_iface_name(name) {
            bail!("refusing to use interface name {name:?} in the firewall");
        }
    }
    if spec.lan_iface == spec.wg_iface {
        bail!("LAN and WireGuard interfaces must differ");
    }
    if spec.webui_port == 0 || spec.ingress_port == 0 || spec.endpoint.port() == 0 {
        bail!("firewall ports must be non-zero");
    }
    if spec.webui_port == spec.ingress_port {
        bail!("the Web UI and Ingress ports must differ");
    }
    let lan = &spec.lan_iface;
    let wg = &spec.wg_iface;
    let webui = spec.webui_port;
    let ingress = spec.ingress_port;
    let ingress_src = spec.ingress_sources.network();
    let ep_ip = spec.endpoint.ip();
    let ep_port = spec.endpoint.port();
    let mark = spec.wg_fwmark;
    // Interval sets reject overlapping elements ("conflicting intervals"),
    // so normalise here too, even though Settings already does.
    // Ingress replies go to the same set, so Home Assistant's network is
    // always part of it.
    let mut lan_cidrs = spec.lan_cidrs.clone();
    lan_cidrs.push(ingress_src);
    let lan_elems = crate::cidr::collapse(&lan_cidrs)
        .iter()
        .map(|c| c.network().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let bt_elems = port_elements(&spec.bt_ports);
    let mut dns = spec.dns_servers.clone();
    dns.sort_unstable();
    dns.dedup();
    // `ip daddr != { }` is invalid, so no DNS server means no DNS at all.
    let dns_match = if dns.is_empty() {
        String::new()
    } else {
        let list = dns.iter().map(Ipv4Addr::to_string).collect::<Vec<_>>();
        format!(" ip daddr != {{ {} }}", list.join(", "))
    };

    let mut s = String::with_capacity(4096);
    // `write!` into a String cannot fail; results are discarded explicitly.
    let _ = writeln!(s, "#!/usr/sbin/nft -f");
    let _ = writeln!(
        s,
        "# rbittorrent fail-closed kill-switch (generated, do not edit)"
    );
    let _ = writeln!(s, "add table {TABLE_FAMILY} {TABLE_NAME}");
    let _ = writeln!(s, "delete table {TABLE_FAMILY} {TABLE_NAME}");
    let _ = writeln!(s, "table {TABLE_FAMILY} {TABLE_NAME} {{");

    let _ = writeln!(s, "\tset {BT_PORT_SET} {{");
    let _ = writeln!(s, "\t\ttype inet_service");
    if !bt_elems.is_empty() {
        let _ = writeln!(s, "\t\telements = {{ {bt_elems} }}");
    }
    let _ = writeln!(s, "\t}}");

    let _ = writeln!(s, "\tset {UI_PORT_SET} {{");
    let _ = writeln!(s, "\t\ttype inet_service");
    let _ = writeln!(
        s,
        "\t\telements = {{ {} }}",
        port_elements(&[webui, ingress])
    );
    let _ = writeln!(s, "\t}}");

    let _ = writeln!(s, "\tset {LAN_SET} {{");
    let _ = writeln!(s, "\t\ttype ipv4_addr");
    let _ = writeln!(s, "\t\tflags interval");
    if !lan_elems.is_empty() {
        let _ = writeln!(s, "\t\telements = {{ {lan_elems} }}");
    }
    let _ = writeln!(s, "\t}}");

    // --- input -----------------------------------------------------------
    let _ = writeln!(s, "\tchain input {{");
    let _ = writeln!(
        s,
        "\t\ttype filter hook input priority filter; policy drop;"
    );
    let _ = writeln!(s, "\t\tiifname \"lo\" accept");
    let _ = writeln!(
        s,
        "\t\tmeta nfproto ipv6 counter drop comment \"no IPv6, ever\""
    );
    let _ = writeln!(s, "\t\tct state invalid counter drop");
    let _ = writeln!(s, "\t\tct state established,related accept");
    let _ = writeln!(
        s,
        "\t\tiifname \"{lan}\" ip saddr {ingress_src} tcp dport {ingress} accept comment \"Home Assistant Ingress proxy only\""
    );
    let _ = writeln!(
        s,
        "\t\tiifname \"{lan}\" ip saddr @{LAN_SET} tcp dport {webui} accept comment \"Web UI/API from LAN + Home Assistant\""
    );
    let _ = writeln!(
        s,
        "\t\tiifname \"{wg}\" tcp dport @{BT_PORT_SET} accept comment \"forwarded BitTorrent port (TCP)\""
    );
    let _ = writeln!(
        s,
        "\t\tiifname \"{wg}\" udp dport @{BT_PORT_SET} accept comment \"forwarded BitTorrent port (UDP)\""
    );
    let _ = writeln!(s, "\t\tcounter comment \"input: dropped by policy\"");
    let _ = writeln!(s, "\t}}");

    // --- forward ---------------------------------------------------------
    let _ = writeln!(s, "\tchain forward {{");
    let _ = writeln!(
        s,
        "\t\ttype filter hook forward priority filter; policy drop;"
    );
    let _ = writeln!(
        s,
        "\t\tmeta nfproto ipv6 counter drop comment \"no IPv6, ever\""
    );
    let _ = writeln!(s, "\t\tcounter comment \"forward: dropped by policy\"");
    let _ = writeln!(s, "\t}}");

    // --- output ----------------------------------------------------------
    let _ = writeln!(s, "\tchain output {{");
    let _ = writeln!(
        s,
        "\t\ttype filter hook output priority filter; policy drop;"
    );
    let _ = writeln!(s, "\t\toifname \"lo\" accept");
    let _ = writeln!(
        s,
        "\t\tmeta nfproto ipv6 counter drop comment \"no IPv6, ever\""
    );
    // Replies of Web UI/API connections only. rtbit can never *open* a
    // connection to the LAN or the router (no DHT/LSD/peer/UPnP leaks).
    let _ = writeln!(
        s,
        "\t\toifname \"{lan}\" ip daddr @{LAN_SET} tcp sport @{UI_PORT_SET} ct state established,related accept comment \"Web UI/API + Ingress replies only\""
    );
    let _ = writeln!(
        s,
        "\t\toifname \"{lan}\" ip daddr @{LAN_SET} icmp type destination-unreachable icmp code frag-needed ct state related accept comment \"PMTU for Web UI/API\""
    );
    // Only the kernel WireGuard device marks packets with its fwmark, so this
    // hole is unusable for anything but the encrypted envelope.
    let _ = writeln!(
        s,
        "\t\toifname != \"{wg}\" meta mark {mark:#010x} ip daddr {ep_ip} udp dport {ep_port} accept comment \"WireGuard envelope\""
    );
    let _ = writeln!(
        s,
        "\t\toifname \"{wg}\" meta l4proto {{ tcp, udp }} th dport 53{dns_match} counter drop comment \"DNS only to the tunnel's DNS servers\""
    );
    let _ = writeln!(
        s,
        "\t\toifname \"{wg}\" accept comment \"everything else: tunnel only\""
    );
    let _ = writeln!(s, "\t\tcounter comment \"output: dropped by policy\"");
    let _ = writeln!(s, "\t}}");

    let _ = writeln!(s, "}}");
    Ok(s)
}

/// Atomically replaces the contents of the `bt_port` set.
pub fn render_bt_port_update(ports: &[u16]) -> String {
    let elems = port_elements(ports);
    let mut s = format!("flush set {TABLE_FAMILY} {TABLE_NAME} {BT_PORT_SET}\n");
    if !elems.is_empty() {
        let _ = writeln!(
            s,
            "add element {TABLE_FAMILY} {TABLE_NAME} {BT_PORT_SET} {{ {elems} }}"
        );
    }
    s
}

/// Loads an nft script in a single transaction.
pub async fn apply_script(runner: &impl Runner, script: &str) -> Result<()> {
    runner
        .run("nft", &["-f", "-"], Some(script.as_bytes()))
        .await
        .map(|_| ())
}

/// Installs the kill-switch, then reads it back to make sure the kernel has it.
pub async fn install(runner: &impl Runner, spec: &RulesetSpec) -> Result<()> {
    let script = render_ruleset(spec)?;
    apply_script(runner, &script)
        .await
        .context("cannot load the nftables kill-switch (does the app have NET_ADMIN?)")?;
    let listing = runner
        .run("nft", &["list", "table", TABLE_FAMILY, TABLE_NAME], None)
        .await
        .context("cannot read back the nftables kill-switch")?;
    verify_listing(&listing.stdout)
}

/// Fail-closed check on `nft list table` output: the table is there and each
/// of the input, forward and output hooks has `policy drop`. Empty or
/// unexpected output is an error, never a pass.
pub fn verify_listing(listing: &str) -> Result<()> {
    let header = format!("table {TABLE_FAMILY} {TABLE_NAME}");
    if !listing.contains(&header) {
        bail!("kill-switch verification failed: `nft list table` did not show `{header}`");
    }
    for hook in ["input", "forward", "output"] {
        let needle = format!("hook {hook} ");
        let dropped = listing
            .lines()
            .any(|l| l.contains(&needle) && l.contains("policy drop"));
        if !dropped {
            bail!("kill-switch verification failed: no `{hook}` chain with policy drop");
        }
    }
    Ok(())
}

/// Opens exactly `ports` for inbound BitTorrent traffic on the tunnel.
pub async fn set_bt_ports(runner: &impl Runner, ports: &[u16]) -> Result<()> {
    apply_script(runner, &render_bt_port_update(ports))
        .await
        .context("cannot update the forwarded-port firewall set")
}

// ---------------------------------------------------------------------------
// Direct connection (VPN off)
// ---------------------------------------------------------------------------

/// The direct-mode table: no kill-switch, but the Web UI and Ingress ports
/// keep the access rules the app promises, and the published BitTorrent port
/// reaches rtbit whatever `listen_port` is.
pub const DIRECT_TABLE: &str = "direct";

#[derive(Debug, Clone)]
pub struct DirectSpec {
    /// LAN ranges allowed to reach the Web UI/API (`local_allow_cidrs`).
    pub lan_cidrs: Vec<Ipv4Cidr>,
    pub webui_port: u16,
    pub ingress_port: u16,
    /// Home Assistant's internal network (Ingress, the watchdog).
    pub ingress_sources: Ipv4Cidr,
    /// The container port Home Assistant publishes for BitTorrent (4240).
    pub published_bt_port: u16,
    /// The port rtbit listens on (`listen_port`).
    pub listen_port: u16,
}

/// Renders the direct-mode table. Only the Web UI and Ingress ports are
/// filtered (input policy stays accept); when `listen_port` differs from
/// the published port, TCP and UDP to the published port are redirected to
/// it, so `host:<mapped> -> container:4240` still lands on rtbit.
pub fn render_direct_ruleset(spec: &DirectSpec) -> Result<String> {
    let ports = [
        spec.webui_port,
        spec.ingress_port,
        spec.published_bt_port,
        spec.listen_port,
    ];
    if ports.contains(&0) {
        bail!("firewall ports must be non-zero");
    }
    if spec.webui_port == spec.ingress_port {
        bail!("the Web UI and Ingress ports must differ");
    }
    if [spec.webui_port, spec.ingress_port].contains(&spec.listen_port) {
        bail!("listen_port must differ from the Web UI and Ingress ports");
    }
    let webui = spec.webui_port;
    let ingress = spec.ingress_port;
    let ingress_src = spec.ingress_sources.network();
    let mut lan_cidrs = spec.lan_cidrs.clone();
    lan_cidrs.push(ingress_src);
    let lan_elems = crate::cidr::collapse(&lan_cidrs)
        .iter()
        .map(|c| c.network().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut s = String::with_capacity(1024);
    let _ = writeln!(s, "#!/usr/sbin/nft -f");
    let _ = writeln!(
        s,
        "# rbittorrent direct connection: port access rules (generated, do not edit)"
    );
    let _ = writeln!(s, "add table {TABLE_FAMILY} {DIRECT_TABLE}");
    let _ = writeln!(s, "delete table {TABLE_FAMILY} {DIRECT_TABLE}");
    let _ = writeln!(s, "table {TABLE_FAMILY} {DIRECT_TABLE} {{");
    let _ = writeln!(s, "\tset {LAN_SET} {{");
    let _ = writeln!(s, "\t\ttype ipv4_addr");
    let _ = writeln!(s, "\t\tflags interval");
    let _ = writeln!(s, "\t\telements = {{ {lan_elems} }}");
    let _ = writeln!(s, "\t}}");
    if spec.listen_port != spec.published_bt_port {
        let from = spec.published_bt_port;
        let to = spec.listen_port;
        let _ = writeln!(s, "\tchain prerouting {{");
        let _ = writeln!(
            s,
            "\t\ttype nat hook prerouting priority dstnat; policy accept;"
        );
        let _ = writeln!(s, "\t\ttcp dport {from} redirect to :{to}");
        let _ = writeln!(s, "\t\tudp dport {from} redirect to :{to}");
        let _ = writeln!(s, "\t}}");
    }
    let _ = writeln!(s, "\tchain input {{");
    let _ = writeln!(
        s,
        "\t\ttype filter hook input priority filter; policy accept;"
    );
    let _ = writeln!(s, "\t\tiifname \"lo\" accept");
    let _ = writeln!(s, "\t\t{DIRECT_NO_IPV6}");
    let _ = writeln!(s, "\t\ttcp dport {ingress} ip saddr {ingress_src} accept");
    let _ = writeln!(s, "\t\ttcp dport {webui} ip saddr @{LAN_SET} accept");
    let _ = writeln!(s, "\t\ttcp dport {{ {webui}, {ingress} }} drop");
    let _ = writeln!(s, "\t}}");
    // IPv6 is dropped on every hook, as with the VPN on: the app is
    // IPv4-only, and the docs promise that no IPv6 leaves it.
    for (chain, iface) in [("forward", "iifname"), ("output", "oifname")] {
        let _ = writeln!(s, "\tchain {chain} {{");
        let _ = writeln!(
            s,
            "\t\ttype filter hook {chain} priority filter; policy accept;"
        );
        if chain == "output" {
            let _ = writeln!(s, "\t\t{iface} \"lo\" accept");
        }
        let _ = writeln!(s, "\t\t{DIRECT_NO_IPV6}");
        let _ = writeln!(s, "\t}}");
    }
    let _ = writeln!(s, "}}");
    Ok(s)
}

/// The direct-mode IPv6 drop rule (after loopback).
const DIRECT_NO_IPV6: &str = "meta nfproto ipv6 counter drop comment \"no IPv6\"";

/// Installs the direct-mode table and reads it back.
pub async fn install_direct(runner: &impl Runner, spec: &DirectSpec) -> Result<()> {
    let script = render_direct_ruleset(spec)?;
    apply_script(runner, &script)
        .await
        .context("cannot load the direct-mode port rules (does the app have NET_ADMIN?)")?;
    let listing = runner
        .run("nft", &["list", "table", TABLE_FAMILY, DIRECT_TABLE], None)
        .await
        .context("cannot read back the direct-mode port rules")?;
    verify_direct_listing(&listing.stdout, spec)
}

/// Fail-closed check: the table, its input hook and the drop rule for the
/// Web UI and Ingress ports are there.
pub fn verify_direct_listing(listing: &str, spec: &DirectSpec) -> Result<()> {
    let header = format!("table {TABLE_FAMILY} {DIRECT_TABLE}");
    if !listing.contains(&header) {
        bail!("direct-mode rules missing: `nft list table` did not show `{header}`");
    }
    let has_input = listing.lines().any(|l| l.contains("hook input "));
    let drops = listing.lines().any(|l| {
        l.contains("drop")
            && l.contains(&spec.webui_port.to_string())
            && l.contains(&spec.ingress_port.to_string())
    });
    if !has_input || !drops {
        bail!("direct-mode rules incomplete: no input rule dropping the Web UI and Ingress ports");
    }
    let ipv6_drops = listing
        .lines()
        .filter(|l| l.contains("meta nfproto ipv6") && l.contains("drop"))
        .count();
    if ipv6_drops < 3 {
        bail!(
            "direct-mode rules incomplete: IPv6 is not dropped on input, forward and output \
             ({ipv6_drops} of 3 rules)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::fake::FakeRunner;
    use std::net::Ipv4Addr;

    fn direct_spec(listen_port: u16) -> DirectSpec {
        DirectSpec {
            lan_cidrs: vec!["192.168.0.0/16".parse().unwrap()],
            webui_port: 8080,
            ingress_port: 8099,
            ingress_sources: "172.30.32.0/23".parse().unwrap(),
            published_bt_port: 4240,
            listen_port,
        }
    }

    #[test]
    fn direct_mode_filters_the_ui_ports_and_redirects_the_published_port() {
        let r = render_direct_ruleset(&direct_spec(51413)).unwrap();
        assert!(
            r.contains("add table inet direct\ndelete table inet direct\n"),
            "{r}"
        );
        assert!(
            r.contains("elements = { 172.30.32.0/23, 192.168.0.0/16 }"),
            "{r}"
        );
        let pre = chain(&r, "prerouting");
        assert_eq!(
            pre,
            vec![
                "type nat hook prerouting priority dstnat; policy accept;",
                "tcp dport 4240 redirect to :51413",
                "udp dport 4240 redirect to :51413",
            ]
        );
        let input = chain(&r, "input");
        assert_eq!(
            input,
            vec![
                "type filter hook input priority filter; policy accept;",
                "iifname \"lo\" accept",
                DIRECT_NO_IPV6,
                "tcp dport 8099 ip saddr 172.30.32.0/23 accept",
                "tcp dport 8080 ip saddr @lan_cidrs accept",
                "tcp dport { 8080, 8099 } drop",
            ]
        );
        assert_eq!(
            chain(&r, "output"),
            vec![
                "type filter hook output priority filter; policy accept;",
                "oifname \"lo\" accept",
                DIRECT_NO_IPV6,
            ]
        );
        assert_eq!(
            chain(&r, "forward"),
            vec![
                "type filter hook forward priority filter; policy accept;",
                DIRECT_NO_IPV6,
            ]
        );
        // Same port: no NAT chain at all.
        let same = render_direct_ruleset(&direct_spec(4240)).unwrap();
        assert!(!same.contains("prerouting"), "{same}");
        // Nonsense is refused.
        assert!(render_direct_ruleset(&direct_spec(8080)).is_err());
        assert!(render_direct_ruleset(&direct_spec(0)).is_err());
    }

    /// `nft list table inet direct` of a complete direct-mode table.
    const DIRECT_LISTING: &str = "table inet direct {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"lo\" accept
\t\tmeta nfproto ipv6 counter packets 0 bytes 0 drop comment \"no IPv6\"
\t\ttcp dport { 8080, 8099 } drop
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tmeta nfproto ipv6 counter packets 0 bytes 0 drop comment \"no IPv6\"
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t\toifname \"lo\" accept
\t\tmeta nfproto ipv6 counter packets 0 bytes 0 drop comment \"no IPv6\"
\t}
}
";

    #[test]
    fn direct_mode_verification_fails_closed() {
        let sp = direct_spec(4240);
        assert!(verify_direct_listing("", &sp).is_err());
        assert!(verify_direct_listing("table inet direct {\n}\n", &sp).is_err());
        assert!(verify_direct_listing(DIRECT_LISTING, &sp).is_ok());
        // Without the IPv6 drops it is incomplete.
        let v4_only = "table inet direct {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport { 8080, 8099 } drop\n\t}\n}\n";
        assert!(verify_direct_listing(v4_only, &sp).is_err());
    }

    #[tokio::test]
    async fn direct_install_pipes_the_script_and_reads_it_back() {
        let sp = direct_spec(51413);
        let listing = DIRECT_LISTING;
        let runner = FakeRunner::default();
        runner.respond("nft list table", listing);
        install_direct(&runner, &sp).await.unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0].line(), "nft -f -");
        assert!(
            calls[0]
                .stdin
                .as_deref()
                .unwrap()
                .contains("redirect to :51413")
        );
        assert_eq!(calls[1].line(), "nft list table inet direct");
        // Without a listing (nft printed nothing), it fails closed.
        let empty = FakeRunner::default();
        assert!(install_direct(&empty, &sp).await.is_err());
    }

    fn spec() -> RulesetSpec {
        RulesetSpec {
            lan_iface: "eth0".into(),
            wg_iface: "wg0".into(),
            lan_cidrs: vec![
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
            ],
            webui_port: 8080,
            ingress_port: 8099,
            ingress_sources: "172.30.32.0/23".parse().unwrap(),
            endpoint: SocketAddrV4::new(Ipv4Addr::new(190, 2, 131, 156), 51820),
            wg_fwmark: 0xca6c,
            bt_ports: vec![],
            dns_servers: vec![Ipv4Addr::new(10, 2, 0, 1)],
        }
    }

    fn chain<'a>(rules: &'a str, name: &str) -> Vec<&'a str> {
        let start = rules.find(&format!("chain {name} {{")).unwrap();
        rules[start..]
            .lines()
            .skip(1)
            .take_while(|l| l.trim() != "}")
            .map(str::trim)
            .collect()
    }

    #[test]
    fn overlapping_lan_cidrs_are_collapsed() {
        let mut sp = spec();
        sp.lan_cidrs.insert(0, "172.30.32.0/23".parse().unwrap());
        sp.lan_cidrs.push("192.168.1.0/24".parse().unwrap());
        let r = render_ruleset(&sp).unwrap();
        assert!(
            r.contains("elements = { 172.16.0.0/12, 192.168.0.0/16 }"),
            "{r}"
        );
    }

    #[test]
    fn atomic_replace_header() {
        let r = render_ruleset(&spec()).unwrap();
        let lines: Vec<&str> = r.lines().collect();
        let add = lines
            .iter()
            .position(|l| *l == "add table inet killswitch")
            .unwrap();
        let del = lines
            .iter()
            .position(|l| *l == "delete table inet killswitch")
            .unwrap();
        let def = lines
            .iter()
            .position(|l| *l == "table inet killswitch {")
            .unwrap();
        assert!(add < del && del < def);
        assert!(r.contains("set bt_port {\n\t\ttype inet_service\n\t}"));
        assert!(
            r.contains("set ui_ports {\n\t\ttype inet_service\n\t\telements = { 8080, 8099 }\n\t}")
        );
        assert!(r.contains("set lan_cidrs {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 172.16.0.0/12, 192.168.0.0/16 }"));
    }

    #[test]
    fn every_chain_drops_by_default_and_ipv6_immediately_after_lo() {
        let r = render_ruleset(&spec()).unwrap();
        for name in ["input", "forward", "output"] {
            let c = chain(&r, name);
            assert!(c[0].ends_with("policy drop;"), "{name}: {c:?}");
            let v6 = c
                .iter()
                .position(|l| l.starts_with("meta nfproto ipv6 counter drop"))
                .unwrap();
            match name {
                "input" => assert_eq!((c[1], v6), ("iifname \"lo\" accept", 2)),
                "output" => assert_eq!((c[1], v6), ("oifname \"lo\" accept", 2)),
                _ => assert_eq!(v6, 1),
            }
        }
    }

    #[test]
    fn output_allows_lan_only_as_webui_replies() {
        let r = render_ruleset(&spec()).unwrap();
        let out = chain(&r, "output");
        let lan_rules: Vec<&&str> = out.iter().filter(|l| l.contains("@lan_cidrs")).collect();
        assert_eq!(lan_rules.len(), 2, "{lan_rules:?}");
        assert!(lan_rules[0].starts_with(
            "oifname \"eth0\" ip daddr @lan_cidrs tcp sport @ui_ports ct state established,related accept"
        ));
        assert!(lan_rules[1].contains("icmp code frag-needed ct state related accept"));
        // No rule lets anything else reach eth0 except the marked WireGuard envelope.
        for l in out.iter().filter(|l| l.contains("accept")) {
            let to_tunnel = l.starts_with("oifname \"wg0\"") || l.starts_with("oifname \"lo\"");
            let lan_reply = l.contains("@lan_cidrs") && l.contains("related accept");
            let envelope =
                l.contains("meta mark 0x0000ca6c ip daddr 190.2.131.156 udp dport 51820 accept");
            assert!(
                to_tunnel || lan_reply || envelope,
                "unexpected output accept: {l}"
            );
        }
        assert!(out.contains(&"oifname != \"wg0\" meta mark 0x0000ca6c ip daddr 190.2.131.156 udp dport 51820 accept comment \"WireGuard envelope\""));
        let wg = out
            .iter()
            .position(|l| l.starts_with("oifname \"wg0\" accept"))
            .unwrap();
        assert_eq!(
            out.last(),
            Some(&"counter comment \"output: dropped by policy\"")
        );
        assert!(wg < out.len() - 1);
    }

    #[test]
    fn dns_is_locked_to_the_tunnel_dns_servers() {
        let rule = |spec: &RulesetSpec| {
            let r = render_ruleset(spec).unwrap();
            let out = chain(&r, "output");
            let dns = out.iter().position(|l| l.contains("th dport 53")).unwrap();
            let wg = out
                .iter()
                .position(|l| l.starts_with("oifname \"wg0\" accept"))
                .unwrap();
            assert!(dns < wg, "the DNS rule must come before the tunnel accept");
            out[dns].to_owned()
        };
        let mut sp = spec();
        assert_eq!(
            rule(&sp),
            "oifname \"wg0\" meta l4proto { tcp, udp } th dport 53 ip daddr != { 10.2.0.1 } counter drop comment \"DNS only to the tunnel's DNS servers\""
        );
        sp.dns_servers = vec![
            Ipv4Addr::new(10, 2, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(10, 2, 0, 1),
        ];
        assert!(rule(&sp).contains("ip daddr != { 1.1.1.1, 10.2.0.1 } counter drop"));
        sp.dns_servers.clear();
        assert!(rule(&sp).contains("th dport 53 counter drop"));
    }

    #[test]
    fn input_rules() {
        let r = render_ruleset(&spec()).unwrap();
        let inp = chain(&r, "input");
        assert!(inp.contains(&"ct state established,related accept"));
        assert!(
            inp.iter().any(
                |l| l.starts_with("iifname \"eth0\" ip saddr @lan_cidrs tcp dport 8080 accept")
            )
        );
        assert!(
            inp.iter()
                .any(|l| l.starts_with("iifname \"wg0\" tcp dport @bt_port accept"))
        );
        assert!(
            inp.iter()
                .any(|l| l.starts_with("iifname \"wg0\" udp dport @bt_port accept"))
        );
        // Ingress (8099) only from Home Assistant's network, never from the LAN set.
        let ingress: Vec<&&str> = inp.iter().filter(|l| l.contains("8099")).collect();
        assert_eq!(ingress.len(), 1, "{ingress:?}");
        assert!(
            ingress[0]
                .starts_with("iifname \"eth0\" ip saddr 172.30.32.0/23 tcp dport 8099 accept")
        );
        // The Web UI is never reachable from the tunnel side.
        assert!(
            !inp.iter()
                .any(|l| l.contains("wg0") && (l.contains("8080") || l.contains("8099")))
        );
        // The Ingress source is always in the reply set.
        let mut sp = spec();
        sp.lan_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
        assert!(
            render_ruleset(&sp)
                .unwrap()
                .contains("elements = { 172.30.32.0/23, 192.168.1.0/24 }")
        );
        sp.ingress_port = 8080;
        assert!(render_ruleset(&sp).is_err());
    }

    #[test]
    fn initial_ports_and_set_updates() {
        let mut sp = spec();
        sp.bt_ports = vec![51234, 0, 51234];
        let r = render_ruleset(&sp).unwrap();
        assert!(r.contains("type inet_service\n\t\telements = { 51234 }"));
        assert_eq!(
            render_bt_port_update(&[42000]),
            "flush set inet killswitch bt_port\nadd element inet killswitch bt_port { 42000 }\n"
        );
        assert_eq!(
            render_bt_port_update(&[42001, 42000]),
            "flush set inet killswitch bt_port\nadd element inet killswitch bt_port { 42000, 42001 }\n"
        );
        assert_eq!(
            render_bt_port_update(&[]),
            "flush set inet killswitch bt_port\n"
        );
    }

    #[test]
    fn static_port_mode_is_open_on_wg0_from_the_first_ruleset() {
        // TorGuard / AirVPN / Windscribe: `Settings::static_bt_ports()` is
        // `[listen_port]` when NAT-PMP is off, and it goes into the very
        // first (atomic) ruleset, never as a later, separate step.
        let mut sp = spec();
        sp.bt_ports = vec![4240];
        let r = render_ruleset(&sp).unwrap();
        assert!(r.contains("set bt_port {\n\t\ttype inet_service\n\t\telements = { 4240 }"));
        let input: Vec<&str> = r
            .lines()
            .map(str::trim)
            .filter(|l| l.contains("@bt_port"))
            .collect();
        assert_eq!(input.len(), 2, "{input:?}");
        assert!(
            input.iter().all(|l| l.starts_with("iifname \"wg0\"")),
            "only on the tunnel: {input:?}"
        );
        assert!(
            !r.contains("iifname \"eth0\" tcp dport @bt_port"),
            "never on the LAN side"
        );
    }

    #[test]
    fn interface_names_cannot_inject_rules() {
        for bad in [
            "",
            "eth0\" accept",
            "a b",
            "averyveryverylongname",
            "eth0;",
            "e/0",
        ] {
            let mut sp = spec();
            sp.lan_iface = bad.into();
            assert!(render_ruleset(&sp).is_err(), "{bad:?}");
        }
        assert!(valid_iface_name("eth0"));
        assert!(valid_iface_name("eth0@if12"));
        let mut same = spec();
        same.lan_iface = "wg0".into();
        assert!(render_ruleset(&same).is_err());
    }

    #[tokio::test]
    async fn install_pipes_script_on_stdin_and_verifies() {
        let runner = FakeRunner::default();
        runner.respond(
            "nft list table",
            "table inet killswitch {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n\t}\n}",
        );
        install(&runner, &spec()).await.unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0].line(), "nft -f -");
        assert!(
            calls[0]
                .stdin
                .as_deref()
                .unwrap()
                .contains("table inet killswitch {")
        );
        set_bt_ports(&runner, &[5000]).await.unwrap();
        assert!(
            runner.calls()[2]
                .stdin
                .as_deref()
                .unwrap()
                .contains("{ 5000 }")
        );

        let broken = FakeRunner::default();
        broken.respond(
            "nft list table",
            "table inet killswitch { chain input { policy accept; } }",
        );
        assert!(install(&broken, &spec()).await.is_err());
    }

    #[test]
    fn verification_fails_closed() {
        // Empty output (nft exiting 0 without printing) is not a pass.
        assert!(verify_listing("").is_err());
        assert!(verify_listing("   \n").is_err());
        // Three drops in the wrong places (or another table) are not enough.
        assert!(
            verify_listing(
                "table inet other {\n\tchain a {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}"
            )
            .is_err()
        );
        let missing_output = "table inet killswitch {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n}";
        assert!(verify_listing(missing_output).is_err());
        // What the renderer produces passes.
        let rendered = render_ruleset(&spec()).unwrap();
        assert!(verify_listing(&rendered).is_ok(), "{rendered}");
    }

    /// Loads the real ruleset into the kernel. Opt-in because it needs root
    /// and must run in a throwaway network namespace:
    /// `NFT_LIVE_TEST=1 unshare -n cargo test nft_live -- --nocapture`
    #[tokio::test]
    async fn nft_live_kernel_accepts_ruleset_and_port_updates() {
        if std::env::var("NFT_LIVE_TEST").as_deref() != Ok("1") {
            eprintln!("skipped (set NFT_LIVE_TEST=1 inside `unshare -n`)");
            return;
        }
        let runner = crate::exec::SystemRunner;
        let mut live = spec();
        live.lan_cidrs.insert(0, "172.30.32.0/23".parse().unwrap());
        install(&runner, &live).await.unwrap();
        // Installing twice must replace, not duplicate (atomic add+delete+define).
        install(&runner, &live).await.unwrap();
        set_bt_ports(&runner, &[41000]).await.unwrap();
        set_bt_ports(&runner, &[41000, 41001]).await.unwrap();
        let out = runner
            .run("nft", &["list", "table", "inet", "killswitch"], None)
            .await
            .unwrap()
            .stdout;
        eprintln!("{out}");
        assert_eq!(out.matches("policy drop").count(), 3);
        assert!(out.contains("41000") && out.contains("41001"));
        // 172.30.32.0/23 is covered by 172.16.0.0/12 and collapsed into it.
        assert!(out.contains("elements = { 172.16.0.0/12, 192.168.0.0/16 }"));
        assert!(out.contains("meta nfproto ipv6 drop") || out.contains("nfproto ipv6"));
        assert!(out.contains("th dport 53 ip daddr != 10.2.0.1"), "{out}");
        set_bt_ports(&runner, &[]).await.unwrap();
        let out = runner
            .run(
                "nft",
                &["list", "set", "inet", "killswitch", "bt_port"],
                None,
            )
            .await
            .unwrap()
            .stdout;
        assert!(!out.contains("41000"), "{out}");
        runner
            .run("nft", &["delete", "table", "inet", "killswitch"], None)
            .await
            .unwrap();

        // Direct mode: the access rules and the port redirect load as well.
        let direct = direct_spec(51413);
        install_direct(&runner, &direct).await.unwrap();
        install_direct(&runner, &direct).await.unwrap();
        let out = runner
            .run("nft", &["list", "table", "inet", "direct"], None)
            .await
            .unwrap()
            .stdout;
        eprintln!("{out}");
        assert!(out.contains("redirect to :51413"), "{out}");
        assert_eq!(out.matches("hook input").count(), 1, "{out}");
        runner
            .run("nft", &["delete", "table", "inet", "direct"], None)
            .await
            .unwrap();
    }
}
