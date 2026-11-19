//! Kernel WireGuard + split-return routing, configured directly with `ip` and
//! `wg` (no `wg-quick`: it needs `sysctl` writes that a container with only
//! NET_ADMIN cannot perform, and its `ip rule`/`suppress_prefixlength` policy
//! routing is unnecessary here).
//!
//! Routing layout inside the app's network namespace:
//!
//! ```text
//! <endpoint>/32      via <eth0 gw> dev eth0   WireGuard envelope
//! <lan cidr>         via <eth0 gw> dev eth0   Web UI/API replies to LAN/HA
//! <connected subnet>           dev eth0       (kernel, untouched)
//! <dns|natpmp gw>/32           dev wg0        never leaks even inside a LAN cidr
//! 0.0.0.0/1 + 128.0.0.0/1      dev wg0        everything else (beats the default route)
//! default            via <eth0 gw> dev eth0   (left alone, shadowed by the /1s)
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use tracing::{debug, info, warn};

use crate::cidr::Ipv4Cidr;
use crate::config::{Endpoint, EndpointHost, WireGuardConfig};
use crate::exec::Runner;
use crate::firewall::valid_iface_name;

pub const WG_IFACE: &str = "wg0";
/// 51820 — the same fwmark wg-quick uses; matched by the kill-switch.
pub const WG_FWMARK: u32 = 0xca6c;
/// Read the private/preshared key from the stdin pipe, never from argv.
const STDIN_PATH: &str = "/proc/self/fd/0";

/// The container's uplink (default route) as found before any change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanRoute {
    pub gateway: Ipv4Addr,
    pub dev: String,
}

/// Parses `ip -4 route show default`, e.g. `default via 172.30.32.1 dev eth0`.
pub fn parse_default_route(out: &str) -> Option<LanRoute> {
    out.lines().find_map(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() != Some(&"default") {
            return None;
        }
        let value_of = |key: &str| {
            words
                .iter()
                .position(|w| *w == key)
                .and_then(|i| words.get(i + 1))
                .copied()
        };
        let gateway = value_of("via")?.parse::<Ipv4Addr>().ok()?;
        let dev = value_of("dev")?;
        valid_iface_name(dev).then(|| LanRoute {
            gateway,
            dev: dev.to_owned(),
        })
    })
}

/// Parses `ip -4 route show` and returns the directly connected subnets
/// (routes with a `dev` but no `via`), e.g. `172.30.32.0/23 dev eth0 proto kernel scope link`.
pub fn parse_connected_routes(out: &str) -> Vec<Ipv4Cidr> {
    out.lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let dest = *words.first()?;
            if dest == "default" || words.contains(&"via") || !words.contains(&"dev") {
                return None;
            }
            // Only unicast routes (skip "broadcast", "local", "unreachable", ...).
            dest.parse::<Ipv4Cidr>().ok()
        })
        .collect()
}

/// LAN ranges that need an explicit `via <gw>` route: anything not already
/// inside a connected subnet (replacing a kernel route would break on-link
/// delivery to Home Assistant).
pub fn plan_lan_routes(allow: &[Ipv4Cidr], connected: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    allow
        .iter()
        .filter(|c| !connected.iter().any(|k| k.contains(c)))
        .copied()
        .collect()
}

/// Parses `wg show wg0 latest-handshakes` (`<peer-key>\t<unix-seconds>`).
pub fn parse_latest_handshake(out: &str, peer_public_key: &str) -> Option<u64> {
    out.lines().find_map(|line| {
        let (peer, ts) = line.split_once(char::is_whitespace)?;
        (peer == peer_public_key)
            .then(|| ts.trim().parse::<u64>().ok())
            .flatten()
            .filter(|t| *t > 0)
    })
}

/// `/etc/resolv.conf` content pointing at the in-tunnel DNS server(s).
pub fn render_resolv_conf(dns: &[Ipv4Addr]) -> String {
    let mut s = String::from(
        "# Managed by rbittorrent rbittorrent-supervisor: DNS only through the WireGuard tunnel\n",
    );
    for ip in dns.iter().take(3) {
        s.push_str(&format!("nameserver {ip}\n"));
    }
    s.push_str("options timeout:2 attempts:2\n");
    s
}

/// Overwrites resolv.conf in place (Docker bind-mounts it, so no rename).
pub fn lock_resolv_conf(path: &Path, dns: &[Ipv4Addr]) -> Result<()> {
    std::fs::write(path, render_resolv_conf(dns))
        .with_context(|| format!("cannot write {}", path.display()))
}

/// Resolves the endpoint to IPv4 once, *before* the kill-switch blocks DNS.
pub async fn resolve_endpoint(endpoint: &Endpoint) -> Result<SocketAddrV4> {
    match &endpoint.host {
        EndpointHost::Ip(ip) => Ok(SocketAddrV4::new(*ip, endpoint.port)),
        EndpointHost::Name(name) => {
            let addrs = tokio::net::lookup_host((name.as_str(), endpoint.port))
                .await
                .with_context(|| format!("cannot resolve WireGuard endpoint {name}"))?;
            addrs
                .filter_map(|a| match a {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                })
                .find(|a| !a.ip().is_unspecified() && !a.ip().is_loopback())
                .ok_or_else(|| anyhow!("WireGuard endpoint {name} has no usable IPv4 address"))
        }
    }
}

/// Reads the uplink and connected subnets before anything is changed.
pub async fn detect_lan(runner: &impl Runner) -> Result<(LanRoute, Vec<Ipv4Cidr>)> {
    let default = runner
        .run("ip", &["-4", "route", "show", "default"], None)
        .await
        .context("cannot read the default route")?;
    let lan = parse_default_route(&default.stdout).ok_or_else(|| {
        anyhow!(
            "no IPv4 default route found (output: {:?}); the app needs its normal \
             Home Assistant network",
            default.stdout.trim()
        )
    })?;
    if lan.dev == WG_IFACE {
        bail!("the default route already points at {WG_IFACE}; refusing to continue");
    }
    let all = runner
        .run("ip", &["-4", "route", "show"], None)
        .await
        .context("cannot read the routing table")?;
    Ok((lan, parse_connected_routes(&all.stdout)))
}

/// Everything needed to bring the tunnel up.
#[derive(Debug, Clone)]
pub struct TunnelPlan {
    pub lan: LanRoute,
    pub endpoint: SocketAddrV4,
    /// LAN CIDRs needing an explicit route via the uplink gateway.
    pub lan_routes: Vec<Ipv4Cidr>,
    /// In-tunnel hosts that get /32 routes on wg0 (DNS, NAT-PMP gateway).
    pub tunnel_hosts: Vec<Ipv4Addr>,
}

async fn ip(runner: &impl Runner, args: &[&str]) -> Result<()> {
    runner.run("ip", args, None).await.map(|_| ())
}

/// Creates and configures `wg0` plus all routes. Idempotent: an existing
/// `wg0` is deleted first and `ip route replace` is used throughout.
pub async fn bring_up(runner: &impl Runner, wg: &WireGuardConfig, plan: &TunnelPlan) -> Result<()> {
    let gw = plan.lan.gateway.to_string();
    let dev = plan.lan.dev.as_str();

    // Stale interface from a previous attempt (ignore "Cannot find device").
    if runner
        .run("ip", &["link", "del", "dev", WG_IFACE], None)
        .await
        .is_ok()
    {
        debug!("removed stale {WG_IFACE}");
    }

    let ep = format!("{}/32", plan.endpoint.ip());
    ip(
        runner,
        &["-4", "route", "replace", &ep, "via", &gw, "dev", dev],
    )
    .await
    .context("cannot route the WireGuard endpoint via the uplink")?;
    for cidr in &plan.lan_routes {
        let c = cidr.network().to_string();
        ip(
            runner,
            &["-4", "route", "replace", &c, "via", &gw, "dev", dev],
        )
        .await
        .with_context(|| format!("cannot add the return route for {c}"))?;
    }

    ip(
        runner,
        &["link", "add", "dev", WG_IFACE, "type", "wireguard"],
    )
    .await
    .context(
        "cannot create the WireGuard interface; the host kernel needs WireGuard \
             (built into Home Assistant OS) and the app needs NET_ADMIN",
    )?;

    let fwmark = format!("{WG_FWMARK:#x}");
    let mut key = wg.private_key.as_base64().to_owned();
    key.push('\n');
    runner
        .run(
            "wg",
            &[
                "set",
                WG_IFACE,
                "fwmark",
                &fwmark,
                "private-key",
                STDIN_PATH,
            ],
            Some(key.as_bytes()),
        )
        .await
        .context("cannot set the WireGuard private key")?;

    let endpoint = plan.endpoint.to_string();
    let keepalive = wg.persistent_keepalive.to_string();
    let mut peer_args = vec!["set", WG_IFACE, "peer", wg.peer_public_key.as_base64()];
    let psk = wg
        .preshared_key
        .as_ref()
        .map(|k| format!("{}\n", k.as_base64()));
    if psk.is_some() {
        peer_args.extend(["preshared-key", STDIN_PATH]);
    }
    peer_args.extend([
        "endpoint",
        &endpoint,
        "persistent-keepalive",
        &keepalive,
        "allowed-ips",
        "0.0.0.0/0",
    ]);
    runner
        .run("wg", &peer_args, psk.as_deref().map(str::as_bytes))
        .await
        .context("cannot configure the WireGuard peer")?;

    let addr = wg.address.to_string();
    ip(runner, &["-4", "address", "add", &addr, "dev", WG_IFACE])
        .await
        .context("cannot assign the tunnel address")?;
    let mtu = wg.mtu.to_string();
    ip(runner, &["link", "set", "dev", WG_IFACE, "mtu", &mtu, "up"])
        .await
        .context("cannot bring the WireGuard interface up")?;

    for host in &plan.tunnel_hosts {
        if *host == wg.address.addr() {
            continue;
        }
        let h = format!("{host}/32");
        ip(runner, &["-4", "route", "replace", &h, "dev", WG_IFACE])
            .await
            .with_context(|| format!("cannot route {h} into the tunnel"))?;
    }
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        ip(runner, &["-4", "route", "replace", half, "dev", WG_IFACE])
            .await
            .with_context(|| format!("cannot route {half} into the tunnel"))?;
    }
    info!(
        interface = WG_IFACE,
        address = %wg.address,
        endpoint = %plan.endpoint,
        mtu = wg.mtu,
        keepalive = wg.persistent_keepalive,
        peer = wg.peer_public_key.short(),
        "WireGuard interface configured"
    );
    Ok(())
}

/// Removes `wg0` (its routes go with it). The kill-switch stays in place.
pub async fn tear_down(runner: &impl Runner) {
    match runner
        .run("ip", &["link", "del", "dev", WG_IFACE], None)
        .await
    {
        Ok(_) => info!("WireGuard interface removed"),
        Err(e) => debug!("removing {WG_IFACE}: {e:#}"),
    }
}

/// The wall-clock time (Unix seconds) of the last handshake with the peer,
/// `None` if there was none.
pub async fn handshake_timestamp(
    runner: &impl Runner,
    wg: &WireGuardConfig,
) -> Result<Option<u64>> {
    let out = runner
        .run("wg", &["show", WG_IFACE, "latest-handshakes"], None)
        .await?;
    Ok(parse_latest_handshake(
        &out.stdout,
        wg.peer_public_key.as_base64(),
    ))
}

/// The wall clock in Unix seconds.
pub fn wall_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seconds since the last handshake with the peer, `None` if there was none.
pub async fn handshake_age(runner: &impl Runner, wg: &WireGuardConfig) -> Result<Option<Duration>> {
    Ok(handshake_timestamp(runner, wg)
        .await?
        .map(|ts| Duration::from_secs(wall_secs().saturating_sub(ts))))
}

/// Turns WireGuard's wall-clock handshake times into ages on the monotonic
/// clock. A board without a real-time clock (a Raspberry Pi) steps its
/// clock when NTP syncs, possibly long after boot: a step forward must not
/// make a fresh tunnel look dead, and a step back must not hide a dead one.
/// A new handshake time counts from when it was first seen (no earlier than
/// the previous poll); an unchanged one keeps aging on the monotonic clock.
#[derive(Debug, Default)]
pub struct HandshakeClock {
    /// The last handshake time seen, and when it happened (monotonic).
    last: Option<(u64, std::time::Instant)>,
    polled: Option<std::time::Instant>,
}

impl HandshakeClock {
    pub fn age(&mut self, ts: u64, wall_now: u64, now: std::time::Instant) -> Duration {
        let wall_age = Duration::from_secs(wall_now.saturating_sub(ts));
        let at = match self.last {
            Some((seen, at)) if seen == ts => at,
            _ => {
                let since_poll = self
                    .polled
                    .map_or(wall_age, |p| now.saturating_duration_since(p));
                let at = now.checked_sub(wall_age.min(since_poll)).unwrap_or(now);
                self.last = Some((ts, at));
                at
            }
        };
        self.polled = Some(now);
        now.saturating_duration_since(at)
    }
}

/// Polls for the first handshake, poking the tunnel with a UDP probe so the
/// kernel initiates one even before rtbit sends anything.
pub async fn wait_for_handshake(
    runner: &impl Runner,
    wg: &WireGuardConfig,
    probe_target: SocketAddrV4,
    limit: Duration,
) -> Result<()> {
    let start = tokio::time::Instant::now();
    let mut last_probe: Option<tokio::time::Instant> = None;
    loop {
        if last_probe.is_none_or(|t| t.elapsed() >= Duration::from_secs(2)) {
            if let Err(e) = crate::natpmp::send_probe(wg.address.addr(), probe_target).await {
                debug!("handshake probe to {probe_target} failed: {e}");
            }
            last_probe = Some(tokio::time::Instant::now());
        }
        match handshake_age(runner, wg).await {
            Ok(Some(age)) => {
                info!(
                    after_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                    age_s = age.as_secs(),
                    "WireGuard handshake completed"
                );
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => warn!("cannot read WireGuard handshake state: {e:#}"),
        }
        if start.elapsed() >= limit {
            bail!(
                "no WireGuard handshake with {} within {}s: check that the private key, \
                 server public key and endpoint come from the same Proton config, that the \
                 config has not been revoked, and that UDP {} is not blocked upstream",
                wg.endpoint,
                limit.as_secs(),
                wg.endpoint.port
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Collects /32 tunnel hosts: DNS servers and the NAT-PMP gateway.
pub fn tunnel_hosts(dns: &[Ipv4Addr], natpmp_gateway: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut hosts: Vec<Ipv4Addr> = dns.to_vec();
    if let Some(gw) = natpmp_gateway
        && !hosts.contains(&gw)
    {
        hosts.push(gw);
    }
    hosts
}

/// True when `ip` is a public unicast address (for log hygiene / sanity checks).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_ages_survive_clock_steps() {
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut c = HandshakeClock::default();
        // Boot clock (1970-ish), handshake 5 s ago.
        assert_eq!(c.age(1_000, 1_005, at(0)), Duration::from_secs(5));
        // NTP steps the wall clock forward by years: same handshake, 30 s on.
        assert_eq!(c.age(1_000, 1_700_000_000, at(30)), Duration::from_secs(35));
        // A new handshake (stamped with the new clock) is fresh.
        assert_eq!(
            c.age(1_700_000_050, 1_700_000_060, at(60)),
            Duration::from_secs(10)
        );
        // The clock steps back: the unchanged handshake keeps aging.
        assert_eq!(
            c.age(1_700_000_050, 1_000, at(260)),
            Duration::from_secs(210)
        );
        // A new handshake stamped in the future (clock stepped back) counts
        // from the poll that saw it.
        assert_eq!(c.age(1_800_000_000, 1_100, at(290)), Duration::ZERO);
        // A handshake reported long ago by the wall clock, but new since the
        // last poll, is at most as old as that poll.
        let mut c = HandshakeClock::default();
        c.age(5_000, 5_000, at(0));
        assert_eq!(c.age(5_010, 99_999, at(30)), Duration::from_secs(30));
    }
    use crate::config::{Options, Paths, Settings};
    use crate::exec::fake::FakeRunner;

    const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PSK: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    fn wg(psk: bool) -> WireGuardConfig {
        let opts = Options {
            wg_private_key: Some(PRIV.into()),
            wg_public_key: Some(PUB.into()),
            wg_preshared_key: psk.then(|| PSK.into()),
            wg_endpoint: Some("190.2.131.156:51820".into()),
            wg_address: Some("10.2.0.2/32".into()),
            ..Options::default()
        };
        Settings::from_options(&opts, &Paths::default())
            .unwrap()
            .vpn
            .expect("the wg_* fields switch the VPN on")
            .wireguard
    }

    fn plan() -> TunnelPlan {
        TunnelPlan {
            lan: LanRoute {
                gateway: Ipv4Addr::new(172, 30, 32, 1),
                dev: "eth0".into(),
            },
            endpoint: SocketAddrV4::new(Ipv4Addr::new(190, 2, 131, 156), 51820),
            lan_routes: vec!["192.168.0.0/16".parse().unwrap()],
            tunnel_hosts: vec![Ipv4Addr::new(10, 2, 0, 1)],
        }
    }

    #[test]
    fn parses_routes() {
        let lan = parse_default_route(
            "default via 172.30.32.1 dev eth0 proto static metric 100\ndefault via 10.0.0.1 dev eth1\n",
        )
        .unwrap();
        assert_eq!(lan.gateway, Ipv4Addr::new(172, 30, 32, 1));
        assert_eq!(lan.dev, "eth0");
        assert!(parse_default_route("").is_none());
        assert!(parse_default_route("default dev wg0 scope link").is_none());
        assert!(parse_default_route("default via 1.2.3.4 dev bad\"name").is_none());

        let connected = parse_connected_routes(
            "default via 172.30.32.1 dev eth0\n\
             172.30.32.0/23 dev eth0 proto kernel scope link src 172.30.33.7\n\
             192.168.0.0/16 via 172.30.32.1 dev eth0\n",
        );
        assert_eq!(connected, vec!["172.30.32.0/23".parse().unwrap()]);
    }

    #[test]
    fn lan_route_planning_never_replaces_connected_subnets() {
        let allow: Vec<Ipv4Cidr> = ["172.16.0.0/12", "172.30.32.0/23", "192.168.0.0/16"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let connected = vec!["172.30.32.0/23".parse().unwrap()];
        let planned: Vec<String> = plan_lan_routes(&allow, &connected)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(planned, vec!["172.16.0.0/12", "192.168.0.0/16"]);
    }

    #[test]
    fn handshake_parsing() {
        let out = format!("{PUB}\t1731942000\nother=\t5\n");
        assert_eq!(parse_latest_handshake(&out, PUB), Some(1_731_942_000));
        assert_eq!(parse_latest_handshake(&format!("{PUB}\t0\n"), PUB), None);
        assert_eq!(parse_latest_handshake("", PUB), None);
    }

    #[test]
    fn resolv_conf_points_only_at_tunnel_dns() {
        let r = render_resolv_conf(&[Ipv4Addr::new(10, 2, 0, 1)]);
        assert!(r.contains("nameserver 10.2.0.1\n"));
        assert_eq!(r.matches("nameserver").count(), 1);
    }

    #[tokio::test]
    async fn bring_up_sequence_keeps_keys_off_the_command_line() {
        let runner = FakeRunner::default();
        bring_up(&runner, &wg(true), &plan()).await.unwrap();
        let calls = runner.calls();
        let lines = runner.lines();
        for c in &calls {
            for a in &c.args {
                assert!(
                    !a.contains(PRIV) && !a.contains(PSK),
                    "secret in argv: {}",
                    c.line()
                );
            }
        }
        let key_call = calls
            .iter()
            .find(|c| c.line().contains("private-key"))
            .unwrap();
        assert_eq!(
            key_call.stdin.as_deref(),
            Some(format!("{PRIV}\n").as_str())
        );
        assert!(
            key_call
                .line()
                .contains("fwmark 0xca6c private-key /proc/self/fd/0")
        );
        let peer_call = calls.iter().find(|c| c.line().contains(" peer ")).unwrap();
        assert_eq!(
            peer_call.stdin.as_deref(),
            Some(format!("{PSK}\n").as_str())
        );
        assert!(peer_call.line().contains(
            "endpoint 190.2.131.156:51820 persistent-keepalive 25 allowed-ips 0.0.0.0/0"
        ));

        let pos = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
        // Uplink routes before the tunnel, split default last.
        assert!(
            pos("route replace 190.2.131.156/32 via 172.30.32.1 dev eth0") < pos("type wireguard")
        );
        assert!(
            pos("route replace 192.168.0.0/16 via 172.30.32.1 dev eth0") < pos("type wireguard")
        );
        assert!(pos("mtu 1420 up") > pos("address add 10.2.0.2/32 dev wg0"));
        assert!(pos("route replace 10.2.0.1/32 dev wg0") > pos("mtu 1420 up"));
        assert!(pos("route replace 0.0.0.0/1 dev wg0") > pos("mtu 1420 up"));
        assert!(pos("route replace 128.0.0.0/1 dev wg0") > pos("0.0.0.0/1"));
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("wg-quick") || l.contains("sysctl") || l.contains("ip rule"))
        );
    }

    #[tokio::test]
    async fn bring_up_without_psk_sends_no_stdin_to_peer() {
        let runner = FakeRunner::default();
        bring_up(&runner, &wg(false), &plan()).await.unwrap();
        let peer_call = runner
            .calls()
            .into_iter()
            .find(|c| c.line().contains(" peer "))
            .unwrap();
        assert!(peer_call.stdin.is_none());
        assert!(!peer_call.line().contains("preshared-key"));
    }

    #[tokio::test]
    async fn bring_up_reports_missing_wireguard_support() {
        let runner = FakeRunner::default();
        runner.fail_on("ip link add dev wg0 type wireguard");
        let err = format!(
            "{:#}",
            bring_up(&runner, &wg(false), &plan()).await.unwrap_err()
        );
        assert!(err.contains("NET_ADMIN"), "{err}");
    }

    #[tokio::test]
    async fn detect_lan_reads_uplink() {
        let runner = FakeRunner::default();
        runner.respond(
            "ip -4 route show default",
            "default via 172.30.32.1 dev eth0\n",
        );
        runner.respond(
            "ip -4 route show",
            "default via 172.30.32.1 dev eth0\n172.30.32.0/23 dev eth0 proto kernel scope link src 172.30.33.2\n",
        );
        let (lan, connected) = detect_lan(&runner).await.unwrap();
        assert_eq!(lan.dev, "eth0");
        assert_eq!(connected.len(), 1);

        let none = FakeRunner::default();
        assert!(detect_lan(&none).await.is_err());
    }

    #[tokio::test]
    async fn resolves_ip_endpoints_without_dns() {
        let ep = Endpoint {
            host: EndpointHost::Ip(Ipv4Addr::new(1, 2, 3, 4)),
            port: 51820,
        };
        assert_eq!(
            resolve_endpoint(&ep).await.unwrap(),
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 51820)
        );
        let local = Endpoint {
            host: EndpointHost::Name("localhost".into()),
            port: 1,
        };
        // localhost resolves only to loopback, which is never a usable endpoint.
        assert!(resolve_endpoint(&local).await.is_err());
    }

    #[test]
    fn tunnel_host_list_and_public_check() {
        let dns = [Ipv4Addr::new(10, 2, 0, 1)];
        assert_eq!(
            tunnel_hosts(&dns, Some(Ipv4Addr::new(10, 2, 0, 1))).len(),
            1
        );
        assert_eq!(
            tunnel_hosts(&dns, Some(Ipv4Addr::new(10, 2, 0, 9))).len(),
            2
        );
        assert!(is_public("185.159.157.7".parse().unwrap()));
        assert!(!is_public("10.2.0.2".parse().unwrap()));
        assert!(!is_public("100.64.1.1".parse().unwrap()));
    }
}
