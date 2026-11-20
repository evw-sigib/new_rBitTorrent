# Changelog

## 1.0.0

First release.

### App

- rtbit (rustTorrent v0.2.0-beta.4), compiled from the pinned, commit-checked
  release source with mimalloc as its allocator, behind kernel WireGuard
  with an atomic nftables kill-switch (`inet killswitch`):
  - default drop,
  - IPv6 dropped,
  - DNS locked to the tunnel,
  - LAN gets replies only.
- Pure-Rust NAT-PMP (RFC 6886):
  - 60 s leases renewed every 45 s,
  - public IP verification,
  - rtbit restarts only when the port changes.
- WireGuard setup from `/config/wg0.conf`, a pasted configuration, or
  separate fields.
- `vpn_enabled`: a fresh install runs on the direct connection with a loud
  warning; any WireGuard setup switches the VPN on, fail-closed, never
  falling back.
- Static port mode (`enable_nat_pmp` off) for TorGuard, AirVPN, Windscribe
  and other WireGuard providers: `listen_port` is opened on `wg0` in the
  first ruleset.

### Moving from qBittorrent

- Web UI and qBittorrent-compatible API on qBittorrent's port 8080.
- One-time takeover of an existing qBittorrent app:
  - WireGuard file,
  - save and temp folders,
  - Web UI user name,
  - categories,
  - optionally its torrents, re-added at their save paths.
- Supervisor checks: a warning while a qBittorrent app still runs, and
  discovery for the qBittorrent integration.

### Home Assistant

- Ingress sidebar with automatic sign-in, streaming bodies and WebSockets.
- Status bar in the sidebar: "Direct Connection (Unprotected)" with setup
  links (dismissible), or a green "VPN Protected" pill with the exit IP and
  port.
- On-demand speed test (`POST /__benchmark`): Cloudflare download and
  latency over the active route, disk write speed in the download folder,
  SHA-1 hashing speed, and regional peering latency with the VPN off.
  Nothing of it runs while idle.
- `/__health` watchdog: 200 only while rtbit runs and (VPN mode) the
  handshake is fresh.
- Low disk space warning, and a status box with the VPN IP, forwarded port,
  qBittorrent import, CPU cores and free space.
