# rBittorrent

![Supports aarch64][aarch64-shield] ![Supports amd64][amd64-shield]

A drop-in replacement for the qBittorrent app. It runs the
[rustTorrent](https://github.com/thedancingdeveloper-org/rusttorrent)
(`rtbit`) engine behind a fail-closed Proton VPN WireGuard kill-switch, with
NAT-PMP port forwarding.

- **qBittorrent's port 8080** and a qBittorrent-compatible API: Sonarr,
  Radarr, Prowlarr and the qBittorrent integration keep working.
- **One-click move from qBittorrent:** takes over its WireGuard file,
  folders, user name, categories and, optionally, its torrents.
- **Fail-closed:**
  - nftables default-drop,
  - no IPv6,
  - DNS only through the tunnel,
  - rtbit starts only after a WireGuard handshake.
- **Forwarded port** leased with NAT-PMP and renewed automatically, or a
  static port for TorGuard, AirVPN, Windscribe and other WireGuard
  providers.
- **Works before the VPN is set up:** a fresh install runs on the normal
  connection with a loud warning. Any WireGuard setup switches the VPN on,
  fail-closed, with no fallback.
- **Sidebar panel** with automatic sign-in (Ingress), a VPN status bar and
  a built-in speed test (line, disk, SHA-1).
- **Watchdog health check:** a stalled tunnel restarts the app.
- **Small:** one static Rust supervisor (about 4 MiB RAM), no shell scripts.
  rtbit is compiled from source with the mimalloc allocator. Asks for
  `NET_ADMIN` only.

Needs Home Assistant OS or Supervised on aarch64 or amd64, with
Supervisor 2026.07 or newer.

See the **Documentation** tab for setup, migration and leak protection.

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
