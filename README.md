# rBittorrent apps for Home Assistant

[![Add repository to Home Assistant][repo-badge]][repo-add]

| App | Description |
|---|---|
| [rBittorrent](rbittorrent/) | Drop-in qBittorrent replacement: the rustTorrent (`rtbit`) engine behind a fail-closed Proton VPN WireGuard kill-switch, with NAT-PMP port forwarding (or a static port for other WireGuard providers). |

## Installation

1. In Home Assistant, go to *Settings* → *Apps* → *App store* → ⋮ →
   *Repositories*.
2. Add `https://github.com/evw-sigib/new_rbittorrent`.
3. Install **rBittorrent** and read its *Documentation* tab. Moving from
   qBittorrent: stop that app first, then start rBittorrent. It takes over
   the VPN file, folders and categories by itself.

## Layout

| Path | Contents |
|---|---|
| `rbittorrent/config.yaml` | App manifest (NET_ADMIN only, Ingress, port 8080, watchdog) |
| `rbittorrent/Dockerfile` | Multi-stage build: static musl supervisor + rtbit compiled from the pinned upstream release |
| `rbittorrent/rtbit/mimalloc.patch` | The one change to rtbit: mimalloc as its global allocator |
| `rbittorrent/supervisor/` | `rbittorrent-supervisor`, the Rust PID 1 (config, firewall, WireGuard, NAT-PMP, migration, process, Ingress, benchmark) |
| `rbittorrent/tests/` | Kernel end-to-end leak test (network namespaces + real WireGuard) |
| `.github/workflows/ci-release.yaml` | fmt, clippy, tests, live nftables, e2e (VPN + direct mode), native per-arch image builds and smoke tests, GHCR release |

## Development

```sh
cd rbittorrent/supervisor
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
NFT_LIVE_TEST=1 unshare -rn cargo test nft_live -- --nocapture   # needs nft
sudo python3 ../tests/e2e_netns.py --supervisor target/release/rbittorrent-supervisor
```

## Credits

[rustTorrent](https://github.com/thedancingdeveloper-org/rusttorrent) (`rtbit`)
is the BitTorrent engine, built from its release source with one change:
the mimalloc allocator (`rbittorrent/rtbit/mimalloc.patch`).

[repo-badge]: https://img.shields.io/badge/Add%20repository-Home%20Assistant-41BDF5?logo=home-assistant
[repo-add]: https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fevw-sigib%2Fnew_rbittorrent
