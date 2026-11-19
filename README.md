# rBittorrent apps for Home Assistant

[![Add repository to Home Assistant][repo-badge]][repo-add]

| App | Description |
|---|---|
| [rBittorrent](rbittorrent/) | Drop-in qBittorrent replacement: the rustTorrent (`rtbit`) engine behind a fail-closed Proton VPN WireGuard kill-switch, with NAT-PMP port forwarding (or a static port for other WireGuard providers). |

## Installation

1. In Home Assistant, go to *Settings* → *Apps* → *App store* → ⋮ →
   *Repositories*.
2. Add `https://github.com/evw-sigib/new_rBitTorrent`.
3. Install **rBittorrent** and read its *Documentation* tab. Moving from
   qBittorrent: stop that app first, then start rBittorrent. It takes over
   the VPN file, folders and categories by itself.

## Layout

| Path | Contents |
|---|---|
| `rbittorrent/config.yaml` | App manifest (NET_ADMIN only, Ingress, port 8080, watchdog) |
| `rbittorrent/Dockerfile` | Multi-stage build: static musl supervisor + rtbit compiled from the pinned upstream release |
| `rbittorrent/rtbit/mimalloc.patch` | mimalloc as rtbit's global allocator |
| `rbittorrent/rtbit/auth-banner.patch` | rtbit's startup log reports the stored Web UI login as `auth: enabled` |
| `rbittorrent/rtbit/swagger-vendored.patch` | Build-only: Swagger UI from a checksum-pinned crate, no download from github.com |
| `rbittorrent/rtbit/ipv4-fallback.patch` | IPv4-only mode opens IPv4 DHT and UDP tracker sockets (hosts booted with `ipv6.disable=1`) |
| `rbittorrent/rtbit/completed-move.patch` | Only torrents in the download folder move to the completed folder; others stay put |
| `rbittorrent/apparmor.txt` | AppArmor profile: rtbit and the Ingress proxy run in confined child profiles (the sandbox on Home Assistant OS) |
| `rbittorrent/supervisor/` | `rbittorrent-supervisor`, the Rust PID 1 (config, firewall, WireGuard, NAT-PMP, migration, process, Ingress, benchmark) |
| `rbittorrent/tests/` | Kernel end-to-end leak test (network namespaces + real WireGuard) |
| `.github/workflows/ci-release.yaml` | fmt, clippy, tests, live nftables, e2e (VPN + direct mode), native per-arch image builds and smoke tests, GHCR publishing of the tested images |

## Development

```sh
cd rbittorrent/supervisor
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
NFT_LIVE_TEST=1 unshare -rn cargo test nft_live -- --nocapture   # needs nft
sudo python3 ../tests/e2e_netns.py --supervisor target/release/rbittorrent-supervisor
```

## Releases

Pull requests build and test the images but publish nothing. A push to
`main` publishes the tested images as `edge`. A release is a tag: set
`version` in `rbittorrent/config.yaml` and the changelog, then push the tag
`v<version>` (e.g. `v1.0.0`). CI checks that the tag matches `config.yaml`,
refuses to overwrite a version that is already published, and pushes
exactly the images it smoke-tested as `<version>` and `latest`.

## Credits

[rustTorrent](https://github.com/thedancingdeveloper-org/rusttorrent) (`rtbit`)
is the BitTorrent engine, built from its release source with four small
patches in `rbittorrent/rtbit/`: the mimalloc allocator, a startup-log fix,
a build-only Swagger UI change and an IPv4 fallback for hosts without IPv6.

[repo-badge]: https://img.shields.io/badge/Add%20repository-Home%20Assistant-41BDF5?logo=home-assistant
[repo-add]: https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fevw-sigib%2Fnew_rBitTorrent
