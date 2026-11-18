# rBittorrent

[rustTorrent](https://github.com/thedancingdeveloper-org/rusttorrent) (`rtbit`)
running behind a **fail-closed Proton VPN WireGuard tunnel**, with automatic
**NAT-PMP port forwarding** and a sidebar panel through Home Assistant
Ingress.

Everything is done by one small Rust program, `rbittorrent-supervisor`, which runs as
PID 1. It sets up kernel WireGuard, loads an nftables kill-switch, leases the
forwarded port, and starts and stops rtbit. There are no shell scripts and no
s6-overlay, OpenVPN, wg-quick, Gluetun or C NAT-PMP library in the image.

## Before you start

- **Proton VPN plan with port forwarding** (Plus or higher) if you want other
  peers to be able to connect to you. Without it, downloads still work but
  are slower, and you should switch `enable_nat_pmp` off.
- **A WireGuard configuration from Proton**:
  [account.protonvpn.com](https://account.protonvpn.com) → *Downloads* →
  *WireGuard configuration*:
  - platform **GNU/Linux** (or Router),
  - turn **NAT-PMP (Port Forwarding)** on,
  - pick a **P2P** server (the double-arrow icon). Leave *VPN Accelerator*
    and *Moderate NAT* as you like.

  Keep the file private: it contains your private key.
- **Home Assistant OS** (or Supervised) on aarch64 (Raspberry Pi 4/5, ...) or
  amd64. WireGuard is built into the HAOS kernel. Nothing has to be loaded
  and the app never asks for `SYS_MODULE`.
- Do not boot the host with `ipv6.disable=1`: rtbit needs IPv6 *sockets* to
  start. All IPv6 *traffic* is still dropped, see [Leak protection](#leak-protection).

## Setting up the VPN: three methods

The app uses the **first** method that is present and ignores the others. The
log names the method it chose (`WireGuard configuration from ...`).

### Method 1: a `wg0.conf` file (recommended)

Copy the Proton file to the app's configuration folder as `wg0.conf`.
- With the *Samba share* or *Studio Code Server* app, the folder is
  `addon_configs/<id>_rbittorrent/`.
- Inside the app it is `/config/wg0.conf`.

The key then stays out of the app's options page.

### Method 2: paste the configuration

Open the file in a text editor, copy everything, and paste it into **WireGuard
configuration (paste)** on the *Configuration* tab.
- Home Assistant sometimes turns the line breaks into spaces. That is fine: a
  single line, or entries separated by `; `, is understood too.
- The structured fields below (method 3) only fill in values the paste does
  not contain.

### Method 3: separate fields

Copy the values from the `.conf` file into the fields:

| `.conf` line | Option |
|---|---|
| `[Interface] PrivateKey` | `wg_private_key` |
| `[Interface] Address` (the IPv4 one, e.g. `10.2.0.2/32`) | `wg_address` |
| `[Interface] DNS` | `wg_dns` (optional, defaults to `10.2.0.1`) |
| `[Peer] PublicKey` | `wg_public_key` |
| `[Peer] Endpoint` | `wg_endpoint` (e.g. `190.2.131.156:51820`) |
| `[Peer] PresharedKey` | `wg_preshared_key` (Proton does not use one) |

Details that apply to every method:
- An endpoint hostname is resolved once at startup, before DNS is locked to
  the tunnel.
- IPv6 addresses in the configuration are ignored.
- The MTU is 1420 unless the configuration sets one.
- Keepalive is 25 s.

## Using the Web UI

### Sidebar (Ingress)

Click **rustTorrent** in the sidebar. The panel is served by a small proxy
inside the app on port 8099. The proxy:
- **signs you in automatically** with the Web UI account, so there is no
  second login after Home Assistant's,
- keeps all links, API calls and live updates inside
  `/api/hassio_ingress/<token>/`, so the panel never shows a blank page,
- streams large `.torrent` uploads and downloads instead of buffering them,
- shows a "rBittorrent is starting..." page that refreshes itself while rtbit
  starts or restarts,
- answers **only Home Assistant's Supervisor (172.30.32.2)**. The firewall
  already limits port 8099 to Home Assistant's internal network; the proxy
  also refuses other apps on that network, so they cannot use the automatic
  sign-in. Port 8099 is never reachable from your LAN or through the VPN.

The proxy runs as an unprivileged user (`nobody`) with no Linux capabilities.

### Directly on your network (port 8080)

`http://<home-assistant-ip>:8080/web/` serves the same Web UI and rtbit's
**qBittorrent-compatible API**, for:
- Sonarr, Radarr and Prowlarr (download client type *qBittorrent*, host = your
  Home Assistant IP, port 8080),
- Home Assistant's **qBittorrent** integration,
- browsers on your LAN.

This port always asks for the Web UI username and password. Only the networks
in `local_allow_cidrs` can reach it, and they only ever get replies: torrent
traffic never leaves through your LAN. To turn the port off, clear the host
port on the *Network* section of the app page.

### The Web UI account

- `webui_username` defaults to `admin`.
- `webui_password`: set your own, 8 to 256 characters. If you leave it empty,
  the app generates a random 24-character password once and stores it in
  `/config/.webui-password` (file mode 0600). The log tells you where it is,
  but never prints the password itself.
- The account is written to rtbit on every start, through rtbit's own
  `auth reset-password` command. The password goes on stdin, never on a
  command line or in the environment. Changing the option and restarting the
  app is therefore all it takes to change the password.

## Options

| Option | Default | What it does |
|---|---|---|
| `wireguard_conf` | empty | Method 2, see above. |
| `wg_*` | empty | Method 3, see above. |
| `webui_username` | `admin` | Web UI / qBittorrent API account. |
| `webui_password` | empty (generated) | See [The Web UI account](#the-web-ui-account). |
| `enable_dht` | `true` | BitTorrent DHT. Turn off for private trackers that forbid it. |
| `enable_nat_pmp` | `true` | Lease a forwarded port from the VPN gateway (RFC 6886). |
| `nat_pmp_gateway` | `10.2.0.1` | NAT-PMP gateway inside the tunnel (Proton's). |
| `listen_port` | `4240` | BitTorrent port while there is no lease, or with NAT-PMP off. |
| `download_dir` | `/media/rbittorrent/downloads` | Incomplete downloads. Below `/media`, `/share` or `/config`. |
| `completed_dir` | `/media/rbittorrent/completed` | Finished torrents. Same rules. |
| `local_allow_cidrs` | private ranges | LAN networks allowed to reach port 8080. Only private IPv4 ranges are accepted, and `172.30.32.0/23` is always added. |
| `log_level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |

Downloads to a USB disk or SSD: mount it in Home Assistant (*Settings* →
*System* → *Storage*), then point `download_dir` and `completed_dir` below
`/media/<disk name>/`.

## Port forwarding (NAT-PMP)

With `enable_nat_pmp` on, the supervisor itself speaks NAT-PMP (RFC 6886,
written in Rust, no libnatpmp):
1. It asks the gateway (`10.2.0.1`) for a TCP and a UDP mapping with a
   60-second lease, and renews it every 45 seconds.
2. It opens exactly that port in the kill-switch and starts rtbit with it.
3. If Proton hands out a different port (after a server-side reset), the
   firewall is updated and rtbit is restarted on the new port, cleanly. The
   log shows `forwarded port changed A -> B` and a fresh status box.

If Proton never answers, the log repeats a hint every 30 minutes. The usual
causes are:
- the configuration was generated with *NAT-PMP* off,
- the server is not a P2P server,
- the plan has no port forwarding.

rtbit keeps running on the fallback port in the meantime, but inbound peers
are blocked.

## The startup status box

At startup and every time the forwarded port changes, the log shows:

```
+------------------------- rBittorrent -------------------------+
| VPN public IP   185.159.156.1 (verified through the tunnel via NAT-PMP)
| Forwarded port  45678 TCP+UDP (NAT-PMP, peers can connect)
| CPU cores       4 (all available to rtbit)
| Storage         412.3 GiB free on /media/rbittorrent/downloads
+---------------------------------------------------------------+
```

The public IP is the one the VPN gateway reports through the tunnel, not
your home IP.

## Health and the Watchdog

- `GET /__health` on port 8099 returns **200** only when rtbit is running
  **and** the WireGuard handshake is recent (under 3 minutes). Otherwise it
  returns **503** with a JSON reason.
- `config.yaml` points Home Assistant's **Watchdog** at it. Turn on
  *Watchdog* on the app page and Home Assistant restarts the app after two
  failed checks. A restart also resolves the VPN server again.
- The Docker `HEALTHCHECK` runs `rbittorrent-supervisor healthcheck`, which gives the
  same verdict.
- Independently, the supervisor restarts rtbit itself if it crashes. If the
  handshake stays stale for 10 minutes, the log shows an error that names
  the VPN server.

## Disk space guard

Before rtbit starts, and every 10 minutes while it runs, the free space on
`download_dir` is checked. Below **1 GiB** the log shows a large
`LOW DISK SPACE` banner, repeated every hour. A common cause on a Raspberry
Pi is a USB disk that is no longer mounted, so the downloads fill the SD card.

## Leak protection

The kill-switch is a single nftables table, `inet killswitch`. It is loaded
atomically **before** the tunnel comes up and stays in place while rtbit
runs:
- **Default drop** in both directions.
- **All IPv6 is dropped**, inbound and outbound.
- **Outbound** traffic may only:
  - go into `wg0`,
  - be the encrypted WireGuard packets to the one VPN server (marked by the
    kernel),
  - be replies on port 8080 to the allowed LAN networks,
  - be replies on port 8099 to the Supervisor's network.
- **Inbound** traffic may only:
  - reach the forwarded port through `wg0`,
  - reach port 8080 from the allowed LAN networks,
  - reach port 8099 from `172.30.32.0/23`,
  - be replies.
- **DNS** is pinned to the tunnel's DNS server. The container's
  `/etc/resolv.conf` is replaced, and nothing else may reach port 53.
- rtbit itself runs without capabilities and with `no_new_privs`, and its
  UPnP, LSD and IPv6 are switched off.
- If the tunnel goes down, traffic stops. Nothing falls back to your normal
  connection.

To verify the protection from your own setup:
1. Add a magnet with a tracker that reports your IP, e.g. *ipleak.net* →
   *Torrent Address detection*. Only the VPN IP from the status box may
   appear.
2. Stop the VPN server side, e.g. by deleting the WireGuard key in your
   Proton account. Downloads stop, and `/__health` turns 503.

## Performance notes

- The supervisor and the Ingress proxy each use a single-threaded runtime
  and about 2 MB of RAM (measured: 1.9 MB idle, 2.6 MB after 400 proxied
  requests). rtbit's own thread pool is not limited: it uses every CPU core
  the container gets.
- Both are built with `opt-level = 3`, fat LTO, one codegen unit, static musl
  and the **mimalloc** allocator. mimalloc's transparent-huge-page hint is
  off, because it quadrupled idle memory.
- rtbit is the upstream static musl binary, pinned by digest. Its SHA-1 piece
  hashing already picks ARMv8 or SHA-NI instructions at runtime. The image
  sets no `target-cpu` flags, so it also runs on a Raspberry Pi 3 or 4.
- The proxy sets `TCP_NODELAY` on both sides and streams every body. Only
  HTML pages up to 4 MiB are buffered, because they are rewritten for
  Ingress.
- WireGuard stays at MTU 1420.
- The supervisor tries to raise `net.core.rmem_max` and `net.core.wmem_max`
  to 7 MiB for fast UDP (uTP, DHT). Home Assistant mounts `/proc/sys`
  read-only inside apps, so the log normally says `read-only here`. That is
  expected and harmless.
- At `log_level: info`, rtbit's chatty per-peer and DHT logs are limited to
  warnings, which saves SD card writes. Use `debug` to see everything.

## Security summary

- The app asks for `NET_ADMIN` only. It uses no `SYS_ADMIN`, `SYS_MODULE`,
  `full_access` or host network.
- `/dev/net/tun` is mapped as the app policy requires. Kernel WireGuard does
  not use it.
- The WireGuard private key is handed to `wg` on stdin only. It is never in
  a command line, the environment or the log.
- The Web UI password follows the same rule.
- The proxy, rtbit and helper processes run without capabilities. The proxy
  also runs as uid 65534.

## Troubleshooting

| Log message | Meaning |
|---|---|
| `no WireGuard private key configured` (or endpoint, address, ...) | None of the three methods is filled in, or the value is missing from your file. |
| `no WireGuard handshake with ...` | Wrong key or endpoint, or the configuration was revoked in your Proton account. Generate a new one. |
| `has not answered for 10 minutes` | The Proton server is down or your key was revoked. Restart the app, or generate a configuration for another server. |
| `Proton VPN did not grant a forwarded port` | See [Port forwarding](#port-forwarding-nat-pmp). |
| `rtbit needs IPv6 sockets to start` | Remove `ipv6.disable=1` from the host kernel command line. |
| `LOW DISK SPACE` | See [Disk space guard](#disk-space-guard). |
| Sidebar says *rBittorrent is starting...* for minutes | rtbit keeps exiting. Check the log, e.g. a download folder that does not exist on a missing disk. |
| Sonarr gets `401` / `403` | Wrong Web UI username or password, or Sonarr's IP is not in `local_allow_cidrs`. |

Report problems with the log at `log_level: debug`. It never contains keys or
passwords.
