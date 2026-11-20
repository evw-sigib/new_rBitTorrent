# rBittorrent

A **drop-in replacement for the qBittorrent app**. It runs the
[rustTorrent](https://github.com/thedancingdeveloper-org/rusttorrent)
(`rtbit`) engine behind a **fail-closed Proton VPN WireGuard tunnel**, with
automatic **NAT-PMP port forwarding** and a sidebar panel through Home
Assistant Ingress. Other WireGuard providers work too, with a
[static forwarded port](#other-wireguard-providers-static-port).

- Same port as qBittorrent (**8080**) and a qBittorrent-compatible API, so
  Sonarr, Radarr, Prowlarr, qBitController and Home Assistant's qBittorrent
  integration keep working.
- On the first start it **takes over an existing qBittorrent app**: its
  WireGuard file, save folders, user name and categories, and optionally its
  torrents (they keep seeding from where they are).

- A fresh install starts on your **normal connection** and says so loudly,
  in the log and in a bar on top of the sidebar panel. As soon as a
  WireGuard configuration exists, the VPN is on and **fail-closed**: see
  [VPN on or off](#vpn-on-or-off).
- A built-in **speed test** measures your line, the disk and the CPU, see
  [Speed test](#speed-test).

Everything is done by one small Rust program, `rbittorrent-supervisor`,
which runs as PID 1:
- sets up kernel WireGuard,
- loads an nftables kill-switch,
- leases the forwarded port,
- imports qBittorrent,
- starts and stops rtbit,
- serves the sidebar.

The image has no shell scripts and no s6-overlay, OpenVPN, wg-quick, Gluetun
or C NAT-PMP library.

## Before you start

- **A VPN (recommended).** Without one, peers and trackers see your own IP
  address. Best: a **Proton VPN plan with port forwarding** (Plus or
  higher), so other peers can connect to you; see
  [Proton VPN setup](#proton-vpn-setup). Any other WireGuard provider with a
  fixed forwarded port works too. Skip this if your qBittorrent app already
  has a WireGuard file: it is taken over, see
  [Moving from qBittorrent](#moving-from-qbittorrent).
- **Home Assistant OS** (or Supervised) on aarch64 (Raspberry Pi 4/5, ...) or
  amd64. WireGuard is built into the HAOS kernel; the app never loads kernel
  modules. It needs **Supervisor 2026.07 or newer**: the manifest uses the
  `app_config` and `all_app_configs` folder types introduced then, and an
  older Supervisor does not list the app. The Supervisor updates itself, so
  this only matters on a system that has not updated since July 2026.
- rBittorrent is IPv4-only: all IPv6 traffic is dropped, with the VPN on
  or off (see [Leak protection](#leak-protection)), and rtbit opens IPv4
  sockets only. A host booted with `ipv6.disable=1` works too.

## Moving from qBittorrent

1. Install rBittorrent. Do **not** start it yet.
2. Stop the qBittorrent app, and turn off its *Start on boot*. Both apps
   want host port 8080, and they must not seed the same files at once.
3. If you want your torrents to continue, set **Import active torrents** on.
   If your old qBittorrent used its own Web UI password, enter it as
   `webui_password`: then Sonarr and Radarr need no changes at all.
4. Start rBittorrent and open the log. You should see:

```
qBittorrent import: found /app_configs/db21ed7f_qbittorrent (settings: yes, categories: yes, torrents: yes, WireGuard files: 1)
qBittorrent import: copied the WireGuard config .../wireguard/wg0.conf to /config/wg0.conf
...
| qBittorrent     from db21ed7f_qbittorrent: WireGuard, folders /media/torrents (incomplete: /media/torrents/incomplete), Web UI user `pi`, 4 categories, torrents (after rtbit starts)
...
qBittorrent import finished: 4 categories (4 new), 37/38 torrents re-added (verifying existing files)
```

### Where it looks

The app reads, **read-only**, from these places:
- every app configuration folder whose name contains `qbittorrent`
  (`/addon_configs/*qbittorrent*` in Samba; inside the app it is
  `/app_configs`),
- `/share/qBittorrent`,
- `/config/qBittorrent`.

It never changes or deletes anything there.

### What is taken over

| What | From | When |
|---|---|---|
| WireGuard file | `wireguard/*.conf` or any `wg0.conf` in the profile | Only if this app has no `wg0.conf` and the VPN options are empty. Copied to `/config/wg0.conf` (mode 0600) and used as [method 1](#method-1-a-wg0conf-file-recommended). |
| Download folder | `Session\TempPath` if qBittorrent's temp folder was enabled, otherwise its save path (`Session\DefaultSavePath`) | Only while `download_dir` and `completed_dir` are both at their defaults. |
| Completed folder | The save path, if the temp folder was enabled; otherwise none, so torrents stay where they downloaded, as in qBittorrent | As above. |
| Web UI user name | `WebUI\Username` | Only while `webui_username` is `admin`. |
| Categories | `categories.json`, with their save paths | Always; existing categories are left alone. |
| Torrents | `BT_backup/*.torrent` + `.fastresume` (save path, category, layout, paused state) | Only with `import_active_torrents` on. |

- Your own option values always win.
- Folders must be below `/media`, `/share` or `/config`. A folder elsewhere,
  e.g. a qBittorrent-internal `/downloads`, is skipped with a note in the log;
  set the folders yourself then.
- The **password cannot be imported**: qBittorrent stores only a PBKDF2 hash.
  Enter the old password as `webui_password`, or leave it empty and update
  Sonarr/Radarr with the generated one.
- Torrents are re-added at their **old save path**. rtbit verifies the
  existing files and continues seeding without downloading again. A torrent
  whose save path does not exist, e.g. a disk that is not mounted, is
  skipped and listed in the log.
- qBittorrent 5 profiles that store torrents only in `torrents.db` (SQLite)
  are not supported. Their categories and settings are still taken over.
- **OpenVPN is not supported.** If the old app has OpenVPN profiles
  (`*.ovpn`, or `*.conf` in an `openvpn` folder) and no WireGuard file, the
  app keeps VPN mode on and stops with `rBittorrent supports WireGuard only`,
  so nothing starts on your real IP address. Get a WireGuard config from your
  provider (Proton: [Proton VPN setup](#proton-vpn-setup)) and put it in
  `/config/wg0.conf`, or turn off **Import from qBittorrent**.
- The same applies when qBittorrent was bound to a VPN interface
  (`Session\Interface` is `tun0`, `wg0`, `tap0`, `nordlynx`, `proton0`, ...)
  and there is no WireGuard file, e.g. a VPN that ran in another container:
  the log says `was bound to the VPN interface`.
- And to WireGuard files that cannot be used, or an app folder too large to
  scan completely: the import never falls back to the direct connection.
- Category and torrent folders must be ones rtbit may write: below `/media`
  or `/share`, or `download_dir` / `completed_dir` themselves. A category
  elsewhere uses the default folder; such a torrent is skipped (both listed
  in the log).

### Running it once, and again

- After the categories are in rtbit, `/config/.migrated` records what was
  taken over. Later starts apply the same folders and user name, but never
  scan again.
- Imported torrents are recorded in `/config/.torrents_migrated`. You can
  turn `import_active_torrents` on later; it then runs once on the next
  start.
- To import again, delete the file and restart the app.
- If rtbit refuses the sign-in, e.g. after a wrong `webui_password`, nothing
  is recorded and the next start tries again.
- Turn off **Import from qBittorrent** to skip all of this.

### Checks against the Supervisor

The app uses Home Assistant's Supervisor API with the *default* role, the
lowest one, before the kill-switch is loaded:
- **Conflict warning:** if a qBittorrent app is still running, the log shows
  a large `!!` banner. It says when that app holds host port 8080.
- **Discovery:** the app offers itself to Home Assistant's **qBittorrent**
  integration on port 8080. If Home Assistant does not pick it up, add the
  integration yourself: URL `http://<home-assistant-ip>:8080`, with the Web UI
  user name and password.

Both are best effort and never stop the app.

## VPN on or off

The app runs in one of three modes. The log says which one at every start,
and so does the bar on top of the sidebar panel.

| Mode | When | Torrent traffic |
|---|---|---|
| **Direct connection** (VPN off) | A fresh install: `vpn_enabled` off and no WireGuard setup anywhere | Your normal connection. Peers and trackers see your own IP. rtbit listens on `listen_port`. |
| **VPN with NAT-PMP** (Proton) | `vpn_enabled` on, or any WireGuard setup exists | Only through WireGuard, behind the kill-switch. The forwarded port is leased automatically. |
| **VPN with a static port** | As above, with `enable_nat_pmp` off | Only through WireGuard. `listen_port` is opened on the tunnel. For TorGuard, AirVPN, Windscribe and others. |

**The VPN switches itself on.** VPN mode starts as soon as any of these
exists, even with `vpn_enabled` off:
- `/config/wg0.conf` (also one taken over from qBittorrent),
- a pasted `wireguard_conf`,
- any `wg_*` field.

**Fail-closed, never a fallback.** Once VPN mode is on, a broken or
incomplete WireGuard setup stops the app with an error such as
`VPN mode is on (auto-enabled: /config/wg0.conf exists): ...`. A tunnel that
goes down later blocks all torrent traffic until it is back. The app never
falls back to your normal connection. To really go back to the direct
connection, remove the WireGuard setup (delete `/config/wg0.conf`, empty the
WireGuard options) and turn `vpn_enabled` off.

On a direct connection, the log shows this at every start:

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! VPN OFF: rBittorrent uses your normal internet connection.
!! Peers and trackers see your real IP address, and no kill-switch
...
```

- There is no kill-switch and no tunnel. rtbit accepts peers on
  `listen_port` (default 4240) over TCP. Its DHT and UDP trackers use their
  own UDP ports (rtbit's uTP is experimental and stays off).
- For inbound peers, map port 4240/tcp in the app's *Network* section (it
  is empty by default) and forward the same host port on your router.
  Inside the container, port 4240 is redirected to `listen_port`, so the
  mapping works whatever `listen_port` is, and rtbit announces the host
  port you mapped to trackers and the DHT (read from Home Assistant at
  every start; the log says `rtbit announces port ...`). Without a mapping
  the log says `container port 4240 is not published`: you can still
  download, but peers cannot connect to you.
  UPnP stays off: the app never opens router ports by itself.
- The Web UI and API port (8080) still only answers `local_allow_cidrs` and
  Home Assistant's own network; the Ingress port (8099) only answers Home
  Assistant. A small nftables table (`inet direct`) enforces this and drops
  all IPv6, in and out; if it cannot be loaded, the app stops instead of
  starting with the Web UI open.

## Proton VPN setup

1. Go to [account.protonvpn.com](https://account.protonvpn.com) →
   *Downloads* → *WireGuard configuration*:
   - platform **GNU/Linux** (or Router),
   - turn **NAT-PMP (Port Forwarding)** on,
   - pick a **P2P** server (the double-arrow icon). Port forwarding needs
     Proton VPN Plus or higher.
2. Download the `.conf` file. Keep it private: it contains your private
   key.
3. Give it to the app, preferably as `/config/wg0.conf`
   ([method 1](#method-1-a-wg0conf-file-recommended)). In Samba that is
   `addon_configs/<id>_rbittorrent/wg0.conf`. Pasting it into the
   *Configuration* tab works too ([method 2](#method-2-paste-the-configuration)).
4. Leave `enable_nat_pmp` on and `nat_pmp_gateway` at `10.2.0.1`.
5. Restart the app. The log shows `VPN mode (auto-enabled: ...)`,
   `kill-switch active`, `VPN exit verified: public IPv4 ...` and
   `NAT-PMP forwarded port ...`. The sidebar bar turns into a green
   **VPN Protected** pill with the exit IP and the port.

## Other WireGuard providers (static port)

Providers such as **TorGuard**, **AirVPN** and **Windscribe** forward one
fixed port that you choose in their web panel, instead of NAT-PMP.

1. In the provider's panel, create a WireGuard configuration and a forwarded
   port, e.g. `51413`. Some providers tie the port to one server or device:
   use the configuration that belongs to it.
2. Give the `.conf` file to the app, like Proton's (`/config/wg0.conf` or the
   paste field). Its `DNS =` line is used; without one, set `wg_dns` to the
   provider's in-tunnel DNS server.
3. Set **`enable_nat_pmp` off** and **`listen_port`** to the forwarded port.
4. Restart. The log shows
   `static port mode: TCP+UDP 51413 opened on wg0`. The port is part of the
   very first kill-switch ruleset (`@bt_port`), on `wg0` only.

Everything else stays the same: the kill-switch, the DNS lock, the
handshake check before rtbit starts. A provider without any port forwarding
also works. Peers then cannot connect to you, so downloads are slower.

## Setting up the VPN: three methods

The configuration comes from the **first** method that is present. The
fields of method 3 never override it: they only fill in values that file or
paste lacks (for example `wg_dns` for a `.conf` without a `DNS =` line), and
the log says when one is ignored. The log names the method it chose:
`VPN mode (...): WireGuard configuration from ...`.

### Method 1: a `wg0.conf` file (recommended)

Put the Proton file in the app's configuration folder as `wg0.conf`.
- With the *Samba share* or *Studio Code Server* app, that is
  `addon_configs/<id>_rbittorrent/wg0.conf`.
- Inside the app it is `/config/wg0.conf`.

The key stays out of the options page. The qBittorrent import fills in this
file for you.

### Method 2: paste the configuration

Open the file in a text editor, copy everything, and paste it into
**WireGuard configuration (paste)** on the *Configuration* tab.
- Home Assistant sometimes turns the line breaks into spaces. That is fine:
  a single line, or one with `; ` between entries, works too.
- The fields of method 3 only fill in values the paste lacks.

### Method 3: separate fields

| `.conf` line | Option |
|---|---|
| `[Interface] PrivateKey` | `wg_private_key` |
| `[Interface] Address` (the IPv4 one, e.g. `10.2.0.2/32`) | `wg_address` |
| `[Interface] DNS` | `wg_dns` (optional, defaults to `10.2.0.1`) |
| `[Peer] PublicKey` | `wg_public_key` |
| `[Peer] Endpoint` | `wg_endpoint` (e.g. `190.2.131.156:51820`) |
| `[Peer] PresharedKey` | `wg_preshared_key` (Proton does not use one) |

For every method:
- An endpoint hostname is resolved once at startup, before DNS is locked to
  the tunnel, through Home Assistant's own resolver. That resolver (and
  your router or ISP) then sees which VPN server you use. Proton's files
  already contain an IP address; for a hostname, paste its IPv4 address
  instead to avoid the lookup.
- IPv6 addresses are ignored.
- The MTU is 1420 unless the file sets one.
- Keepalive is 25 s.

## Using the Web UI

### Sidebar (Ingress)

Click **rBittorrent** in the sidebar. A small proxy inside the app on port
8099 serves the panel. It:
- **signs you in automatically** with the Web UI account, so there is no
  second login after Home Assistant's,
- keeps all links, API calls and live updates inside
  `/api/hassio_ingress/<token>/`, so the panel never turns blank,
- streams large `.torrent` uploads and downloads; only small HTML pages are
  buffered, to rewrite them,
- shows a self-refreshing "rBittorrent is starting..." page while rtbit
  starts or restarts,
- adds the [status bar](#status-bar) on top of the Web UI,
- answers **only Home Assistant's Supervisor** (172.30.32.2).

The firewall already limits port 8099 to Home Assistant's internal network.
The proxy also refuses other apps there, so they cannot use the automatic
sign-in. Port 8099 is never reachable from your LAN or through the VPN. The
proxy runs as user `nobody`, with no Linux capabilities.

### Status bar

The sidebar panel has a slim bar on top of rtbit's Web UI. It refreshes
every 15 seconds from `/__health`.

- **VPN off:** an orange bar, `🔓 Direct Connection (Unprotected)`, with:
  - **⚡ Speed Test**: see [Speed test](#speed-test),
  - **📘 Proton VPN Setup**: opens [Proton VPN setup](#proton-vpn-setup),
  - **Custom / Static WireGuard**: opens
    [Other WireGuard providers](#other-wireguard-providers-static-port),
  - **✕ Dismiss**: hides the bar for good in this browser (kept in the
    browser's local storage). The log keeps warning.
- **VPN on:** a green pill,
  `🔒 VPN Protected (185.159.156.1 • Port 45678)`, with
  **⚡ Test VPN Speed**. The IP is the exit address NAT-PMP reports, so in
  static port mode only the port is shown. While the tunnel reconnects, the
  pill reads `VPN reconnecting (kill-switch on)`.

The bar lives in its own shadow DOM, so it cannot change rtbit's styling. It
only appears in the sidebar, never on port 8080, so it never gets in the way
of Sonarr or Radarr.

### Speed test

**⚡ Speed Test** in the status bar runs a test of about 10 seconds and
shows the results in a dialog:

| Result | How |
|---|---|
| Download | [Cloudflare's speed test](https://speed.cloudflare.com), 4 parallel HTTPS streams for 6 seconds, counted from the first byte (slow connection setup does not count), over the active route: `wg0` with the VPN, `eth0` without. |
| Latency | Median of 5 small requests, plus the Cloudflare location that answered. |
| Public IP | The address Cloudflare saw: the VPN exit IP when the VPN is on. |
| Disk write | One 4 MiB file in `download_dir`, written, flushed to disk with `fsync` and deleted immediately. |
| SHA-1 hashing | 64 MiB hashed, the piece hash BitTorrent uses. It shows how fast rtbit can verify downloads (ARMv8 crypto or SHA-NI when the CPU has them). |
| Regional peering | VPN off only: TCP connect time to Cloudflare (1.1.1.1), Google (8.8.8.8) and Quad9 (9.9.9.9), best of 3, all three at once. |

- Nothing of the test runs or uses memory until you press the button. The
  threads and buffers are gone again afterwards.
- One test at a time, with 10 seconds between tests.
- It runs as `POST /__benchmark` on port 8099, reachable only through
  Ingress. It only accepts JSON requests from the panel itself.
- With the VPN on but the tunnel down, the kill-switch blocks the download
  test. The dialog says so, and still shows the disk and CPU results.

### On your network (port 8080)

`http://<home-assistant-ip>:8080/web/` serves the same Web UI and rtbit's
**qBittorrent-compatible API**, for:
- Sonarr, Radarr and Prowlarr: download client *qBittorrent*, host = your
  Home Assistant IP, port 8080, the Web UI user name and password,
- Home Assistant's **qBittorrent** integration,
- browsers on your LAN.

It always asks for the user name and password. Only the networks in
`local_allow_cidrs` can reach it, and they only ever get replies: torrent
traffic never leaves through your LAN.

Like qBittorrent with a temp folder, the API reports `completed_dir` as the
save path and `download_dir` as the temp path (without `completed_dir`,
both are `download_dir`). These are the app's own paths (`/media/...`):
Sonarr or Radarr on another machine needs a *Remote Path Mapping* from
them to the same share on that machine.

CI checks the calls these clients make against the real rtbit, inside
both sandboxes (`tests/qbit_api_smoke.py`): login and logout,
`app/version`, `webapiVersion`, `preferences`, `defaultSavePath`,
categories, `.torrent` uploads with a category, save path and `paused`,
`torrents/info` with its filters, `properties`, `files`, `trackers`,
`setCategory`, tags, pause/resume/start/stop/recheck, `transfer/info`,
`sync/maindata` and `delete`. One difference from qBittorrent: rtbit
answers a **magnet** link only once it has the torrent's metadata from
peers (usually a few seconds; with no peers, the request waits and may
time out in Sonarr, which then retries).

To use another host port, change it in the *Network* section of the app
page. Clear it to close the port. Inside the container it stays 8080.

### The Web UI account

- `webui_username` defaults to `admin`, or to the imported qBittorrent user
  name.
- `webui_password`: 8 to 256 characters. Leave it empty and the app
  generates a random 24-character password once, in
  `/config/.webui-password` (mode 0600). The log says where it is, never
  what it is.
- The account is written to rtbit on every start through rtbit's own
  `auth reset-password` command. The password goes on stdin, never on a
  command line or in the environment. To change it, change the option and
  restart.

## Options

| Option | Default | What it does |
|---|---|---|
| `vpn_enabled` | `false` | Force VPN mode. Also switched on automatically by any WireGuard setup, see [VPN on or off](#vpn-on-or-off). |
| `wireguard_conf` | empty | Method 2, see above. |
| `wg_*` | empty | Method 3, see above. |
| `webui_username` | `admin` | Web UI / qBittorrent API account. |
| `webui_password` | empty (generated) | See [The Web UI account](#the-web-ui-account). |
| `import_from_qbittorrent` | `true` | Take over a qBittorrent app on the first start. |
| `import_active_torrents` | `false` | Also re-add its torrents at their old save paths. |
| `enable_dht` | `true` | BitTorrent DHT. Turn off for private trackers that forbid it. |
| `enable_nat_pmp` | `true` | Lease a forwarded port from the VPN gateway (RFC 6886). |
| `nat_pmp_gateway` | `10.2.0.1` | NAT-PMP gateway inside the tunnel (Proton's). |
| `listen_port` | `4240` | BitTorrent port: the direct connection's port, the provider's fixed port with NAT-PMP off, or the port used until the first NAT-PMP lease. |
| `download_dir` | `/media/rbittorrent/downloads` | Incomplete downloads. Below `/media`, `/share` or `/config`. |
| `completed_dir` | `/media/rbittorrent/completed` | Finished torrents are moved here. Same rules. Optional: clear it to keep them in `download_dir`. Only torrents directly in `download_dir` are moved; category folders and paths a client chose stay put. |
| `local_allow_cidrs` | `172.30.32.0/23`, `172.16.0.0/12`, `192.168.0.0/16`, `10.0.0.0/8` | Networks that may reach port 8080. Private IPv4 ranges only; `172.30.32.0/23` is always added. |
| `log_level` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |
| `allow_unsandboxed` | off (optional) | Start even if neither AppArmor nor Landlock can sandbox rtbit, see [Filesystem sandbox](#filesystem-sandbox). Leave it off. |

Notes:
- **USB disk or SSD:** mount it in Home Assistant (*Settings* → *System* →
  *Storage*), then use folders below `/media/<disk name>/`.
- **`10.0.0.0/8` and Proton:** Proton's in-tunnel addresses (`10.2.0.1` for
  DNS and NAT-PMP) are in that range, but they always stay inside the tunnel.
  The LAN list only lets those networks *reach* port 8080.

## Port forwarding (NAT-PMP)

With `enable_nat_pmp` on, the supervisor itself speaks NAT-PMP (RFC 6886,
written in Rust, no libnatpmp):
1. It asks the gateway for its public address, which verifies that traffic
   leaves through Proton.
2. It requests a TCP and a UDP mapping with a 60-second lease, and renews
   them every 45 seconds. Retries start at 250 ms and double, 4 attempts.
3. It opens exactly that port in the kill-switch and starts rtbit with it.
4. If Proton hands out a different port, e.g. after a server-side reset, the
   firewall is updated and rtbit restarts on the new port. The log shows
   `forwarded port changed A -> B` and a fresh status box. Renewals that keep
   the port never restart rtbit.

With `enable_nat_pmp` off, see
[Other WireGuard providers (static port)](#other-wireguard-providers-static-port).

If Proton never answers, the log repeats a hint every 30 minutes. The usual
causes:
- the configuration was generated with *NAT-PMP* off,
- the server is not a P2P server,
- the plan has no port forwarding.

rtbit keeps running on the fallback port meanwhile, with inbound peers
blocked.

## The status box

At startup and whenever the forwarded port changes, the log shows:

```
+------------------------- rBittorrent -------------------------+
| VPN public IP   185.159.156.1 (verified through the tunnel via NAT-PMP)
| Forwarded port  45678 TCP+UDP (NAT-PMP, peers can connect)
| qBittorrent     done earlier (from db21ed7f_qbittorrent)
| CPU cores       4 (rtbit at nice 10, below Home Assistant)
| Storage         412.3 GiB free on /media/torrents/incomplete
+---------------------------------------------------------------+
```

The public IP is the one the VPN gateway reports through the tunnel, not
your home IP. On a direct connection the box says
`VPN OFF: direct connection, your own IP is visible`, and the port line
reads `4240 (direct; map it in the Network section for inbound peers)`.

## Health and the Watchdog

- `GET /__health` on port 8099 returns **200** only while rtbit runs **and**,
  with the VPN on, the WireGuard handshake is recent (under 3 minutes).
  Otherwise it returns **503** with a JSON reason. The JSON also carries
  `vpn`, `port` and `public_ip` for the status bar.
- Turn on *Watchdog* on the app page: Home Assistant then restarts the app
  after two failed checks, which also resolves the VPN server again.
- The Docker `HEALTHCHECK` runs `rbittorrent-supervisor healthcheck`, with
  the same verdict.
- The supervisor restarts rtbit itself if it crashes. If the handshake stays
  stale for 10 minutes, the log shows an error naming the VPN server.

## Disk space guard

Before rtbit starts, and every 10 minutes while it runs, the free space of
`download_dir` is checked. Below **1 GiB** the log shows a large
`LOW DISK SPACE` banner, repeated every hour. On a Raspberry Pi this often
means a USB disk is no longer mounted and the downloads fill the SD card.

## Leak protection

This section is about VPN mode. On a direct connection there is no
kill-switch, see [VPN on or off](#vpn-on-or-off).

The kill-switch is a single nftables table, `inet killswitch`. It is loaded
atomically, with `nft -f -`, **before** the tunnel comes up. It stays in
place while rtbit runs:
- **Default drop** on input, forward and output.
- **All IPv6 is dropped**, right after loopback.
- Named sets:
  - `@bt_port`: the forwarded port (NAT-PMP), or `listen_port` in static
    port mode, already in the first ruleset,
  - `@ui_ports`: `{ 8080, 8099 }`,
  - `@lan_cidrs`: `local_allow_cidrs` plus Home Assistant's network.

| Direction | What is allowed |
|---|---|
| In | Port 8099 from `172.30.32.0/23` only; port 8080 from `@lan_cidrs`; `@bt_port` through `wg0`; replies. |
| Out | Replies from `@ui_ports` to `@lan_cidrs` (`ct state established,related`); the encrypted WireGuard packets to the one VPN server (kernel fwmark); everything else only through `wg0`. |
| DNS | Only to the tunnel's DNS servers, through `wg0`. `/etc/resolv.conf` is replaced too. |

Routing:
- Only the VPN server's address (`/32`) and your LAN ranges use the normal
  gateway.
- Everything else goes through `wg0`, as two `/1` routes.
- rtbit starts only after a WireGuard handshake is verified.

rtbit itself runs without any network capability and with `no_new_privs`;
it keeps only the four file capabilities root needs on shared storage
(`CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`). A
[filesystem sandbox](#filesystem-sandbox) (AppArmor, plus Landlock where the
kernel has it) limits it to `/media`, `/share` and its own state: `/data`,
`/app_configs` and the WireGuard key in `/config` are out of reach. Its UPnP, LSD and IPv6 are off. (rtbit remembers a download
folder chosen in its own Web UI, and that choice wins over `download_dir`;
keep it under `/media` or `/share`, or the sandbox refuses the writes.) If the tunnel goes down, traffic stops: nothing falls back
to your normal connection.

CI tests this in the kernel, on both architectures, with the binaries from
the image: rtbit downloads a torrent through a real WireGuard tunnel from
a seeder behind it. The tracker there sees only the tunnel address and the
NAT-PMP port, a tracker on the LAN hears nothing, every rtbit socket is
bound to `wg0`, and the router counts no packet from the app other than
WireGuard, Web UI replies and the one call to the Supervisor API.

To check it yourself:
1. Add a magnet with a tracker that reports your IP, e.g. *ipleak.net* →
   *Torrent Address detection*. Only the VPN IP from the status box may
   appear.
2. Revoke the WireGuard key in your Proton account. Downloads stop and
   `/__health` turns 503.

## Performance notes

- The supervisor and the Ingress proxy each use a single-threaded runtime
  and about 4 MiB of RAM (resident, measured in CI on aarch64 and amd64).
  rtbit itself uses about 21 to 26 MiB idle, 32 to 38 MiB with 30
  paused torrents, and 28 to 42 MiB right after it downloaded a torrent
  through the tunnel and while it seeds it.
- rtbit yields to Home Assistant: it runs at `nice` 10 and the lowest
  best-effort I/O priority, so hashing and peer I/O on a Pi never starve
  Core or the supervisor's health checks. Its limits follow the board:
  pieces of at most `cores / 2` torrents (1 to 5) are checked at once at
  startup, its blocking pool has `2 × cores` threads (4 to 8), and each
  torrent talks to at most 100 peers. The DHT routing table is saved every
  15 minutes instead of every minute, to spare the SD card.
- Both are built with `opt-level = 3`, fat LTO, one codegen unit, static musl
  and the **mimalloc** allocator. mimalloc's transparent-huge-page hint is
  off, because it quadrupled idle memory.
- **rtbit is compiled from source** in the image build: the pinned upstream
  release `v0.2.0-beta.4`, commit-checked. The one change to how it runs:
  **mimalloc** as its global allocator (`rtbit/mimalloc.patch`). musl's own
  allocator makes all threads wait on one lock and keeps freed memory.
  mimalloc uses per-thread heaps and returns memory to the kernel, so rtbit
  scales over all cores and shrinks again after a burst, which matters on a
  4 GB Pi. It is built with `opt-level = 3`, thin LTO and one codegen unit.
  Two more small patches: `rtbit/auth-banner.patch` makes rtbit's startup
  log say `auth: enabled` for the login the supervisor stored (upstream
  printed "not set up" although the API was protected), and the build-only
  `rtbit/swagger-vendored.patch` takes the Swagger UI page from a
  checksum-pinned crate. `rtbit/ipv4-fallback.patch` makes rtbit's
  IPv4-only mode open IPv4 sockets for the DHT and the UDP tracker client
  (upstream opened `[::]` and exited at once on a host booted with
  `ipv6.disable=1`). `rtbit/completed-move.patch` moves a finished torrent
  to `completed_dir` only when it lies in `download_dir`: upstream also
  moved torrents saved elsewhere (category folders, imported torrents,
  paths Sonarr/Radarr chose) and flattened them into `completed_dir`, again
  at every restart. The torrent now moves with its files and keeps seeding:
  upstream left it pointing at `download_dir`, so the API gave Sonarr and
  Radarr the old path and the next start looked for the files there. A
  `completed_dir` on another filesystem works too (the files are copied). `rtbit/qbit-save-path.patch` makes the qBittorrent
  API report `completed_dir` as the save path and `download_dir` as the
  temp path, the way qBittorrent reports a temp folder (upstream reported
  `download_dir`, where finished torrents no longer are). Everything the
  build downloads is pinned: crates by
  `Cargo.lock`, and the Web UI's npm packages (rtbit's build runs `npm ci`)
  by upstream's `package-lock.json`. The patches apply in this order, as
  the Dockerfile does: `mimalloc`, `auth-banner`, `swagger-vendored`,
  `ipv4-fallback`, `completed-move`, `qbit-save-path` (each later one
  expects the earlier ones' changes).
- Its SHA-1 piece hashing picks ARMv8 or SHA-NI instructions at runtime. No
  `target-cpu` flags are set, so it also runs on a Raspberry Pi 3 or 4.
- The [speed test](#speed-test) costs nothing while idle: its threads and
  buffers exist only while it runs.
- The proxy sets `TCP_NODELAY` on both sides and streams every body. Only
  HTML pages up to 4 MiB are buffered, for the Ingress rewrite.
- WireGuard stays at MTU 1420.
- The supervisor tries to raise `net.core.rmem_max` and `wmem_max` to 7 MiB
  for fast UDP (DHT, UDP trackers). Home Assistant mounts `/proc/sys` read-only, so
  the log normally says `read-only here`. That is harmless.
- At `log_level: info`, rtbit's per-peer and DHT logs are limited to
  warnings (`RUST_LOG=info,librtbit=warn`), sparing SD cards. Use `debug` to
  see everything.

## Security summary

- **Capabilities:** `NET_ADMIN` only. No `SYS_ADMIN`, `SYS_MODULE`,
  `full_access` or host network.
- **Supervisor API:** `hassio_api` with the default role, for the conflict
  warning and discovery. The Supervisor token never reaches rtbit.
- **Other apps' folders:** mapped read-only (`all_app_configs`), only to find
  a qBittorrent profile.
- **Devices:** none. Kernel WireGuard does not need `/dev/net/tun`.
- **AppArmor:** the app's own profile confines rtbit and the Ingress proxy,
  see [Filesystem sandbox](#filesystem-sandbox).
- **Secrets:** the WireGuard private key goes to `wg` on stdin only, never on
  a command line, in the environment or in the log. The Web UI password
  follows the same rule.
- **Processes:** rtbit has no network capability, only the four file
  capabilities listed above; the proxy runs as uid 65534 with none at all.
  Both run with `no_new_privs`.
- **Filesystem sandbox:** rtbit may write only to `/media`, `/share` and its
  own state, and the Ingress proxy may write nowhere. The app does not start
  without the sandbox, see [Filesystem sandbox](#filesystem-sandbox).
- **The supervisor's secrets:** the Supervisor token is wiped from the
  process environment at start, and the supervisor is not dumpable, so rtbit
  (root, but without `CAP_SYS_PTRACE`) cannot read its environment or
  memory.
- **Direct connection:** without a VPN, the app runs without a kill-switch
  and says so in the log and the sidebar. Any WireGuard setup switches the
  VPN on, and from then on it never falls back.
- **Speed test:** contacts only `speed.cloudflare.com` (and, with the VPN
  off, 1.1.1.1, 8.8.8.8 and 9.9.9.9 for a TCP connect), and only when you
  press the button.

## Filesystem sandbox

rtbit runs as root with `CAP_DAC_OVERRIDE` so it can manage files other apps
wrote to `/media` and `/share`. File permissions alone therefore cannot keep
it away from your secrets. Two kernel features confine it by path instead,
and the app uses every one the kernel has:

- **AppArmor** (Home Assistant OS, and Supervised installs on Debian). The
  app ships its own profile, `apparmor.txt`, which Home Assistant loads for
  it. rtbit and the Ingress proxy switch to child profiles of it
  (`<slug>//rtbit`, `<slug>//ingress`) as they start, before they set
  `no_new_privs` and run their binary, and the supervisor checks each
  child's profile before it trusts it. Home Assistant OS kernels have
  AppArmor but no Landlock, so this is the sandbox there.
- **Landlock** (Linux 5.19 or newer with Landlock among the kernel's security
  modules, as on most current desktop and server distributions). It narrows
  rtbit to the exact folders it was given.

What rtbit can reach:

- read and write: `/media`, `/share` and its own database and cache in
  `/config/db` and `/config/cache` (with Landlock: only `/media`, `/share`,
  its download and completed folders, and the database and cache);
- read only: `/etc`, `/proc`, `/sys`, `/dev` and the system folders it
  starts from;
- nothing else. `/config/wg0.conf`, `/config/.webui-password`,
  `/data/options.json`, every other app's folder in `/app_configs`, and the
  supervisor's memory and environment are out of reach, even for root.

The Ingress proxy gets a stricter policy: it may write nowhere, and AppArmor
also keeps it off the network except for TCP and UDP.

The supervisor checks every start: it reads the label of each child it
started and stops the child if it is not in its child profile. The log says
which sandbox is active:

```text
AppArmor profile `<slug>` confines the app; rtbit and the Ingress proxy start in its child profiles
rtbit filesystem sandbox active (AppArmor `<slug>//rtbit`): ...
```

With Landlock as well, the second line reads `(AppArmor ... + Landlock ABI
N)`. `/__health` reports `"fs_sandbox": true`. A download folder you pick in
rtbit's own Web UI must stay below `/media` or `/share`, or rtbit cannot
write to it.

**Fails closed.** When neither AppArmor nor Landlock can confine rtbit (for
example a Supervised install whose host has AppArmor off, or a kernel without
Landlock), the app refuses to start and says why, with the VPN on or off.
If you accept the risk, enable *Show unused optional configuration options*,
set `allow_unsandboxed: true` and start the app again. An unsandboxed rtbit
is then logged at every start, and the sidebar's status bar shows
**⚠ No filesystem sandbox** (it cannot be dismissed).

## Troubleshooting

| Log message | Meaning |
|---|---|
| `VPN mode is on (...)` followed by an error | A WireGuard setup exists but is incomplete or broken. The app stops instead of running unprotected. Fix the file or options, or remove them all for the direct connection. |
| `no WireGuard private key configured` (or endpoint, address, ...) | VPN mode is on, but no method is filled in, or the value is missing from your file. |
| `rBittorrent supports WireGuard only` | Your old qBittorrent app used OpenVPN. See [What is taken over](#what-is-taken-over). |
| `VPN OFF: rBittorrent uses your normal internet connection` | No WireGuard setup was found. See [Proton VPN setup](#proton-vpn-setup). |
| `qBittorrent is still running` | Stop the old app and turn off its *Start on boot*. |
| `qBittorrent import: ... is outside /media, /share and /config` | Set `download_dir` / `completed_dir` yourself. |
| `... is outside the folders rtbit may write` | A qBittorrent category or torrent used a folder the sandbox does not allow (below `/config`, but not `download_dir` or `completed_dir`). The category uses the default folder; the torrent is skipped. Move the data below `/media` or `/share`. |
| `rtbit refused the Web UI login` | The import retries on the next start. Check `webui_username` / `webui_password`. |
| `no WireGuard handshake with ...` | Wrong key or endpoint, or the configuration was revoked in your Proton account. Generate a new one. |
| `has not answered for 10 minutes` | The Proton server is down or your key was revoked. Restart the app, or use another server. |
| `Proton VPN did not grant a forwarded port` | See [Port forwarding](#port-forwarding-nat-pmp). |
| `the filesystem sandbox is not available` | Neither the app's AppArmor profile nor Landlock is active, so the app stops. See [Filesystem sandbox](#filesystem-sandbox). |
| `rtbit is not confined` / `the Ingress proxy is not confined` | The child did not switch to its AppArmor child profile (an outdated or edited `apparmor.txt`). Rebuild or update the app. |
| `LOW DISK SPACE` | See [Disk space guard](#disk-space-guard). |
| Sidebar shows *rBittorrent is starting...* for minutes | rtbit keeps exiting. Check the log, e.g. for a folder on a missing disk. |
| Sonarr gets `401` / `403` | Wrong user name or password, or Sonarr's IP is not in `local_allow_cidrs`. |

When reporting a problem, include the log at `log_level: debug`. It never
contains keys or passwords.

## Credits

The BitTorrent engine is
[rustTorrent](https://github.com/thedancingdeveloper-org/rusttorrent)
(`rtbit`), built from its release source with six small patches: the
mimalloc allocator, a startup-log fix, Swagger UI from the checksum-pinned
`utoipa-swagger-ui-vendored` crate instead of a download at build time,
an IPv4 fallback for hosts without IPv6, a fix for moving finished
torrents, and the save path the qBittorrent API reports.
