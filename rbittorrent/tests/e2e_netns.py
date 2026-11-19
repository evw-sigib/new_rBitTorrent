#!/usr/bin/env python3
"""Kernel end-to-end test of rbittorrent-supervisor (CI only; needs root + WireGuard).

Topology (three network namespaces, nothing touches the host network):

    e2e-cli (the app)          e2e-rtr (LAN router)        e2e-inet ("internet")
    eth0 10.99.0.2/24 <------> lan0 10.99.0.1/24
                               wan0 198.51.100.254/24 <--> eth0 198.51.100.1/24
                                                           wgs  10.2.0.1/24 (WireGuard
                                                                server, NAT-PMP, canaries)

The real supervisor runs in e2e-cli with a stand-in rtbit (fake_rtbit.py).
The test checks the kill-switch from the outside: nothing may leave e2e-cli
except the WireGuard envelope and Web UI replies to the LAN.

The app starts with no VPN options at all: it takes the WireGuard file,
folders, user name, categories and torrents over from a fake qBittorrent
app's config folder, the way a real user moving from qBittorrent would
(the copied wg0.conf switches VPN mode on by itself).

A second scenario starts a fresh install with no WireGuard setup anywhere:
the direct connection (VPN off) must run rtbit on `listen_port` without a
kill-switch, a tunnel or NAT-PMP, and say loudly that it is unprotected.

Usage: sudo python3 e2e_netns.py --supervisor PATH [--keep]
"""

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

NS_CLI, NS_RTR, NS_INET = "e2e-cli", "e2e-rtr", "e2e-inet"
WORK = Path("/tmp/rbittorrent-e2e")
MEDIA = Path("/media/rbittorrent-e2e")
ENDPOINT_IP = "198.51.100.1"
TUNNEL_GW = "10.2.0.1"
CLIENT_TUNNEL_IP = "10.2.0.2"
# What the fake NAT-PMP gateway reports as the exit IP (never contacted).
PUBLIC_EXIT_IP = "185.159.156.1"
LAN_SERVICE_PORT = 8082
INGRESS_PORT = 8099
# Home Assistant's Supervisor (Ingress + watchdog) and another app's address.
SUPERVISOR_IP, OTHER_APP_IP = "172.30.32.2", "172.30.32.3"
DIRECT_LISTEN_PORT = 51413
PORT_A, PORT_B = 45678, 45679
CANARY_TCP, CANARY_UDP = 8081, 53

# The old qBittorrent app's config folder (as mounted at /app_configs).
LEGACY_SLUG = "db21ed7f_qbittorrent"
LEGACY_USER = "legacyadmin"
QBT_SAVE = MEDIA / "qbt"
QBT_TEMP = MEDIA / "qbt" / "incomplete-qbt"
QBT_TV = MEDIA / "qbt" / "tv"
HASH_OK, HASH_GONE = "a" * 40, "b" * 40

HERE = Path(__file__).resolve().parent
FAILURES = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def sh(*cmd, ns=None, check=True, input_text=None, timeout=30):
    full = (["ip", "netns", "exec", ns] if ns else []) + list(cmd)
    r = subprocess.run(
        full, input=input_text, capture_output=True, text=True, timeout=timeout
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(full)} failed ({r.returncode}): {r.stderr.strip()}")
    return r


def step(msg):
    print(f"\n=== {msg}", flush=True)


def check(cond, msg):
    if cond:
        print(f"  PASS  {msg}", flush=True)
    else:
        print(f"  FAIL  {msg}", flush=True)
        FAILURES.append(msg)
    return cond


def wait_for(pred, timeout, what, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = pred()
        if v:
            return v
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout}s waiting for {what}")


def tcp_probe(ns, ip, port, timeout=3):
    code = (
        "import socket,sys\n"
        f"s=socket.socket();s.settimeout({timeout})\n"
        "try:\n"
        f"  s.connect(({ip!r},{port}));print('open')\n"
        "except Exception as e:\n"
        "  print('closed',type(e).__name__,e)\n"
    )
    out = sh("python3", "-c", code, ns=ns, check=False, timeout=timeout + 10).stdout.strip()
    return out.startswith("open"), out


def udp_send(ns, ip, port, payload=b"leak-probe"):
    code = (
        "import socket\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "try:\n"
        f"  s.sendto({payload!r},({ip!r},{port}));print('sent')\n"
        "except Exception as e:\n"
        "  print('blocked',type(e).__name__,e)\n"
    )
    return sh("python3", "-c", code, ns=ns, check=False).stdout.strip()


def http_get(ns, src, ip, port, path, timeout=5):
    """(status, body) of a plain HTTP GET sent from `src`, or (None, error)."""
    code = (
        "import socket,sys\n"
        f"s=socket.create_connection(('{ip}',{port}),timeout={timeout},source_address=('{src}',0))\n"
        f"s.sendall(b'GET {path} HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n')\n"
        "d=b''\n"
        "while True:\n"
        "  c=s.recv(65536)\n"
        "  if not c: break\n"
        "  d+=c\n"
        "sys.stdout.write(d.decode('utf-8','replace'))\n"
    )
    r = sh(sys.executable, "-c", code, ns=ns, check=False, timeout=timeout + 5)
    if r.returncode != 0:
        return None, (r.stderr.strip().splitlines() or ["?"])[-1]
    # sh() captures in text mode, which already turned CRLF into LF.
    head, _, body = r.stdout.replace("\r\n", "\n").partition("\n\n")
    try:
        return int(head.split()[1]), body
    except (IndexError, ValueError):
        return None, head


def proc_status_of(cmd_fragment):
    """/proc/<pid>/status of the first process whose cmdline contains the fragment."""
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            cmdline = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode()
            if cmd_fragment in cmdline:
                return (d / "status").read_text()
        except OSError:
            continue
    return ""


def wg_keypair():
    priv = sh("wg", "genkey").stdout.strip()
    pub = sh("wg", "pubkey", input_text=priv + "\n").stdout.strip()
    return priv, pub


# --------------------------------------------------------------------------
# "internet" side services (run inside e2e-inet via --role inet)
# --------------------------------------------------------------------------


def inet_services(state_path: Path, switch_path: Path):
    """NAT-PMP gateway on 10.2.0.1:5351 plus TCP/UDP canaries on all addresses."""
    lock = threading.Lock()
    state = {"pmp": [], "tcp": [], "udp": []}
    start = time.monotonic()

    def save():
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(state_path)

    def epoch():
        return int(time.monotonic() - start) + 1000

    def natpmp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((TUNNEL_GW, 5351))
        while True:
            data, addr = s.recvfrom(64)
            if len(data) < 2 or data[0] != 0:
                continue
            op = data[1]
            if op == 0 and len(data) == 2:
                reply = struct.pack("!BBHI4s", 0, 128, 0, epoch(), socket.inet_aton(PUBLIC_EXIT_IP))
                rec = {"op": 0}
            elif op in (1, 2) and len(data) == 12:
                _, _, _, internal, suggested, lifetime = struct.unpack("!BBHHHI", data)
                port = PORT_B if switch_path.exists() else PORT_A
                reply = struct.pack("!BBHIHHI", 0, 128 + op, 0, epoch(), internal, port, lifetime)
                rec = {"op": op, "internal": internal, "suggested": suggested, "lifetime": lifetime}
            else:
                continue
            rec["src"] = addr[0]
            with lock:
                state["pmp"].append(rec)
                save()
            s.sendto(reply, addr)

    def tcp_canary():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", CANARY_TCP))
        s.listen(16)
        while True:
            c, addr = s.accept()
            with lock:
                state["tcp"].append({"src": addr[0], "dst": c.getsockname()[0]})
                save()
            c.close()

    def udp_canary():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO
        s.bind(("0.0.0.0", CANARY_UDP))
        while True:
            _, anc, _, addr = s.recvmsg(512, 64)
            dst = "?"
            for level, typ, d in anc:
                if level == socket.IPPROTO_IP and typ == 8:
                    dst = socket.inet_ntoa(d[8:12])
            with lock:
                state["udp"].append({"src": addr[0], "dst": dst})
                save()

    with lock:
        save()
    for fn in (natpmp, tcp_canary, udp_canary):
        threading.Thread(target=fn, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        time.sleep(3600)


# --------------------------------------------------------------------------
# setup / teardown
# --------------------------------------------------------------------------


def cleanup():
    for ns in (NS_CLI, NS_RTR, NS_INET):
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
    shutil.rmtree(MEDIA, ignore_errors=True)


def setup_network(cli_pub):
    for ns in (NS_CLI, NS_RTR, NS_INET):
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)

    sh("ip", "link", "add", "e2e-c", "type", "veth", "peer", "name", "e2e-rl")
    sh("ip", "link", "set", "e2e-c", "netns", NS_CLI)
    sh("ip", "link", "set", "e2e-rl", "netns", NS_RTR)
    sh("ip", "link", "set", "e2e-c", "name", "eth0", ns=NS_CLI)
    sh("ip", "link", "set", "e2e-rl", "name", "lan0", ns=NS_RTR)

    sh("ip", "link", "add", "e2e-rw", "type", "veth", "peer", "name", "e2e-i")
    sh("ip", "link", "set", "e2e-rw", "netns", NS_RTR)
    sh("ip", "link", "set", "e2e-i", "netns", NS_INET)
    sh("ip", "link", "set", "e2e-rw", "name", "wan0", ns=NS_RTR)
    sh("ip", "link", "set", "e2e-i", "name", "eth0", ns=NS_INET)

    sh("ip", "addr", "add", "10.99.0.2/24", "dev", "eth0", ns=NS_CLI)
    sh("ip", "link", "set", "eth0", "up", ns=NS_CLI)
    sh("ip", "route", "add", "default", "via", "10.99.0.1", ns=NS_CLI)

    sh("ip", "addr", "add", "10.99.0.1/24", "dev", "lan0", ns=NS_RTR)
    # Stand-ins for Home Assistant's Supervisor and another app (172.30.32.0/23).
    for ip in (SUPERVISOR_IP, OTHER_APP_IP):
        sh("ip", "addr", "add", f"{ip}/32", "dev", "lan0", ns=NS_RTR)
    sh("ip", "addr", "add", "198.51.100.254/24", "dev", "wan0", ns=NS_RTR)
    sh("ip", "link", "set", "lan0", "up", ns=NS_RTR)
    sh("ip", "link", "set", "wan0", "up", ns=NS_RTR)
    sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=NS_RTR)

    sh("ip", "addr", "add", f"{ENDPOINT_IP}/24", "dev", "eth0", ns=NS_INET)
    sh("ip", "link", "set", "eth0", "up", ns=NS_INET)
    sh("ip", "route", "add", "10.99.0.0/24", "via", "198.51.100.254", ns=NS_INET)

    srv_priv, srv_pub = wg_keypair()
    key_file = WORK / "server.key"
    key_file.write_text(srv_priv + "\n")
    key_file.chmod(0o600)
    sh("ip", "link", "add", "wgs", "type", "wireguard", ns=NS_INET)
    sh("wg", "set", "wgs", "listen-port", "51820", "private-key", str(key_file),
       "peer", cli_pub, "allowed-ips", f"{CLIENT_TUNNEL_IP}/32", ns=NS_INET)
    sh("ip", "addr", "add", f"{TUNNEL_GW}/24", "dev", "wgs", ns=NS_INET)
    sh("ip", "link", "set", "wgs", "up", ns=NS_INET)
    return srv_pub


def runs():
    path = WORK / "config" / "db" / "fake_rtbit_runs.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def starts():
    return [r for r in runs() if r["event"] == "start"]


def inet_state():
    try:
        return json.loads((WORK / "inet.json").read_text())
    except (OSError, ValueError):
        return {"pmp": [], "tcp": [], "udp": []}


def log_text():
    return (WORK / "supervisor.log").read_text(errors="replace")


def api_events(path):
    return [r for r in runs() if r["event"] == "api" and r["path"] == path]


def bstr(s):
    b = s.encode()
    return str(len(b)).encode() + b":" + b


def write_legacy_qbittorrent(root: Path, wg_conf: str):
    """A qBittorrent app profile like alexbelgium's, with a WireGuard file."""
    (root / "wireguard").mkdir(parents=True)
    wg = root / "wireguard" / "wg0.conf"
    wg.write_text(wg_conf)
    wg.chmod(0o600)
    qbt = root / "qBittorrent"
    (qbt / "BT_backup").mkdir(parents=True)
    (qbt / "qBittorrent.conf").write_text(
        "[BitTorrent]\n"
        f"Session\\DefaultSavePath={QBT_SAVE}/\n"
        f"Session\\TempPath={QBT_TEMP}\n"
        "Session\\TempPathEnabled=true\n\n"
        "[Preferences]\n"
        f"WebUI\\Username={LEGACY_USER}\n"
        "WebUI\\Port=8080\n"
    )
    (qbt / "categories.json").write_text(json.dumps({
        "tv-sonarr": {"save_path": str(QBT_TV)},
        "radarr": {"save_path": ""},
    }))
    torrent = (b"d4:infod6:lengthi1e4:name5:a.mkv12:piece lengthi16384e"
               b"6:pieces20:" + b"x" * 20 + b"ee")
    for h, save in ((HASH_OK, QBT_TV), (HASH_GONE, MEDIA / "unmounted-disk")):
        (qbt / "BT_backup" / f"{h}.torrent").write_bytes(torrent)
        (qbt / "BT_backup" / f"{h}.fastresume").write_bytes(
            b"d9:save_path" + bstr(str(save)) + b"12:qBt-category" + bstr("tv-sonarr")
            + b"17:qBt-contentLayout" + bstr("Original") + b"e"
        )


def nft_bt_ports():
    out = sh("nft", "list", "set", "inet", "killswitch", "bt_port", ns=NS_CLI, check=False).stdout
    return out


# --------------------------------------------------------------------------
# the test
# --------------------------------------------------------------------------


def run_test(supervisor: Path):
    cleanup()
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "data").mkdir(parents=True)
    (WORK / "config").mkdir()
    (WORK / "share").mkdir()
    QBT_TV.mkdir(parents=True)

    step("network namespaces + WireGuard server")
    cli_priv, cli_pub = wg_keypair()
    srv_pub = setup_network(cli_pub)

    # The Ingress child drops to uid 65534, so the binary must be reachable
    # for "nobody" (a checkout under /home/runner may not be).
    sup_copy = WORK / "rbittorrent-supervisor"
    shutil.copy(supervisor, sup_copy)
    sup_copy.chmod(0o755)
    supervisor = sup_copy

    fake = WORK / "fake_rtbit.py"
    shutil.copy(HERE / "fake_rtbit.py", fake)
    fake.chmod(0o755)
    resolv = WORK / "resolv.conf"
    resolv.write_text("nameserver 8.8.8.8\n")

    conf = f"""[Interface]
# Key for e2e test
# NAT-PMP (Port Forwarding) = on
PrivateKey = {cli_priv}
Address = {CLIENT_TUNNEL_IP}/32, fd00::2/128
DNS = {TUNNEL_GW}

[Peer]
PublicKey = {srv_pub}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {ENDPOINT_IP}:51820
"""
    write_legacy_qbittorrent(WORK / "app_configs" / LEGACY_SLUG, conf)
    # No VPN options, default folders and user: everything comes from qBittorrent.
    options = {
        "import_from_qbittorrent": True,
        "import_active_torrents": True,
        "enable_nat_pmp": True,
        "nat_pmp_gateway": TUNNEL_GW,
        "listen_port": 4240,
        "local_allow_cidrs": ["10.99.0.0/24"],
        "enable_dht": False,
        "log_level": "debug",
    }
    (WORK / "data" / "options.json").write_text(json.dumps(options))

    lan_service = subprocess.Popen(
        ["ip", "netns", "exec", NS_RTR, sys.executable, "-c",
         "import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         f"s.bind(('10.99.0.1',{LAN_SERVICE_PORT}));s.listen(8)\n"
         "while True:\n  c,_=s.accept();c.close()\n"],
    )
    inet = subprocess.Popen(
        ["ip", "netns", "exec", NS_INET, sys.executable, str(Path(__file__).resolve()),
         "--role", "inet", "--state", str(WORK / "inet.json"),
         "--switch", str(WORK / "switch_port")],
    )

    step("start rbittorrent-supervisor in e2e-cli")
    log = open(WORK / "supervisor.log", "w")
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "RBITTORRENT_OPTIONS": str(WORK / "data" / "options.json"),
        "RBITTORRENT_CONFIG_ROOT": str(WORK / "config"),
        "RBITTORRENT_RTBIT": str(fake),
        "RBITTORRENT_RESOLV_CONF": str(resolv),
        "RBITTORRENT_APP_CONFIGS": str(WORK / "app_configs"),
        "RBITTORRENT_SHARE": str(WORK / "share"),
    }
    sup = subprocess.Popen(
        ["ip", "netns", "exec", NS_CLI, str(supervisor)],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        checks(sup, cli_priv, supervisor)
    finally:
        if sup.poll() is None:
            sup.kill()
        inet.terminate()
        lan_service.terminate()
        log.close()
        print("\n----- supervisor log -----")
        print(log_text())
        print("----- end of log -----")


def checks(sup, cli_priv, supervisor):
    wait_for(lambda: starts(), 90, "rtbit (fake) to start")
    wait_for(lambda: f"forwarded port {PORT_A}" in log_text(), 30, "NAT-PMP lease")
    first = starts()[0]
    env = first["env"]
    text = log_text()

    step("startup order and configuration")
    check("kill-switch active" in text, "kill-switch reported active")
    check(text.find("kill-switch active") < text.find("rtbit started"),
          "kill-switch installed before rtbit started")
    check(f"VPN exit verified: public IPv4 {PUBLIC_EXIT_IP}" in text, "public IP via NAT-PMP op 0")
    check("ignoring IPv6 tunnel address fd00::2/128" in text, "IPv6 address in .conf ignored with a note")
    check(env.get("RTBIT_LISTEN_PORT") == str(PORT_A), f"rtbit listens on leased port {PORT_A}")
    check(env.get("RTBIT_BIND_DEVICE") == "wg0", "rtbit bound to wg0")
    check(env.get("RTBIT_LISTEN_IP") == CLIENT_TUNNEL_IP, "rtbit listen IP = tunnel IP")
    check(env.get("RTBIT_UPNP_PORT_FORWARD_DISABLE") == "true", "UPnP port forwarding disabled")
    check(env.get("RTBIT_LSD_DISABLE") == "true", "LSD disabled")
    check(env.get("XDG_DATA_HOME", "").endswith("/config/db"), "XDG_DATA_HOME=/config/db")
    check(env.get("XDG_CACHE_HOME", "").endswith("/config/cache"), "XDG_CACHE_HOME=/config/cache")
    secret_seen = any(cli_priv in v for v in env.values()) or any(cli_priv in a for a in first["argv"])
    check(not secret_seen, "WireGuard private key not in rtbit env/argv")
    check(cli_priv not in text, "WireGuard private key never logged")
    check(env.get("RTBIT_DHT_DISABLE") == "true", "enable_dht: false -> RTBIT_DHT_DISABLE=true")
    check("RUST_LOG" not in env, "log_level debug passes rtbit's full logs (no RUST_LOG filter)")

    step("qBittorrent takeover (before rtbit starts)")
    wg0 = WORK / "config" / "wg0.conf"
    check(wg0.is_file() and (wg0.stat().st_mode & 0o777) == 0o600,
          "WireGuard file copied to /config/wg0.conf (0600)")
    check("copied the WireGuard config" in text, "WireGuard takeover logged")
    check(f"found {WORK / 'app_configs' / LEGACY_SLUG}" in text, "old qBittorrent app found")
    check(env.get("RTBIT_COMPLETED_FOLDER") == str(QBT_SAVE),
          f"completed folder = qBittorrent save path ({env.get('RTBIT_COMPLETED_FOLDER')})")
    check(env.get("RTBIT_DOWNLOAD_FOLDER") == str(QBT_TEMP),
          f"download folder = qBittorrent temp path ({env.get('RTBIT_DOWNLOAD_FOLDER')})")
    check("| qBittorrent     from " in text, "status box shows the qBittorrent import")

    step("Web UI account set before rtbit starts")
    auths = [r for r in runs() if r["event"] == "auth"]
    check(len(auths) == 1, f"rtbit auth reset-password ran once ({len(auths)})")
    if auths:
        a = auths[0]
        check(a["argv"] == ["auth", "reset-password", f"--username={LEGACY_USER}"],
              f"imported qBittorrent user name used ({a['argv']})")
        check(a["password_len"] == 24, "generated 24-character password arrived on stdin")
        check(not a["password_in_argv"] and not a["password_in_env"], "password not in argv/env")
        check(a["time"] < first["time"], "credentials stored before rtbit started")
    pw_file = WORK / "config" / ".webui-password"
    check(pw_file.exists() and (pw_file.stat().st_mode & 0o777) == 0o600,
          "generated password saved in /config/.webui-password (0600)")
    if pw_file.exists():
        check(pw_file.read_text().strip() not in text, "Web UI password never logged")
    check("generated a random password" in text, "generated password announced in the log")
    check(QBT_SAVE.is_dir() and QBT_TEMP.is_dir(), "imported download/completed folders exist")
    check(not Path("/media/rbittorrent").exists(), "default folders not created (import wins)")
    resolv = (WORK / "resolv.conf").read_text()
    check("nameserver 10.2.0.1" in resolv and "8.8.8.8" not in resolv,
          "resolv.conf locked to in-tunnel DNS")

    step("qBittorrent import into the running rtbit")
    wait_for(lambda: "qBittorrent import finished" in log_text(), 60, "qBittorrent import")
    text = log_text()
    logins = api_events("/api/v2/auth/login")
    check(any(e["ok"] and e["username"] == LEGACY_USER for e in logins),
          f"signed in to rtbit's qBittorrent API as {LEGACY_USER}")
    check(not [r for r in runs() if r.get("denied")], "no API call without the session cookie")
    cats = {e["form"].get("category"): e["form"].get("savePath")
            for e in api_events("/api/v2/torrents/createCategory")}
    check(cats.get("tv-sonarr") == str(QBT_TV), f"category tv-sonarr with its save path ({cats})")
    check("radarr" in cats, "category without its own save path imported too")
    adds = api_events("/api/v2/torrents/add")
    check(len(adds) == 1, f"one torrent re-added, the missing one skipped ({len(adds)})")
    if adds:
        f = adds[0]["fields"]
        check(f.get("savepath") == str(QBT_TV) and f.get("category") == "tv-sonarr",
              f"torrent added at its old save path + category ({f})")
        check(f.get("torrents", {}).get("filename") == f"{HASH_OK}.torrent"
              and f.get("contentLayout") == "Original" and f.get("stopped") == "false",
              "torrent file, layout and state passed on")
    check(f"{HASH_GONE}.torrent" in text and "does not exist" in text,
          "torrent with a missing save path reported as skipped")
    for marker in (".migrated", ".torrents_migrated"):
        m = WORK / "config" / marker
        check(m.is_file() and (m.stat().st_mode & 0o777) == 0o600, f"/config/{marker} written (0600)")

    step("rtbit capability sandbox")
    st = first["status"]
    bnd, eff = int(st["CapBnd"], 16), int(st["CapEff"], 16)
    check(bnd & ~0x1B == 0, f"bounding set limited to CHOWN|DAC_OVERRIDE|FOWNER|FSETID (CapBnd={bnd:#x})")
    check(eff & (1 << 12) == 0 and eff & (1 << 13) == 0 and eff & (1 << 21) == 0,
          f"no NET_ADMIN/NET_RAW/SYS_ADMIN (CapEff={eff:#x})")
    check(int(st["CapAmb"], 16) == 0 and int(st["CapInh"], 16) == 0, "no ambient/inheritable caps")
    check(st.get("NoNewPrivs") == "1", "no_new_privs set")
    probes = first.get("probes", {})
    if "rtbit filesystem sandbox active" in log_text():
        for name in ("wg0.conf", "webui-password", "options.json", "app_configs", "write-config"):
            check(probes.get(name) == "denied",
                  f"Landlock: rtbit cannot reach {name} ({probes.get(name)})")
        check(probes.get("write-db") == "writable", "Landlock: rtbit can write its database folder")
        check(not (WORK / "config" / "planted").exists(), "Landlock: nothing planted in /config")
    else:
        print(f"  info  Landlock unavailable on this kernel; rtbit probes: {probes}")

    step("routes, tunnel and firewall state")
    routes = sh("ip", "-4", "route", "show", ns=NS_CLI).stdout
    check("0.0.0.0/1 dev wg0" in routes and "128.0.0.0/1 dev wg0" in routes, "split default routes via wg0")
    check(f"{ENDPOINT_IP} via 10.99.0.1 dev eth0" in routes, "endpoint /32 via LAN gateway")
    mtu = sh("ip", "link", "show", "wg0", ns=NS_CLI).stdout
    check("mtu 1420" in mtu, "wg0 MTU 1420")
    wgshow = sh("wg", "show", "wg0", ns=NS_CLI).stdout
    check("persistent keepalive: every 25 seconds" in wgshow, "keepalive 25 s")
    check("latest handshake" in wgshow, "handshake completed")
    v6 = sh("ip", "-6", "addr", "show", "dev", "wg0", ns=NS_CLI, check=False).stdout
    check("fd00::2" not in v6, "no IPv6 address on wg0")
    check(str(PORT_A) in nft_bt_ports(), "leased port opened in nft bt_port set")

    step("leak tests from the app namespace")
    ok, out = tcp_probe(NS_CLI, ENDPOINT_IP, CANARY_TCP)
    check(not ok, f"direct TCP to the internet is blocked ({out})")
    ok, out = tcp_probe(NS_INET, "10.99.0.1", LAN_SERVICE_PORT)
    check(ok, "LAN service is up (reachable from elsewhere)")
    ok, out = tcp_probe(NS_CLI, "10.99.0.1", LAN_SERVICE_PORT)
    check(not ok, f"new connections into the LAN are blocked ({out})")
    print("  info  UDP to public DNS:", udp_send(NS_CLI, ENDPOINT_IP, CANARY_UDP))
    udp_send(NS_CLI, TUNNEL_GW, CANARY_UDP)
    ok, out = tcp_probe(NS_CLI, TUNNEL_GW, CANARY_TCP)
    check(ok, "TCP through the tunnel works")
    time.sleep(1)
    st = inet_state()
    direct_tcp = [c for c in st["tcp"] if c["dst"] == ENDPOINT_IP]
    tunnel_tcp = [c for c in st["tcp"] if c["src"] == CLIENT_TUNNEL_IP]
    direct_udp = [c for c in st["udp"] if c["dst"] == ENDPOINT_IP]
    tunnel_udp = [c for c in st["udp"] if c["src"] == CLIENT_TUNNEL_IP]
    check(not direct_tcp, "no TCP leaked outside the tunnel (canary)")
    check(not direct_udp, "no UDP/DNS leaked outside the tunnel (canary)")
    check(bool(tunnel_tcp) and bool(tunnel_udp), "canaries do see tunnelled traffic (test is meaningful)")

    step("inbound rules")
    ok, out = tcp_probe(NS_RTR, "10.99.0.2", 8080)
    check(ok, f"Web UI reachable from the LAN ({out})")
    ok, out = tcp_probe(NS_RTR, "10.99.0.2", PORT_A)
    check(not ok, f"BitTorrent port NOT reachable from the LAN ({out})")
    ok, out = tcp_probe(NS_INET, CLIENT_TUNNEL_IP, PORT_A)
    check(ok, f"forwarded BitTorrent port reachable through the tunnel ({out})")
    ok, out = tcp_probe(NS_INET, CLIENT_TUNNEL_IP, 8080)
    check(not ok, f"Web UI NOT reachable through the tunnel ({out})")

    step("Ingress proxy (8099) + watchdog")
    st = proc_status_of("ingress-proxy")
    uid = next((l.split()[1] for l in st.splitlines() if l.startswith("Uid:")), None)
    eff = next((l.split()[1] for l in st.splitlines() if l.startswith("CapEff:")), None)
    check(uid == "65534" and eff is not None and int(eff, 16) == 0,
          f"Ingress proxy runs as uid 65534 without capabilities (uid={uid}, CapEff={eff})")
    status, body = wait_for(
        lambda: (lambda r: r if r[0] == 200 else None)(
            http_get(NS_RTR, SUPERVISOR_IP, "10.99.0.2", INGRESS_PORT, "/__health")),
        60, "watchdog /__health = 200 from the Supervisor address")
    check(status == 200 and '"status":"ok"' in body, f"/__health healthy for the Supervisor ({body})")
    check(f'"port":{PORT_A}' in body, "/__health reports the forwarded port")
    status, body = http_get(NS_RTR, OTHER_APP_IP, "10.99.0.2", INGRESS_PORT, "/__health")
    check(status == 403, f"other apps on 172.30.32.0/23 are refused by the proxy ({status})")
    ok, out = tcp_probe(NS_RTR, "10.99.0.2", INGRESS_PORT)
    check(not ok, f"Ingress port NOT reachable from the LAN ({out})")
    ok, out = tcp_probe(NS_INET, CLIENT_TUNNEL_IP, INGRESS_PORT)
    check(not ok, f"Ingress port NOT reachable through the tunnel ({out})")
    r = sh(str(supervisor), "healthcheck", ns=NS_CLI, check=False)
    check(r.returncode == 0, f"`rbittorrent-supervisor healthcheck` passes ({r.stderr.strip()})")
    check("CPU cores" in text and "Forwarded port  " + str(PORT_A) in text,
          "startup status banner logged")

    step("NAT-PMP renewal without port change keeps rtbit running")
    maps_before = len([p for p in inet_state()["pmp"] if p["op"] in (1, 2)])
    wait_for(lambda: len([p for p in inet_state()["pmp"] if p["op"] in (1, 2)]) >= maps_before + 2,
             70, "a NAT-PMP renewal")
    time.sleep(1)
    reqs = [p for p in inet_state()["pmp"] if p["op"] in (1, 2)]
    check(all(p["lifetime"] == 60 for p in reqs), "lease lifetime 60 s")
    check(all(p["internal"] == 0 for p in reqs), "Proton convention: internal port 0")
    check(reqs[0]["suggested"] == 1, "first request suggests port 1")
    check(any(p["suggested"] == PORT_A for p in reqs[2:]), "renewal suggests the current port")
    check(len(starts()) == 1, "rtbit NOT restarted on unchanged port")
    try:
        status = Path(f"/proc/{sup.pid}/status").read_text()
        rss = [l for l in status.splitlines() if l.startswith(("VmRSS", "VmHWM", "Threads"))]
        print("  info  supervisor steady state: " + ", ".join(" ".join(l.split()) for l in rss))
    except OSError as e:
        print(f"  info  supervisor RSS unavailable: {e}")

    step("NAT-PMP port change restarts rtbit on the new port")
    (WORK / "switch_port").touch()
    wait_for(lambda: f"changed {PORT_A} -> {PORT_B}" in log_text(), 70, "port change")
    wait_for(lambda: len(starts()) >= 2, 20, "rtbit restart")
    second = starts()[1]
    check(second["env"]["RTBIT_LISTEN_PORT"] == str(PORT_B), f"rtbit restarted on {PORT_B}")
    stops = [r for r in runs() if r["event"] == "stop"]
    check(any(r["pid"] == first["pid"] for r in stops), "old rtbit stopped gracefully (SIGTERM)")
    ports = nft_bt_ports()
    check(str(PORT_B) in ports and str(PORT_A) not in ports, "nft set switched to the new port")

    step("rtbit crash is respawned")
    os.kill(second["pid"], signal.SIGKILL)
    wait_for(lambda: len(starts()) >= 3, 30, "rtbit respawn")
    check(starts()[2]["env"]["RTBIT_LISTEN_PORT"] == str(PORT_B), "respawned on the same port")

    check(len(api_events("/api/v2/torrents/add")) == 1, "rtbit restarts do not import twice")

    step("orderly shutdown on SIGTERM")
    third = starts()[2]
    sup.send_signal(signal.SIGTERM)
    try:
        code = sup.wait(timeout=40)
    except subprocess.TimeoutExpired:
        code = None
    check(code == 0, f"supervisor exited 0 (got {code})")
    stops = [r for r in runs() if r["event"] == "stop"]
    check(any(r["pid"] == third["pid"] for r in stops), "rtbit stopped before teardown")
    releases = [p for p in inet_state()["pmp"] if p["op"] in (1, 2) and p["lifetime"] == 0]
    check(len(releases) >= 2, "NAT-PMP mappings released (lifetime 0)")
    links = sh("ip", "link", "show", ns=NS_CLI).stdout
    check("wg0" not in links, "wg0 removed")
    text = log_text()
    check(text.find("rtbit stopped") < text.find("shutdown complete"), "rtbit stopped before tunnel teardown")


def run_direct_test(supervisor: Path):
    """Fresh install, no WireGuard anywhere: direct connection (VPN off)."""
    cleanup()
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "data").mkdir(parents=True)
    (WORK / "config").mkdir()
    (WORK / "share").mkdir()
    (WORK / "app_configs").mkdir()

    step("direct mode: network namespaces (the WireGuard server stays unused)")
    _, cli_pub = wg_keypair()
    setup_network(cli_pub)
    sup_copy = WORK / "rbittorrent-supervisor"
    shutil.copy(supervisor, sup_copy)
    sup_copy.chmod(0o755)
    fake = WORK / "fake_rtbit.py"
    shutil.copy(HERE / "fake_rtbit.py", fake)
    fake.chmod(0o755)
    resolv = WORK / "resolv.conf"
    resolv.write_text("nameserver 8.8.8.8\n")
    options = {
        # Not 4240: Home Assistant publishes container port 4240, so the
        # direct-mode table must redirect it to listen_port.
        "listen_port": DIRECT_LISTEN_PORT,
        "download_dir": str(MEDIA / "downloads"),
        "completed_dir": str(MEDIA / "completed"),
        "local_allow_cidrs": ["10.99.0.0/24"],
        "enable_dht": False,
        "log_level": "debug",
    }
    (WORK / "data" / "options.json").write_text(json.dumps(options))
    inet = subprocess.Popen(
        ["ip", "netns", "exec", NS_INET, sys.executable, str(Path(__file__).resolve()),
         "--role", "inet", "--state", str(WORK / "inet.json"),
         "--switch", str(WORK / "switch_port")],
    )
    log = open(WORK / "supervisor.log", "w")
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "RBITTORRENT_OPTIONS": str(WORK / "data" / "options.json"),
        "RBITTORRENT_CONFIG_ROOT": str(WORK / "config"),
        "RBITTORRENT_RTBIT": str(fake),
        "RBITTORRENT_RESOLV_CONF": str(resolv),
        "RBITTORRENT_APP_CONFIGS": str(WORK / "app_configs"),
        "RBITTORRENT_SHARE": str(WORK / "share"),
    }
    step("direct mode: start rbittorrent-supervisor without any VPN setup")
    sup = subprocess.Popen(
        ["ip", "netns", "exec", NS_CLI, str(sup_copy)],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        wait_for(lambda: starts(), 60, "rtbit (fake) to start on a direct connection")
        first = starts()[0]
        text = log_text()
        check("VPN OFF" in text, "loud warning: the connection is unprotected")
        check("real IP address" in text, "the warning says peers see the real IP address")
        check(first["env"].get("RTBIT_LISTEN_PORT") == str(DIRECT_LISTEN_PORT),
              f"rtbit listens on listen_port {DIRECT_LISTEN_PORT}")
        check("RTBIT_BIND_DEVICE" not in first["env"], "rtbit is not bound to wg0")
        check(first["env"].get("RTBIT_LISTEN_IP") == "0.0.0.0", "rtbit listens on all addresses")
        check("SUPERVISOR_TOKEN" not in first["env"], "no Supervisor token in rtbit's environment")
        tables = sh("nft", "list", "tables", ns=NS_CLI, check=False).stdout
        check("killswitch" not in tables, f"no kill-switch table in direct mode ({tables.strip()!r})")
        check("inet direct" in tables, f"direct-mode port rules installed ({tables.strip()!r})")
        rules = sh("nft", "list", "table", "inet", "direct", ns=NS_CLI, check=False).stdout
        check(f"udp dport 4240 redirect to :{DIRECT_LISTEN_PORT}" in rules,
              "UDP to the published port 4240 is redirected to listen_port")
        links = sh("ip", "link", "show", ns=NS_CLI).stdout
        check("wg0" not in links, "no wg0 in direct mode")
        check(resolv.read_text() == "nameserver 8.8.8.8\n", "resolv.conf untouched")
        check(not inet_state()["pmp"], "no NAT-PMP requests")
        ok, out = tcp_probe(NS_RTR, "10.99.0.2", 4240)
        check(ok, f"peers reach rtbit through the published port 4240 ({out})")
        ok, out = tcp_probe(NS_RTR, "10.99.0.2", DIRECT_LISTEN_PORT)
        check(ok, f"peers reach listen_port {DIRECT_LISTEN_PORT} directly ({out})")
        ok, out = tcp_probe(NS_RTR, "10.99.0.2", 8080)
        check(ok, f"the LAN (local_allow_cidrs) reaches the Web UI ({out})")
        ok, out = tcp_probe(NS_INET, "10.99.0.2", 8080)
        check(not ok, f"the Web UI is closed to addresses outside local_allow_cidrs ({out})")
        ok, out = tcp_probe(NS_INET, "10.99.0.2", INGRESS_PORT)
        check(not ok, f"the Ingress port is closed to the internet ({out})")
        ok, out = tcp_probe(NS_RTR, "10.99.0.2", INGRESS_PORT)
        check(not ok, f"the Ingress port is closed to the LAN ({out})")
        status, body = wait_for(
            lambda: (lambda r: r if r[0] == 200 else None)(
                http_get(NS_RTR, SUPERVISOR_IP, "10.99.0.2", INGRESS_PORT, "/__health")),
            60, "watchdog /__health = 200 in direct mode")
        check('"vpn":false' in body and f'"port":{DIRECT_LISTEN_PORT}' in body,
              f"/__health reports the direct connection for the status bar ({body})")
        status, body = http_get(NS_RTR, OTHER_APP_IP, "10.99.0.2", INGRESS_PORT, "/__health")
        check(status == 403, f"the Ingress proxy still refuses other apps ({status})")

        step("direct mode: orderly shutdown on SIGTERM")
        sup.send_signal(signal.SIGTERM)
        try:
            code = sup.wait(timeout=40)
        except subprocess.TimeoutExpired:
            code = None
        check(code == 0, f"supervisor exited 0 (got {code})")
        stops = [r for r in runs() if r["event"] == "stop"]
        check(any(r["pid"] == first["pid"] for r in stops), "rtbit stopped gracefully")
    finally:
        if sup.poll() is None:
            sup.kill()
        inet.terminate()
        log.close()
        print("\n----- supervisor log (direct mode) -----")
        print(log_text())
        print("----- end of log -----")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--supervisor", type=Path)
    ap.add_argument("--keep", action="store_true", help="keep namespaces for debugging")
    ap.add_argument("--role", default="test")
    ap.add_argument("--state", type=Path)
    ap.add_argument("--switch", type=Path)
    a = ap.parse_args()
    if a.role == "inet":
        inet_services(a.state, a.switch)
        return 0
    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr)
        return 2
    if not a.supervisor or not a.supervisor.exists():
        print("--supervisor PATH is required", file=sys.stderr)
        return 2
    for scenario in (run_test, run_direct_test):
        try:
            scenario(a.supervisor.resolve())
        except Exception as e:  # noqa: BLE001 - report any setup failure as a test failure
            FAILURES.append(f"{scenario.__name__} aborted: {e}")
            print(f"\nABORTED: {e}", flush=True)
        finally:
            if not a.keep:
                cleanup()
    if FAILURES:
        print(f"\n{len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\nall end-to-end checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
