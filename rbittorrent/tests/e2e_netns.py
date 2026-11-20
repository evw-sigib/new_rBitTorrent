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

With --rtbit, a third scenario runs the real rtbit in VPN mode: it downloads
a torrent from a seeder behind the WireGuard server, announced by a tracker
there, while a tracker on the LAN must hear nothing. Everything rtbit sends
must come out of the tunnel as 10.2.0.2 with the NAT-PMP port, and nothing
but WireGuard and Web UI replies may leave the app on the LAN.

Usage: sudo python3 e2e_netns.py --supervisor PATH [--rtbit PATH]
           [--scenario all|vpn|direct|real] [--keep]
"""

import argparse
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
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
# A second address behind the tunnel: DNS to it must be refused (only the
# configured tunnel DNS server may answer), plain TCP to it must work.
OTHER_TUNNEL_HOST = "192.0.2.53"
# IPv6 on the LAN link: the kill-switch must drop it, direct mode must not.
CLI_V6, RTR_V6 = "fd99::2", "fd99::1"
LAN6_PORT, APP6_PORT = 8083, 8084
# Set in the supervisor's environment; must never reach rtbit or the proxy.
E2E_SUPERVISOR_TOKEN = "e2e-supervisor-token-must-not-leak"
PORT_A, PORT_B = 45678, 45679
CANARY_TCP, CANARY_UDP = 8081, 53

# The old qBittorrent app's config folder (as mounted at /app_configs).
LEGACY_SLUG = "db21ed7f_qbittorrent"
LEGACY_USER = "legacyadmin"
QBT_SAVE = MEDIA / "qbt"
QBT_TEMP = MEDIA / "qbt" / "incomplete-qbt"
QBT_TV = MEDIA / "qbt" / "tv"
HASH_OK, HASH_GONE = "a" * 40, "b" * 40

# The real-rtbit scenario: a tracker and a seeder behind the WireGuard
# server, a tracker on the LAN that must hear nothing.
TRACKER_PORT, SEED_PORT = 6969, 6881
PAYLOAD_NAME = "e2e-payload.bin"
PAYLOAD_SIZE = 8 * 1024 * 1024 + 1234
PIECE_LENGTH = 256 * 1024
REAL_USER, REAL_PASSWORD = "e2e", "e2e-not-a-secret"

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
    fam = "socket.AF_INET6" if ":" in ip else "socket.AF_INET"
    code = (
        "import socket,sys\n"
        f"s=socket.socket({fam});s.settimeout({timeout})\n"
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


def app_processes():
    """/proc entries of the processes inside the app's network namespace
    (not the whole host: another job's processes must not match)."""
    try:
        app_ns = os.stat(f"/run/netns/{NS_CLI}").st_ino
    except OSError:
        return []
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            if os.stat(d / "ns" / "net").st_ino == app_ns:
                out.append(d)
        except OSError:
            continue
    return out


def proc_status_of(cmd_fragment):
    """/proc/<pid>/status of the first app process whose cmdline contains the fragment."""
    for d in app_processes():
        try:
            cmdline = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode()
            if cmd_fragment in cmdline:
                return (d / "status").read_text()
        except OSError:
            continue
    return ""


def proc_environ_of(cmd_fragment):
    """/proc/<pid>/environ of every app process whose cmdline contains the fragment."""
    out = []
    for d in app_processes():
        try:
            cmdline = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode()
            if cmd_fragment in cmdline:
                out.append((d / "environ").read_bytes().decode(errors="replace"))
        except OSError:
            continue
    return out


def supervisor_environ(supervisor):
    """/proc/<pid>/environ of the supervisor itself (read as root), or None."""
    for d in app_processes():
        try:
            argv = (d / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
            if len(argv) == 1 and argv[0].decode() == str(supervisor):
                return (d / "environ").read_bytes().decode(errors="replace")
        except OSError:
            continue
    return None


def tcp_listener(ns, host, port):
    """A background TCP listener that accepts and closes connections."""
    fam = "socket.AF_INET6" if ":" in host else "socket.AF_INET"
    code = (
        "import socket\n"
        f"s=socket.socket({fam});s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"s.bind(({host!r},{port}));s.listen(8)\n"
        "while True:\n  c,_=s.accept();c.close()\n"
    )
    return subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, "-c", code])


def leak_probe_count():
    """Packets with the `leak` payload that reached the VPN server's port 51820."""
    out = sh("nft", "list", "table", "inet", "e2e", ns=NS_INET).stdout
    m = re.search(r'packets (\d+) bytes \d+ comment "leak-probe"', out)
    return int(m.group(1)) if m else -1


def wg_keypair():
    priv = sh("wg", "genkey").stdout.strip()
    pub = sh("wg", "pubkey", input_text=priv + "\n").stdout.strip()
    return priv, pub


def in_netns(ns, fn, *args):
    """Runs fn(*args) in a thread that joined the network namespace `ns`
    (a network namespace is per thread), and returns its result."""
    result = {}

    def run():
        fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
        try:
            os.setns(fd, os.CLONE_NEWNET)
        finally:
            os.close(fd)
        try:
            result["value"] = fn(*args)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            result["error"] = e

    t = threading.Thread(target=run)
    t.start()
    t.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


# --------------------------------------------------------------------------
# "internet" side services (run inside e2e-inet via --role inet)
# --------------------------------------------------------------------------


def bt_tracker(host, peer, record):
    """A minimal HTTP tracker: records every announce and hands out `peer`."""
    import http.server

    class Announce(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server's naming
            url = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(url.query, encoding="latin-1")

            def one(key):
                return q.get(key, [""])[0]

            record({"src": self.client_address[0], "path": url.path,
                    "info_hash": one("info_hash").encode("latin-1").hex(),
                    "port": one("port"), "event": one("event"), "left": one("left")})
            body = (b"d8:intervali30e12:min intervali10e5:peers6:"
                    + socket.inet_aton(peer[0]) + struct.pack("!H", peer[1]) + b"e")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    http.server.ThreadingHTTPServer((host, TRACKER_PORT), Announce).serve_forever()


def bt_seeder(host, meta, record, save, hold=4.0):
    """A minimal BitTorrent seeder (BEP 3: handshake, bitfield, unchoke,
    piece). Records each connection's source and the bytes it was sent.
    The last piece is offered only `hold` seconds after the handshake, so
    the download stays open long enough to look at its sockets."""
    data = Path(meta["payload"]).read_bytes()
    plen = meta["piece_length"]
    pieces = (len(data) + plen - 1) // plen
    info_hash = bytes.fromhex(meta["info_hash"])
    bitfield = bytearray((pieces + 7) // 8)
    for i in range(pieces - 1):
        bitfield[i // 8] |= 0x80 >> (i % 8)

    def serve(c, addr):
        rec = record({"src": addr[0], "bytes": 0, "handshake": False})

        def recv(n):
            buf = b""
            while len(buf) < n:
                chunk = c.recv(n - len(buf))
                if not chunk:
                    raise EOFError
                buf += chunk
            return buf

        send_lock = threading.Lock()

        def send(b):
            with send_lock:
                c.sendall(b)

        def offer_last():
            try:
                send(struct.pack("!IBI", 5, 4, pieces - 1))  # have
            except OSError:
                pass

        timer = threading.Timer(hold, offer_last)
        try:
            c.settimeout(120)
            hs = recv(68)
            if hs[1:20] != b"BitTorrent protocol" or hs[28:48] != info_hash:
                return
            rec["handshake"] = True
            send(b"\x13BitTorrent protocol" + bytes(8) + info_hash
                 + b"-E2E0001-" + os.urandom(11))
            send(struct.pack("!IB", 1 + len(bitfield), 5) + bitfield)
            send(struct.pack("!IB", 1, 1))  # unchoke
            timer.start()
            blocks = 0
            while True:
                (length,) = struct.unpack("!I", recv(4))
                if length == 0:
                    continue
                msg = recv(length)
                if msg[0] == 6 and length == 13:  # request
                    index, begin, size = struct.unpack("!III", msg[1:])
                    off = index * plen + begin
                    block = data[off:off + size]
                    send(struct.pack("!IBII", 9 + len(block), 7, index, begin) + block)
                    rec["bytes"] += len(block)
                    blocks += 1
                    if blocks % 16 == 0:
                        save()
                elif msg[0] == 2:  # interested
                    send(struct.pack("!IB", 1, 1))
        except (OSError, EOFError, struct.error):
            pass
        finally:
            timer.cancel()
            save()
            c.close()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, SEED_PORT))
    s.listen(8)
    while True:
        c, addr = s.accept()
        threading.Thread(target=serve, args=(c, addr), daemon=True).start()


def inet_services(state_path: Path, switch_path: Path):
    """NAT-PMP gateway on 10.2.0.1:5351 plus TCP/UDP canaries on all addresses.
    With a torrent in seed/ next to the state file, also a tracker and a
    seeder on 192.0.2.53 (behind the tunnel)."""
    lock = threading.Lock()
    state = {"pmp": [], "tcp": [], "udp": [], "announces": [], "peers": []}
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

    def locked_save():
        with lock:
            save()

    def recorder(key):
        def record(rec):
            with lock:
                state[key].append(rec)
                save()
            return rec
        return record

    services = [natpmp, tcp_canary, udp_canary]
    meta_path = state_path.parent / "seed" / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        services.append(lambda: bt_tracker(
            OTHER_TUNNEL_HOST, (OTHER_TUNNEL_HOST, SEED_PORT), recorder("announces")))
        services.append(lambda: bt_seeder(
            OTHER_TUNNEL_HOST, meta, recorder("peers"), locked_save))
    with lock:
        save()
    for fn in services:
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
    sh("ip", "-6", "addr", "add", f"{CLI_V6}/64", "dev", "eth0", "nodad", ns=NS_CLI)
    sh("ip", "link", "set", "eth0", "up", ns=NS_CLI)
    sh("ip", "route", "add", "default", "via", "10.99.0.1", ns=NS_CLI)

    sh("ip", "addr", "add", "10.99.0.1/24", "dev", "lan0", ns=NS_RTR)
    # Stand-ins for Home Assistant's Supervisor and another app (172.30.32.0/23).
    for ip in (SUPERVISOR_IP, OTHER_APP_IP):
        sh("ip", "addr", "add", f"{ip}/32", "dev", "lan0", ns=NS_RTR)
    sh("ip", "-6", "addr", "add", f"{RTR_V6}/64", "dev", "lan0", "nodad", ns=NS_RTR)
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
    sh("ip", "addr", "add", f"{OTHER_TUNNEL_HOST}/32", "dev", "wgs", ns=NS_INET)
    sh("ip", "link", "set", "wgs", "up", ns=NS_INET)
    # Counts plain (unencrypted, unmarked) UDP that reaches the VPN server's
    # port: WireGuard messages never start with "leak".
    sh("nft", "-f", "-", ns=NS_INET, input_text=(
        "table inet e2e {\n chain input {\n"
        "  type filter hook input priority -10; policy accept;\n"
        "  udp dport 51820 @th,64,32 0x6c65616b counter comment \"leak-probe\"\n"
        " }\n}\n"))
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
    # The Supervisor writes every option config.yaml gives a default, so the
    # default folders are in options.json (a missing `completed_dir` means
    # the user cleared it, and then the imported folders are not used).
    options = {
        "download_dir": "/media/rbittorrent/downloads",
        "completed_dir": "/media/rbittorrent/completed",
        "import_from_qbittorrent": True,
        "import_active_torrents": True,
        "enable_nat_pmp": True,
        "nat_pmp_gateway": TUNNEL_GW,
        "listen_port": 4240,
        # The default range 10.0.0.0/8 also covers the tunnel's 10.2.0.1
        # (NAT-PMP, DNS): those must still go through wg0.
        "local_allow_cidrs": ["10.0.0.0/8"],
        "enable_dht": False,
        "log_level": "debug",
    }
    (WORK / "data" / "options.json").write_text(json.dumps(options))

    lan_service = tcp_listener(NS_RTR, "10.99.0.1", LAN_SERVICE_PORT)
    lan6 = tcp_listener(NS_RTR, "::", LAN6_PORT)
    app6 = tcp_listener(NS_CLI, "::", APP6_PORT)
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
        "SUPERVISOR_TOKEN": E2E_SUPERVISOR_TOKEN,
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
        for p in (lan_service, lan6, app6):
            p.terminate()
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
    check(env.get("HOME", "").endswith("/config/db"), "HOME=/config/db (inside the sandbox)")
    secret_seen = any(cli_priv in v for v in env.values()) or any(cli_priv in a for a in first["argv"])
    check(not secret_seen, "WireGuard private key not in rtbit env/argv")
    check(cli_priv not in text, "WireGuard private key never logged")
    check("SUPERVISOR_TOKEN" not in env and E2E_SUPERVISOR_TOKEN not in json.dumps(first),
          "the Supervisor token never reaches rtbit")
    check(E2E_SUPERVISOR_TOKEN not in text, "the Supervisor token is never logged")
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
    check(first.get("nice") == 10, f"rtbit runs at nice 10 ({first.get('nice')})")
    probes = first.get("probes", {})
    # Required: with the VPN on, the app never runs rtbit without Landlock.
    check("rtbit filesystem sandbox active" in log_text(), "rtbit filesystem sandbox active")
    check("Ingress proxy filesystem sandbox active" in log_text(),
          "Ingress proxy filesystem sandbox active")
    for name in ("wg0.conf", "webui-password", "options.json", "app_configs", "write-config"):
        check(probes.get(name) == "denied",
              f"Landlock: rtbit cannot reach {name} ({probes.get(name)})")
    check(probes.get("write-db") == "writable", "Landlock: rtbit can write its database folder")
    check(not (WORK / "config" / "planted").exists(), "Landlock: nothing planted in /config")
    check(probes.get("supervisor-environ") == "denied",
          f"rtbit cannot read the supervisor's environment ({probes.get('supervisor-environ')})")
    sup_env = supervisor_environ(supervisor)
    check(sup_env is not None and E2E_SUPERVISOR_TOKEN not in sup_env,
          "the Supervisor token is wiped from the supervisor's own environment block")

    step("routes, tunnel and firewall state")
    routes = sh("ip", "-4", "route", "show", ns=NS_CLI).stdout
    check("0.0.0.0/1 dev wg0" in routes and "128.0.0.0/1 dev wg0" in routes, "split default routes via wg0")
    check(f"{ENDPOINT_IP} via 10.99.0.1 dev eth0" in routes, "endpoint /32 via LAN gateway")
    check("10.0.0.0/8 via 10.99.0.1 dev eth0" in routes and f"{TUNNEL_GW} dev wg0" in routes,
          "the LAN range 10.0.0.0/8 goes to the LAN, the tunnel's own 10.2.0.1 stays in wg0")
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
    print("  info  DNS to another server through the tunnel:",
          udp_send(NS_CLI, OTHER_TUNNEL_HOST, CANARY_UDP))
    ok, out = tcp_probe(NS_CLI, TUNNEL_GW, CANARY_TCP)
    check(ok, "TCP through the tunnel works")
    ok, out = tcp_probe(NS_CLI, OTHER_TUNNEL_HOST, CANARY_TCP)
    check(ok, f"TCP to another host through the tunnel works ({out})")
    time.sleep(1)
    st = inet_state()
    direct_tcp = [c for c in st["tcp"] if c["src"] != CLIENT_TUNNEL_IP]
    tunnel_tcp = [c for c in st["tcp"] if c["src"] == CLIENT_TUNNEL_IP]
    direct_udp = [c for c in st["udp"] if c["src"] != CLIENT_TUNNEL_IP]
    tunnel_udp = [c for c in st["udp"] if c["src"] == CLIENT_TUNNEL_IP]
    check(all(c["dst"] != "?" for c in st["udp"]),
          "the UDP canary knows every destination address (IP_PKTINFO)")
    check(not direct_tcp, f"no TCP leaked outside the tunnel (canary: {direct_tcp})")
    check(not direct_udp, f"no UDP/DNS leaked outside the tunnel (canary: {direct_udp})")
    check({c["dst"] for c in tunnel_udp} == {TUNNEL_GW},
          f"DNS through the tunnel only reaches the configured server {TUNNEL_GW} ({tunnel_udp})")
    check(bool(tunnel_tcp) and bool(tunnel_udp), "canaries do see tunnelled traffic (test is meaningful)")

    step("unmarked UDP to the VPN server port and IPv6")
    before = leak_probe_count()
    print("  info  plain UDP to the endpoint port:", udp_send(NS_CLI, ENDPOINT_IP, 51820))
    time.sleep(1)
    check(before == 0 and leak_probe_count() == 0,
          "plain UDP to the VPN server's port does not leave (only marked WireGuard packets do)")
    udp_send(NS_RTR, ENDPOINT_IP, 51820)
    time.sleep(1)
    check(leak_probe_count() == 1, "the endpoint-port counter does count (test is meaningful)")
    ok, out = tcp_probe(NS_CLI, RTR_V6, LAN6_PORT)
    check(not ok, f"IPv6 out of the app is blocked ({out})")
    ok, out = tcp_probe(NS_RTR, CLI_V6, APP6_PORT)
    check(not ok, f"IPv6 into the app is blocked ({out})")

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
    check('"fs_sandbox":true' in body, "/__health reports the filesystem sandbox")
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
    i_stop = text.rfind("rtbit stopped")
    i_wg = text.rfind("WireGuard interface removed")
    i_done = text.rfind("shutdown complete")
    check(-1 < i_stop < i_wg < i_done,
          f"rtbit stopped before the tunnel was removed (offsets {i_stop}, {i_wg}, {i_done})")


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
        "SUPERVISOR_TOKEN": E2E_SUPERVISOR_TOKEN,
    }
    lan6 = tcp_listener(NS_RTR, "::", LAN6_PORT)
    app6 = tcp_listener(NS_CLI, "::", APP6_PORT)
    # Positive control for every IPv6 check (VPN and direct): before the
    # supervisor runs, IPv6 works both ways.
    step("IPv6 works before the app starts (positive control)")
    wait_for(lambda: tcp_probe(NS_CLI, RTR_V6, LAN6_PORT)[0], 15, "IPv6 out of e2e-cli")
    check(True, "IPv6 out of the app's namespace works without the app")
    wait_for(lambda: tcp_probe(NS_RTR, CLI_V6, APP6_PORT)[0], 15, "IPv6 into e2e-cli")
    check(True, "IPv6 into the app's namespace works without the app")
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
        check("SUPERVISOR_TOKEN" not in first["env"] and E2E_SUPERVISOR_TOKEN not in json.dumps(first),
              "the Supervisor token never reaches rtbit")
        proxies = proc_environ_of("ingress-proxy")
        check(bool(proxies) and all(E2E_SUPERVISOR_TOKEN not in e for e in proxies),
              f"the Supervisor token never reaches the Ingress proxy ({len(proxies)} found)")
        check(E2E_SUPERVISOR_TOKEN not in log_text(), "the Supervisor token is never logged")
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
        # The app is IPv4-only on a direct connection too.
        ok, out = tcp_probe(NS_CLI, RTR_V6, LAN6_PORT)
        check(not ok, f"IPv6 out of the app is dropped on a direct connection ({out})")
        ok, out = tcp_probe(NS_RTR, CLI_V6, APP6_PORT)
        check(not ok, f"IPv6 into the app is dropped on a direct connection ({out})")
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
        lan6.terminate()
        app6.terminate()
        log.close()
        print("\n----- supervisor log (direct mode) -----")
        print(log_text())
        print("----- end of log -----")


# --------------------------------------------------------------------------
# the real rtbit in VPN mode
# --------------------------------------------------------------------------


def make_seed_torrent():
    """Random content, a .torrent for it and the seeder's metadata."""
    import hashlib
    import qbit_api_smoke as qbit

    seed = WORK / "seed"
    seed.mkdir(parents=True)
    data = os.urandom(PAYLOAD_SIZE)
    (seed / PAYLOAD_NAME).write_bytes(data)
    info = {
        "name": PAYLOAD_NAME, "piece length": PIECE_LENGTH, "length": len(data),
        # Private: trackers only, no DHT or peer exchange.
        "private": 1,
        "pieces": b"".join(hashlib.sha1(data[i:i + PIECE_LENGTH]).digest()
                           for i in range(0, len(data), PIECE_LENGTH)),
    }
    inet_tracker = f"http://{OTHER_TUNNEL_HOST}:{TRACKER_PORT}/announce"
    lan_tracker = f"http://10.99.0.1:{TRACKER_PORT}/announce"
    torrent = qbit.bencode({"announce": inet_tracker,
                            "announce-list": [[inet_tracker], [lan_tracker]], "info": info})
    info_hash = hashlib.sha1(qbit.bencode(info)).hexdigest()
    (seed / "meta.json").write_text(json.dumps({
        "payload": str(seed / PAYLOAD_NAME), "piece_length": PIECE_LENGTH,
        "info_hash": info_hash}))
    return torrent, info_hash, hashlib.sha1(data).hexdigest()


def recording_listener(ns, host, port, log: Path):
    """A TCP listener that writes one line per connection to `log`."""
    code = (
        "import socket,sys\n"
        "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f"s.bind(({host!r},{port}));s.listen(8)\n"
        "while True:\n"
        "  c,a=s.accept()\n"
        f"  open({str(log)!r},'a').write(a[0]+'\\n');c.close()\n"
    )
    return subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, "-c", code])


def lan_counters():
    """Packets the app sent onto the LAN, by kind (counted on the router)."""
    out = sh("nft", "list", "table", "inet", "e2elan", ns=NS_RTR, check=False).stdout
    return {m.group(2): int(m.group(1))
            for m in re.finditer(r'packets (\d+) bytes \d+ comment "(\w+)"', out)}


def rtbit_pid():
    for d in app_processes():
        try:
            argv = (d / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        except OSError:
            continue
        if argv and argv[0].endswith(b"/rtbit") and b"server" in argv:
            return int(d.name)
    return None


def run_real_rtbit_test(supervisor: Path, rtbit: Path):
    """VPN mode with the real rtbit: a download through the tunnel."""
    import hashlib
    import qbit_api_smoke as qbit

    cleanup()
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "data").mkdir(parents=True)
    (WORK / "config").mkdir()
    (WORK / "share").mkdir()
    (WORK / "app_configs").mkdir()
    downloads, completed = MEDIA / "downloads", MEDIA / "completed"

    step("real rtbit: network namespaces, WireGuard server, tracker and seeder")
    cli_priv, cli_pub = wg_keypair()
    srv_pub = setup_network(cli_pub)
    # Both binaries must be reachable for the sandboxed children ("nobody"
    # for the Ingress proxy; Landlock allows exactly the binary's path).
    binaries = {}
    for name, src in (("rbittorrent-supervisor", supervisor), ("rtbit", rtbit)):
        binaries[name] = WORK / name
        shutil.copy(src, binaries[name])
        binaries[name].chmod(0o755)
    torrent, info_hash, payload_sha1 = make_seed_torrent()
    resolv = WORK / "resolv.conf"
    resolv.write_text("nameserver 8.8.8.8\n")
    # Everything the app sends onto the LAN, counted where it arrives.
    sh("nft", "-f", "-", ns=NS_RTR, input_text=(
        "table inet e2elan {\n chain pre {\n"
        "  type filter hook prerouting priority -300; policy accept;\n"
        f"  iifname \"lan0\" ip saddr 10.99.0.2 ip daddr {ENDPOINT_IP} udp dport 51820"
        " counter comment \"wireguard\" accept\n"
        "  iifname \"lan0\" ip saddr 10.99.0.2 tcp sport { 8080, 8099 }"
        " counter comment \"webui\" accept\n"
        # Home Assistant's Supervisor API, asked once before the kill-switch.
        f"  iifname \"lan0\" ip saddr 10.99.0.2 ip daddr {SUPERVISOR_IP} tcp dport 80"
        " counter comment \"supervisor\" accept\n"
        "  iifname \"lan0\" ip saddr 10.99.0.2 counter comment \"other\""
        " log prefix \"e2e-lan-other \" accept\n"
        " }\n}\n"))
    lan_tracker_log = WORK / "lan-tracker.log"
    lan_tracker = recording_listener(NS_RTR, "10.99.0.1", TRACKER_PORT, lan_tracker_log)

    conf = f"""[Interface]
# NAT-PMP (Port Forwarding) = on
PrivateKey = {cli_priv}
Address = {CLIENT_TUNNEL_IP}/32
DNS = {TUNNEL_GW}

[Peer]
PublicKey = {srv_pub}
AllowedIPs = 0.0.0.0/0
Endpoint = {ENDPOINT_IP}:51820
"""
    options = {
        "vpn_enabled": True,
        "wireguard_conf": conf,
        "webui_username": REAL_USER,
        "webui_password": REAL_PASSWORD,
        "import_from_qbittorrent": False,
        "download_dir": str(downloads),
        "completed_dir": str(completed),
        "enable_nat_pmp": True,
        "nat_pmp_gateway": TUNNEL_GW,
        "listen_port": 4240,
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

    step("real rtbit: start rbittorrent-supervisor in e2e-cli")
    log = open(WORK / "supervisor.log", "w")
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "RBITTORRENT_OPTIONS": str(WORK / "data" / "options.json"),
        "RBITTORRENT_CONFIG_ROOT": str(WORK / "config"),
        "RBITTORRENT_RTBIT": str(binaries["rtbit"]),
        "RBITTORRENT_RESOLV_CONF": str(resolv),
        "RBITTORRENT_APP_CONFIGS": str(WORK / "app_configs"),
        "RBITTORRENT_SHARE": str(WORK / "share"),
        "SUPERVISOR_TOKEN": E2E_SUPERVISOR_TOKEN,
    }
    sup = subprocess.Popen(
        ["ip", "netns", "exec", NS_CLI, str(binaries["rbittorrent-supervisor"])],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    base = "http://10.99.0.2:8080"
    client = qbit.Client(base)

    def login():
        try:
            status, text = client.call(
                "POST", "auth/login", form={"username": REAL_USER, "password": REAL_PASSWORD})
        except OSError:
            return None
        return status == 200 and text.strip() == "Ok."

    def api(method, path):
        return in_netns(NS_RTR, client.call, method, path)

    def info():
        status, text = in_netns(NS_RTR, client.call, "GET", "torrents/info")
        return json.loads(text) if status == 200 else []

    try:
        wait_for(lambda: in_netns(NS_RTR, login), 120,
                 "rtbit's qBittorrent API to accept the login from the LAN")
        text = log_text()
        check("kill-switch active" in text
              and text.find("kill-switch active") < text.find("rtbit started"),
              "kill-switch installed before the real rtbit started")
        check("rtbit filesystem sandbox active" in text, "rtbit runs in the filesystem sandbox")
        check("rtbit privileges dropped" in text, "rtbit runs without its dropped capabilities")
        check(f"forwarded port {PORT_A}" in text, f"NAT-PMP leased port {PORT_A}")
        check(cli_priv not in text and REAL_PASSWORD not in text,
              "neither the WireGuard key nor the Web UI password is logged")

        step("real rtbit: the save path Sonarr and Radarr see")
        status, body = api("GET", "app/preferences")
        prefs = json.loads(body) if status == 200 else {}
        check(prefs.get("save_path") == str(completed),
              f"preferences.save_path is completed_dir ({prefs.get('save_path')!r})")
        check(prefs.get("temp_path_enabled") is True and prefs.get("temp_path") == str(downloads),
              f"the temp path is download_dir ({prefs.get('temp_path_enabled')!r}, "
              f"{prefs.get('temp_path')!r})")
        status, body = api("GET", "app/defaultSavePath")
        check(body.strip() == str(completed), f"app/defaultSavePath is completed_dir ({body!r})")

        step("real rtbit: download a torrent through the tunnel")
        status, body = in_netns(NS_RTR, client.call, "POST", "torrents/add", None, {},
                                {"torrents": ("e2e.torrent", torrent)})
        check(status == 200 and body.strip() == "Ok.", f"torrents/add answers Ok. ({status} {body!r})")

        seen_socks = set()

        def done():
            # rtbit's connections to the seeder and the tracker, while they last.
            socks = sh("ss", "-Htn", "state", "established", ns=NS_CLI).stdout
            seen_socks.update(
                " ".join(line.split()[2:4]) for line in socks.splitlines()
                if f"{OTHER_TUNNEL_HOST}:{SEED_PORT}" in line
                or f"{OTHER_TUNNEL_HOST}:{TRACKER_PORT}" in line)
            ts = [t for t in info() if t["hash"] == info_hash]
            return ts[0] if ts and ts[0]["progress"] >= 1 else None

        try:
            wait_for(done, 180, "the download to finish")
        except Exception as e:  # noqa: BLE001 - report, then look at the rest
            check(False, f"the download finished ({e}; {info()})")
        final = completed / PAYLOAD_NAME
        try:
            wait_for(lambda: final.is_file() and final.stat().st_size == PAYLOAD_SIZE, 60,
                     "the finished file in completed_dir")
        except Exception:  # noqa: BLE001 - the check below reports it
            pass
        got = hashlib.sha1(final.read_bytes()).hexdigest() if final.is_file() else None
        check(got == payload_sha1, f"the file arrived intact in completed_dir ({final})")
        check(not (downloads / PAYLOAD_NAME).exists(), "and is no longer in download_dir")
        ts = [t for t in info() if t["hash"] == info_hash]
        check(bool(ts) and ts[0]["save_path"].rstrip("/") == str(completed),
              f"torrents/info reports the completed folder ({ts[0]['save_path'] if ts else None!r})")
        pid = rtbit_pid()
        rss = None
        if pid:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
        print(f"  info  rtbit VmRSS after an {PAYLOAD_SIZE >> 20} MiB download, "
              f"seeding: {rss} KiB", flush=True)

        step("real rtbit: everything went through the tunnel")
        state = inet_state()
        announces = [a for a in state["announces"] if a["info_hash"] == info_hash]
        check(bool(announces), f"the tracker behind the tunnel got announces ({len(announces)})")
        check(all(a["src"] == CLIENT_TUNNEL_IP for a in announces),
              f"every announce came from the tunnel address "
              f"({sorted({a['src'] for a in announces})})")
        check(all(a["port"] == str(PORT_A) for a in announces),
              f"every announce gives the NAT-PMP port {PORT_A} "
              f"({sorted({a['port'] for a in announces})})")
        peers = [p for p in state["peers"] if p.get("handshake")]
        check(bool(peers) and all(p["src"] == CLIENT_TUNNEL_IP for p in peers),
              f"rtbit reached the seeder from the tunnel address "
              f"({sorted({p['src'] for p in peers})})")
        check(sum(p["bytes"] for p in peers) >= PAYLOAD_SIZE,
              f"the seeder sent the whole file ({sum(p['bytes'] for p in peers)} bytes)")
        check(not lan_tracker_log.exists(),
              f"the tracker on the LAN heard nothing "
              f"({lan_tracker_log.read_text().split() if lan_tracker_log.exists() else []})")
        print("  info  rtbit's connections seen:", *sorted(seen_socks), sep="\n    ")
        check(any(f"{OTHER_TUNNEL_HOST}:{SEED_PORT}" in c for c in seen_socks)
              and all(c.startswith(f"{CLIENT_TUNNEL_IP}%wg0:") for c in seen_socks),
              "rtbit's peer and tracker sockets are bound to wg0")
        counters = lan_counters()
        check(counters.get("wireguard", 0) > 0,
              f"the WireGuard envelope went over the LAN ({counters})")
        check(counters.get("other", -1) == 0,
              f"nothing but WireGuard, Web UI replies and the Supervisor API reached the LAN "
              f"({counters})")
        ok, out = tcp_probe(NS_INET, CLIENT_TUNNEL_IP, PORT_A)
        check(ok, f"peers reach rtbit on the forwarded port through the tunnel ({out})")
        ok, out = tcp_probe(NS_RTR, "10.99.0.2", PORT_A)
        check(not ok, f"the forwarded port is closed on the LAN side ({out})")

        def stop(what):
            sup.send_signal(signal.SIGTERM)
            try:
                code = sup.wait(timeout=60)
            except subprocess.TimeoutExpired:
                code = None
            check(code == 0, f"supervisor exited 0 {what} (got {code})")
            check(rtbit_pid() is None, f"rtbit is gone {what}")

        step("real rtbit: orderly shutdown on SIGTERM")
        stop("on SIGTERM")

        step("real rtbit: after a restart the torrent is still finished, in completed_dir")
        served = sum(p["bytes"] for p in inet_state()["peers"])
        sup = subprocess.Popen(
            ["ip", "netns", "exec", NS_CLI, str(binaries["rbittorrent-supervisor"])],
            env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        client = qbit.Client(base)
        wait_for(lambda: in_netns(NS_RTR, login), 120, "the login after the restart")
        ts = wait_for(lambda: [t for t in info() if t["hash"] == info_hash], 60,
                      "the torrent after the restart")
        time.sleep(5)
        ts = [t for t in info() if t["hash"] == info_hash] or ts
        check(ts[0]["progress"] >= 1 and ts[0]["save_path"].rstrip("/") == str(completed),
              f"finished, in completed_dir ({ts[0]['progress']}, {ts[0]['save_path']!r})")
        again = sum(p["bytes"] for p in inet_state()["peers"]) - served
        check(again == 0 and not (downloads / PAYLOAD_NAME).exists(),
              f"nothing downloaded again ({again} bytes)")
        stop("after the restart")
    finally:
        if sup.poll() is None:
            sup.kill()
        inet.terminate()
        lan_tracker.terminate()
        log.close()
        print("\n----- supervisor log (real rtbit) -----")
        print(log_text()[-60000:])
        print("----- end of log -----")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--supervisor", type=Path)
    ap.add_argument("--rtbit", type=Path, help="the real rtbit, for the third scenario")
    ap.add_argument("--scenario", choices=("all", "vpn", "direct", "real"), default="all")
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
    scenarios = {"vpn": run_test, "direct": run_direct_test}
    if a.rtbit:
        if not a.rtbit.exists():
            print("--rtbit PATH does not exist", file=sys.stderr)
            return 2
        def run_real(sup):
            run_real_rtbit_test(sup, a.rtbit.resolve())
        scenarios["real"] = run_real
    elif a.scenario == "real":
        print("--scenario real needs --rtbit PATH", file=sys.stderr)
        return 2
    chosen = [f for name, f in scenarios.items() if a.scenario in ("all", name)]
    for scenario in chosen:
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
