#!/usr/bin/env python3
"""Stand-in for rtbit in the kernel end-to-end test (never shipped).

Records how the supervisor launched it (env, argv, capabilities), listens on
the Web UI port and on the BitTorrent port it was given, and exits cleanly on
SIGTERM, like rtbit does.

* `auth reset-password --username=USER` reads the password from stdin and records
  only whether it arrived there (never the value). The value is kept in a
  private file so the fake qBittorrent login below can check it.
* The Web UI port answers `/healthz` and the qBittorrent API calls the
  qBittorrent import uses (`auth/login`, `torrents/createCategory`,
  `torrents/add`); every API call is recorded.
"""

import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.parse

DATA = os.environ.get("XDG_DATA_HOME", "/tmp")
REPORT = DATA + "/fake_rtbit_runs.jsonl"
CREDS = DATA + "/fake_rtbit_credentials.json"
SID = "fake-sid-1"
LOCK = threading.Lock()


def record(event):
    with LOCK, open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def status_fields():
    fields = {}
    with open("/proc/self/status", encoding="ascii") as f:
        for line in f:
            key, _, value = line.partition(":")
            if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"):
                fields[key] = value.strip()
    return fields


def read_request(conn):
    """(method, path, headers, body) of one HTTP/1.1 request, or None."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        data += chunk
        if len(data) > 1 << 20:
            return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, path, _ = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0") or 0)
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return method, path.split("?", 1)[0], headers, body


def multipart_fields(headers, body):
    boundary = headers.get("content-type", "").split("boundary=")[-1].encode()
    fields = {}
    for part in body.split(b"--" + boundary):
        if b"\r\n\r\n" not in part:
            continue
        head, _, value = part.partition(b"\r\n\r\n")
        head = head.decode("latin-1")
        if 'name="' not in head:
            continue
        name = head.split('name="', 1)[1].split('"', 1)[0]
        if value.endswith(b"\r\n"):
            value = value[:-2]
        if 'filename="' in head:
            fname = head.split('filename="', 1)[1].split('"', 1)[0]
            fields[name] = {"filename": fname, "size": len(value)}
        else:
            fields[name] = value.decode("utf-8", "replace")
    return fields


def respond(conn, status, body=b"Ok.", extra=""):
    reason = {200: "OK", 403: "Forbidden", 404: "Not Found", 409: "Conflict"}[status]
    conn.sendall(
        f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n{extra}"
        "Connection: close\r\n\r\n".encode() + body
    )


def handle_api(conn, categories):
    req = read_request(conn)
    if req is None:
        return
    method, path, headers, body = req
    if path == "/healthz":
        return respond(conn, 200, b"ok")
    if method == "POST" and path == "/api/v2/auth/login":
        form = dict(urllib.parse.parse_qsl(body.decode()))
        try:
            with open(CREDS, encoding="utf-8") as f:
                creds = json.load(f)
        except OSError:
            creds = {}
        ok = (form.get("username") == creds.get("username")
              and form.get("password") == creds.get("password"))
        record({"event": "api", "path": path, "ok": ok, "username": form.get("username")})
        if ok:
            return respond(conn, 200, extra=f"Set-Cookie: SID={SID}; Path=/; HttpOnly\r\n")
        return respond(conn, 403, b"Fails.")
    if path.startswith("/api/v2/"):
        if f"SID={SID}" not in headers.get("cookie", ""):
            record({"event": "api", "path": path, "denied": True})
            return respond(conn, 403, b"Forbidden")
        if path == "/api/v2/torrents/createCategory":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            record({"event": "api", "path": path, "form": form})
            if form.get("category") in categories:
                return respond(conn, 409, b"Unable to create category")
            categories.add(form.get("category"))
            return respond(conn, 200)
        if path == "/api/v2/torrents/add":
            record({"event": "api", "path": path, "fields": multipart_fields(headers, body)})
            return respond(conn, 200)
        return respond(conn, 404, b"Not Found")
    return respond(conn, 200, b"ok")


def serve(sock, api):
    categories = set()
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        with conn:
            try:
                conn.settimeout(5)
                if api:
                    handle_api(conn, categories)
                else:
                    # BitTorrent port: only reachability matters.
                    conn.recv(1)
            except (OSError, ValueError):
                pass


def listen(ip, port, api):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(16)
    threading.Thread(target=serve, args=(s, api), daemon=True).start()
    return s


def auth_command():
    password = sys.stdin.readline().rstrip("\n")
    arg = sys.argv[-1]
    username = arg.split("=", 1)[1] if arg.startswith("--username=") else arg
    record({
        "event": "auth",
        "pid": os.getpid(),
        "argv": sys.argv[1:],
        "password_len": len(password),
        "password_in_argv": bool(password) and any(password in a for a in sys.argv),
        "password_in_env": bool(password) and any(password in v for v in os.environ.values()),
        "time": time.time(),
    })
    fd = os.open(CREDS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"username": username, "password": password}, f)
    print(f"stored new credentials for {username}")


def main():
    if sys.argv[1:3] == ["auth", "reset-password"]:
        auth_command()
        return
    env = dict(os.environ)
    api_ip, _, api_port = env["RTBIT_HTTP_API_LISTEN_ADDR"].rpartition(":")
    bt_ip = env.get("RTBIT_LISTEN_IP", "0.0.0.0")
    bt_port = int(env["RTBIT_LISTEN_PORT"])
    listen(api_ip, int(api_port), api=True)
    listen(bt_ip, bt_port, api=False)
    record({
        "event": "start",
        "pid": os.getpid(),
        "argv": sys.argv[1:],
        "env": env,
        "status": status_fields(),
        "time": time.time(),
    })

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    record({"event": "stop", "pid": os.getpid(), "time": time.time()})


if __name__ == "__main__":
    main()
