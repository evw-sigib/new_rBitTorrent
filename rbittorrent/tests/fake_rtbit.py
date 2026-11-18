#!/usr/bin/env python3
"""Stand-in for rtbit in the kernel end-to-end test (never shipped).

Records how the supervisor launched it (env, argv, capabilities), listens on
the Web UI port and on the BitTorrent port it was given, and exits cleanly on
SIGTERM, like rtbit does. `auth reset-password -u USER` reads the password
from stdin and records only whether it arrived there (never the value).
"""

import json
import os
import signal
import socket
import sys
import threading
import time

REPORT = os.environ.get("XDG_DATA_HOME", "/tmp") + "/fake_rtbit_runs.jsonl"


def status_fields():
    fields = {}
    with open("/proc/self/status", encoding="ascii") as f:
        for line in f:
            key, _, value = line.partition(":")
            if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"):
                fields[key] = value.strip()
    return fields


def serve(sock):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        with conn:
            try:
                # Read the request head first: closing with unread data would
                # reset the connection under an HTTP client (the /__health probe).
                conn.settimeout(2)
                head = b""
                while b"\r\n\r\n" not in head and len(head) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass


def listen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(16)
    threading.Thread(target=serve, args=(s,), daemon=True).start()
    return s


def auth_command():
    password = sys.stdin.readline().rstrip("\n")
    record = {
        "event": "auth",
        "pid": os.getpid(),
        "argv": sys.argv[1:],
        "password_len": len(password),
        "password_in_argv": bool(password) and any(password in a for a in sys.argv),
        "password_in_env": bool(password) and any(password in v for v in os.environ.values()),
        "time": time.time(),
    }
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    print(f"stored new credentials for {sys.argv[-1]}")


def main():
    if sys.argv[1:3] == ["auth", "reset-password"]:
        auth_command()
        return
    env = dict(os.environ)
    record = {
        "event": "start",
        "pid": os.getpid(),
        "argv": sys.argv[1:],
        "env": env,
        "status": status_fields(),
        "time": time.time(),
    }
    api_ip, _, api_port = env["RTBIT_HTTP_API_LISTEN_ADDR"].rpartition(":")
    bt_ip = env.get("RTBIT_LISTEN_IP", "0.0.0.0")
    bt_port = int(env["RTBIT_LISTEN_PORT"])
    listen(api_ip, int(api_port))
    listen(bt_ip, bt_port)
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps({"event": "stop", "pid": os.getpid(), "time": time.time()}) + "\n")


if __name__ == "__main__":
    main()
