#!/usr/bin/env python3
"""The qBittorrent Web API calls Sonarr, Radarr, Prowlarr, qBitController and
Home Assistant's qBittorrent integration make, against the real rtbit.

    qbit_api_smoke.py BASE_URL USER PASSWORD [SAVE_DIR]
    qbit_api_smoke.py --load N BASE_URL USER PASSWORD

The second form only adds N paused torrents (for memory measurements).

BASE_URL is rtbit's Web UI (e.g. http://172.17.0.2:8080). SAVE_DIR is a
folder rtbit may write (inside the app: under /media or /share). Uses only
the standard library, so it runs on any CI runner. Exits non-zero on the
first failed check.

Torrents are added as .torrent files: a magnet would wait for metadata from
peers that a CI runner does not have.
"""

import hashlib
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

def check(ok, what):
    print(("  PASS  " if ok else "  FAIL  ") + what, flush=True)
    if not ok:
        sys.exit(1)


def bencode(v):
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(bencode(x) for x in v) + b"e"
    if isinstance(v, dict):
        items = sorted((k.encode() if isinstance(k, str) else k, x) for k, x in v.items())
        return b"d" + b"".join(bencode(k) + bencode(x) for k, x in items) + b"e"
    raise TypeError(type(v))


def make_torrent(name, multi=False):
    """A private torrent with random content; returns (bytes, info hash)."""
    piece = 16384
    if multi:
        files = [(["a.bin"], os.urandom(piece)), (["sub", "b.bin"], os.urandom(piece // 2))]
        data = b"".join(d for _, d in files)
        info = {"name": name, "piece length": piece, "private": 1,
                "files": [{"path": p, "length": len(d)} for p, d in files]}
    else:
        data = os.urandom(piece * 2 + 100)
        info = {"name": name, "piece length": piece, "private": 1, "length": len(data)}
    info["pieces"] = b"".join(
        hashlib.sha1(data[i:i + piece]).digest() for i in range(0, len(data), piece))
    meta = {"announce": "http://127.0.0.1:1/announce", "info": info}
    return bencode(meta), hashlib.sha1(bencode(info)).hexdigest()


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, query=None, form=None, files=None):
        url = f"{self.base}/api/v2/{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        body, headers = None, {}
        if files is not None:
            boundary = uuid.uuid4().hex
            parts = []
            for k, v in (form or {}).items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"'
                             f"\r\n\r\n{v}\r\n".encode())
            for k, (fname, data) in files.items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; '
                             f'filename="{fname}"\r\nContent-Type: application/x-bittorrent'
                             "\r\n\r\n".encode() + data + b"\r\n")
            body = b"".join(parts) + f"--{boundary}--\r\n".encode()
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def json(self, path, query=None):
        status, text = self.call("GET", path, query)
        if status != 200:
            check(False, f"GET {path} {query or ''} answers 200 (got {status}: {text[:80]})")
        return json.loads(text)

    def post(self, path, form=None, files=None):
        status, text = self.call("POST", path, form=form if form is not None else {}, files=files)
        if status != 200:
            check(False, f"POST {path} answers 200 (got {status}: {text[:80]})")
        return text


def load(n, base, user, password):
    c = Client(base)
    text = c.post("auth/login", {"username": user, "password": password})
    check(text.strip() == "Ok.", "login")
    for i in range(n):
        data, _ = make_torrent(f"load-{i:03}.bin", multi=bool(i % 2))
        if c.post("torrents/add", {"paused": "true"}, files={"torrents": (f"{i}.torrent", data)}).strip() != "Ok.":
            check(False, f"torrents/add #{i}")
    count = len(c.json("torrents/info"))
    check(count >= n, f"{count} torrents loaded")


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "--load":
        return load(int(sys.argv[2]), *sys.argv[3:6])
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    base, user, password = sys.argv[1:4]
    save_dir = sys.argv[4] if len(sys.argv) > 4 else None
    c = Client(base)

    print("=== auth")
    status, _ = c.call("GET", "torrents/info")
    check(status in (401, 403), f"torrents/info without a login is refused ({status})")
    status, text = c.call("POST", "auth/login", form={"username": user, "password": password + "x"})
    check(text.strip() == "Fails.", f"a wrong password gets `Fails.` ({status} {text!r})")
    check(not any(k.name == "SID" for k in c.jar), "no SID cookie for a wrong password")
    text = c.post("auth/login", {"username": user, "password": password})
    check(text.strip() == "Ok.", f"login answers `Ok.` ({text!r})")
    check(any(k.name == "SID" for k in c.jar), "login sets the SID cookie")

    print("=== app")
    status, version = c.call("GET", "app/version")
    check(status == 200 and version.strip(), f"app/version ({version.strip()!r})")
    status, webapi = c.call("GET", "app/webapiVersion")
    parts = webapi.strip().split(".")
    check(status == 200 and parts[0] == "2" and all(p.isdigit() for p in parts),
          f"app/webapiVersion is 2.x ({webapi.strip()!r})")
    prefs = c.json("app/preferences")
    check(isinstance(prefs.get("save_path"), str) and prefs["save_path"],
          f"app/preferences has save_path ({prefs.get('save_path')!r})")
    for key in ("listen_port", "dht", "max_active_downloads"):
        check(key in prefs, f"app/preferences has {key}")
    status, default_save = c.call("GET", "app/defaultSavePath")
    check(status == 200 and default_save.strip(), f"app/defaultSavePath ({default_save.strip()!r})")
    check(default_save.strip() == prefs["save_path"],
          "app/defaultSavePath is the preferences' save_path")
    if prefs.get("temp_path_enabled"):
        check(prefs.get("temp_path") and prefs["temp_path"] != prefs["save_path"],
              f"the temp path is the download folder ({prefs.get('temp_path')!r})")
    else:
        check(not prefs.get("temp_path"), "no temp path without a completed folder")

    print("=== categories")
    cat_path = save_dir or prefs["save_path"]
    c.post("torrents/createCategory", {"category": "smoke-tv", "savePath": cat_path})
    cats = c.json("torrents/categories")
    check("smoke-tv" in cats, f"torrents/categories lists smoke-tv ({sorted(cats)})")
    check(cats["smoke-tv"].get("savePath", "").rstrip("/") == cat_path.rstrip("/"),
          f"the category keeps its save path ({cats['smoke-tv']})")
    c.post("torrents/createCategory", {"category": "smoke-movies"})

    print("=== add (.torrent files)")
    single, h1 = make_torrent("smoke-single.bin")
    multi, h2 = make_torrent("smoke-multi", multi=True)
    form = {"category": "smoke-tv", "paused": "true", "stopped": "true"}
    if save_dir:
        form["savepath"] = save_dir
    text = c.post("torrents/add", form, files={"torrents": ("single.torrent", single)})
    check(text.strip() == "Ok.", f"torrents/add (file, category, paused) answers `Ok.` ({text!r})")
    text = c.post("torrents/add", {"paused": "true"}, files={"torrents": ("multi.torrent", multi)})
    check(text.strip() == "Ok.", f"torrents/add (second file) answers `Ok.` ({text!r})")
    status, text = c.call("POST", "torrents/add", form={}, files={"torrents": ("bad.torrent", b"nope")})
    check(status != 200 or text.strip() == "Fails.", f"a broken .torrent is refused ({status} {text!r})")

    print("=== info")
    info = c.json("torrents/info")
    by_hash = {t["hash"]: t for t in info}
    check(h1 in by_hash and h2 in by_hash, f"torrents/info lists both ({len(info)} torrents)")
    t1 = by_hash[h1]
    for key in ("name", "state", "progress", "size", "save_path", "category", "added_on",
                "dlspeed", "upspeed", "eta", "ratio", "content_path"):
        check(key in t1, f"torrents/info has {key}")
    check(t1["name"] == "smoke-single.bin", f"name ({t1['name']!r})")
    check(t1["category"] == "smoke-tv", f"category ({t1['category']!r})")
    check(t1["size"] == 16384 * 2 + 100, f"size ({t1['size']})")
    if save_dir:
        check(t1["save_path"].rstrip("/") == save_dir.rstrip("/"),
              f"save path follows savepath ({t1['save_path']!r})")
    check("paused" in t1["state"].lower() or "stopped" in t1["state"].lower(),
          f"added paused ({t1['state']!r})")
    only = c.json("torrents/info", {"category": "smoke-tv"})
    check([t["hash"] for t in only] == [h1], "the category filter returns only that torrent")
    only = c.json("torrents/info", {"hashes": h2})
    check([t["hash"] for t in only] == [h2], "the hashes filter returns only that torrent")
    check(c.json("torrents/info", {"hashes": f"{h1}|{h2}"}).__len__() == 2,
          "the hashes filter takes several hashes")

    print("=== properties and files")
    props = c.json("torrents/properties", {"hash": h1})
    check(props.get("total_size") == 16384 * 2 + 100, f"properties total_size ({props.get('total_size')})")
    check(props.get("pieces_num") == 3, f"properties pieces_num ({props.get('pieces_num')})")
    check("save_path" in props, "properties has save_path")
    files = c.json("torrents/files", {"hash": h2})
    names = sorted(f["name"] for f in files)
    check(len(files) == 2 and names[0].endswith("a.bin") and names[1].endswith("b.bin"),
          f"torrents/files lists the files ({names})")
    for key in ("size", "progress", "priority"):
        check(key in files[0], f"torrents/files has {key}")
    trackers = c.json("torrents/trackers", {"hash": h1})
    check(any(t.get("url") == "http://127.0.0.1:1/announce" for t in trackers),
          "torrents/trackers lists the announce URL")

    print("=== actions")
    c.post("torrents/setCategory", {"hashes": h2, "category": "smoke-movies"})
    check(c.json("torrents/info", {"hashes": h2})[0]["category"] == "smoke-movies",
          "setCategory moves the torrent to the category")
    c.post("torrents/setCategory", {"hashes": h2, "category": ""})
    check(c.json("torrents/info", {"hashes": h2})[0]["category"] == "",
          "setCategory with an empty name clears it")
    c.post("torrents/addTags", {"hashes": h1, "tags": "smoke"})
    check("smoke" in c.json("torrents/info", {"hashes": h1})[0].get("tags", ""), "addTags")
    for action in ("resume", "pause", "start", "stop", "recheck", "reannounce"):
        c.post(f"torrents/{action}", {"hashes": h1})
    check(True, "resume, pause, start, stop, recheck and reannounce answer 200")
    c.post("torrents/setForceStart", {"hashes": h1, "value": "false"})

    print("=== transfer and sync")
    transfer = c.json("transfer/info")
    for key in ("dl_info_speed", "up_info_speed", "dl_info_data", "connection_status"):
        check(key in transfer, f"transfer/info has {key}")
    main_data = c.json("sync/maindata", {"rid": 0})
    check(isinstance(main_data.get("rid"), int), f"sync/maindata has rid ({main_data.get('rid')})")
    check(h1 in main_data.get("torrents", {}), "sync/maindata lists the torrents")
    check("server_state" in main_data, "sync/maindata has server_state")
    check("smoke-tv" in main_data.get("categories", {}), "sync/maindata lists the categories")
    delta = c.json("sync/maindata", {"rid": main_data["rid"]})
    check(isinstance(delta.get("rid"), int), "sync/maindata answers an incremental request")

    print("=== delete")
    c.post("torrents/delete", {"hashes": f"{h1}|{h2}", "deleteFiles": "true"})
    left = {t["hash"] for t in c.json("torrents/info")}
    check(h1 not in left and h2 not in left, "torrents/delete removes both")
    c.post("torrents/removeCategories", {"categories": "smoke-tv\nsmoke-movies"})
    cats = c.json("torrents/categories")
    check("smoke-tv" not in cats and "smoke-movies" not in cats, "removeCategories")

    print("=== logout")
    c.post("auth/logout")
    status, _ = c.call("GET", "torrents/info")
    check(status in (401, 403), f"the session ends at logout ({status})")
    print("qBittorrent API: all checks passed")


if __name__ == "__main__":
    main()
