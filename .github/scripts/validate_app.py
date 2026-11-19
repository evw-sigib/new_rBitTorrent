#!/usr/bin/env python3
"""Validate an app folder with the Home Assistant Supervisor's own schemas.

Usage: PYTHONPATH=<supervisor checkout> python3 validate_app.py <app dir>

Runs config.yaml through SCHEMA_APP_CONFIG (with deprecation warnings
turned into failures), translations/*.yaml through SCHEMA_APP_TRANSLATIONS,
validates the default options against the options schema, and enforces this
repository's security policy.
"""

import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from supervisor.apps.options import AppOptions, UiOptions
from supervisor.apps.validate import SCHEMA_APP_CONFIG, SCHEMA_APP_TRANSLATIONS
from supervisor.utils.apparmor import adjust_profile, get_profile_name

FORBIDDEN_CAPS = {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "BPF", "PERFMON"}
FORBIDDEN_TRUE = ("full_access", "host_network", "host_pid", "docker_api", "kernel_modules",
                  "homeassistant_api", "auth_api", "host_dbus")
FORBIDDEN_MAPS = {"homeassistant_config", "ssl", "backup", "config"}
# Mappings that are only acceptable read-only.
READ_ONLY_MAPS = {"all_app_configs", "all_addon_configs"}


class Collect(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def check_apparmor(profile: Path, slug: str) -> list:
    """apparmor.txt as the Supervisor loads it: exactly one top-level
    profile, renamed to the app's slug, with the rtbit and ingress child
    profiles the supervisor verifies at runtime."""
    errors = []
    print(f"apparmor.txt: profile {get_profile_name(profile)!r}")
    text = profile.read_text()
    for child in ("rtbit", "ingress"):
        if f"profile {child} " not in text or f"cx -> {child}," not in text:
            errors.append(f"apparmor.txt has no child profile `{child}` with a cx transition")
    with tempfile.TemporaryDirectory() as tmp:
        adjusted = Path(tmp) / "profile"
        adjust_profile(slug, profile, adjusted)
        if get_profile_name(adjusted) != slug:
            errors.append(f"the Supervisor's rename does not yield profile {slug!r}")
        parser = shutil.which("apparmor_parser")
        if parser is None:
            print("apparmor.txt: apparmor_parser not installed, compile check skipped")
            return errors
        # -N: the names of the profiles the file defines (no kernel needed).
        out = subprocess.run([parser, "-Q", "-K", "-T", "-N", str(adjusted)],
                             capture_output=True, text=True)
        names = set(out.stdout.split())
        want = {slug, f"{slug}//rtbit", f"{slug}//ingress"}
        if out.returncode != 0 or names != want:
            errors.append(f"apparmor_parser: {out.stderr.strip() or sorted(names)} "
                          f"(want {sorted(want)})")
        else:
            print(f"apparmor.txt: compiles to {', '.join(sorted(names))}")
    return errors


def main(app_dir: Path) -> int:
    warnings = Collect()
    logging.getLogger("supervisor").addHandler(warnings)
    errors = []

    raw = yaml.safe_load((app_dir / "config.yaml").read_text())
    try:
        cfg = SCHEMA_APP_CONFIG(raw)
    except Exception as e:  # voluptuous.Invalid and friends
        print(f"config.yaml: INVALID: {e}")
        return 1
    print(f"config.yaml: valid ({cfg['name']} {cfg['version']}, arch={cfg['arch']})")

    # Default options must satisfy the options schema (what users get on install).
    schema = cfg["schema"]
    for key in cfg["options"]:
        if key not in schema:
            errors.append(f"option '{key}' has no schema entry")
    for key, typ in schema.items():
        optional = isinstance(typ, str) and typ.endswith("?")
        if not optional and key not in cfg["options"]:
            errors.append(f"required option '{key}' has no default")
    # The Supervisor's own option validator, as on install. coresys is only
    # needed for `device` options and `!secret` values, which none use.
    try:
        AppOptions(None, schema, cfg["name"], cfg["slug"], resolve_secrets=False)(
            dict(cfg["options"]))
    except Exception as e:  # voluptuous.Invalid
        errors.append(f"default options do not satisfy the schema: {e}")
    try:
        UiOptions(None)(schema)
    except Exception as e:
        errors.append(f"the schema cannot be shown in the UI: {e}")

    for path in sorted((app_dir / "translations").glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        try:
            tr = SCHEMA_APP_TRANSLATIONS(data)
        except Exception as e:
            errors.append(f"{path.name}: {e}")
            continue
        missing = set(schema) - set(tr.get("configuration", {}))
        if missing:
            errors.append(f"{path.name}: no translation for {sorted(missing)}")
        print(f"{path.name}: valid")

    # Security policy for this repository.
    caps = {str(c) for c in cfg.get("privileged", [])}
    if caps & FORBIDDEN_CAPS:
        errors.append(f"forbidden capabilities: {sorted(caps & FORBIDDEN_CAPS)}")
    if caps - {"NET_ADMIN"}:
        errors.append(f"unexpected capabilities: {sorted(caps - {'NET_ADMIN'})}")
    for key in FORBIDDEN_TRUE:
        if cfg.get(key):
            errors.append(f"'{key}: true' is forbidden")
    # Kernel WireGuard needs no device node (/dev/net/tun is for userspace VPNs).
    if cfg.get("devices"):
        errors.append(f"no devices may be mapped, got {cfg.get('devices')}")
    # The AppArmor profile is the filesystem sandbox on Home Assistant OS.
    if cfg.get("apparmor") is False:
        errors.append("apparmor must not be disabled (apparmor.txt confines rtbit)")
    profile = app_dir / "apparmor.txt"
    if not profile.is_file():
        errors.append("apparmor.txt is missing")
    else:
        errors += check_apparmor(profile, f"local_{cfg['slug']}")
    if cfg.get("init") is not False:
        errors.append("init must be false (the supervisor is PID 1)")
    maps = {str(m["type"]) for m in cfg["map"]}
    if maps & FORBIDDEN_MAPS:
        errors.append(f"forbidden mappings: {sorted(maps & FORBIDDEN_MAPS)}")
    for m in cfg["map"]:
        if str(m["type"]) in READ_ONLY_MAPS and not m.get("read_only", True):
            errors.append(f"mapping {m['type']} must be read_only")
    # The Supervisor API with the default role only (no elevated hassio_role).
    if cfg.get("hassio_api") and str(cfg.get("hassio_role", "default")) != "default":
        errors.append(f"hassio_role must stay 'default', got {cfg.get('hassio_role')}")
    if (app_dir / "build.yaml").exists():
        errors.append("build.yaml is deprecated; build parameters belong in the Dockerfile")

    for w in warnings.records:
        errors.append(f"Supervisor warning: {w}")

    for e in errors:
        print(f"ERROR: {e}")
    if not errors:
        print("policy: ok (NET_ADMIN only, no devices, AppArmor profile, no "
              "full_access/host_network, app configs read-only, default Supervisor role)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
