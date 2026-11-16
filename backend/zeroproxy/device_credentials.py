"""Per-device data-plane identities; legacy shared credentials remain compatible."""
from __future__ import annotations
import copy
import hashlib
import json
import os
import secrets
import uuid
from . import config


def active(state: dict) -> list[dict]:
    bucket = state.get("devices") or {}
    return [d for d in bucket.get("items", []) if isinstance(d, dict) and not d.get("deleted")
            and isinstance(d.get("dataplane"), dict) and d["dataplane"].get("uuid")]


def enable(device: dict) -> None:
    if not device.get("dataplane"):
        device["dataplane"] = {"uuid": str(uuid.uuid4()), "trojan_password": secrets.token_urlsafe(24),
                               "hysteria_password": secrets.token_urlsafe(24)}


def subscription_state(state: dict, device: dict) -> dict:
    result = copy.deepcopy(state)
    credentials = device.get("dataplane") or {}
    for key in ("uuid", "trojan_password", "hysteria_password"):
        if credentials.get(key):
            result[key] = credentials[key]
    return result


def write_hysteria_auth(state: dict) -> None:
    """Hysteria's command authenticator stays usable when the panel is offline."""
    home = config.paths()["hysteria_dir"]
    passwords = {"main": state["hysteria_password"]}
    passwords.update({d["id"]: d["dataplane"]["hysteria_password"] for d in active(state)})
    config.atomic_write_json(os.path.join(home, "auth.json"), passwords, mode=0o600)
    # Hysteria calls an executable with addr/auth/tx arguments. Never print the
    # supplied credential or invoke a shell with it.
    script = """#!/usr/bin/env python3
import hmac,json,os,sys
try:
    if len(sys.argv) != 4: raise ValueError()
    with open(os.path.join(os.path.dirname(__file__), "auth.json"), encoding="utf-8") as f:
        credentials=json.load(f)
    for identity,password in credentials.items():
        if hmac.compare_digest(str(password), sys.argv[2]):
            print(identity)
            sys.exit(0)
except (OSError, ValueError, TypeError):
    pass
sys.exit(1)
"""
    config.atomic_write_text(os.path.join(home, "auth.py"), script, mode=0o700)


def revision(state: dict) -> str:
    values = sorted((d["id"], d["dataplane"]) for d in active(state))
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:24]
