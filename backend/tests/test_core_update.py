import hashlib
import io
import json
from pathlib import Path

import pytest

from zeroproxy import config, core_update, services, update


def test_check_uses_architecture_and_official_digest(monkeypatch):
    digest = "1" * 64
    release = {"tag_name": "app/v2.14.0", "assets": [
        {"name": "hysteria-linux-amd64", "digest": "sha256:" + digest, "size": 6},
        {"name": "hysteria-linux-arm64", "digest": "", "size": 5},
    ]}
    monkeypatch.setattr(core_update.platform, "machine", lambda: "x86_64")
    requested = []

    def response(url, timeout):
        requested.append(url)
        return io.BytesIO(json.dumps(release).encode())

    monkeypatch.setattr(core_update, "_request", response)
    result = core_update._release("hysteria2", "2.14.0")
    assert result["digest"] == digest
    assert result["url"].endswith("/app/v2.14.0/hysteria-linux-amd64")
    assert requested[0].endswith("/releases/tags/app/v2.14.0")
    with pytest.raises(ValueError, match="版本不一致"):
        core_update._release("hysteria2", "2.14.1")


def test_checksum_rejects_wrong_payload(monkeypatch, tmp_path):
    payload = b"upstream"
    monkeypatch.setattr(core_update, "_request", lambda *_: io.BytesIO(payload))
    metadata = {"url": "test", "size": len(payload), "digest": hashlib.sha256(payload).hexdigest()}
    dest = tmp_path / "asset"
    core_update._download(metadata, dest)
    assert dest.read_bytes() == payload
    with pytest.raises(ValueError, match="SHA-256"):
        core_update._download({**metadata, "digest": "0" * 64}, dest)


def test_core_routes_require_auth_and_validation(client, configured):
    assert client.post("/api/update/cores", json={"core": "nginx", "version": "1.2.3"}).status_code == 409
    client.post("/api/logout")
    assert client.get("/api/update/cores").status_code == 401
    assert client.post("/api/update/cores", json={"core": "xray", "version": "26.11.9"}).status_code == 401


def test_core_queue_and_panel_update_are_mutually_exclusive(client, configured, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(services, "is_prod", lambda: True)
    monkeypatch.setattr(services, "service_version", lambda _: "Xray 26.7.28 (build metadata)")
    monkeypatch.setattr(core_update, "_managed", lambda _: True)
    monkeypatch.setattr(core_update.shutil, "which", lambda _: "/bin/systemd-run")
    monkeypatch.setattr(services, "run", lambda cmd, **_: (calls.append(cmd) is None, ""))
    Path(config.paths()["upgrade_script"]).touch()
    assert client.post("/api/update/cores", json={"core": "xray", "version": "26.7.28"}).status_code == 409
    assert client.post("/api/update/cores", json={"core": "xray", "version": "26.11.9"}).status_code == 200
    job = update._read_status()
    assert job["core_name"] == "xray" and job["from"] == "26.7.28"
    assert calls[0][-3:] == ["xray", "26.11.9", job["job_id"]]
    assert client.post("/api/update", json={}).status_code == 409
    assert client.post("/api/hysteria/hopping").status_code == 409
    assert len(calls) == 1


@pytest.mark.parametrize("fail_new", [False, True])
def test_upgrade_replaces_selected_binary_and_restores_old_service_on_failure(home, monkeypatch, fail_new):
    binary = home / "hysteria"
    binary.write_bytes(b"old")
    other = home / "xray"
    other.write_bytes(b"untouched")
    core = "hysteria2"
    version = "2.14.0"
    job = {"state": "queued", "core_name": core, "from": "2.13.0", "to": version,
           "job_id": "11", "rolled_back": False, "steps": []}
    update._write_status(job)
    monkeypatch.setattr(core_update, "_binary", lambda _: binary)
    monkeypatch.setattr(core_update, "_managed", lambda _: True)
    monkeypatch.setattr(core_update, "_running_binary", lambda *args: True)
    monkeypatch.setattr(core_update, "_release", lambda *_: {})
    monkeypatch.setattr(core_update, "_download", lambda _, dest: dest.write_bytes(b"new"))
    monkeypatch.setattr(services, "run", lambda cmd, **_: (
        True, "Version: v2.13.0" if Path(cmd[0]).read_bytes() == b"old" else "Version: v2.14.0",
    ))
    restarted = []

    def restart(key, target):
        assert key == core
        restarted.append(target.read_bytes())
        if restarted[-1] == b"new" and fail_new:
            raise RuntimeError("failed to start new binary")

    monkeypatch.setattr(core_update, "_restart_and_verify", restart)
    assert not core_update.run(core, version, "stale-job")
    assert core_update.run(core, version, "11") is not fail_new
    result = update._read_status()
    assert result["state"] == ("failed" if fail_new else "success")
    assert result["rolled_back"] is fail_new
    assert restarted == ([b"new", b"old"] if fail_new else [b"new"])
    assert binary.read_bytes() == (b"old" if fail_new else b"new")
    assert other.read_bytes() == b"untouched"
