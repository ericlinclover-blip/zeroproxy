"""Independent, versioned updates for the two bundled server cores."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile

from . import config, services, update, wireguard

CORES = {
    "xray": ("Xray 核心", "XTLS/Xray-core", "xray", "v"),
    "hysteria2": ("Hysteria 2", "HyNetworks/hysteria", "hysteria", "app/v"),
}
_VERSION = re.compile(r"\bv?(\d+\.\d+\.\d+)(?:[-+][^\s]+)?\b")
_STABLE = re.compile(r"\d+\.\d+\.\d+")
MAX_ASSET = 128 * 1024 * 1024
PLAN = ["下载并校验发行包", "验证候选核心", "替换并重启核心", "确认服务正在运行"]


def version_number(output: str) -> str:
    match = _VERSION.search(output)
    return match.group(1) if match else ""


def _asset_names(core: str) -> tuple[str, ...]:
    arch = platform.machine().lower()
    if arch in {"aarch64", "arm64"}:
        return ("Xray-linux-arm64-v8a.zip", "Xray-linux-arm64.zip") if core == "xray" else ("hysteria-linux-arm64",)
    if arch in {"x86_64", "amd64"}:
        return ("Xray-linux-64.zip",) if core == "xray" else ("hysteria-linux-amd64",)
    return ()


def _request(url: str, timeout: int):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ZeroProxy"}), timeout=timeout)


def _release(core: str, version: str = "") -> dict:
    _, repo, _, prefix = CORES[core]
    ref = f"tags/{prefix}{version}" if version else "latest"
    with _request(f"https://api.github.com/repos/{repo}/releases/{ref}", 6) as response:
        release = json.loads(response.read(2 * 1024 * 1024))
    tag = release.get("tag_name", "")
    latest = tag.removeprefix(prefix)
    if release.get("draft") or release.get("prerelease") or tag != prefix + latest or not _STABLE.fullmatch(latest):
        raise ValueError("上游未返回稳定发行版")
    if version and latest != version:
        raise ValueError("发行版本与确认的版本不一致")
    assets = {entry.get("name"): entry for entry in release.get("assets", [])}
    for name in _asset_names(core):
        asset = assets.get(name) or {}
        digest = asset.get("digest") or ""
        size = asset.get("size") or 0
        if re.fullmatch(r"sha256:[a-f0-9]{64}", digest) and isinstance(size, int) and 0 < size <= MAX_ASSET:
            return {"version": latest, "digest": digest[7:], "size": size,
                    "url": f"https://github.com/{repo}/releases/download/{tag}/{name}"}
    raise ValueError("上游未提供与本机架构匹配且带 SHA-256 的发行包")


def _binary(core: str) -> Path:
    return Path("/usr/local/bin") / CORES[core][2]


def _managed(core: str) -> bool:
    binary = _binary(core)
    detected = services.bin_path(core)
    return bool(detected and binary.is_file() and not binary.is_symlink()
                and os.path.realpath(detected) == str(binary))


def status() -> dict:
    def check(core: str) -> tuple[str, dict]:
        current = version_number(services.service_version(core))
        item = {"current": current, "latest": "", "available": False, "error": ""}
        try:
            release = _release(core)
            item["latest"] = release["version"]
            if current:
                item["available"] = update.is_newer(item["latest"], current)
            else:
                item["error"] = "未能识别已安装版本"
        except (OSError, ValueError) as exc:
            item["error"] = str(exc) if type(exc) is ValueError else "暂时无法读取官方发行信息"
        item["can_update"] = services.is_prod() and bool(shutil.which("systemd-run")) and _managed(core)
        return core, item

    with ThreadPoolExecutor(max_workers=len(CORES)) as pool:
        return {"cores": dict(pool.map(check, CORES)), "running": update.is_running()}


def start(core: str, version: str) -> tuple[bool, str]:
    if core not in CORES or not _STABLE.fullmatch(version):
        return False, "请先检查核心版本，再选择要升级的稳定版"
    runner = shutil.which("systemd-run")
    if not services.is_prod() or not runner or not _managed(core):
        return False, "当前环境不支持从面板升级这个核心"
    if update.is_running():
        return False, "已有升级任务正在运行"
    current = version_number(services.service_version(core))
    if not current or not update.is_newer(version, current):
        return False, "目标版本须高于当前已安装版本，请重新检查"
    home = config.paths()["home"]
    started = time.time()
    job_id = str(time.time_ns())
    job = {"state": "queued", "core_name": core, "from": current, "to": version, "trigger": "panel",
           "job_id": job_id, "started_at": int(started), "finished_at": 0, "rolled_back": False, "plan": PLAN, "steps": []}
    update._write_status(job)
    cmd = [runner, "--no-block", "--collect", f"--unit=zeroproxy-core-update-{job_id}",
           "--property=Type=oneshot", f"--working-directory={home}", f"--setenv=ZP_HOME={home}",
           f"--setenv=PYTHONPATH={home}", str(Path(home) / "venv/bin/python"), "-m", "zeroproxy.core_update",
           core, version, job_id]
    ok, detail = services.run(cmd, timeout=10)
    if not ok:
        message = f"无法启动核心升级：{detail[:140]}"
        if update._read_status() == job:
            update._write_status({**job, "state": "failed", "message": message, "finished_at": int(time.time())})
        return False, message
    return True, "核心升级已排队"


def _download(release: dict, target: Path) -> None:
    digest = hashlib.sha256()
    size = 0
    deadline = time.monotonic() + 180
    with _request(release["url"], 15) as response, target.open("wb") as out:
        while chunk := response.read(256 * 1024):
            size += len(chunk)
            if size > release["size"] or time.monotonic() > deadline:
                raise ValueError("下载超出发行包大小或时间限制")
            digest.update(chunk)
            out.write(chunk)
    if size != release["size"] or digest.hexdigest() != release["digest"]:
        raise ValueError("发行包大小或 SHA-256 校验失败")


def _running_binary(core: str, binary: Path) -> bool:
    ok, pid = services.run(["systemctl", "show", "--property=MainPID", "--value", core], timeout=6)
    if not ok or not pid.strip().isdigit() or int(pid) <= 1:
        return False
    try:
        return (Path("/proc") / pid.strip() / "exe").samefile(binary) and services.service_state(core) == "active"
    except OSError:
        return False


def _restart_and_verify(core: str, binary: Path) -> None:
    ok, detail = services.restart_service(core, timeout=45)
    if not ok:
        raise RuntimeError(detail)
    consecutive = 0
    for _ in range(8):
        time.sleep(0.75)
        consecutive = consecutive + 1 if _running_binary(core, binary) else 0
        if consecutive >= 3:
            return
    raise RuntimeError("未确认目标二进制正在运行，请查看服务日志")


def run(core: str, version: str, job_id: str) -> bool:
    job = update._read_status()
    if (core not in CORES or not _STABLE.fullmatch(version) or job.get("state") != "queued"
            or job.get("core_name") != core or job.get("to") != version or job.get("job_id") != job_id):
        return False

    def step(index: int) -> None:
        job.update(current=PLAN[index], state="running")
        update._write_status(job)

    def done(detail: str) -> None:
        job["steps"].append({"name": job["current"], "ok": True, "detail": detail})
        update._write_status(job)

    binary = _binary(core)
    try:
        step(0)
        Path(config.paths()["update_log"]).write_text("", encoding="utf-8")
        release = _release(core, version)
        with tempfile.TemporaryDirectory(prefix=".zp-core-", dir=binary.parent) as workspace:
            asset = Path(workspace) / "asset"
            candidate = Path(workspace) / binary.name
            _download(release, asset)
            done("所选发行包 SHA-256 校验通过")
            with wireguard.operation():
                step(1)
                if not _managed(core) or not _running_binary(core, binary):
                    raise RuntimeError("未确认当前核心由本机标准服务运行，请先检查运行状态")
                current_ok, current = services.run([str(binary), "version"], timeout=12)
                if not current_ok or version_number(services.version_from_output(current)) != job["from"]:
                    raise RuntimeError("已装版本发生变化，请重新检查后再试")
                if core == "xray":
                    with zipfile.ZipFile(asset) as package:
                        member = package.getinfo("xray")
                        if member.file_size > MAX_ASSET:
                            raise ValueError("候选核心超过大小限制")
                        with package.open(member) as archive, candidate.open("wb") as out:
                            shutil.copyfileobj(archive, out)
                else:
                    asset.rename(candidate)
                candidate.chmod(0o755)
                ok, output = services.run([str(candidate), "version"], timeout=12)
                if not ok or version_number(services.version_from_output(output)) != version:
                    raise ValueError("候选二进制的版本与所选版本不一致")
                if core == "xray":
                    ok, output = services.run([str(candidate), "-test", "-c", config.paths()["xray_config"]],
                                              timeout=45, env=services.xray_env())
                    if not ok:
                        raise RuntimeError("候选核心未通过现有配置检查：" + output[-200:])
                done(f"候选版本 v{version}" + ("，配置检查通过" if core == "xray" else ""))
                step(2)
                backup = binary.with_name(f".{binary.name}.zp-previous-{job_id}")
                os.link(binary, backup)
                try:
                    os.replace(candidate, binary)
                except OSError:
                    backup.unlink(missing_ok=True)
                    raise
                try:
                    done("已替换二进制，正在重启并核对服务")
                    step(3)
                    _restart_and_verify(core, binary)
                except Exception:
                    try:
                        os.replace(backup, binary)
                        _restart_and_verify(core, binary)
                        job["rolled_back"] = True
                    except (OSError, RuntimeError) as exc:
                        job["rollback_error"] = f"未确认旧服务恢复：{exc}"
                        if backup.exists():
                            job["rollback_error"] += f"。旧二进制备份：{backup}"
                    raise
                done(f"{CORES[core][0]} v{version} 正在运行")
                with contextlib.suppress(OSError):
                    backup.unlink(missing_ok=True)
        job["state"] = "success"
        job["message"] = "核心升级完成"
    except Exception as exc:
        job["state"] = "failed"
        job["message"] = str(exc) or type(exc).__name__
        job["steps"].append({"name": job["current"], "ok": False, "detail": job["message"]})
    finally:
        job.update(current="", finished_at=int(time.time()))
        update._write_status(job)
    return job["state"] == "success"


if __name__ == "__main__":
    sys.exit(0 if len(sys.argv) == 4 and run(*sys.argv[1:]) else 1)
