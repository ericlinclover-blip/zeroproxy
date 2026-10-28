from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AGENT = os.path.join(ROOT, "backend", "zeroproxy", "client", "runtime", "agent.sh")
INSTALL = os.path.join(
    ROOT, "backend", "zeroproxy", "client", "router-install.sh"
)


def _function(source: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", source, re.S | re.M)
    assert match, f"找不到 shell 函数 {name}"
    return match.group(0)


def test_apply_config_rejects_failed_validator_without_timeout_command(tmp_path):
    """A failed `mihomo -t` must preserve the previous config on lightweight routers."""
    source = open(AGENT, encoding="utf-8").read()
    func = _function(source, "apply_config")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("grep", "rm", "sleep", "kill", "mkdir", "mv"):
        target = shutil.which(name)
        assert target
        os.symlink(target, bindir / name)

    home = tmp_path / "router"
    home.mkdir()
    old_config = home / "config.yaml"
    old_config.write_text("proxy-groups:\n  - name: old\n", encoding="utf-8")
    validator = home / "mihomo"
    validator.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    validator.chmod(0o755)
    func = func.replace("/etc/zeroproxy/mihomo", str(validator))

    script = f"""
set -u
ZP_DIR={str(home)!r}
CONF="$ZP_DIR/config.yaml"
log() {{ :; }}
ensure_geo() {{ return 0; }}
build_config() {{
  printf '%s\\n' 'proxy-groups:'
  printf '%s\\n' '  - name: invalid-new-config'
}}
core_up() {{ return 1; }}
{func}
apply_config
printf 'rc=%s\\n' "$?"
"""
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(bindir)},
        timeout=20,
    )
    assert "rc=1" in proc.stdout, proc.stdout + proc.stderr
    assert old_config.read_text(encoding="utf-8") == "proxy-groups:\n  - name: old\n"


def test_report_fields_use_device_capabilities_and_measured_bench(tmp_path):
    """Heartbeat telemetry must come from caps and the saved bench result."""
    source = open(AGENT, encoding="utf-8").read()
    funcs = "\n".join(
        _function(source, name)
        for name in ("json_escape", "caps_get", "ipv6_flag", "tun_mtu_flag", "report_fields_json")
    )
    (tmp_path / "caps").write_text(
        "schema=2\nipv6=0\ntun_mtu=1420\noffload=1\n",
        encoding="utf-8",
    )
    (tmp_path / "bench").write_text(
        "direct_kbps=1200\nproxy_kbps=500\n",
        encoding="utf-8",
    )
    script = f"""
set -u
ZP_DIR={str(tmp_path)!r}
ZP_STATE="$ZP_DIR/.state"
ZP_VERSION=1.2.3
DP_REPORT=tun
COV_REPORT=full
OVERRIDE=off
{funcs}
report_fields_json
"""
    proc = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["ipv6"] == "0"
    assert report["mtu"] == "1420"
    assert report["offload"] == "1"
    assert report["bench_direct"] == "1200"
    assert report["bench_proxy"] == "500"
    assert report["override"] == "off"


def test_report_fields_include_each_level_reason_when_nothing_is_covered(tmp_path):
    """When no datapath works, the heartbeat must explain all failed levels."""
    source = open(AGENT, encoding="utf-8").read()
    funcs = "\n".join(
        _function(source, name)
        for name in ("json_escape", "caps_get", "ipv6_flag", "tun_mtu_flag", "report_fields_json")
    )
    (tmp_path / "caps").write_text(
        "schema=2\nipv6=0\ntun_mtu=1500\nwhy.tun=no tun\nwhy.tproxy=no nft\nwhy.redirect=no ipt\n",
        encoding="utf-8",
    )
    script = f"""
set -u
ZP_DIR={str(tmp_path)!r}
ZP_STATE="$ZP_DIR/.state"
ZP_VERSION=1.2.3
DP_REPORT=none
COV_REPORT=none
OVERRIDE=
{funcs}
report_fields_json
"""
    proc = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["why"] == "tun: no tun · tproxy: no nft · redirect: no ipt"


def test_switch_core_does_not_claim_success_when_api_never_starts(tmp_path):
    """A failed core start must not create the core.up success marker."""
    source = open(AGENT, encoding="utf-8").read()
    func = _function(source, "switch_core").replace(
        "/etc/init.d/zeroproxy", str(tmp_path / "initd")
    )
    initd = tmp_path / "initd"
    initd.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    initd.chmod(0o755)
    script = f"""
set -u
ZP_DIR={str(tmp_path)!r}
sleep() {{ :; }}
local_api_ready() {{ return 1; }}
http_get() {{ return 7; }}
flush_dns() {{ :; }}
{func}
switch_core on
printf 'rc=%s\\n' "$?"
"""
    proc = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert "rc=1" in proc.stdout, proc.stdout + proc.stderr
    assert not (tmp_path / "core.up").exists()


def test_wait_core_api_uses_a_single_short_probe():
    """The outer readiness loop must not multiply the panel HTTP retry budget."""
    source = open(INSTALL, encoding="utf-8").read()
    func = _function(source, "wait_core_api")
    script = f"""
set -u
ZP_API=127.0.0.1:9090
calls=0
sleep() {{ :; }}
http_get() {{ calls=999; return 1; }}
http_probe_once() {{ calls=$((calls + 1)); return 0; }}
{func}
wait_core_api
printf 'rc=%s calls=%s\\n' "$?" "$calls"
"""
    proc = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert "rc=0 calls=1" in proc.stdout, proc.stdout + proc.stderr


def test_run_with_timeout_returns_as_soon_as_command_exits():
    """A fast validator must not consume the whole timeout budget."""
    source = open(INSTALL, encoding="utf-8").read()
    func = _function(source, "run_with_timeout")
    script = f"""
set -u
{func}
run_with_timeout 30 /bin/sh -c 'exit 0'
printf 'ok=%s\\n' "$?"
run_with_timeout 30 /bin/sh -c 'exit 7'
printf 'bad=%s\\n' "$?"
"""
    proc = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert "ok=0" in proc.stdout, proc.stdout + proc.stderr
    assert "bad=7" in proc.stdout, proc.stdout + proc.stderr
