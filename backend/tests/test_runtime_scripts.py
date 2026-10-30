from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AGENT = os.path.join(ROOT, "backend", "zeroproxy", "client", "runtime", "agent.sh")
CLI = os.path.join(ROOT, "backend", "zeroproxy", "client", "runtime", "cli")
PERF = os.path.join(ROOT, "backend", "zeroproxy", "client", "runtime", "perf.sh")
CGI = os.path.join(ROOT, "backend", "zeroproxy", "client", "luci", "cgi")
INSTALL = os.path.join(
    ROOT, "backend", "zeroproxy", "client", "router-install.sh"
)
DIST = os.path.join(ROOT, "backend", "zeroproxy", "client", "agent", "dist")


def _function(source: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", source, re.S | re.M)
    assert match, f"找不到 shell 函数 {name}"
    return match.group(0)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _enclosing_function(source: str, offset: int) -> str:
    """返回 offset 所在的 shell 函数正文 (用于"这一行有没有被降级闸门包住"这类断言)。"""
    head = source[:offset]
    starts = [m for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{", head, re.M)]
    assert starts, "该行不在任何函数里"
    start = starts[-1].start()
    end_match = re.search(r"^\}", source[starts[-1].end():], re.M)
    end = starts[-1].end() + (end_match.end() if end_match else 0)
    return source[start:end]


def _toolchain(bindir, *names: str) -> None:
    """把宿主机上的基础命令链进一个临时 PATH (shell 夹具用)。"""
    bindir.mkdir(parents=True, exist_ok=True)
    for name in names:
        target = shutil.which(name)
        assert target, f"宿主机没有 {name}"
        os.symlink(target, bindir / name)


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


# ---------------------------------------------------------------- 鉴权 / 契约 (cgi)
def test_luci_cgi_rejects_get_for_state_changing_actions(tmp_path):
    """A prefetched or cross-site GET must not be able to turn the proxy off."""
    source = open(CGI, encoding="utf-8").read()
    zdir = tmp_path / "zp"
    zdir.mkdir()
    (zdir / "ui.token").write_text("test-token\n", encoding="utf-8")
    called = tmp_path / "called"
    cli = tmp_path / "cli"
    cli.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{called}"\n', encoding="utf-8")
    cli.chmod(0o755)
    source = source.replace("ZP_DIR=/etc/zeroproxy", f"ZP_DIR={zdir}")
    source = source.replace("CLI=/usr/bin/zeroproxy", f"CLI={cli}")
    source = source.replace("TOKFILE=/etc/zeroproxy/ui.token", f"TOKFILE={zdir / 'ui.token'}")
    script = tmp_path / "cgi"
    script.write_text(source, encoding="utf-8")
    proc = subprocess.run(
        ["/bin/sh", str(script)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": "a=toggle&k=test-token",
            "HTTP_COOKIE": "",
        },
        timeout=10,
    )
    assert "Status: 405" in proc.stdout
    assert not called.exists()


def _run_cgi(tmp_path, *, query: str, method: str, cookies: str, ubus_body: str = "", body: str = ""):
    """跑一份路径已改写的 cgi, 返回 (stdout, 被调到的 CLI 参数)。"""
    source = open(CGI, encoding="utf-8").read()
    zdir = tmp_path / "zp"
    zdir.mkdir(parents=True, exist_ok=True)
    (zdir / "ui.token").write_text("test-token\n", encoding="utf-8")
    called = tmp_path / "called"
    cli = tmp_path / "cli"
    cli.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{called}"\n', encoding="utf-8")
    cli.chmod(0o755)
    source = source.replace("ZP_DIR=/etc/zeroproxy", f"ZP_DIR={zdir}")
    source = source.replace("CLI=/usr/bin/zeroproxy", f"CLI={cli}")
    source = source.replace("TOKFILE=/etc/zeroproxy/ui.token", f"TOKFILE={zdir / 'ui.token'}")
    script = tmp_path / "cgi"
    script.write_text(source, encoding="utf-8")
    env = {
        **os.environ,
        "REQUEST_METHOD": method,
        "QUERY_STRING": query,
        "HTTP_COOKIE": cookies,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    if ubus_body:
        bindir = tmp_path / "ubusbin"
        bindir.mkdir(exist_ok=True)
        ubus = bindir / "ubus"
        ubus.write_text("#!/bin/sh\n" + ubus_body, encoding="utf-8")
        ubus.chmod(0o755)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        # cgi 自己在第 9 行重设了 PATH (cron/cgi 环境的固定路径) —— 把临时目录塞到最前面
        source = source.replace(
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            f"PATH={bindir}:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        script.write_text(source, encoding="utf-8")
    proc = subprocess.run(
        ["/bin/sh", str(script)],
        input=body,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    invoked = called.read_text(encoding="utf-8") if called.exists() else ""
    return proc.stdout, invoked


def test_luci_cgi_requires_root_or_app_acl_for_luci_sessions(tmp_path):
    """会话有效 ≠ 有权限: cgi 以 root 执行 CLI, 非 root 会话必须被 ACL 兜住 (P2-8)。"""
    sid = "0123456789abcdef0123456789abcdef"
    cookies = f"sysauth={sid}"
    # root 会话: 放行 (页面本身无需授权, 这里打的是数据接口)
    out, _ = _run_cgi(
        tmp_path / "root",
        query="a=status",
        method="GET",
        cookies=cookies,
        ubus_body="printf '%s\\n' '{\"values\":{\"username\":\"root\"}}'\n",
    )
    assert '"ok":true' in out, out
    # 非 root 且没有本应用 ACL: 拒绝
    out, invoked = _run_cgi(
        tmp_path / "guest",
        query="a=toggle",
        method="POST",
        cookies=cookies,
        ubus_body="printf '%s\\n' '{\"values\":{\"username\":\"guest\"}}'\n",
    )
    assert "未授权" in out, out
    assert invoked == "", "非 root 会话不该执行 CLI"
    # 非 root 但 ACL 明确放行本应用: 放行
    out, invoked = _run_cgi(
        tmp_path / "acl",
        query="a=toggle",
        method="POST",
        cookies=cookies,
        ubus_body="printf '%s\\n' '{\"values\":{\"username\":\"guest\",\"access\":{\"luci-app-zeroproxy\":true}}}'\n",
        body='{"on":"yes"}',
    )
    assert '"ok":true' in out, out
    assert invoked.strip() == "on"


def test_luci_cgi_status_reports_packets_and_security_headers(tmp_path):
    """cgi 的 status 必须带 packets (与 zpcore 对齐), 两个入口都发安全头。"""
    out, _ = _run_cgi(
        tmp_path, query="a=status&k=test-token", method="GET", cookies=""
    )
    assert '"packets":0' in out, out
    for header in (
        "X-Frame-Options: SAMEORIGIN",
        "Content-Security-Policy: frame-ancestors 'self'",
        "X-Content-Type-Options: nosniff",
    ):
        assert header in out, out


def test_luci_cgi_escapes_control_chars_and_unknown_action():
    """CLI 输出里的裸控制字符与动作名回显都必须转义, 否则前端 JSON.parse 失败。"""
    body = open(CGI, encoding="utf-8").read()
    jstr = _function(body, "jstr")
    assert "[[:cntrl:]]" in jstr, "jstr 必须清掉控制字符 (裸 TAB 会让 JSON 非法)"
    jval_s = _function(body, "jval_s")
    assert "[[:cntrl:]]" in jval_s
    assert 'fail "未知操作: $(jval_s "$action")"' in body


def test_luci_cgi_toggle_boolean_matches_zpcore():
    """`on:"yes"` 在两个入口不能一个开一个关 (P2-8 的布尔解析不一致)。"""
    body = open(CGI, encoding="utf-8").read()
    func = _function(body, "run_cli")
    toggle = body.split("    toggle)", 1)[1].split(";;", 1)[0]
    assert "true|1|yes|on" in toggle, toggle
    assert func  # run_cli 还在 (动作统一走它)


# ---------------------------------------------------------------- TLS 降级
def test_cli_never_disables_certificate_verification_unconditionally():
    """P1-3: 无条件 `-k` / `--no-check-certificate` 不能再出现。

    判据是"每一处跳过校验的调用都被降级闸门包住": 同一函数里必须出现 zp_tls_error 或
    zp_err_is_tls 判定 (先正常校验, 只有证书错误才降级)。
    """
    source = _read(CLI)
    assert "zp_tls_error()" in source and "zp_tls_warn()" in source
    offenders = []
    for match in re.finditer(r"-fsSk|--no-check-certificate", source):
        line = source[: match.start()].count("\n") + 1
        text = source.splitlines()[line - 1]
        column = match.start() - (source.rfind("\n", 0, match.start()) + 1)
        if "#" in text[:column]:
            continue  # 注释里提到旧写法不算
        func = _enclosing_function(source, match.start())
        if "zp_tls_error" not in func and "zp_err_is_tls" not in func:
            offenders.append(f"cli:{line}")
    assert not offenders, f"这些位置的证书校验降级没有 TLS 错误判据: {offenders}"


def test_perf_shals_never_disables_certificate_verification_unconditionally():
    source = _read(PERF)
    assert "_zp_perf_tls_rc()" in source
    offenders = []
    for match in re.finditer(r"-fsSk|--no-check-certificate", source):
        line = source[: match.start()].count("\n") + 1
        text = source.splitlines()[line - 1]
        column = match.start() - (source.rfind("\n", 0, match.start()) + 1)
        if "#" in text[:column] or "ZP_PERF_PROBE" in text:
            continue  # 注释 / 出口 IP 探针 (探的是 cloudflare, 与面板凭据无关)
        func = _enclosing_function(source, match.start())
        if "_zp_perf_tls_rc" not in func:
            offenders.append(f"perf.sh:{line}")
    assert not offenders, offenders


def test_agent_report_prefers_bearer_header(tmp_path):
    """设备凭据优先走 Authorization: Bearer (?k= 只作旧面板回退) —— P2-6。"""
    source = _read(AGENT)
    func = _function(source, "http_post")
    assert "Authorization: Bearer" in func
    assert 'zp_tls_rc "$_rc"' in func, "证书降级必须只在证书错误时发生"
    bindir = tmp_path / "bin"
    _toolchain(bindir, "mktemp", "rm", "sleep", "grep")
    log = tmp_path / "curl.log"
    fake = bindir / "curl"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    script = f"""
set -u
log() {{ :; }}
{func}
http_post https://panel.example/c/report '{{"device":"d","k":"sec"}}' sec
printf 'rc=%s\\n' "$?"
"""
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(bindir)},
        timeout=20,
    )
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    called = log.read_text(encoding="utf-8")
    assert "Authorization: Bearer sec" in called, called
    assert "-fsSk" not in called, "首次请求必须是校验证书的那条"


def _two_attempt_curl(bindir, log):
    """造一个 curl 替身: 第一次用 $FAKE_CURL_RC 退出, 第二次成功 (用来验降级)。"""
    bindir.mkdir(parents=True, exist_ok=True)
    state = bindir / ".count"
    fake = bindir / "curl"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        f'n=0; [ -f "{state}" ] && n="$(cat "{state}")"\n'
        f'n=$((n + 1)); printf "%s\\n" "$n" > "{state}"\n'
        'out=""; hdr=""\n'
        'while [ $# -gt 0 ]; do\n'
        '  case "$1" in\n'
        '    -o) out="$2"; shift 2 ;;\n'
        '    -D) hdr="$2"; shift 2 ;;\n'
        '    *) shift ;;\n'
        '  esac\n'
        'done\n'
        'rc="${FAKE_CURL_RC:-0}"\n'
        '[ "$n" -gt 1 ] && rc=0\n'
        '[ -n "$out" ] && printf "body" > "$out"\n'
        '[ -n "$hdr" ] && printf "X-ZP-Sha256: 00\\r\\n" > "$hdr"\n'
        'exit "$rc"\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)


def test_device_secret_fallbacks_are_http_level_only():
    """P2-6: 只有面板明确拒绝 (HTTP 4xx) 才把 secret 拼回 URL。

    超时/丢包时回退, 等于把 secret 塞进一次可能成功的请求的 URL —— 那是日志泄漏面,
    而它并不能证明"对面是旧面板"。
    """
    cli = _read(CLI)
    bench = _function(cli, "bench_run")
    assert "401|403|404" in bench, "bench 的 ?k= 回退必须只认 4xx"
    post = _function(cli, "http_post_out")
    assert '[ "$_rpo" = "22" ]' in post, "POST 的旧面板回退只认 curl 22 (HTTP 4xx/5xx)"
    agent_post = _function(_read(AGENT), "http_post")
    assert '"$_rc" != "22"' in agent_post
    perf_get = _function(_read(PERF), "zp_perf_get")
    assert "401" in perf_get and "403" in perf_get


def test_agent_reports_applied_rev_only_after_config_is_applied():
    """P2-9: 心跳要显式报 applied_rev (下载≠应用), 且只在 apply_config 成功后写。"""
    agent = _read(AGENT)
    body = agent.split("心跳上报", 1)[1]
    assert '"applied_rev"' in body
    assert '"healthy"' in body
    apply_block = agent.split("if apply_config; then", 1)[1].split("\n    fi", 1)[0]
    assert "APPLIED_REV" in apply_block
    assert '"$ZP_DIR/applied.rev"' in apply_block
    # agent 重启后读回已应用版本 (不必等下一次配置变更)
    head = agent.split('LAST_REV=""', 1)[1][:600]
    assert "APPLIED_REV" in head


def test_cli_get_degrades_only_on_certificate_errors(tmp_path):
    """P1-3: 超时/丢包 (curl 28) 不降级; 证书错误 (curl 60) 才降级一次。"""
    source = _read(CLI)
    funcs = "\n".join(
        _function(source, name) for name in ("zp_tls_error", "zp_tls_warn", "http_get_to")
    )
    for rc, want_second in ((28, False), (60, True)):
        bindir = tmp_path / f"bin{rc}"
        log = tmp_path / f"curl{rc}.log"
        _two_attempt_curl(bindir, log)
        for name in ("mktemp", "rm", "cat"):
            target = shutil.which(name)
            os.symlink(target, bindir / name)
        script = f"""
set -u
ZP_TLS_WARNED=""
{funcs}
export FAKE_CURL_RC={rc}
http_get_to https://panel.example/c/install.sh {str(tmp_path / f'out{rc}')!r} 5 || rrc=$?
printf 'rc=%s\\n' "${{rrc:-0}}"
"""
        proc = subprocess.run(
            ["/bin/sh", "-c", script],
            capture_output=True,
            text=True,
            env={**os.environ, "PATH": str(bindir)},
            timeout=20,
        )
        called = log.read_text(encoding="utf-8")
        assert ("-fsSk" in called) is want_second, (rc, called)
        if rc == 28:
            # 丢包/超时: 不降级、不告警"证书", 并把原始退出码如实返回
            assert "rc=28" in proc.stdout, proc.stdout
            assert "证书校验没通过" not in proc.stderr, proc.stderr
        else:
            # 证书错误: 降级一次, 而且说出来
            assert "rc=0" in proc.stdout, proc.stdout
            assert "证书校验没通过" in proc.stderr, proc.stderr


def test_cli_post_prefers_bearer_header(tmp_path):
    source = _read(CLI)
    func = _function(source, "http_post_out")
    bindir = tmp_path / "bin"
    _toolchain(bindir, "mktemp", "cat", "rm")
    log = tmp_path / "curl.log"
    fake = bindir / "curl"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    script = f"""
set -u
zp_tls_error() {{ case "${{1:-}}" in 35|51|58|59|60) return 0 ;; *) return 1 ;; esac; }}
zp_tls_warn() {{ :; }}
{func}
http_post_out https://panel.example/c/report 15 '{{"k":"sec"}}' sec
"""
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(bindir)},
        timeout=20,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    called = log.read_text(encoding="utf-8")
    assert "Authorization: Bearer sec" in called, called
    assert "-fsSk" not in called


def test_cli_add_requires_replace_for_another_panel():
    """P1-4: 已配对后再接另一台面板必须显式 --replace。"""
    body = _read(CLI)
    add = body.split("    add)", 1)[1].split("    drop)", 1)[0]
    assert "--replace" in add
    assert "zeroproxy add --replace <链接>" in add
    assert "exit 2" in add


def test_cli_update_is_pinned_to_the_install_panel():
    """P1-4: update 的 base 固定为装机面板, 不认后来 add 进来的服务器。"""
    body = _read(CLI)
    update = body.split("    update)", 1)[1].split("    update-log)", 1)[0]
    assert "panel.base" in update
    assert "_pin_base" in update
    # 安装脚本必须在装机时写下这个文件, 否则老设备升级后永远缺它
    install = _read(INSTALL)
    assert '> "$ZP_DIR/panel.base"' in install


def test_cli_update_verifies_the_panel_install_script_sha256():
    body = _read(CLI)
    update = body.split("    update)", 1)[1].split("    update-log)", 1)[0]
    assert "X-ZP-Install-Sha256" in update
    assert "file_sha256" in update
    assert "header_get" in update


def test_install_probe_only_degrades_on_certificate_errors(tmp_path):
    """P1-3: 超时/丢包不降级 —— 只有证书错误才置 insecure。"""
    source = _read(INSTALL)
    func = _function(source, "http_probe")
    bindir = tmp_path / "bin"
    _toolchain(bindir, "mktemp", "rm", "grep")
    for name, rc, want in (("timeout", 28, ""), ("tls", 60, "insecure")):
        script = f"""
set -u
HTTP=curl
TLS_OPTS=""
TLS_WHY=""
warn() {{ :; }}
http_get() {{ return {rc}; }}
{func}
http_probe https://panel.example/api/status || true
printf 'tls=%s\\n' "$TLS_OPTS"
"""
        proc = subprocess.run(
            ["/bin/sh", "-c", script],
            capture_output=True,
            text=True,
            env={**os.environ, "PATH": str(bindir)},
            timeout=20,
        )
        assert f"tls={want}" in proc.stdout, (name, proc.stdout, proc.stderr)


def test_install_verifies_panel_sha256_for_downloads(tmp_path):
    """P1-2: 面板下发的 X-ZP-Sha256 必须比对, 不一致就丢弃。"""
    source = _read(INSTALL)
    assert "zp_verify_sha()" in source
    for site in ('zp_verify_sha "$_tmp" "$_tmp.hdr" "本地控制面', 'zp_verify_sha "$_b" "$_b.hdr"'):
        assert site in source, f"缺摘要闸门: {site}"
    func = _function(source, "zp_verify_sha")
    bindir = tmp_path / "bin"
    _toolchain(bindir, "mktemp", "rm", "grep", "cut", "head", "sed", "tr")
    digest = "a" * 64
    fake = bindir / "sha256sum"
    fake.write_text(f"#!/bin/sh\nprintf '%s  %s\\n' {digest} \"$1\"\n", encoding="utf-8")
    fake.chmod(0o755)
    target = tmp_path / "blob"
    target.write_bytes(b"payload")
    hdr = tmp_path / "blob.hdr"

    script = f"""
set -u
warn() {{ printf 'WARN %s\\n' "$*" >&2; }}
note() {{ :; }}
{func}
zp_verify_sha {str(target)!r} {str(hdr)!r} 测试 || rc=$?
printf 'rc=%s\\n' "${{rc:-0}}"
"""
    hdr.write_text("X-ZP-Sha256: " + "b" * 64 + "\r\n", encoding="utf-8")
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(bindir)},
        timeout=20,
    )
    assert "rc=1" in proc.stdout, (proc.stdout, proc.stderr)
    hdr.write_text("X-ZP-Sha256: " + digest + "\r\n", encoding="utf-8")
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(bindir)},
        timeout=20,
    )
    assert "rc=0" in proc.stdout, (proc.stdout, proc.stderr)


# ---------------------------------------------------------------- 供应链 (面板侧)
def test_pinned_sha256_table_holds_official_release_digests():
    from zeroproxy import router_client as rc

    # mihomo: CORE_VERSION 的每一档都要有固定摘要, 否则面板只能回到"警告 + 未校验"
    for arch in rc.ARCHES:
        name = rc.asset_name(arch)
        assert re.fullmatch(r"[0-9a-f]{64}", rc.expected_sha256(name)), name
    # dae: 同上
    for arch in rc.PERF_ASSET:
        assert re.fullmatch(r"[0-9a-f]{64}", rc.expected_sha256(rc.PERF_ASSET[arch])), arch


def test_verify_asset_rejects_a_tampered_payload(tmp_path, monkeypatch):
    from zeroproxy import router_client as rc

    blob = tmp_path / "blob.gz"
    blob.write_bytes(b"tampered")
    real = hashlib.sha256(b"genuine").hexdigest()
    monkeypatch.setattr(rc, "PINNED_SHA256", {**rc.PINNED_SHA256, "fake-asset.gz": real})
    monkeypatch.setattr(rc, "SUPPLY_VERIFY", True)
    ok, why = rc.verify_asset(str(blob), "fake-asset.gz", kind="测试")
    assert not ok and "sha256" in why
    # 没登记的资产: 如实记录后放行 (绝不静默当"校验过")
    ok, why = rc.verify_asset(str(blob), "unknown-asset.gz", kind="测试")
    assert ok and "未校验" in why


def test_agent_sha256_matches_dist_sumfile():
    from zeroproxy import router_client as rc

    sums = os.path.join(DIST, "SHA256SUMS")
    assert os.path.isfile(sums), "dist/SHA256SUMS 不存在 —— 重跑 scripts/build-agent.sh"
    entries = {}
    with open(sums, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2:
                entries[parts[-1]] = parts[0]
    assert len(entries) >= 6, entries
    for arch in rc.ARCHES:
        name = f"zpcore-{arch}-{rc.AGENT_VERSION}.gz"
        if name not in entries:
            continue  # mips64/mips64le 是"不发"的档 (路由器会退回固件界面)
        assert rc.agent_sha256(arch) == entries[name], name
        digest = hashlib.sha256()
        with open(os.path.join(DIST, name), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        assert digest.hexdigest() == entries[name], f"{name} 的 SHA256SUMS 与文件不一致"
    # 旧版本制品不能留在 dist 里 (面板按 AGENT_VERSION 挑文件)
    stale = [n for n in os.listdir(DIST) if n.endswith(".gz") and f"-{rc.AGENT_VERSION}.gz" not in n]
    assert not stale, f"dist 里还有旧版本制品: {stale}"


def test_install_script_sha256_header_matches_rendered_script():
    from zeroproxy import router_client as rc

    body = rc.render_script("https://panel.example:8899", "deadbeef")
    assert rc.sha256_hex(body.encode("utf-8")) == rc.install_script_sha256(
        "https://panel.example:8899", "deadbeef"
    )


# ---------------------------------------------------------------- 心跳报文
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
