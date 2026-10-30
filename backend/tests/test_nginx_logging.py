"""Nginx 访问日志脱敏与 HSTS 的回归测试。

背景: 设备 secret / 订阅 token / 一次性链接会出现在 URI 或 query 里。发行版 nginx
默认用 `$request` 记日志, query 会原样落盘; 因此生成的配置必须:
  1. 使用不含 query 的 `$uri` 作为请求行字段;
  2. 对 /c/、/sub/、/wg/one/ (含 /panel/ 前缀) 整条不记录;
  3. 对 HTTPS 入口下发 HSTS。
"""
from __future__ import annotations

import re


def _conf(home):
    from zeroproxy import config, nginx_config

    state = config.load_state()
    return nginx_config.build_nginx_conf(state)


def test_finished_conf_redacts_query_strings_and_sensitive_paths(home):
    conf = _conf(home)
    # 自定义日志格式: 只记 $uri, 不记 query
    assert "log_format zeroproxy_safe" in conf
    start = conf.index("log_format zeroproxy_safe")
    format_block = conf[start : conf.index(";", start)]
    assert "$uri" in format_block
    assert '"$request"' not in format_block
    # 敏感路径不记录
    assert "map $uri $zeroproxy_loggable" in conf
    assert re.search(r"~\^/\(\?:panel/\)\?c/ 0;", conf)
    assert re.search(r"~\^/\(\?:panel/\)\?sub/ 0;", conf)
    assert re.search(r"~\^/\(\?:panel/\)\?wg/one/ 0;", conf)
    # 每个 server 块都显式套用带条件的日志
    assert conf.count("if=$zeroproxy_loggable") >= 3
    assert "/var/log/nginx/zeroproxy.access.log" in conf


def test_finished_conf_sends_hsts_on_https_entries(home):
    conf = _conf(home)
    assert conf.count('add_header Strict-Transport-Security "max-age=31536000" always;') >= 2


def test_setup_conf_is_also_redacted(home):
    from zeroproxy import config, nginx_config

    state = config.load_state()
    conf = nginx_config.build_setup_nginx_conf(state, ["203.0.113.10"])
    assert "log_format zeroproxy_safe" in conf
    assert "if=$zeroproxy_loggable" in conf
    assert 'Strict-Transport-Security "max-age=31536000"' in conf
    assert "$request\"" not in conf
