"""性能模式 (eBPF / dae) 的数据面配置 —— dae 用的是它**自己的一套**配置语言。

为什么单独渲染一份, 而不是从 mihomo 的 YAML 改过来
--------------------------------------------------
dae 的 `global` / `node` / `group` / `dns` / `routing` 与 Clash 的 YAML 没有任何对应关系,
硬套只会两边都写歪; 它的分流数据也是另一套格式 (v2ray 的 geoip.dat / geosite.dat ——
面板本来就为 Xray 下好了这两份, 正好复用)。所以这里是一份独立的渲染器, 与 mihomo 那几份并列。

两个刻意的选择
--------------
* **节点内联成分享链接**, 不写 `subscription:` —— 后者会要求 dae 在自己正接管这台机器流量的
  时候再去拉面板的订阅地址 (自己咬自己的环)。链接与主订阅是同一份实现 (`share_links`),
  所以两个数据面看到的节点完全一致。
* **面板地址直连**: 与 mihomo 那边同一条理由 (见 `share_links.management_direct_rules`) ——
  管理面不能依赖代理, 否则"节点挂了连面板都连不上"这个死锁会重演。

一条硬事实
----------
dae 支持 VLESS (含 Reality) / Trojan / Hysteria2 等, 但**不支持 XHTTP** (它的 VLESS 传输只有
TCP / WS / TLS / gRPC / Meek / HTTPUpgrade)。所以 `vless-xhttp` 会被排除, 并把这件事如实返回
给调用方 —— 少一个节点, 而不是让整份配置起不来。

`geo=False` 是降级: 面板上还没有 geoip.dat / geosite.dat 时, 引用它们的规则**不是**"不生效"
而是让 dae 起不来 (读不到文件)。那就把那些规则整条去掉 —— 与 mihomo 那边的降级配置同一个道理。
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import share_links

#: dae 认不了的节点 (按 node id)。目前只有 XHTTP 那一个。
UNSUPPORTED = frozenset({"vless-xhttp"})

#: dae 的内核态 tproxy 端口 (不是 HTTP/SOCKS 口, 只给 eBPF 程序用)。固定值: 面板与路由器
#: 两侧都要知道它, 而且它得避开我们自己的 7890 / 7892 / 7893 / 7874。
TPROXY_PORT = 12345

#: DNS 上游 —— 取向与 mihomo 那份一致: 国内域名走国内 DNS, 其余走国外。
DNS_UPSTREAMS: tuple[tuple[str, str], ...] = (
    ("alidns", "udp://dns.alidns.com:53"),
    ("googledns", "tcp+udp://dns.google:53"),
)

#: 关闭 h3 (QUIC) —— dae 官方 example.dae 里的性能建议: UDP 443 在用户态要额外一顿处理,
#: 而浏览器拿不到 h3 会自动回落 TCP/2。这一条影响行为, 所以写在配置里、也写进说明。
QUIC_BLOCK = "l4proto(udp) && dport(443) -> block"


def _quote(value: str) -> str:
    """dae 的字符串字面量: 单引号包裹, 内部转义。"""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


#: node 段里键名允许的字符。别的字符一律换成 **下划线**。
#: 为什么不能像值那样用引号把键括起来: dae 的语法里键是**裸标识符**, `'a': 'link'` 不是
#: "带引号的键", 而是一个语法错误 —— 真机 (v2.1.1) 上 `dae validate` 会直接回
#: `mismatched input ':' expecting '}'` (这一版之前就是这么写的, 于是性能模式永远起不来)。
_IDENT_BAD = re.compile(r"[^0-9A-Za-z_.\-]")


def _ident(value: str) -> str:
    """把节点 id 变成 dae 认的裸键名。

    实测 (dae v2.1.1 的 ANTLR 语法): 首字符不能是数字或 `-`, 不能出现 `:` 与非 ASCII;
    中段允许字母数字与 `_ . / + @ # % -`。节点 id 是我们自己生成的 (vless-reality /
    vless-ws / trojan / hysteria2), 本来就合规 —— 这里做净化是为了"以后加节点"时
    面板仍然发得出一份**能起**的配置, 而不是把这个问题再留给下一次真机。
    """
    name = _IDENT_BAD.sub("_", str(value))
    if not name or not (name[0].isascii() and (name[0].isalpha() or name[0] == "_")):
        name = "n" + name
    return name


def panel_direct_rules(base: str) -> list[str]:
    """管理面 (面板) 直连 —— 与 mihomo 那边同一条规则、同一套理由。"""
    try:
        host = (urlsplit(base).hostname or "").strip().lower()
    except ValueError:
        return []
    if not host:
        return []
    if host.replace(".", "").isdigit():
        return [f"dip({host}/32) -> direct"]
    return [f"domain(suffix: {host}) -> direct"]


def usable_nodes(state: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """(dae 能拨的节点, 被跳过的 node id)。

    节点集合来自 `share_links.enabled_links` —— 与主订阅同一份实现, 于是"面板上关掉的节点"
    在性能模式里也是关掉的。
    """
    out: list[tuple[str, str]] = []
    skipped: list[str] = []
    for node_id, link in share_links.enabled_links(state):
        if node_id in UNSUPPORTED:
            skipped.append(node_id)
            continue
        out.append((node_id, link))
    return out, skipped


def render(
    state: dict,
    base: str,
    *,
    lan_interface: str = "br-lan",
    template: str | None = None,
    geo: bool = True,
) -> tuple[str, list[str]]:
    """生成 dae 配置。返回 (正文, 被跳过的节点 id 列表)。

    `lan_interface` 由**设备**报上来 (dae 不会自己猜局域网口, 只有 wan 能 auto)。
    """
    tpl = template or share_links.template_of(state)
    nodes, skipped = usable_nodes(state)
    lines: list[str] = []
    add = lines.append

    add("# ZeroProxy 性能模式 (eBPF / dae) 配置。")
    add("# 由面板生成 —— 重跑安装命令或改节点后会自动覆盖, 别在这里手改。")
    add(f"# 分流模板: {tpl} · 内核态 tproxy 口: {TPROXY_PORT} · 分流数据: {'有' if geo else '无(降级)'}")
    if skipped:
        add(f"# 跳过了 dae 不支持的节点: {', '.join(skipped)} (dae 没有 XHTTP 传输)")
    add("")

    add("global {")
    add(f"    tproxy_port: {TPROXY_PORT}")
    # 只接管从局域网侧进来的包 —— 与 mihomo 那边一样, 不碰 WAN 侧入站。
    add(f"    lan_interface: {lan_interface}")
    # WAN 侧绑定 = 路由器自身的流量也走它 (mihomo 那边的 TUN 档也是"含路由器自身")
    add("    wan_interface: auto")
    add("    tproxy_port_protect: true")
    add("    auto_config_kernel_parameter: true")
    add("    log_level: info")
    add("    tls_implementation: tls")
    add("}")
    add("")

    add("node {")
    # 键名净化之后要防撞名 (两个不同的 id 可能净成同一个键): dae 会因为"同名节点"而只剩
    # 一个, 那是**静默少一个节点** —— 比报错更难发现, 所以在这里就让它们彼此区分开。
    used: set[str] = set()
    for node_id, link in nodes:
        key = _ident(node_id)
        if key in used:
            suffix = 2
            while f"{key}_{suffix}" in used:
                suffix += 1
            key = f"{key}_{suffix}"
        used.add(key)
        add(f"    {key}: {_quote(link)}")
    add("}")
    add("")

    add("group {")
    add("    proxy {")
    # 无 filter = 用全部节点; min_moving_avg 与 mihomo 那份 url-test 的取向一致
    # (取延迟移动平均最小的那个, 且避免个别抖动把整组带偏)。
    add("        policy: min_moving_avg")
    add("    }")
    add("}")
    add("")

    add("dns {")
    add("    upstream {")
    for name, url in DNS_UPSTREAMS:
        add(f"        {name}: {_quote(url)}")
    add("    }")
    add("    routing {")
    add("        request {")
    if geo:
        add("            qname(geosite:cn) -> alidns")
    add("            fallback: googledns")
    add("        }")
    add("    }")
    add("}")
    add("")

    add("routing {")
    add("    # 本机网络管理器直连 (否则绑定 WAN 时的连通性检查会自欺)")
    add("    pname(NetworkManager) -> direct")
    add("    # 组播 / 广播不该进代理")
    add("    dip(224.0.0.0/3, 'ff00::/8') -> direct")
    add("    dip(geoip:private) -> direct")
    for rule in panel_direct_rules(base):
        add(f"    {rule}")
    if tpl == "direct":
        add("    # 模板: 全直连 (只保留上面的放行) —— 与 mihomo 的 direct 模板同一个意思")
        add("    fallback: direct")
    else:
        if geo:
            add("    # 广告拦截 —— 与 mihomo smart / global 模板同一档 (需分流数据)")
            add("    domain(geosite:category-ads-all) -> block")
        add(f"    {QUIC_BLOCK}   # 关 h3: 省下 UDP 443 的用户态开销, 浏览器会自动回落 TCP/2")
        if tpl == "smart":
            if geo:
                add("    # 国内直连 —— 与 mihomo smart 模板同一档")
                add("    dip(geoip:cn) -> direct")
                add("    domain(geosite:cn) -> direct")
        add("    fallback: proxy")
    add("}")
    add("")
    return "\n".join(lines), skipped
