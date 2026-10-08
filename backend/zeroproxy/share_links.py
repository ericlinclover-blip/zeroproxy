"""客户端分享链接与订阅服务 (技术文档 §6 各协议客户端配置)。

单节点链接均为各客户端 App 可直接导入的标准 URI:
  - vless://     VLESS Reality / XHTTP Reality / WebSocket
  - trojan://    Trojan
  - hysteria2:// Hysteria 2 (含端口跳跃)

订阅输出三种格式 (同一 URL, `?format=` 切换):
  - base64 (默认): 换行拼接后整体 Base64, 通用格式
  - clash         : mihomo / Clash.Meta 可直接加载的完整 YAML 配置
  - singbox       : sing-box 可直接加载的 JSON 配置

分流模板 (同一 URL, `?rules=smart|global|direct` 或面板「高级设置」切换):
   - smart  : 国内直连 + 广告拦截, 其余走代理 (默认)
   - global : 除局域网外全部走代理, 仅保留广告拦截
   - direct : 全部直连, 不下载任何 geo 数据 (完全离线可用)

字段级依据 (均为上游一手来源):
  - hysteria2 URI: `app/cmd/client.go` 的 parseURI() — `user:pass@` 会把整串
    "user:pass" 当作 auth 发给服务端, 而 `extras/auth/password.go` 是整串比较,
    因此这里**只写密码**; 端口跳跃写在 host 的端口部分 (`host:30001,31001`),
    官方客户端用 isPortHoppingPort() 判定后走 udphop。
  - 订阅 URL 恒定不变 — 配置变化时仅内容更新, 客户端 App 自动拉取。
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote

import yaml

from . import config
from .config import WS_PATH, XHTTP_PATH

#: 客户端分流数据库镜像 (mihomo geox-url)。GitHub Release 在受限网络下不可达,
#: 客户端首次导入订阅若拉不到 geoip.metadb 会直接报配置失败, 因此换成可用镜像。
#:
#: 手机/电脑端只有这一条路。**路由器端不走这里**: 它由面板自己分发 (见
#: router_client.GEO_FILES 与 /c/geo/…) —— 装机时它还没有任何代理可用, 让它去
#: GitHub 拉 4 MB 的 geox 数据就是"安装卡在写入运行文件"的那个 bug。
GEOX_BASE = "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"

#: 面板自己的分流数据接口 (路由器端 geox-url 指向这里)。
GEO_PATH = "/c/geo/"

#: sing-box 1.12 起内置 geoip/geosite 字段被彻底移除 (实测报错
#: "geosite database is deprecated in sing-box 1.8.0 and removed in 1.12.0"),
#: 分流只能用远程 rule-set, 同样换成可用镜像。
SRS_BASE = "https://fastly.jsdelivr.net/gh/SagerNet/"

#: sing-box 远程 rule-set 的"下载出口"字段分两代 (均为上游源码 + 真实二进制实测):
#:   - 1.8 ~ 1.13: 只能写 `route.rule_set[].download_detour`
#:   - 1.14 起: 新增顶层 `http_clients` + `route.default_http_client`,
#:     `download_detour` 标记废弃并在 1.16 移除
#: 关键风险 (实测): 不指定下载出口时, rule-set 会**走默认出站 (节点组)** 下载。
#: 节点不可达时 sing-box 直接 FATAL 起不来 —— 这就是引导期死锁。
#: 因此默认格式统一写成 `download_detour: "direct"` (1.13.21 / 1.14.2 实测均可用,
#: 且在 1.13 上无需任何额外字段), 另有 `?format=singbox-next` 给 1.14+ 客户端
#: 生成零废弃警告的 http_clients 写法。

#: smart 模板的"基础"rule-set: 广告拦截 + 国内 IP 段。
#: 国内**域名**那几类由 CN_RULE_SETS 提供, "必须走落地"那几类由 LANDING_RULE_SETS
#: 提供 —— 三者合起来才是完整的 smart 规则集 (见 smart_rule_sets())。
SMART_RULE_SETS = (
    ("ads", "sing-geosite@rule-set/geosite-category-ads-all.srs"),
    ("cn-ip", "sing-geoip@rule-set/geoip-cn.srs"),
)
ADS_RULE_SET = ("ads", "sing-geosite@rule-set/geosite-category-ads-all.srs")

#: 新版写法里默认 HTTP 客户端的标签。留空 detour = 直连下载。
#: (不能写 detour: "direct": 实测报 "detour to an empty direct outbound makes no sense")
DEFAULT_HTTP_CLIENT = "bootstrap-direct"

#: 分流模板。smart = 国内直连 + 广告拦截; global = 全部走代理; direct = 全部直连
TEMPLATES = ("smart", "global", "direct")
DEFAULT_TEMPLATE = "smart"

#: 策略组名 (Clash 与 sing-box 共用, 保证两种格式语义一致)
G_SELECT = "🚀 节点选择"
G_AUTO = "♻️ 自动选择"
G_FINAL = "🐟 漏网之鱼"
G_ADS = "🛑 广告拦截"
G_DIRECT = "🎯 全球直连"

#: 落地节点组 + "必须走落地"的站点。
#:
#: 为什么需要它: 链式节点 (中转 → 落地) 的延迟永远高于直连节点, 所以"自动选择"不会选它;
#: 而 OpenAI / Netflix 这类服务**只认落地地区的 IP** —— 结果是香港直连节点能上网, 但这些
#: 站点一律拒绝。解决办法不是全局切到落地 (那会很慢), 而是把这几类域名单独指过去:
#: 默认走最快的节点, 只有它们走落地。
#:
#: 规则写法有两类, 缺一不可:
#:   * GEOSITE/GEOIP: 覆盖广 (一个分类几百上千个域名), 但依赖 geo 数据库里有这个分类;
#:   * DOMAIN-SUFFIX: 显式域名, 不依赖数据库 —— 对"必须能通"的服务用这种兜底。
G_LANDING = "🌍 落地节点"

#: AI 服务: 地域限制最硬的一类, 用显式域名 (不依赖 geo 数据库的收录情况)
LANDING_DOMAINS = (
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai",
    "gemini.google.com", "bard.google.com", "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "perplexity.ai", "x.ai", "grok.com", "midjourney.com",
    "poe.com", "character.ai", "sora.com",
    "primevideo.com", "hulu.com", "max.com", "hbomax.com",
    "disneyplus.com", "spotify.com", "soundcloud.com", "deezer.com",
    "pandora.com", "crunchyroll.com", "paramountplus.com", "peacocktv.com",
)

#: 流媒体/服务分类 (geo 数据库收录广, 一个分类顶几百个域名)
LANDING_GEOSITES = ("netflix", "disney", "hbo", "primevideo", "youtube")


def _landing_rules(geo: bool = True) -> list[str]:
    """"必须走落地"的规则 (放在最前面, 早于国内直连)。

    `geo=False` 时只留显式域名那批: GEOSITE 需要分流数据库, 而这一步的意思是
    "这台设备现在拿不到数据库"。
    """
    rules = [f"DOMAIN-SUFFIX,{d},{G_LANDING}" for d in LANDING_DOMAINS]
    if geo:
        rules += [f"GEOSITE,{g},{G_LANDING}" for g in LANDING_GEOSITES]
    return rules


#: 「必须走直连」的国内应用生态域名 —— **纯域名规则, 不依赖分流数据库**。
#:
#: 为什么单列一层, 而不是只靠 `geosite:cn` —— 两条独立理由, 都不是锦上添花:
#:
#:   1. **降级路径 (真机踩过)**: 路由器拿不到分流数据库时, 面板给的是一份不含任何
#:      geo 规则的配置 (见 share_links.clash_profile 的 `geo` 参数)。那一份里原本
#:      **一条国内直连规则都没有** —— 全屋流量, 包括微信 / 支付宝 / 公众号 / 小程序,
#:      全部走节点。真机上的表现正是"国内网站、公众号、小程序都打不开或者很慢"。
#:      这一层是域名规则, 不需要数据库, 所以降级配置里也照发。
#:   2. **覆盖缺口 (实测)**: `geosite:cn` 有 11.1 万条, 覆盖了绝大多数国内域名, 但
#:      **不是全部**。拿 MetaCubeX 的实际 geosite.dat 逐条核对后, 下面这些确定的国内
#:      域名并不在 `cn` 分类里 (见 docs/RESEARCH.md #19):
#:        alipaylog.com · aliapp.org · mmstat.com · alimama.com · amap.net ·
#:        snssdk.com · baidustatic.com · hao222.com · duapp.com · duapps.com ·
#:        quyaoya.com · cup62.cn · chinaunionpay.com.cn · alipay.cn · alipay.com.cn
#:      对"必须能通"的服务用显式域名兜底 —— 与落地组 (LANDING_DOMAINS) 是同一种做法。
#:
#: 顺序: 放在广告拦截与落地组之后、geo 直连之前 —— 显式域名优先于分类匹配。
#: 生态分组只是给人看的, 匹配语义与顺序无关 (mihomo 对 DOMAIN-SUFFIX 用域名树)。
CN_DIRECT_DOMAINS = (
    # ---- 微信 / Weixin (公众号 mp.weixin.qq.com、小程序运行环境 servicewechat.com、
    #      图片与静态资源 qpic/qlogo/gtimg、登录与长连接全在 qq.com 之下、支付 tenpay) ----
    "qq.com", "qq.com.cn", "weixin.com", "weixinbridge.com", "weixinsxy.com",
    "wechat.com", "wechatpay.com", "servicewechat.com",
    "tenpay.com", "globaltenpay.com",
    "qpic.cn", "qlogo.cn", "gtimg.cn", "gtimg.com", "gtimg.com.cn",
    "qcloud.com", "myqcloud.com", "tencent.com", "tencent-cloud.net",
    "tencentcloudapi.com", "tencentcos.cn", "wegame.com",
    # ---- 支付宝 / 阿里 (含支付宝小程序 alipayobjects、云闪付之外的自有域名) ----
    "alipay.com", "alipay.cn", "alipay.com.cn", "alipayobjects.com", "alipaydev.com",
    "alipaylog.com", "alipaydns.com", "alipay-eco.com", "aliapp.org", "mybank.cn",
    "antgroup.com", "antfin.com", "antgroup-inc.cn",
    "alibaba.com", "alibaba-inc.com", "alibabacloud.com", "alibabacorp.com",
    "alicdn.com", "aliyun.com", "aliyuncs.com", "aliyun-inc.com",
    "taobao.com", "tmall.com", "tbcdn.cn", "tbcache.com", "mmstat.com", "taobaocdn.com",
    "1688.com", "alimama.com", "alimama.cn",
    "amap.com", "amap.net", "gaode.com", "autonavi.com",
    "dingtalk.com", "dingtalk.cn", "ele.me", "elemecdn.com",
    "uc.cn", "ucweb.com", "quark.cn", "sm.cn", "youku.com",
    # ---- 字节 (抖音 / 头条 / 飞书) ----
    "bytedance.com", "bytedance.cn", "byteimg.com", "bytednsdoc.com", "bytecdn.cn",
    "douyin.com", "douyinpic.com", "douyinstatic.com", "douyinvod.com",
    "feishu.cn", "larkoffice.com", "snssdk.com", "toutiao.com",
    "ixigua.com", "ixiguavideo.com", "volces.com", "volcengine.com", "zijieapi.com",
    # ---- 百度 (含 .com 短域名, 这几个都不在 geosite:cn 里) ----
    "baidu.com", "baidu.cn", "baidu.com.cn", "baidustatic.com", "bdstatic.com", "bdimg.com",
    "bcebos.com", "baidubce.com", "bce-cdn.cn", "bdycdn.cn", "bdydns.cn", "baiduyuncdn.cn",
    "hao123.com", "hao222.com", "duapp.com", "duapps.com", "duurl.cn", "dwz.cn",
    "quyaoya.com", "jomocdn.cn", "jomodns.cn",
    # ---- 支付 / 银联 / 银行 (银联的国内域名几乎都不在 cn 分类里) ----
    "unionpay.com", "unionpayintl.cn", "unionpaysecure.com", "chinaunionpay.com.cn",
    "cup.com.cn", "cup62.cn", "95516.com",
    "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankofchina.com", "bankcomm.com",
    "cmbchina.com", "cmbchina.cn", "spdb.com.cn", "citicbank.com", "cebbank.com",
    "cgbchina.com.cn", "pingan.com", "pingancdn.com", "psbc.com",
    # ---- 电商 / 生活服务 / 出行 ----
    "jd.com", "360buyimg.com", "pinduoduo.com", "yangkeduo.com", "pddpic.com",
    "meituan.com", "meituan.net", "dianping.com", "sankuai.com",
    "xiaojukeji.com", "didichuxing.com", "didistatic.com",
    "ctrip.com", "qunar.com", "ly.com", "hellobike.com", "mobike.com",
    # ---- 社交 / 内容 / 视频 / 音乐 ----
    "weibo.com", "weibo.cn", "sina.com.cn", "sinaimg.cn", "sinajs.cn",
    "zhihu.com", "zhimg.com", "xiaohongshu.com", "xhscdn.com",
    "douban.com", "doubanio.com",
    "bilibili.com", "hdslb.com", "acfun.cn", "kuaishou.com",
    "douyu.com", "huya.com", "yystatic.com",
    "163.com", "126.net", "127.net", "netease.com",
    "kugou.com", "kglink.cn", "kuwo.cn",
    "iqiyi.com", "qiyi.com", "iqiyipic.com", "mgtv.com", "hunantv.com",
    "sohu.com", "letv.com", "le.com", "ximalaya.com", "xmcdn.com",
    # ---- 办公 / 开发 ----
    "wps.cn", "wps.com", "kingsoft.com", "kdocs.cn", "yuque.com",
    "coding.net", "gitee.com", "oschina.net", "csdn.net", "cnblogs.com",
    "juejin.cn", "teambition.com",
    # ---- 手机 / 硬件 / 家电 ----
    "mi.com", "miui.com", "xiaomi.com", "mijia.tech", "xiaomiyoupin.com",
    "huawei.com", "hicloud.com", "huaweicloud.com",
    "oppo.com", "vivo.com", "heytap.com", "coloros.com", "meizu.com", "tcl.com",
    # ---- 安全 / 搜索 / 教育 / 快递 / 游戏 / 运营商 ----
    "360.cn", "360.com", "360safe.com", "qihoo.com", "qhimg.com", "qhimgs.com",
    "sogou.com", "sogoucdn.com", "liebao.cn",
    "xueersi.com", "zybang.com", "17zuoye.com", "chaoxing.com", "kaikeba.com",
    "sf-express.com", "yundaex.com",
    "mihoyo.com", "yuanshen.com",
    "chinatelecom.com.cn", "chinamobile.com", "chinaunicom.com.cn", "10010.com",
)

#: 「国内直连」的分类 geo 规则 (需要分流数据库, 因此只在 `geo=True` 时下发)。
#:
#: 全部来自客户端实际下载的 MetaCubeX geosite.dat —— **分类名拼错会让整个配置加载失败**
#: (实测 v1.19.32: `GEOSITE,不存在的分类` → `list … not found in geosite.dat` →
#: `configuration file test failed`), 所以这张表只收已经在两份上游数据里都核对过的分类,
#: 并由 tests/test_panel.py 的白名单断言守着。
#:
#:   cn              国内主表 (11.1 万条, 含 .cn TLD)
#:   geolocation-cn  v2fly 的"中国地理位置"表 —— 补 cn 没收的那 1300 多条
#:   tencent/alibaba/aliyun/bytedance/baidu/unionpay
#:                   公司级分类; 实测这些分类里各有几十~几百条域名不在 cn 里
#:                   (其中不少是各自 App 的 App 内接口, 正是"App 用不了"的来源)
CN_DIRECT_GEOSITES = (
    "cn",
    "geolocation-cn",
    "tencent",
    "alibaba",
    "aliyun",
    "bytedance",
    "baidu",
    "unionpay",
)


def _cn_direct_rules(geo: bool = True) -> list[str]:
    """"必须走直连"的国内规则 (放在 geo 通用直连之前)。

    域名那批**永远在** (降级配置里也留) —— 这是"国内 App 一定直连"的保证;
    分类规则需要数据库, 只在 `geo=True` 时追加。
    """
    rules = [f"DOMAIN-SUFFIX,{d},{G_DIRECT}" for d in CN_DIRECT_DOMAINS]
    if geo:
        rules += [f"GEOSITE,{g},{G_DIRECT}" for g in CN_DIRECT_GEOSITES]
    return rules


#: sing-box 侧的远程 rule-set —— 与 Clash 侧的两层规则一一对应:
#:   LANDING_RULE_SETS  ← LANDING_GEOSITES
#:   CN_RULE_SETS       ← CN_DIRECT_GEOSITES
#: 名字都在 SagerNet/sing-geosite 的 rule-set 分支里 (实测可直接下载)。
LANDING_RULE_SETS = tuple(
    (g, f"sing-geosite@rule-set/geosite-{g}.srs") for g in LANDING_GEOSITES
)
CN_RULE_SETS = tuple((g, f"sing-geosite@rule-set/geosite-{g}.srs") for g in CN_DIRECT_GEOSITES)


def smart_rule_sets() -> tuple[tuple[str, str], ...]:
    """smart 模板的全部远程 rule-set。

    tag 唯一是硬要求 —— sing-box 对重复的 rule-set tag 直接拒绝启动。三个来源的
    tag 集合互不相交 (ads / cn-ip / cn / geolocation-cn / 各公司分类 / 各落地分类)。
    """
    return tuple(SMART_RULE_SETS + CN_RULE_SETS + LANDING_RULE_SETS)


#: 健康检查目标 (url-test 用它判断哪个节点/哪台服务器可用)
HEALTH_URL = "http://www.gstatic.com/generate_204"

#: 路由器端配置文件 (profile=router)。手机/电脑端导入订阅就完事, 路由器端不一样:
#: 它要接管**全屋**流量, 配置里少一个字段就是"某类 App 用不了"的工单。这里逐项说明
#: 为什么这么写 —— 这些都是"上网体验不受影响"的关键, 不是随手加的调优参数。
#
#:   dns + fake-ip        路由器上必须由内核接管 DNS。fake-ip 让域名在连接前就拿到一个
#:                        可路由的假 IP, 分流规则按域名判定 → 国内站点不会被误判成
#:                        "未知 IP 走代理"。dnsmasq 完全不用改 (见下面 dns-hijack)。
#:   nameserver-policy    国内域名用国内 DNS 解析 (拿到最近的 CDN 节点), 国外域名走
#:                        DoH 且经代理出去 —— 这是"全屋走代理"但不拖慢国内站点的核心。
#:   proxy-server-nameserver
#:                        解析节点自己的域名必须直连。若它跟着规则走了代理, 就成了
#:                        "要先连上代理才能解析代理地址"的死锁, 表现是开机后一直转圈。
#:   sniffer              有些 App 直接连 IP, 规则只能看到 IP。开 SNI 嗅探后仍按域名
#:                        分流, 国内直连的准确率明显变好 (尤其是 App 内的 CDN 回源)。
#:   fake-ip-filter       这些域名必须拿到真实 IP: 局域网设备发现 (mDNS/SSDP)、路由器
#:                        自己的管理域名、NTP、微信本地回环登录 —— 给成假 IP 会直接
#:                        让"打印机找不到""智能音箱配不上网""时间同步失败"。
#:   find-process-mode    路由器上没有进程匹配能力, 关掉省 CPU 和内存。
#:   tun + auto-route     全屋透明的实现方式。用 tun 而不是自写 nftables 规则, 是因为
#:                        tun 由内核接管路由且**可逆**: 内核一停, 网络立刻回到原样。
#:   tun.dns-hijack       dnsmasq 的查询也要进内核, 否则局域网设备拿到的还是真实 IP。
#:                        有了它就不用改 /etc/config/dhcp, 卸载/关开关都不留残留。
#:   log-level: warning   路由器闪存写日志是慢性损耗, 正常运行不该刷 info。
ROUTER_FAKE_IP_FILTER = [
    "*.lan",
    "*.local",
    "*.localdomain",
    "*.home.arpa",
    "localhost.ptlogin2.qq.com",
    "localhost.*.wechat.com",
    "*.msftconnecttest.com",
    "*.msftncsi.com",
    "time.*.com",
    "time.*.gov",
    "ntp.*.com",
    "*.pool.ntp.org",
    "*.ntp.org.cn",
    "+.market.xiaomi.com",
    "*.stun.*",
    "stun.*",
    "*.*.stun.*",
    "*.turn.*",
    "*.webrtc.*",
]

#: 路由器端 `dns` 段。国内域名走国内 DNS (快、拿到就近 CDN), 国外域名走 DoH 且经代理
#: 出口 (不被污染)。DoH 的域名解析走 default-nameserver (纯 IP, 国内), 所以引导期
#: 不会绕回代理 —— 整条链路上没有死循环。
ROUTER_DNS = {
    "enable": True,
    # 0.0.0.0 而不是 127.0.0.1: tproxy 回退模式下 nft 会把局域网 DNS 重定向到这个
    # 端口, 只监听回环就收不到。tun 模式下用不到它 (走 dns-hijack)。
    "listen": "0.0.0.0:7874",
    "ipv6": False,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": ROUTER_FAKE_IP_FILTER,
    # 只用来解析下面这些 DoH 服务器的主机名 (它们是 IP, 通常用不到, 但要有)
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "nameserver": ["223.5.5.5", "119.29.29.29"],
    "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
    "direct-nameserver": ["223.5.5.5", "119.29.29.29"],
    # 只给"要直连的域名"指定国内 DNS。**国外域名故意不在这里配 DoH**:
    #
    # 真机反馈: YouTube 首屏要十几秒, 但视频一开始播就满速。原因是给国外域名配了
    # "DoH 经代理出去" —— 每解析一个新域名都是 路由器 → 内核 → 节点 → Cloudflare
    # 两个来回; 一个页面首屏要碰几十个域名, 串起来就是十几秒。播放快是因为那条
    # 长连接的域名早就解析完了。
    #
    # 被代理的域名本来就不需要在本地解析: mihomo 的 fake-ip 已经把域名映射留在手里,
    # 转发给节点时带的是**域名**, 由落地节点在本地解析 —— 又快又不怕污染。
    # 所以这里只留"国内/私有域名走国内 DNS"这一条。
    "nameserver-policy": {
        "geosite:private,cn": ["223.5.5.5", "119.29.29.29"],
    },
}

#: 路由器端 `tun` 段 (全屋透明的实现)。gvisor 栈兼容性最好; mtu 压到 1500 是因为
#: 部分宽带/光猫对巨帧不友好, 表现为"能连上但大文件卡死"。
ROUTER_TUN = {
    "enable": True,
    # stack: system —— 用内核的 tun 收发, 而不是 gvisor 的用户态协议栈。
    # gvisor 兼容性最好但**每一个包都要过用户态**, 在 MT7981 这种双核 A53 上就是
    # 吞吐天花板 (真机反馈: 比电脑上直接跑代理慢一截)。system 走内核路径, 同样的
    # 硬件通常能快出成倍。万一某台设备的 system 栈有问题, 把它改回 "gvisor" 即可。
    "stack": "system",
    "device": "zp-tun",
    "auto-route": True,
    "auto-redirect": True,
    "auto-detect-interface": True,
    "mtu": 1500,
    "dns-hijack": ["any:53"],
}


def router_tun(tproxy: bool = True) -> dict:
    """路由器端的 `tun` 段 (按设备的实际能力裁剪)。

    `auto-redirect` 会往内核里写 nftables 规则 (sing-tun 在 OpenWrt 上还会写
    `/etc/nftables.d/0-*-auto-redirect.nft` 再 `fw4 reload`) —— 设备不支持时, **tun 会
    因为这一步失败而建不出来**: 现象是装完之后 `zp-tun` 一直不出现, 于是脚本退回
    tproxy, 而那台设备的 tproxy 往往是同一个原因不可用, 最后"全屋透明代理"名存实亡
    (真机: GL.iNet 原厂 OpenWrt 21.02-SNAPSHOT / 内核 5.4.281, 见 README 8.45)。

    "全屋"的本体是 `auto-route` (它用 ip rule + 独立路由表接管所有流量, 含局域网转发),
    所以去掉 auto-redirect 不影响功能。设备在装机时探一次自己有没有 nft/tproxy, 用
    `?tproxy=0` 告诉面板 —— 有就用, 没有就别写, 别让它把 tun 拖垮。
    """
    if tproxy:
        return dict(ROUTER_TUN)
    trimmed = dict(ROUTER_TUN)
    trimmed.pop("auto-redirect", None)
    return trimmed


#: 路由器端 `dns` 段在**没有**分流数据库时的样子: nameserver-policy 的键是
#: `geosite:private,cn`, 它自己也要 geosite.dat 才成立 (mihomo 会为它去加载数据库)。
#: 数据库实在取不到时, 宁可少一条"国内域名走国内 DNS"的优化, 也不能让配置加载失败。
def router_dns(geo: bool = True) -> dict:
    if geo:
        return ROUTER_DNS
    return {k: v for k, v in ROUTER_DNS.items() if k != "nameserver-policy"}


def template_of(state: dict, override: str | None = None) -> str:
    """生效的分流模板: URL 参数 > 面板设置 > 默认值。"""
    candidate = (override or "").strip().lower()
    if candidate in TEMPLATES:
        return candidate
    saved = str((state.get("routing") or {}).get("template", "")).strip().lower()
    return saved if saved in TEMPLATES else DEFAULT_TEMPLATE


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [x for x in items if not (x in seen or seen.add(x))]

#: 各客户端对 XHTTP 传输的支持情况 — 已用真实二进制验证:
#: mihomo v1.19.31 接受 network: xhttp + xhttp-opts, sing-box 1.14.2 接受
#: transport.type=http, 两者配置校验均通过 (scripts/verify.py 可复现)。
CLASH_XHTTP = True
SINGBOX_XHTTP = True

SUB_FORMATS = ("base64", "clash", "singbox")


# ---------------------------------------------------------------- 通用小工具

def _q(text: str) -> str:
    """URL 组件编码 (分享链接里的名字/路径)。"""
    return quote(text, safe="")


def _pbk(public_key: str) -> str:
    """Reality pbk 参数要求 base64url 无填充 (state 中即该格式, 容错 std 输入)。"""
    if any(c in public_key for c in "+/") or public_key.endswith("="):
        raw = base64.urlsafe_b64decode(
            public_key.replace("-", "+").replace("_", "/") + "=" * (-len(public_key) % 4)
        )
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return public_key


def _insecure(state: dict) -> bool:
    """自签证书 → 客户端需要跳过证书链校验。"""
    return state["cert"]["type"] != "letsencrypt"


def _node_name(node_id: str) -> str:
    meta = config.NODE_BY_ID.get(node_id)
    return f"ZeroProxy {meta['name']}" if meta else node_id


def chain_entry_of(state: dict, node_id: str) -> dict | None:
    """`chain-<短id>` → 链式条目 (不是链式节点则返回 None)。"""
    if not node_id.startswith("chain-"):
        return None
    short = node_id[len("chain-"):]
    for entry in (state.get("chain") or {}).get("entries") or []:
        if entry.get("id") == short:
            return entry
    return None


def chain_node_name(entry: dict) -> str:
    """订阅里显示的名字: 中转链路对客户端只是一个普通节点, 名字里标出落地在哪。"""
    label = (entry.get("label") or "").strip() or entry.get("host", "")
    return f"ZeroProxy 链式 · {label}"


def _hysteria_ports(state: dict) -> list[int]:
    """Hysteria 2 实际监听的 UDP 端口列表。"""
    if state.get("nodes", {}).get("hysteria2") and state.get("hysteria_hopping", False):
        return list(state.get("hysteria_ports") or [state["ports"]["hysteria"]])
    return [state["ports"]["hysteria"]]


def _hysteria_hop_span(state: dict) -> str:
    """端口跳跃的紧凑写法: 连续端口折叠成 `a-b`, 否则逗号列表。"""
    ports = sorted(_hysteria_ports(state))
    if len(ports) > 2 and ports == list(range(ports[0], ports[-1] + 1)):
        return f"{ports[0]}-{ports[-1]}"
    return ",".join(str(p) for p in ports)


# ---------------------------------------------------------------- 单节点链接

def share_links(state: dict) -> dict[str, str]:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    x = state.get("xhttp") or {}
    uuid = state["uuid"]
    xhttp_host = (x.get("host") or "").strip() or r["server_name"]
    xhttp_path = x.get("path") or XHTTP_PATH

    links: dict[str, str] = {}

    links["vless-reality"] = (
        f"vless://{uuid}@{host}:{ports['reality']}"
        # flow 必须与服务端 xray_config._reality_inbound 的 xtls-rprx-vision 一致,
        # 否则 Reality+Vision 双端不匹配会导致握手失败 (技术文档 §7.2)
        f"?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp"
        f"&pbk={_pbk(r['public_key'])}&sid={r['short_id']}"
        f"&sni={_q(r['server_name'])}&fp=chrome"
        f"#{_q(_node_name('vless-reality'))}"
    )

    links["vless-xhttp"] = (
        f"vless://{uuid}@{host}:{ports['xhttp']}"
        f"?encryption=none&security=reality&type=xhttp"
        f"&path={_q(xhttp_path)}&host={_q(xhttp_host)}&mode={_q(x.get('mode') or 'auto')}"
        f"&pbk={_pbk(r['public_key'])}&sid={r['short_id']}"
        f"&sni={_q(r['server_name'])}&fp=chrome"
        f"#{_q(_node_name('vless-xhttp'))}"
    )

    links["vless-ws"] = (
        f"vless://{uuid}@{host}:443"
        f"?type=ws&security=tls&path={_q(WS_PATH)}"
        f"&host={_q(host)}&sni={_q(host)}&fp=chrome"
        f"&allowInsecure={1 if _insecure(state) else 0}"
        f"#{_q(_node_name('vless-ws'))}"
    )

    links["trojan"] = (
        f"trojan://{_q(state['trojan_password'])}@{host}:{ports['trojan']}"
        f"?type=tcp&security=tls&sni={_q(host)}"
        f"&allowInsecure={1 if _insecure(state) else 0}"
        f"#{_q(_node_name('trojan'))}"
    )

    # 端口跳跃: 端口写在 host 上 (官方客户端据此启用 udphop), 同时附 mport 供
    # 支持该参数的三方客户端使用; 官方客户端会忽略未知查询参数。
    hop_ports = _hysteria_hop_span(state)
    links["hysteria2"] = (
        f"hysteria2://{_q(state['hysteria_password'])}@{host}:{hop_ports}"
        f"?sni={_q(host)}&insecure=1"
        f"&mport={_q(hop_ports)}"
        f"#{_q(_node_name('hysteria2'))}"
    )

    # 链式中转节点: 地址/密钥是**本机**的 (客户端连本机), 出口在落地服务器那一侧 ——
    # 因此对客户端来说它就是"多了个普通 Reality 节点", 中转链路完全透明。
    for entry in (state.get("chain") or {}).get("entries") or []:
        if not entry.get("enabled", True) or not entry.get("local_port"):
            continue
        links[f"chain-{entry['id']}"] = (
            f"vless://{uuid}@{host}:{int(entry['local_port'])}"
            f"?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp"
            f"&pbk={_pbk(r['public_key'])}&sid={r['short_id']}"
            f"&sni={_q(r['server_name'])}&fp=chrome"
            f"#{_q(chain_node_name(entry))}"
        )

    return links


def enabled_links(state: dict) -> list[tuple[str, str]]:
    """[(node_id, link)] — 仅包含启用中的节点: 先是 5 个主力节点, 再是链式中转节点。"""
    links = share_links(state)
    nodes = state.get("nodes", {})
    order = [n["id"] for n in config.NODES]
    out = [(nid, links[nid]) for nid in order if nodes.get(nid, True) and links.get(nid)]
    out += [(nid, link) for nid, link in links.items() if nid.startswith("chain-")]
    return out


# ---------------------------------------------------------------- 订阅: base64

def subscription_content(state: dict) -> str:
    """仅包含启用节点的链接 (换行分隔)。"""
    return "\n".join(link for _, link in enabled_links(state))


def subscription_b64(state: dict) -> str:
    return base64.b64encode(subscription_content(state).encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------- 订阅: Clash

def _clash_proxy(state: dict, node_id: str) -> dict | None:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    x = state.get("xhttp") or {}

    entry = chain_entry_of(state, node_id)
    if entry is not None:
        # 链式中转节点: 客户端连本机 (Reality + Vision), 出网走落地端
        return {
            "name": chain_node_name(entry),
            "type": "vless",
            "server": host,
            "port": int(entry["local_port"]),
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "flow": "xtls-rprx-vision",
            "servername": r["server_name"],
            "client-fingerprint": "chrome",
            "network": "tcp",
            "reality-opts": {"public-key": _pbk(r["public_key"]), "short-id": r["short_id"]},
        }
    if node_id == "vless-reality":
        return {
            "name": _node_name(node_id),
            "type": "vless",
            "server": host,
            "port": ports["reality"],
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "flow": "xtls-rprx-vision",
            "servername": r["server_name"],
            "client-fingerprint": "chrome",
            "network": "tcp",
            "reality-opts": {"public-key": _pbk(r["public_key"]), "short-id": r["short_id"]},
        }
    if node_id == "vless-xhttp":
        if not CLASH_XHTTP:
            return None
        return {
            "name": _node_name(node_id),
            "type": "vless",
            "server": host,
            "port": ports["xhttp"],
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "servername": r["server_name"],
            "client-fingerprint": "chrome",
            "network": "xhttp",
            "xhttp-opts": {
                "path": x.get("path") or XHTTP_PATH,
                "host": (x.get("host") or "").strip() or r["server_name"],
                "mode": x.get("mode") or "auto",
            },
            "reality-opts": {"public-key": _pbk(r["public_key"]), "short-id": r["short_id"]},
        }
    if node_id == "vless-ws":
        return {
            "name": _node_name(node_id),
            "type": "vless",
            "server": host,
            "port": 443,
            "uuid": state["uuid"],
            "udp": True,
            "tls": True,
            "servername": host,
            "skip-cert-verify": _insecure(state),
            "client-fingerprint": "chrome",
            "network": "ws",
            "ws-opts": {"path": WS_PATH, "headers": {"Host": host}},
        }
    if node_id == "trojan":
        return {
            "name": _node_name(node_id),
            "type": "trojan",
            "server": host,
            "port": ports["trojan"],
            "password": state["trojan_password"],
            "udp": True,
            "sni": host,
            "skip-cert-verify": _insecure(state),
            "client-fingerprint": "chrome",
        }
    if node_id == "hysteria2":
        proxy = {
            "name": _node_name(node_id),
            "type": "hysteria2",
            "server": host,
            "password": state["hysteria_password"],
            "sni": host,
            "skip-cert-verify": True,
        }
        hop = _hysteria_hop_span(state)
        if "," in hop or "-" in hop:
            proxy["ports"] = hop
            proxy["hop-interval"] = 30
        else:
            proxy["port"] = int(hop)
        return proxy
    return None


def _groups_for(names: list[str], tpl: str) -> list[dict]:
    """节点直接内联时的策略组 (手机/电脑端订阅, 以及单服务器的路由器配置)。

    节点全关时也要产出可用的配置: 策略组退化为只含 DIRECT。
    `♻️ 自动选择` 只在有节点时才定义, 所以候选列表里也必须跟着省掉 —— 以前无条件把它
    写进 `🚀 节点选择`, 于是"节点全关"时 mihomo 会因为引用到一个不存在的策略组直接
    拒绝加载整份订阅。
    """
    select_members = _dedup(([G_AUTO] if names else []) + names + ["DIRECT"])
    groups: list[dict] = []
    if names:
        groups.append(
            {"name": G_AUTO, "type": "url-test", "url": HEALTH_URL, "interval": 300, "proxies": names}
        )
    # 落地组: 成员是链式节点 (中转→落地)。没有链式节点时兜底成员就是"节点选择",
    # 于是行为与从前完全一致 —— 没配落地的用户无感。
    landing = [n for n in names if "链式" in n]
    groups += [
        {"name": G_SELECT, "type": "select", "proxies": select_members},
        {"name": G_LANDING, "type": "select", "proxies": landing + [G_SELECT]},
        {"name": G_DIRECT, "type": "select", "proxies": ["DIRECT", G_SELECT]},
        {"name": G_ADS, "type": "select", "proxies": ["REJECT", "DIRECT"]},
        {
            "name": G_FINAL,
            "type": "select",
            # direct 模板下"漏网之鱼"默认直连, 其余模板默认交给节点选择
            "proxies": [G_SELECT, "DIRECT"] if tpl != "direct" else ["DIRECT", G_SELECT],
        },
    ]
    return groups


def clash_profile(
    state: dict,
    template: str | None = None,
    router: bool = False,
    device: str = "",
    skeleton: bool = False,
    geo: bool = True,
    base: str = "",
    tproxy: bool = True,
) -> str:
    """Clash / mihomo 配置。

    `router=True` 时输出路由器端专用版本: 多出 tun / dns / 嗅探三段, 由路由器
    整机接管全屋流量 (见 ROUTER_DNS / ROUTER_TUN 上面的说明)。
    `device` 只用于注释里标注是哪台设备拉的, 不影响配置内容。

    `base` 是面板自己的对外地址 (仅路由器端用): 分流数据库的下载地址指向面板,
    而不是让路由器自己翻墙去 GitHub —— 装机时它还没有任何代理可用。
    `geo=False` 是**降级**: 面板暂时给不出数据库时, 输出一份不引用 geo 的规则
    (少一层国内直连与广告拦截, 但能跑起来), 等数据到位后 agent 会自己换回来。
    `tproxy=False` 同理, 是设备侧的能力: 那台路由器没有 nft/tproxy 时不要写
    `auto-redirect` (它会让 tun 建不起来), 见 router_tun。
    """
    proxies: list[dict] = []
    skipped: list[str] = []
    for node_id, _ in enabled_links(state):
        proxy = _clash_proxy(state, node_id)
        if proxy:
            proxies.append(proxy)
        else:
            skipped.append(_node_name(node_id))

    tpl = template_of(state, template)
    names = [p["name"] for p in proxies]
    # 多服务器模式 (skeleton): 节点不在这份配置里, 而是由路由器挂成若干个
    # proxy-provider。这里只出"骨架" —— 端口 / DNS / tun / 嗅探 / 规则都在,
    # 唯独 providers 与组的成员留空, 由路由器按行填 (见 router-install.sh)。
    # 用"空结构"而不是自定义标记, 是为了让骨架本身就一份合法的 mihomo 配置:
    # 出问题时能直接拿它去跑, 不用先做文本替换。
    if skeleton:
        groups = [
            {"name": G_AUTO, "type": "url-test", "url": HEALTH_URL, "interval": 300, "use": []},
            # 注意成员顺序: mihomo 组装 select 组时**先把内联 proxies 放前面**, provider
            # 的节点跟在后面, 而 select 的默认值就是第一个成员。这里若只写 [DIRECT],
            # 多服务器模式的默认选择就变成"直连"—— 真机表现: 节点全在, 但所有流量直连、
            # 境外全超时。把自动选择组放在首位, DIRECT 仍然可选。
            {"name": G_SELECT, "type": "select", "use": [], "proxies": [G_AUTO, "DIRECT"]},
            # 落地组: 从各 provider 的节点里挑名字含"链式"的 (多服务器模式的节点名
            # 带面板域名前缀, 但"链式"这个标记保留)。filter 匹配不到任何节点时,
            # 兜底成员"节点选择"保证这个组永远可用。
            {
                "name": G_LANDING,
                "type": "select",
                "use": [],
                "filter": "(?i)链式",
                "proxies": [G_SELECT],
            },
            {"name": G_DIRECT, "type": "select", "proxies": ["DIRECT", G_SELECT]},
            {"name": G_ADS, "type": "select", "proxies": ["REJECT", "DIRECT"]},
            {
                "name": G_FINAL,
                "type": "select",
                "proxies": [G_SELECT, "DIRECT"] if tpl != "direct" else ["DIRECT", G_SELECT],
            },
        ]
    else:
        groups = _groups_for(names, tpl)

    if tpl == "smart":
        # 顺序即优先级: 广告拦截 → 落地 → 国内 App 直连 → 国内通用直连 → 漏网之鱼。
        # 落地规则必须早于国内直连 (这些站点要用落地 IP, 不能被 cn 规则抢先放行);
        # 国内 App 直连层早于通用 geo 规则, 而且**不依赖数据库** —— 降级配置里它是
        # 唯一的国内直连来源 (见 CN_DIRECT_DOMAINS 的说明)。
        rules = []
        if geo:
            rules.append(f"GEOSITE,category-ads-all,{G_ADS}")
        rules += _landing_rules(geo)
        rules += _cn_direct_rules(geo)
        if geo:
            rules.append(f"GEOSITE,private,{G_DIRECT}")
        # GEOIP,LAN 是内建判断 (私有地址), 不需要数据库 —— 降级时也留着
        rules.append(f"GEOIP,LAN,{G_DIRECT},no-resolve")
        if geo:
            rules.append(f"GEOIP,CN,{G_DIRECT}")
        rules.append(f"MATCH,{G_FINAL}")
    elif tpl == "global":
        rules = []
        if geo:
            rules.append(f"GEOSITE,category-ads-all,{G_ADS}")
        rules += _landing_rules(geo)
        rules += [f"GEOIP,LAN,{G_DIRECT},no-resolve", f"MATCH,{G_SELECT}"]
    else:  # direct: 不依赖任何 geo 数据 (无需下载), 只做广告拦截与手动切换
        rules = [f"MATCH,{G_FINAL}"]

    # 分流数据库下载地址: mihomo 默认从 GitHub 拉取, 在受限网络下会超时
    # (实测: 首次拉取失败会导致整个订阅加载失败)。这里改成可用镜像,
    # 客户端首次导入时仍能自动拿到 geoip/geosite 数据。
    geox = {
        "mmdb": GEOX_BASE + "geoip.metadb",
        "geoip": GEOX_BASE + "geoip.dat",
        "geosite": GEOX_BASE + "geosite.dat",
        "asn": GEOX_BASE + "GeoLite2-ASN.mmdb",
    }
    if router and base:
        # 路由器端: 数据库由面板分发 —— 路由器只需要能访问面板 (它装机时没有任何代理,
        # 连不上 GitHub 是常态)。命令里两边都是同一个地址, 所以有面板就不该再回 GitHub。
        geox["mmdb"] = base.rstrip("/") + GEO_PATH + "geoip.metadb"
        geox["geosite"] = base.rstrip("/") + GEO_PATH + "geosite.dat"
    if router:
        # 路由器端: 键的书写顺序 = 运维时 cat 一眼的阅读顺序 (端口 → 内核参数 →
        # 分流数据 → 节点)。
        profile = {
            "mixed-port": 7890,          # 局域网里手动填代理地址时用
            "redir-port": 7892,          # TCP 透明代理 (tproxy 回退模式)
            "tproxy-port": 7893,         # TCP/UDP 透明代理 (tproxy 回退模式)
            "allow-lan": True,
            "bind-address": "*",
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            # 并发建连 + 统一延迟: 多设备同时上网时体感差别明显
            "tcp-concurrent": True,
            "unified-delay": True,
            # 路由器没有进程匹配能力, 关掉省 CPU
            "find-process-mode": "off",
            "keep-alive-interval": 30,
            # 本机控制口: 安装脚本用它做健康检查, 也留作以后"只重载不断连"的入口
            "external-controller": "127.0.0.1:9090",
            # store-selected 故意关掉: 面板才是开关的唯一出处, 路由器不需要记住
            # "上次手选了哪个节点"。开着它有个真机踩过的坑 —— 开机瞬间节点还没加载
            # (provider 还没拉下来) 时 mihomo 会把组落到 DIRECT 并**记住**,
            # 之后节点回来了也照样直连: 表现就是"全是超时, 页面加载极慢"。
            "profile": {"store-selected": False, "store-fake-ip": True},
            "sniffer": {
                "enable": True,
                "sniff": {
                    "HTTP": {"ports": [80, "8080-8880"]},
                    "TLS": {"ports": [443, 8443]},
                    "QUIC": {"ports": [443, 8443]},
                },
                # 这两类域名被嗅探后推送/米家设备的证书校验会出问题, 跳过
                "skip-domain": ["Mijia Cloud", "+.push.apple.com"],
            },
            "dns": router_dns(geo),
            "tun": router_tun(tproxy),
            "geox-url": geox,
            # 多服务器模式: 节点由路由器挂成 proxy-providers, 这里留一个空 map 当锚点
            **({"proxy-providers": {}} if skeleton else {"proxies": proxies}),
            "proxy-groups": groups,
            "rules": rules,
        }
    else:
        profile = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "geox-url": geox,
            "proxies": proxies,
            "proxy-groups": groups,
            "rules": rules,
        }
    tpl_note = (
        " (国内直连 + 广告拦截)" if tpl == "smart"
        else " (全部走代理)" if tpl == "global"
        else " (全部直连, 不下载 geo 数据)"
    )
    if router:
        head = [
            "# ZeroProxy 路由器客户端配置 — mihomo",
            "# 由面板自动生成, 请勿手改: 节点启停 / 端口变更 / 分流切换都会自动同步",
            f"# 分流模板: {tpl}{tpl_note}",
            "# 全屋透明代理由 tun + auto-route 接管, DNS 走 fake-ip + 嗅探;",
            "# dnsmasq / 防火墙都不需要改动, 停掉内核即完全恢复原状",
        ]
        if device:
            head.append(f"# 设备: {device}")
        if tpl != "direct":
            head.append(
                "# 分流数据库 (GeoIP / GeoSite) 随安装由面板下发, 已放在本目录; "
                "geox-url 也指向面板, 无需访问 GitHub"
                if geo
                else "# 注意: 本机没有分流数据库, 这份配置不含国内直连与广告拦截规则"
            )
    else:
        head = [
            "# ZeroProxy 订阅 — Clash / mihomo",
            "# 直接导入 App 或保存为 config.yaml 使用; 订阅内容会随面板配置自动更新",
            f"# 分流模板: {tpl}{tpl_note}",
            "# 切换模板: 面板「高级设置 → 分流模板」, 或在订阅 URL 后加 ?rules=smart|global|direct",
        ]
    if tpl != "direct" and not router:
        head.append("# 分流依赖客户端 geo 数据; 已内置 geox-url 镜像, 首次导入会自动下载")
    if skipped:
        head.append(f"# 本客户端不支持的节点已跳过: {', '.join(skipped)} (请用 sing-box / 单节点链接)")
    body = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return "\n".join(head) + "\n" + body


# ---------------------------------------------------------------- 订阅: sing-box

def _singbox_outbound(state: dict, node_id: str) -> dict | None:
    host = state["domain"]
    ports = state["ports"]
    r = state["reality"]
    x = state.get("xhttp") or {}
    tag = _node_name(node_id)

    entry = chain_entry_of(state, node_id)
    if entry is not None:
        # 链式中转节点: 客户端连本机, 落地在对方那一侧
        return {
            "type": "vless",
            "tag": chain_node_name(entry),
            "server": host,
            "server_port": int(entry["local_port"]),
            "uuid": state["uuid"],
            "flow": "xtls-rprx-vision",
            "packet_encoding": "xudp",
            "tls": {
                "enabled": True,
                "server_name": r["server_name"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": _pbk(r["public_key"]),
                    "short_id": r["short_id"],
                },
            },
        }
    if node_id == "vless-reality":
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": ports["reality"],
            "uuid": state["uuid"],
            "flow": "xtls-rprx-vision",
            "packet_encoding": "xudp",
            "tls": {
                "enabled": True,
                "server_name": r["server_name"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": _pbk(r["public_key"]),
                    "short_id": r["short_id"],
                },
            },
        }
    if node_id == "vless-xhttp":
        if not SINGBOX_XHTTP:
            return None
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": ports["xhttp"],
            "uuid": state["uuid"],
            "packet_encoding": "xudp",
            "transport": {
                "type": "http",
                "host": [(x.get("host") or "").strip() or r["server_name"]],
                "path": x.get("path") or XHTTP_PATH,
            },
            "tls": {
                "enabled": True,
                "server_name": r["server_name"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": _pbk(r["public_key"]),
                    "short_id": r["short_id"],
                },
            },
        }
    if node_id == "vless-ws":
        return {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": 443,
            "uuid": state["uuid"],
            "packet_encoding": "xudp",
            "transport": {"type": "ws", "path": WS_PATH, "headers": {"Host": host}},
            "tls": {
                "enabled": True,
                "server_name": host,
                "insecure": _insecure(state),
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
        }
    if node_id == "trojan":
        return {
            "type": "trojan",
            "tag": tag,
            "server": host,
            "server_port": ports["trojan"],
            "password": state["trojan_password"],
            "tls": {
                "enabled": True,
                "server_name": host,
                "insecure": _insecure(state),
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
        }
    if node_id == "hysteria2":
        out = {
            "type": "hysteria2",
            "tag": tag,
            "server": host,
            "password": state["hysteria_password"],
            "tls": {"enabled": True, "server_name": host, "insecure": True},
        }
        ports_list = sorted(_hysteria_ports(state))
        if len(ports_list) == 1:
            out["server_port"] = ports_list[0]
        else:
            out["server_ports"] = [f"{p}:{p}" for p in ports_list]
            out["hop_interval"] = "30s"
        return out
    return None


def _singbox_rule_set(tag: str, name: str, next_gen: bool = False) -> dict:
    """一条远程 rule-set 规则。

    next_gen=True 走 1.14+ 的 http_clients 写法 (不写 download_detour);
    否则写 download_detour=direct, 保证下载不经过节点、也不依赖节点是否可用。
    """
    ruleset: dict = {
        "type": "remote",
        "tag": tag,
        "format": "binary",
        "url": f"{SRS_BASE}{name}",
    }
    if not next_gen:
        ruleset["download_detour"] = "direct"
    return ruleset


def singbox_profile(state: dict, template: str | None = None, next_gen: bool = False) -> str:
    """sing-box 单文件配置。next_gen=True 面向 sing-box ≥1.14 (零废弃警告)。"""
    outbounds: list[dict] = []
    for node_id, _ in enabled_links(state):
        out = _singbox_outbound(state, node_id)
        if out:
            outbounds.append(out)

    tags = [o["tag"] for o in outbounds]
    tpl = template_of(state, template)
    outbounds.append({"type": "direct", "tag": "direct"})

    if tags:
        outbounds.append(
            {
                "type": "urltest",
                "tag": G_AUTO,
                "outbounds": tags,
                "url": "http://www.gstatic.com/generate_204",
                "interval": "5m",
            }
        )
    # 同 Clash: 没有节点时 `♻️ 自动选择` 不存在, 选择组里不能引用它 (sing-box 会拒绝启动)
    select_members = _dedup(([G_AUTO] if tags else []) + tags + ["direct"])
    outbounds.append(
        {
            "type": "selector",
            "tag": G_SELECT,
            "outbounds": select_members,
            "default": tags[0] if tags else "direct",
        }
    )
    outbounds.append(
        {
            "type": "selector",
            "tag": G_DIRECT,
            "outbounds": ["direct", G_SELECT],
            "default": "direct",
        }
    )
    # 落地组: 成员是链式节点 (名字里带"链式"), 没有时兜底到"节点选择"。
    # 与 Clash 侧同义 —— 之前 sing-box 侧漏了这一组, 结果同一个订阅在手机上
    # 打开 ChatGPT 会走最快的直连节点 (不是落地), 属于"三端一致"的缺口。
    landing_tags = [t for t in tags if "链式" in t]
    outbounds.append(
        {
            "type": "selector",
            "tag": G_LANDING,
            "outbounds": landing_tags + [G_SELECT],
            "default": landing_tags[0] if landing_tags else G_SELECT,
        }
    )
    outbounds.append(
        {
            "type": "selector",
            "tag": G_FINAL,
            "outbounds": [G_SELECT, "direct"] if tpl != "direct" else ["direct", G_SELECT],
            "default": G_SELECT if tpl != "direct" else "direct",
        }
    )

    rule_set: list[dict] = []
    rules: list[dict] = [
        # sing-box 1.11 起 sniff 等 legacy inbound 字段被移除, 改用路由动作
        {"action": "sniff"},
        {"ip_is_private": True, "action": "route", "outbound": G_DIRECT},
    ]
    if tpl == "smart":
        rule_set = [_singbox_rule_set(tag, name, next_gen) for tag, name in smart_rule_sets()]
        rules.append({"rule_set": ["ads"], "action": "reject"})
        # 落地优先于国内直连 (与 Clash 侧同一顺序), 否则 AI / 流媒体会被 cn 规则放行
        rules.append(
            {"domain_suffix": list(LANDING_DOMAINS), "action": "route", "outbound": G_LANDING}
        )
        rules.append(
            {
                "rule_set": [tag for tag, _ in LANDING_RULE_SETS],
                "action": "route",
                "outbound": G_LANDING,
            }
        )
        # 国内 App 直连: 域名那批**不依赖 rule-set**, 所以没有网络也能生效
        rules.append(
            {"domain_suffix": list(CN_DIRECT_DOMAINS), "action": "route", "outbound": G_DIRECT}
        )
        rules.append(
            {
                "rule_set": [tag for tag, _ in CN_RULE_SETS] + ["cn-ip"],
                "action": "route",
                "outbound": G_DIRECT,
            }
        )
        final = G_SELECT
    elif tpl == "global":
        rule_set = [_singbox_rule_set(*ADS_RULE_SET, next_gen)]
        rules.append({"rule_set": ["ads"], "action": "reject"})
        final = G_SELECT
    else:  # direct: 不引用任何远程 rule-set, 客户端零下载
        final = G_FINAL

    route: dict = {"rules": rules, "final": final}
    if rule_set:
        route = {"rule_set": rule_set, **route}

    profile: dict = {"log": {"level": "info", "timestamp": True}}
    if rule_set:
        # 远程 rule-set 落地缓存: 实测第二次启动零下载 (断网也能直接用上次数据)
        profile["experimental"] = {"cache_file": {"enabled": True}}
    if rule_set and next_gen:
        # 1.14+ 的写法: 显式声明下载用的 HTTP 客户端, 消除废弃警告
        profile["http_clients"] = [{"tag": DEFAULT_HTTP_CLIENT}]
        route["default_http_client"] = DEFAULT_HTTP_CLIENT
    profile["inbounds"] = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        }
    ]
    profile["outbounds"] = outbounds
    profile["route"] = route
    return json.dumps(profile, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 订阅出口

def provider_profile(state: dict, prefix: str = "") -> str:
    """路由器端多服务器模式: 单台面板的节点列表 (`?format=provider`)。

    只出 `proxies`, 不出 rules / groups —— 路由器把每台面板的这份内容挂成一个
    mihomo `proxy-provider`, 合并与健康检查都由 mihomo 自己做, 面板之间不需要
    互相认识 (也就不会互相泄露凭据)。

    节点名带面板域名的前缀, 这是**必须**的: 两台面板各自有一个"东京-01"时, 同名
    节点会让 mihomo 拒绝加载整份配置 (README 里"两条链同名导不进来"是同一个原因)。
    用域名当默认前缀不需要路由器传任何参数 —— 域名本来就是每台面板唯一的。
    """
    label = (prefix or str(state.get("domain") or "")).strip()
    proxies: list[dict] = []
    for node_id, _ in enabled_links(state):
        proxy = _clash_proxy(state, node_id)
        if not proxy:
            continue
        if label:
            proxy["name"] = f"{label} · {proxy['name']}"
        proxies.append(proxy)
    head = [
        "# ZeroProxy 节点源 (mihomo proxy-provider) — 路由器端多服务器聚合用",
        "# 本文件只含节点; 规则 / DNS / tun 由路由器侧的骨架提供",
        f"# 节点名前缀: {label or '(无)'}",
    ]
    body = yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
    return "\n".join(head) + "\n" + body


def router_skeleton(
    state: dict,
    template: str | None = None,
    device: str = "",
    geo: bool = True,
    base: str = "",
    tproxy: bool = True,
) -> str:
    """路由器端多服务器模式的骨架 (`?format=skeleton`)。

    端口 / DNS / tun / 嗅探 / 分流规则都在, `proxy-providers` 是空 map、组的
    `use` 是空列表 —— 路由器按行填进它自己那几台服务器的 provider 定义。
    """
    return clash_profile(
        state, template, router=True, device=device, skeleton=True, geo=geo, base=base,
        tproxy=tproxy,
    )


def subscription_body(
    state: dict,
    fmt: str = "base64",
    template: str | None = None,
    router: bool = False,
    device: str = "",
    prefix: str = "",
    geo: bool = True,
    base: str = "",
    tproxy: bool = True,
) -> tuple[str, str]:
    """返回 (响应体, media_type)。

    `router=True` 只对 clash 格式有效 (手机/电脑端的 base64 与 sing-box 输出不变):
    路由器端要的是"整机接管"的配置, 不是一份节点清单。
    """
    fmt = (fmt or "base64").lower()
    if fmt in ("provider", "nodes"):
        return provider_profile(state, prefix=prefix), "text/yaml; charset=utf-8"
    if fmt in ("skeleton", "router-skeleton"):
        return router_skeleton(
            state, template, device=device, geo=geo, base=base, tproxy=tproxy
        ), "text/yaml; charset=utf-8"
    if fmt in ("clash", "mihomo", "yaml", "yml"):
        return clash_profile(
            state, template, router=router, device=device, geo=geo, base=base, tproxy=tproxy
        ), "text/yaml; charset=utf-8"
    if fmt in ("singbox-next", "singbox14", "singbox-1.14", "singbox-new"):
        # 面向 sing-box ≥1.14: 用 http_clients 指定下载出口 (无废弃警告)
        return singbox_profile(state, template, next_gen=True), "application/json; charset=utf-8"
    if fmt in ("singbox", "sing-box", "singbox-json", "json"):
        return singbox_profile(state, template), "application/json; charset=utf-8"
    return subscription_b64(state), "text/plain; charset=utf-8"


def subscription_userinfo(traffic: dict | None) -> str | None:
    """订阅流量头 (客户端据此显示已用流量)。无统计数据时返回 None。"""
    if not traffic:
        return None
    up = int(traffic.get("uplink", 0) or 0)
    down = int(traffic.get("downlink", 0) or 0)
    return f"upload={up}; download={down}; total=0; expire=0"


def panel_base_url(request, state: dict) -> str:
    """面板对外基址。

    已配置域名时优先用域名: 配合面板 TLS 的 SNI 真实证书, https://<域名>:<port>
    即为浏览器可信地址; 否则回退到请求本身 (bootstrap 阶段用 IP:端口)。
    """
    scheme = request.url.scheme
    domain = (state.get("domain") or "").strip()
    if not domain:
        return f"{scheme}://{request.headers.get('host', request.url.netloc)}"
    # 以面板对外端口为准 (经 nginx 反代时 Host 头不含端口)
    port = config.PANEL_PORT
    netloc = domain if port in (80, 443) else f"{domain}:{port}"
    return f"{scheme}://{netloc}"


def subscription_url(request, state: dict) -> str:
    return f"{panel_base_url(request, state)}/sub/{state['subscription_token']}"
