# Protocol compatibility and stability research — 2026-11-15

Scope: source-level review for ZeroProxy's Xray/Hysteria generators and OpenWrt mihomo **v1.19.32**. Primary sources only; no private state was uploaded. Research initially inspected current upstream server sources, then pinned the relevant findings to the live server version reported by the parent: **Xray 26.11.9, commit 676eaf6** and Hysteria **2.13.0**. UI version strings are the local observation; upstream dependency contents are independently verified below. This report does not establish throughput or regional reachability.

## Highest-priority finding: REALITY hybrid key-share compatibility

mihomo v1.19.32 defines `reality-opts.support-x25519mlkem768` as a boolean. Its default is false, and the REALITY handshake explicitly removes the hybrid key share when false. The REALITY dependency pinned by Xray 26.11.9 rejects ClientHello messages lacking X25519MLKEM768 before the optional X25519 share. Therefore, **the reported Xray 26.11.9 server can reject both TCP REALITY and XHTTP REALITY from an otherwise correctly configured mihomo v1.19.32 client**. This is independent of VLESS UUID, XHTTP path, and Vision flow. Sources: [pinned option parser](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/adapter/outbound/reality.go), [pinned handshake, lines 54–55](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/component/tls/reality.go), [pinned server TLS implementation, lines 203–223](https://raw.githubusercontent.com/XTLS/REALITY/4bb46b2afd8b/tls.go).

Recommended diagnostic: preserve the current profile, add `support-x25519mlkem768: true` under `reality-opts` to temporary copies of both failed nodes, then run the **same router core** against the same endpoint. Use a modern Chrome fingerprint already supported by this core. If success changes only with this flag, capture both outcomes before changing the generator. Do not assume the flag is universally appropriate for old servers: the client source explicitly explains its compatibility workaround for old REALITY implementations. Xray commit 676eaf6 and tag v26.11.9 both pin `github.com/xtls/reality v0.0.0-20261108101329-4bb46b2afd8b`; this exact dependency contains the rejection rule. The isolated router test remains the behavioral acceptance criterion. [Commit dependency manifest](https://raw.githubusercontent.com/XTLS/Xray-core/676eaf6/go.mod), [release-tag manifest](https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/go.mod), [release version commit](https://github.com/XTLS/Xray-core/commit/676eaf6).

## Correct the minClientVer explanation

The comment in `backend/zeroproxy/xray_config.py` claiming an empty minimum automatically equals the server's current version is not supported by the inspected upstream code. The pinned Xray 676eaf6 config builder leaves the minimum nil for an empty setting; REALITY accepts a nil minimum. A historical Xray commit did set a **fixed 26.3.27** minimum; Xray 676eaf6 retains that assignment only as a comment. Explicit `0.0.0` avoids an explicit version floor but does not bypass key-share shape checks. Sources: [pinned config builder, lines 99–116](https://raw.githubusercontent.com/XTLS/Xray-core/676eaf6/infra/conf/transport_security.go), [historical change](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770), [pinned REALITY acceptance condition, lines 260–263](https://raw.githubusercontent.com/XTLS/REALITY/4bb46b2afd8b/tls.go).

The reported live version now maps to a verified upstream tag/commit. A speculative query for older tag `v26.10.29` returned 404; that does not affect the pinned 26.11.9 conclusion. mihomo's REALITY handshake reports version bytes **1.8.2**; do not confuse its product version 1.19.32 with those wire bytes. [Pinned handshake, lines 69–71](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/component/tls/reality.go).

## Configuration by protocol

| Protocol | Practical compatible baseline | Verification that matters |
| --- | --- | --- |
| VLESS + TCP + REALITY / Vision | Matching UUID and `flow: xtls-rprx-vision`; `tls: true`, `network: tcp`, explicit SNI, Chrome fingerprint, REALITY public key and short ID; retain xudp for Xray UDP framing | Authenticate through the proxy and fetch HTTPS; a TCP-open check alone proves only a listener |
| VLESS + XHTTP + REALITY | Matching UUID; omit Vision flow on both ends; `network: xhttp`; native mihomo `xhttp-opts` with path/host/mode; REALITY parameters as above | Check core parse plus actual HTTP proxy request; validate stream mode and server matching path |
| VLESS + WebSocket + TLS | Matching UUID, no Vision; `network: ws`; matching WS path/Host; TLS servername matching the certificate; nginx must forward the HTTP Upgrade route | HTTPS certificate verification, successful Upgrade, and an actual proxied HTTPS response |
| Trojan + TLS | Matching password and endpoint; mihomo uses `sni` for TLS name; certificate validation or explicit pin; ordinary TCP unless both sides configure another transport | Real password-authenticated proxy request; TLS connect alone is insufficient |
| Hysteria 2 | UDP route/firewall working; matching password and optional obfuscator; correct SNI and certificate/pin; avoid invented bandwidth estimates | Actual QUIC authentication, TCP transfer through the tunnel, and separate UDP test where needed |

The table's validation column is engineering guidance. Field/transport sources: [mihomo VLESS](https://wiki.metacubex.one/en/config/proxies/vless/), [Xray VLESS flow combinations](https://xtls.github.io/en/config/inbounds/vless.html), [mihomo transports](https://wiki.metacubex.one/en/config/proxies/transport/), [Xray WebSocket](https://xtls.github.io/en/config/transports/websocket.html), [mihomo Trojan](https://wiki.metacubex.one/en/config/proxies/trojan/), [pinned Hysteria adapter](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/adapter/outbound/hysteria2.go).

### XHTTP specifics for v1.19.32

This exact client version implements XHTTP; it must not be excluded merely because older Clash clients lack support. The pinned parser accepts `path`, `host`, `mode`, headers, and native kebab-case extra options, including `reuse-settings` and `download-settings`. Do not dump Xray camelCase `extra` objects unchanged into mihomo YAML. The existing ZeroProxy path/host/mode export matches the client schema. [Pinned VLESS adapter](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/adapter/outbound/vless.go).

For `auto`, mihomo chooses `stream-one` with REALITY and no download config; with REALITY plus download config it chooses `stream-up`; without REALITY it chooses `packet-up`. Thus forcing `stream-one` is not automatically a performance improvement over existing auto. [Pinned XHTTP config](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/transport/xhttp/config.go).

HTTP/2 is the documented default. Keep H2 for REALITY; the adapter explicitly refuses REALITY security in its H3 path. `stream-one` cannot be combined with `download-settings`. [Mihomo transport docs](https://wiki.metacubex.one/en/config/proxies/transport/), [pinned adapter checks](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/adapter/outbound/vless.go).

### REALITY target selection and alignment

Upstream's baseline target supports TLS 1.3 and H2 and is not merely a redirecting hostname. Check from the VPS with the actual intended SNI; geographic closeness is useful but is not a guarantee of compatibility. Server allowed names must include the client's SNI, the client's public key must correspond to the configured private key, and client short ID must be accepted by the server. Short IDs are hex, even-length, up to 16 characters; empty is valid only if allowed. [Official REALITY README](https://github.com/XTLS/REALITY), [Xray REALITY fields](https://xtls.github.io/en/config/transports/reality.html).

A successful target TLS probe does not authenticate the REALITY tunnel. Conversely, an HTTP redirect from a target's home page is a suitability consideration, not proof that its TLS handshake cannot work. Current Xray docs expose `xray tls ping` for target inspection; use the installed binary's supported commands before depending on this diagnostic. [Official field documentation](https://xtls.github.io/en/config/transports/reality.html).

## Delay, url-test stability, and throughput

`url-test` uses the delay for its test URL. In v1.19.32 it keeps the current working node until its delay exceeds the fastest node by the configured tolerance; failure also permits switching. The official example uses tolerance 50 ms and interval 300 seconds. A nonzero tolerance is useful to avoid switching on small noise, but **50 ms is an example, not an empirically optimal setting for this router**. [Pinned selection logic](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/adapter/outboundgroup/urltest.go), [official url-test example](https://wiki.metacubex.one/en/config/proxy-groups/url-test/).

Health timeout is milliseconds, interval is seconds. An explicit expected status (e.g. 204 for a chosen 204 endpoint) distinguishes an unexpected response from a successful check; provider health checks have their own settings. Keep controller/manual test timeouts aligned with the intended health-check budget so an external timeout does not terminate an otherwise valid slow check. [Official group fields](https://wiki.metacubex.one/en/config/proxy-groups/).

Inference: low latency for a small HTTP health request measures responsiveness to that endpoint, not sustained download throughput, jitter, congestion, or recovery. Choose the stability policy from repeated tests, and measure throughput separately with a bounded transfer through a fixed selected node. Do not promote a protocol as fastest using one delay sample.

## Hysteria 2 bandwidth and defaults

Current Hysteria documentation uses non-Brutal BBR by default when bandwidth is absent; supplying client bandwidth selects Brutal for that direction. Overstating it can create congestion. Server bandwidth acts as a cap; server caps alone do not make every client use Brutal. `ignoreClientBandwidth` is an explicit override, not an implicit default. [Official client congestion/bandwidth](https://v2.hysteria.network/docs/advanced/Full-Client-Config/), [official server negotiation flow](https://v2.hysteria.network/docs/advanced/Full-Server-Config/).

Mihomo v1.19.32 forwards parsed `up` and `down` as send/receive rates and exposes `bbr-profile`; native Hysteria `congestion` YAML is not its proxy schema. Its Hysteria handshake-timeout is seconds. Use the established client schema rather than copying the server YAML. [Pinned adapter](https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/adapter/outbound/hysteria2.go), [official mihomo Hysteria fields](https://wiki.metacubex.one/en/config/proxies/hysteria2/).

Local findings: `hysteria_config.py` currently hardcodes server 1 Gbps down / 500 Mbps up; `chain_quic.py` includes client bandwidth. These are configuration values, not measured path capacity. Conservative next step is to make intentional measured values configurable or use automatic congestion for unspecified capacity, then compare stability. No bandwidth changes were applied by this research.

Hysteria 2.13.0 version pin: its native client parser allows bandwidth omission and forwards congestion configuration separately. This agrees with the current documentation, while the actual router uses mihomo's separate schema. [Pinned Hysteria 2.13.0 client parser, lines 451–482](https://raw.githubusercontent.com/apernet/hysteria/app/v2.13.0/app/cmd/client.go), [official release](https://github.com/HyNetworks/hysteria/releases/tag/app%2Fv2.13.0).

## Remaining uncertainties and acceptance sequence

1. Xray 26.11.9 / 676eaf6 and its REALITY dependency are source-verified; preserve the local version observation and router binary hash with the test evidence without logging credentials.
2. Compare ordinary REALITY with a temporary hybrid-enabled client profile before changing targets or unrelated socket settings.
3. Validate target TLS 1.3/H2 and SNI from each VPS, then verify key-pair/short-ID/UUID consistency locally.
4. Validate generated configs with installed engines; confirm end-to-end proxy requests separately for all five protocols.
5. Repeat latency and bounded throughput measurements from the actual router. The research establishes neither protocol ranking nor OpenWrt CPU/UDP offload capacity.

No production files or service settings were modified by the researcher. Only this report was written.
