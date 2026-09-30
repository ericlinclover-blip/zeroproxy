# ZeroProxy Architecture & Interaction Analysis

## 1. Project Overview

**ZeroProxy** (v2.6.18) is a self-hosted proxy management panel that orchestrates Xray, Hysteria 2, and Nginx on a single server. It provides a web dashboard — a zero-framework, zero-build single-file SPA (`index.html`, plain JS, no CDN) — that manages proxy nodes, subscriptions, chained proxies, GeoIP-based routing, and service lifecycle.

- **Root**: `/Users/eric/Desktop/sbpn/zeroproxy/`
- **Backend**: `/Users/eric/Desktop/sbpn/zeroproxy/backend/zeroproxy/` (Python, FastAPI)
- **Frontend**: `/Users/eric/Desktop/sbpn/zeroproxy/backend/static/index.html` (vanilla JS SPA, ~172 KB, no framework/build step)
- **Data Dir**: `$ZP_HOME/data/state.json` (runtime state, version 4)
- **Tech Stack**: FastAPI + uvicorn (panel), Xray (proxy core), Hysteria 2 (QUIC transport), Nginx (TLS termination + reverse proxy)

## 2. Architecture

### 2.1 Process Topology

```
                    ┌──────────────────────────────────────┐
                    │  Nginx (port 8899 / 443 / 80)        │
                    │  - TLS termination (LE or self-signed)│
                    │  - /ws/zeroproxy → Xray WS inbound   │
                    │  - 8899 → uvicorn panel (127.0.0.1:9900)│
                    └──────────────────────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    ┌─────────▼────────┐  ┌────────▼─────────┐  ┌────────▼────────┐
    │ Xray (systemd)   │  │ Hysteria 2       │  │ uvicorn (panel) │
    │ - VLESS-Reality  │  │ - QUIC/UDP       │  │ - FastAPI REST  │
    │ - VLESS-XHTTP    │  │ - masquerade     │  │ - static SPA    │
    │ - VLESS-WS       │  └──────────────────┘  │ - async jobs    │
    │ - Trojan         │                         │ - daemon threads│
    │ - Stats API      │  ┌──────────────────┐   └─────────────────┘
    │ - chain-exit     │  │ hysteria children│        ▲
    │ - chain-<id>     │  │ (panel-managed,  │────────┘ spawned by panel
    └──────────────────┘  │  chain QUIC only)│
                          └──────────────────┘
```

### 2.2 Core Modules

| Module | Size | Responsibility |
|--------|------|----------------|
| `config.py` | 24KB | Runtime state management, concurrency model (`config.locked()`), constants |
| `routes.py` | 96KB | All API endpoints (33 router routes + `/`, `/api/info`), session/auth, dashboard, config mutation, **async job table** (`_APPLY_JOBS`) |
| `apply.py` | 26KB | The 6-step landing loop ("generate → real-binary verify → reload → re-check ports"); shared by the panel and `upgrade.sh` |
| `services.py` | 47KB | Service adaptation layer (systemctl, certbot, firewall), traffic stats |
| `xray_config.py` | 16KB | Xray JSON config generator (4 inbounds + chain + routing) |
| `share_links.py` | 28KB | Client share links, subscriptions (base64/clash/singbox), routing templates |
| `chain.py` | 32KB | Chained proxy: pairing codes, port allocation, real handshake probing |
| `chain_quic.py` | 19KB | QUIC inner-layer: hysteria process management, config sync, supervisor loop |
| `geodata.py` | 22KB | GeoIP/GeoSite download (multi-mirror fallback), validation, auto-update |
| `hysteria_config.py` | 3KB | Hysteria 2 config template (port hopping, masquerade) |
| `nginx_config.py` | 7KB | Nginx config template (ACME, WS proxy, panel HTTPS, fake homepage) |
| `crypto.py` | 4KB | Key generation (VLESS UUID, Reality X25519), password hashing (PBKDF2) |
| `update.py` | 13KB | Panel self-update: version check, `upgrade.sh` staging & execution |
| `main.py` | 6KB | Entry point, security-header middleware, static mount, startup port check; lifespan runs the GeoIP auto-update loop + chain-QUIC supervisor |

## 3. Concurrency & State Management

### 3.1 `config.locked()` (File: `config.py`)
- **Mechanism**: `threading.RLock` + `fcntl.flock` for thread/process safety
- **Atomic writes**: Temp file → fsync → rename prevents JSON corruption during crashes
- **State version**: `STATE_VERSION = 4`

### 3.2 Async Job System (File: `routes.py`)
- **Purpose**: Config mutation ("generate → restart → verify ports") takes 2-4 seconds; background threading prevents blocking the browser
- **Implementation**: `_APPLY_JOBS` dict with thread-safe locking; frontend polls `GET /api/apply/job?id=` at 400ms intervals
- **Environment switch**: `ZP_APPLY_ASYNC=0` disables async (for local testing)
- **Job lifecycle**:
  1. `POST /api/...` → `_reapply_job()` → writes state to disk → starts daemon thread
  2. Returns `{"job": {"id": "1", "state": "running", ...}}`
  3. Frontend polls `GET /api/apply/job?id=1` until `state` is `"done"` or `"failed"`
- **Concurrency control**: Jobs acquire `config.locked()` internally; concurrent clicks serialize automatically

### 3.3 GeoIP Update Lock (File: `geodata.py`)
- `UPDATE_LOCK = threading.Lock()` — prevents simultaneous downloads from multiple paths (manual button + auto-update thread)

## 4. Configuration Flow (The "Reapply" Loop)

### 4.1 6-Step Verification (File: `apply.py`)

```python
STEP_NAMES = (
    "校验 Reality 密钥与伪装目标",   # ensure_reality_settings — X25519 配对 + 旧 dest 迁移
    "重新生成 Xray 配置",           # xray_config.write_xray_config + 真实 `xray -test`
    "重新生成 Nginx 配置",          # nginx_config.write_nginx_conf + `nginx -t`
    "重新生成 Hysteria 2 配置",     # hysteria_config.write_hysteria_config
    "重载服务 (nginx/xray/hysteria2)",  # 并发重启; 只重启配置指纹变了的服务
    "验证端口监听",                 # 双向校验 (该开的在听 + 该关的关了)
)
```

注意第一步不是"生成配置"而是**前置校验**: v2.3.2 及更早误用 Ed25519 生成的 Reality 密钥对、以及
证书链超过 REALITY 8KB 缓冲的旧默认伪装目标(`www.microsoft.com`),都会在这里被就地修正 ——
这两者都会让"服务全绿但四个 TCP 节点全不通"。

第 5 步不再拆成"重启 Xray / 重启 Hysteria 2"两个独立步骤: 三个服务**并发**收敛, 且用
`_config_digests()` 比对三份配置的 sha256, 只有真正变了的服务才重启(链式操作只动 Xray 时,
nginx / hysteria 不再陪着重启一次)。

**Verification logic** (`_VERIFY_POLL` + `_VERIFY_PROBE_TIMEOUT`):
- Dynamic polling instead of fixed sleeps — avoids unnecessary delays on fast loopback
- Probes each port with TCP/UDP connect to confirm actual listeners (not just "service started")
- Prevents "false success" where service reports started but port isn't listening yet

### 4.2 Full Setup Flow (`POST /api/setup`, File: `routes.py`)

```
1. Generate keys (UUID, Reality X25519, subscription token)
2. Persist state (domain, admin, trojan/hysteria passwords)
3. Generate Hysteria 2 cert
4. Pre-provision self-signed cert (bootstrap nginx -test)
5. Generate Nginx config (port 80 ACME path)
6. Reload Nginx (80 port ready for ACME challenge)
7. Install cert (Let's Encrypt via certbot)
8. Generate Xray config (with real cert paths)
9. Generate Nginx config (with real cert paths)
10. Generate Hysteria 2 config
11. Start/restart all services
12. Verify ports
```

## 5. API Endpoints (File: `routes.py`)

### 5.1 Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/login` | POST | Login with username/password; returns session cookie |
| `/api/logout` | POST | Invalidate current session |
| `/api/logout-all` | POST | Invalidate all sessions |
| `/api/status` | GET | Check auth status (unauthenticated) |

**Session management**:
- Cookie: `zp_session` (httponly, samesite=lax, secure=auto)
- Rate limiting: `LOGIN_FREE_TRIES=3`, exponential backoff up to `LOGIN_MAX_BLOCK=300s`
- Max sessions: `config.MAX_SESSIONS` (evict oldest on overflow)
- Client IP extracted via `X-Forwarded-For` (nginx reverse proxy aware)

### 5.2 Dashboard & Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard` | GET | Full dashboard data (nodes, traffic, cert, chain, geodata, audit) |
| `/api/status` | GET | Minimal status check (configured, authenticated) |
| `/api/audit` | GET | Paginated audit log with filters (category, q, failed) |
| `/api/traffic` | GET | Per-node traffic stats (via Xray Stats API) |
| `/api/diagnose` | GET | Multi-check diagnostics (services, config, ports, certs, chain reachability) |
| `/api/repair` | POST | One-click self-heal (reapply + diagnose) |

### 5.3 Config Mutation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/nodes/{node_id}/toggle` | POST | Toggle node on/off |
| `/api/hysteria/hopping` | POST | Toggle port hopping (auto-open firewall) |
| `/api/settings` | POST | Update SNI, masquerade URL, ports, routing template, GeoIP settings |
| `/api/apply` | POST | Re-apply all config (full reapply loop) |
| `/api/renew` | POST | Renew Let's Encrypt certificate |

**`/api/settings` validation** (File: `routes.py`):
- `_DOMAIN_RE`: `^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`
- `_USER_RE`: `^[A-Za-z0-9._-]{2,32}$`
- `_SNI_RE`: `^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`
- `_URL_RE`: `^https?://[^\s\"'<>]+$`
- Port conflict detection: checks merged port table + reserved ports (nginx/chain) + live bind probes

### 5.4 Chained Proxy

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/chain/exit` | POST | Generate/rotate/disable exit node credentials |
| `/api/chain/entries` | POST | Add chain entry (paste pairing code → probe → land) |
| `/api/chain/entries/{id}` | POST | Enable/disable, set default exit, rename, switch transport (Brutal bandwidth) |
| `/api/chain/entries/{id}/probe` | POST | Single-chain speed test |
| `/api/chain/entries/{id}` | DELETE | Remove chain entry |
| `/api/chain/exit/qr` | GET | QR code for pairing code |

### 5.5 GeoIP Data

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/geodata/update` | POST | Download & verify GeoIP/GeoSite data + reapply |

### 5.6 Subscription

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sub/{token}` | GET | Subscription feed (base64/clash/singbox formats) |
| `/api/nodes/{id}/qr` | GET | QR code for node share link |
| `/api/subscription/qr` | GET | QR code for subscription URL |

### 5.7 Utilities

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/backup` | GET | Export full state (JSON, with checksum) |
| `/api/restore` | POST | Restore from backup (verify checksum → merge → reapply) |
| `/api/probe` | GET | Node health check (fast/shallow or deep/real handshake) |
| `/api/logs/{service}` | GET | Journalctl tail for xray/hysteria2/nginx/zeroproxy |
| `/api/update` | GET/POST | Panel version check / trigger upgrade |

## 6. Data Flows

### 6.1 Dashboard Data Flow

```
Frontend (vanilla-JS SPA)
  │
  ├─ GET /api/dashboard (after login)
  │    │
  │    ├─ config.locked() → load_state()
  │    ├─ services.xray_stats(state) → "xray api statsquery" (subprocess)
  │    ├─ _node_view(state, traffic) → per-node traffic from Stats API
  │    ├─ _cert_view(state) → cert expiry from state["cert"]["not_after"]
  │    ├─ _chain_view(state) → chain entries, QUIC process status
  │    ├─ geodata.status(state) → file sizes, sha256, last_error
  │    └─ config.audit_query(state) → last 20 audit entries
  │
  ├─ Poll: GET /api/apply/job?id={id} (400ms interval)
  │    └─ Reads in-memory job dict (no config lock needed)
  │
  └─ GET /api/traffic (periodic)
       └─ "xray api statsquery" → parse counter names (↑/↓ per-user)
```

### 6.2 Config Mutation Flow

```
User clicks "Toggle Node" or "Save Settings"
  │
  ├─ POST /api/nodes/{id}/toggle  (or /api/settings)
  │    │
  │    ├─ config.locked() → load_state()
  │    ├─ Mutate state["nodes"][node_id] or state["ports"] etc.
  │    ├─ save_state(state)
  │    └─ _reapply_job(state, request)
  │         │
  │         ├─ Async mode (default):
  │         │   ├─ Start daemon thread → _run_apply_job(job_id)
  │         │   └─ Return {"job": {"id": "1", "state": "running"}}
  │         │
  │         └─ Sync mode (ZP_APPLY_ASYNC=0):
  │             └─ Return steps with full 6-step results
  │
  └─ [Async] Frontend polls GET /api/apply/job?id=1
       └─ Progress bar updates until state="done"
```

### 6.3 Subscription Flow

```
Client requests: GET /sub/{subscription_token}?format=clash
  │
  ├─ load_state() (no lock needed — read-only)
  ├─ HMAC compare: token == state["subscription_token"]
  ├─ share_links.subscription_body(state, "clash", rules)
  │    │
  │    ├─ Generate VLESS URIs for enabled nodes
  │    ├─ Apply routing template (smart/global/direct)
  │    ├─ Convert to Clash YAML or singbox JSON
  │    └─ Handle sing-box version-specific rule-set download detours
  │
  └─ Response headers:
       - profile-update-interval: 12
       - subscription-userinfo: upload=XXX;download=XXX;total=XXX;expire=XXX
```

### 6.4 Chain Proxy Flow

```
1. Exit node setup (landing server):
   POST /api/chain/exit {action: "generate", port: 8447}
   → Generates dedicated UUID + port + (optional QUIC password)
   → Xray config adds "chain-exit" inbound (VLESS Reality)
   → Returns pairing code: "ZPC1~{base64payload}~{sha256[:6]}"

2. Entry node setup (transit server):
   POST /api/chain/entries {code: "ZPC1~..."}
   │
   ├─ Parse & validate pairing code (version 1 or 2)
   ├─ [Outside lock] chain.probe_target(target) — real handshake
   │   ├─ TCP connect to exit node (5s timeout)
   │   ├─ Start temp Xray client (VLESS Reality outbound)
   │   ├─ Read exit IP via HTTP echo service (ip.3322.net, ifconfig.me, ipify)
   │   └─ Return: {ok, tcp_ms, exit_ip, detail}
   │
   ├─ config.locked() → add entry to state["chain"]["entries"]
   ├─ Xray config adds: chain-{id} inbound + chain-out-{id} outbound + routing rule
   ├─ [Optional] chain_quic.sync() — start temp hysteria client for QUIC inner layer
   └─ Open firewall port for entry node

3. Warmup on restart:
   chain.warmup_in_background(state)
   → Starts temp Xray clients for each Reality inbound
   → Prevents 5s cold-start penalty on first user connection
```

### 6.5 GeoIP Data Flow

```
Auto-update thread (main.py):
  │
  └─ Every 6 hours: geodata.auto_tick(state)
       ├─ If data missing or TTL expired (GEODATA_TTL):
       │   ├─ Download from multi-mirror sources (jsdelivr CDN × 4 + GitHub Release)
       │   ├─ Size validation (min 1MB each file)
       │   ├─ SHA256 checksum
       │   ├─ Real xray -test validation (config with geoip:private rule)
       │   └─ Atomic install (staging dir in same filesystem → rename)
       │
       └─ If data changed → reapply config (Xray restart)

Manual update (POST /api/geodata/update):
  │
  ├─ Acquire geodata.UPDATE_LOCK
  ├─ Start background thread: _run_geo_job(job_id)
  │   ├─ Download + validate (same as auto)
  │   ├─ geodata.merge_result(fresh, state, ok)
  │   ├─ apply.reapply() if successful
  │   └─ Save steps to state["steps"]
  └─ Frontend polls GET /api/apply/job?id={job_id}
```

## 7. Key Constants & Defaults (File: `config.py`)

```python
DEFAULT_REALITY_DEST = "www.cloudflare.com:443"  # Stays under Xray's 8KB cert limit
WS_PATH = "/ws/zeroproxy"
XHTTP_PATH = "/xhttp-zeroproxy"
DEFAULT_MASQUERADE = "https://www.microsoft.com/"
PANEL_PORT = 8899        # 对外 (nginx 在 8899 终结 TLS)
PANEL_BIND_PORT = 9900   # 面板进程自身 (仅 127.0.0.1, nginx 反代到它)
SESSION_TTL = 72 * 3600  # 72 hours
MAX_SESSIONS = 8         # 超出时淘汰最早到期的一个
GEODATA_TTL = 7 * 86400  # 7 days — 过期后后台线程自动更新
STATE_VERSION = 4

# 以下不在 config.py: 端口跳跃的偏移量定义在 routes.py (HOP_OFFSETS),
# 跳跃端口 = 主端口 + 每个偏移, 并随主端口变更自动重排。
HOP_OFFSETS = (0, 1000, 2000)
```

## 8. Chained Proxy Details (Files: `chain.py`, `chain_quic.py`)

### 8.1 Pairing Code Format

```
ZPC1~{base64url(JSON payload)}~{sha256(payload)[:6]}

v1 payload (Reality only):
{"v":1,"h":"host","n":"sni","l":"label","p":8447,"u":"uuid","k":"pbk","s":"sid","f":"flow"}

v2 payload (Reality + QUIC):
{"v":2,"h":"host","n":"sni","l":"label",
 "r":{"p":8447,"u":"uuid","k":"pbk","s":"sid","f":"flow"},
 "y":{"p":8448,"w":"hy_password","n":"hy_sni"}}
```

### 8.2 Port Allocation

```
Exit node: 8447 (Reality TCP), 8448 (QUIC UDP) — configurable
Entry nodes: 8446+ (scanned sequentially for free ports)
QUIC client SOCKS: 8470+ (scanned sequentially)
```

### 8.3 QUIC Inner-Layer Process Management (`chain_quic.py`)

- **Hysteria processes are panel-managed** (not systemd), allowing:
  - Same code path in dev vs prod (no systemd dependency)
  - On-demand lifecycle (start/stop per chain entry)
  - Auto-restart via `supervisor_loop()` (20s check interval)
- **Config sync**: `sync(state)` compares desired configs → spawns/stops processes as needed
- **Certificate**: Self-signed per-SNI, regenerated on mismatch or file loss

## 9. Nginx Configuration (File: `nginx_config.py`)

### 9.1 Multi-Server Block Structure

```nginx
# Block 1: Port 80 — ACME challenge + 301 to HTTPS
server { listen 80; location /.well-known/acme-challenge/ { root ... } }

# Block 2: Port 443 — TLS termination + WS proxy + fake homepage
server {
    listen 443 ssl;
    location = /ws/zeroproxy { proxy_pass http://zeroproxy_vless_ws; }
    location / { root /path/to/www; index index.html; }  # "Domain Reserved" page
}

# Block 3: Port 8899 default — self-signed cert (IP access / bootstrap)
server { listen 8899 ssl default_server; ssl_certificatepanel_cert; }

# Block 4: Port 8899 with SNI — Let's Encrypt cert (domain access)
server { listen 8899 ssl; server_name domain.com; ssl_certificate cert; }
```

### 9.2 WebSocket Proxy Headers
```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 3600s;  # Long-lived WS connections
```

## 10. Xray Configuration (File: `xray_config.py`)

### 10.1 Four Inbound Protocols

| Tag | Protocol | Network | Security | TLS |
|-----|----------|---------|----------|-----|
| `vless-reality` | VLESS | TCP | Reality | None (Reality) |
| `vless-xhttp` | VLESS | XHTTP | Reality | None (Reality) |
| `vless-ws` | VLESS | WebSocket | None | Nginx 443 |
| `trojan` | Trojan | TCP | TLS 1.3 | LE/Self-signed |

### 10.2 Routing Rules Order
```
1. API inbound → api service (stats queries)
2. Geo block rules (geoip:private, geosite:category-ads-all)
3. Default chain exit (if set — redirects all local traffic through exit)
4. Individual chain entries (per-entry inbound → per-entry outbound)
```

### 10.3 Socket Options
```python
sockopt = {
    "tcpFastOpen": True,      # Saves 1 RTT on new connections
    "tcpNoDelay": True,       # Disables Nagle — better for request-response
    "tcpKeepAliveInterval": 15,  # Probes dead long connections
}
```

## 11. Startup Sequence (File: `main.py`)

```
1. Module import: resolve ZP_HOME / PANEL_PORT / PANEL_BIND_HOST / PANEL_BIND_PORT from env
2. create_app(): attach security-header middleware, include the API router,
   mount /static, serve index.html with `cache-control: no-cache` (ETag revalidation)
3. _check_startup_ports(): probe the panel's public port + bind port for conflicts
   (prints a warning only — never blocks start; a leftover old process must not look
   like "the panel is running" while another service owns the port)
4. ASGI lifespan starts two daemon threads:
     a. zp-geodata  — first tick after 90 s, then every 6 h; downloads only when the
                      data is missing or past GEODATA_TTL; on change it restarts Xray
     b. zp-chain-quic — reconciles panel-managed hysteria children every 20 s
5. __main__: uvicorn binds 127.0.0.1:9900 with proxy_headers=True,
   forwarded_allow_ips="127.0.0.1" (trusts only the local nginx)
```

两处容易误解的地方:

- **引导令牌不是启动时校验**: `main.py` 里没有"首次运行保护"这一步。令牌只在 `POST /api/setup`
  里常量时间比对(`config.bootstrap_token()` 优先级: 环境变量 → `data/bootstrap_token`),
  本地开发两者都不存在时允许无令牌初始化。
- **链式预热不占启动路径**: `chain.warmup_in_background()` 由 `apply.restart_services()` 在
  Xray 重启成功后触发, 不在 `main.py` 的启动序列里。

## 12. Key Design Decisions

1. **Single-process panel**: All config mutation serializes through `config.locked()` — no distributed state complexity
2. **Async apply pattern**: Frontend polls for progress instead of blocking HTTP — prevents "request killed during Xray restart"
3. **Multi-mirror GeoIP download**: 4 jsdelivr CDN endpoints + GitHub Release with size validation — resilient to partial CDN failures
4. **Atomic config writes**: Staging directory → validate → rename — prevents partial writes corrupting running configs
5. **Panel-managed Hysteria processes**: Not systemd units — enables on-demand lifecycle, dev/prod parity, and auto-restart via supervisor loop
6. **Reality cold-start mitigation**: `chain.warmup()` proactively hits each Reality listener to absorb the ~5s first-handshake penalty
7. **Pairing code versioning**: v1 (Reality only) / v2 (Reality + QUIC) — forward-compatible parsing with explicit version check
8. **Subscription format flexibility**: base64 (standard), clash (YAML), singbox (JSON) — routing templates (smart/global/direct) only affect client-side subscription output

## 13. Cross-Module Dependencies

```
routes.py ──┬── config.py (state, locked, audit)
            ├── apply.py (reapply, STEP_NAMES)
            ├── services.py (systemctl, firewall, xray_stats, probe)
            ├── xray_config.py (build_xray_config, chain_exit_enabled)
            ├── share_links.py (subscription, templates)
            ├── chain.py (parse_code, probe_target, warmup)
            ├── chain_quic.py (sync, status, binary)
            ├── geodata.py (update, status, UPDATE_LOCK)
            ├── update.py (panel self-update status/start)
            └── crypto.py (new_reality_keys, derive_uuid)

(nginx_config.py / hysteria_config.py 不直接被 routes 引用 —— 只经 apply.py 落地。)

main.py ────┬── config.py
            ├── routes.py (create_app / include_router)
            ├── geodata.py (auto-update loop + `guard` CLI)
            ├── chain_quic.py (supervisor_loop)
            └── services.py (restart_service, is_prod 等)

apply.py ───┬── xray_config.py (gen_xray)
            ├── nginx_config.py (gen_nginx)
            ├── hysteria_config.py (gen_hysteria)
            ├── chain.py (warmup_in_background —— 预热挂在重启成功之后)
            ├── chain_quic.py (sync —— 内层 QUIC 进程在 Xray 之前对齐)
            └── services.py (restart_services, verify_listeners)
```

## 14. Frontend-Backend Synchronization

The frontend (vanilla-JS SPA) is pull-only: **no WebSocket, no server push, no CORS** —
same-origin `fetch` with `credentials: "same-origin"`.

1. **Session-based auth**: `zp_session` cookie (HttpOnly / SameSite=Lax / Secure when
   the request is HTTPS or `X-Forwarded-Proto: https`), validated on every request.
2. **Dashboard polling**: `GET /api/dashboard` on mount and then every 20 s — but the
   interval is **suspended while `opBusy > 0` or an apply job is running**, otherwise a
   full re-render would wipe the "in progress" state of a button and let the user click
   the same chain operation twice.
3. **Apply-job polling**: `GET /api/apply/job?id=` every 400 ms (budget 120 s for
   config apply, 480 s for GeoIP download, matching the backend's own 180 s deadline).
   Update polling is a separate 2.5 s loop on `GET /api/update`.
4. **Traffic**: read from `dash.traffic` inside the dashboard payload — the frontend
   **never calls** `GET /api/traffic`; that endpoint exists for external consumers.
   The rate curve is sampled client-side (24 in-memory points, ~8 min) because the
   Xray Stats API only exposes cumulative counters.
5. **Config mutation**: the response body *is* the fresh dashboard payload plus either
   `steps: [{name, ok, detail, ms}]` (sync mode, `ZP_APPLY_ASYNC=0`) or
   `job: {id, kind, state, index, total, current}` (async mode, the default).
6. **Audit log**: the newest 30 entries + per-category facet counts ride along in
   `/api/dashboard` (zero extra requests). Only once the user filters/pages does the
   frontend switch to `GET /api/audit?limit=30&before=<id>&category=<auth|config|chain|data|system>&q=&failed=1`
   — cursor paging by monotonic `id`, never `offset`, so new entries arriving mid-paging
   cannot shift a row into the next page.
7. **Dropped connections are not failures**: a `fetch` throw or a 502/504 is marked
   `e.dropped` and triggers reconnect-and-reconcile (`syncAfterDrop`) instead of an error
   toast or a redirect to the login view — because restarting Xray legitimately kills the
   browser's own tunnel when the user is browsing through their own node.
8. **Draft protection**: every full re-render first snapshots the text/number inputs the
   user is editing (value + caret) and restores them afterwards, so a 20 s refresh can
   never overwrite a half-typed SNI, port or pairing code.

The frontend renders:
- Node cards with traffic graphs, QR codes, share links
- Chain proxy manager (exit/entries UI with pairing code flow)
- GeoIP data card with download button and last-error display
- Diagnostics panel with pass/fail items and one-click repair
- Backup/restore file upload/download
