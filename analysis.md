# ZeroProxy Architecture & Interaction Analysis

## 1. Project Overview

**ZeroProxy** (v2.6.17) is a self-hosted proxy management panel that orchestrates Xray, Hysteria 2, and Nginx on a single server. It provides a web dashboard (Svelte-based SPA served as a single `index.html`) that manages proxy nodes, subscriptions, chained proxies, GeoIP-based routing, and service lifecycle.

- **Root**: `/Users/eric/Desktop/sbpn/zeroproxy/`
- **Backend**: `/Users/eric/Desktop/sbpn/zeroproxy/backend/zeroproxy/` (Python, FastAPI)
- **Frontend**: `/Users/eric/Desktop/sbpn/zeroproxy/backend/static/index.html` (Svelte SPA)
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
    │ - VLESS-XHTTP    │  │ - masquerade     │  │ - Svelte SPA    │
    │ - VLESS-WS       │  └──────────────────┘  │ - WebSocket     │
    │ - Trojan         │                         │ - async jobs    │
    │ - Stats API      │                         └─────────────────┘
    └──────────────────┘
```

### 2.2 Core Modules

| Module | Size | Responsibility |
|--------|------|----------------|
| `config.py` | 24KB | Runtime state management, concurrency model (`config.locked()`), constants |
| `routes.py` | 96KB | All FastAPI endpoints (100+), session/auth, dashboard, config mutation |
| `apply.py` | 26KB | 6-step verification loop ("generate → verify → reload"), async job system |
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
| `main.py` | 6KB | Entry point, uvicorn setup, GeoIP auto-update loop |

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
STEP_NAMES = [
    "生成 Xray 配置",       # xray_config.write_xray_config(state)
    "生成 Nginx 配置",     # nginx_config.write_nginx_conf(state)
    "生成 Hysteria 2 配置", # hysteria_config.write_hysteria_config(state)
    "重启 Xray",           # systemctl restart xray
    "重启 Hysteria 2",     # systemctl restart hysteria2
    "验证端口监听",        # Dynamic polling (not fixed sleep)
]
```

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
| `/api/chain/entries/{id}` | PATCH | Enable/disable, set default exit, rename, switch transport |
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
Frontend (Svelte SPA)
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
PANEL_PORT = 8899
PANEL_BIND_PORT = 9900
SESSION_TTL = 3600  # 1 hour
GEODATA_TTL = 2592000  # 30 days
STATE_VERSION = 4
HOP_OFFSETS = (0, 1000, 2000)  # Port hopping intervals
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
1. Parse config → ZP_HOME, ports, bind address
2. Bootstrap token check (first-run protection)
3. Load state from disk
4. Start uvicorn (panel) on 127.0.0.1:9900
5. Background GeoIP auto-update thread (checks every 6h)
6. Background chain warmup thread (on config change)
7. Background chain QUIC supervisor loop (20s)
```

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
            ├── geodata.py (update, status, guard)
            ├── nginx_config.py (write_nginx_conf)
            ├── hysteria_config.py (write_hysteria_config)
            └── crypto.py (new_reality_keys, derive_uuid)

main.py ────┬── config.py
            ├── geodata.py (auto_update_thread)
            ├── chain.py (warmup_in_background)
            ├── chain_quic.py (supervisor_loop)
            └── services.py (bin_path, port_available)

apply.py ───┬── xray_config.py (gen_xray)
            ├── nginx_config.py (gen_nginx)
            ├── hysteria_config.py (gen_hysteria)
            └── services.py (restart_services, verify_listeners)
```

## 14. Frontend-Backend Synchronization

The frontend (Svelte SPA) communicates with the backend via:

1. **Session-based auth**: `zp_session` cookie set on login, validated on each request
2. **Dashboard polling**: `GET /api/dashboard` on mount, `GET /api/apply/job?id=` during apply operations
3. **Real-time traffic**: `GET /api/traffic` every 10-30s (or on demand)
4. **Config mutation**: POST endpoints return either:
   - Sync: `{ok: true, steps: [{name, ok, detail, ms}, ...]}`
   - Async: `{ok: true, job: {id, state, index, total, current}}`
5. **Audit log**: Paginated `GET /api/audit?limit=50&before=0&category=toggle_node`

The frontend renders:
- Node cards with traffic graphs, QR codes, share links
- Chain proxy manager (exit/entries UI with pairing code flow)
- GeoIP data card with download button and last-error display
- Diagnostics panel with pass/fail items and one-click repair
- Backup/restore file upload/download
