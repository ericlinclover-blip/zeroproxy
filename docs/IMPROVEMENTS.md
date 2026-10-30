# ZeroProxy 交互体验优化 — 改进说明

> 日期: 2026-10-30
> 目标: 减少面板卡顿感, 提升流畅度, 降低不必要的网络请求

---

## 改进清单

### 1. 智能轮询间隔 (state.js + dashboard.js + routes.py)
- **问题:** 固定 20s 轮询 `/api/dashboard`, 即使用户没做任何操作、数据完全没有变化
- **方案:**
  - 后端新增 `_dash_fingerprint()` 函数, 生成轻量数据指纹（节点开关/服务状态/证书类型/链式状态, 不含流量数字）
  - 前端对比新旧指纹, 连续 3 次无变化则拉长轮询间隔到 60s
  - 用户操作触发刷新时恢复 10s（灵敏反馈）
  - 正常状态保持 20s
- **效果:** 安静期减少 67% 的 HTTP 请求, 面板整体响应更"跟手"

### 2. 进度条轮询优化 (jobs.js)
- **问题:** 配置落地轮询固定 400ms, 前 2 秒用户最急于看到进度
- **方案:** 前 2 秒用 100ms 快速采样, 之后退回 400ms
- **效果:** 用户点击后 0.1s 内就能看到进度变化, 感知"秒响应"

### 3. 后端流量统计缓存 (services.py)
- **问题:** 每次 dashboard 渲染都 fork `xray api` 子进程 + 解析 JSON, 即使 20s 内流量差值 < 1KB
- **方案:** 添加 5s TTL 的内存缓存, 只合并同一时刻的并发读取
- **效果:** 保留并发去重, 同时保证 20s 采样能反映真实速率变化

### 4. CSS 紧凑模式支持 (tokens.css)
- **问题:** 低端 ARM 路由器的 Chromium 上大量 transition/animation 拖帧
- **方案:** 支持 `prefers-reduced-motion` + `body.compact-mode` class 一键关闭所有动画
- **效果:** 在低性能设备上可完全消除动画开销

### 5. 初始化页稳定性与标准 443 入口 (v2.12.13)
- **问题:** `/api/setup` 在证书申请、nginx 重载和服务重启期间一直持有全局状态锁；
  同时证书完成前就提交 `configured=true` 并替换 IP 初始化入口。certbot 一慢，面板请求
  被锁住；任一步失败后，用户既进不了初始化页，也无法用原令牌重试。
- **方案:** 初始化改为“短事务读状态 → 锁外执行证书 / 服务步骤 → 成功后提交”；
  证书阶段保留同时承接 IP、域名与 ACME webroot 的临时 nginx 配置；失败不消耗令牌。
- **方案:** 正式面板新增 `https://<域名>/panel/`，API、静态资源和订阅同路径反代；
  8899 保留兼容。标准 443 通常已在云安全组放行，避免面板只能靠额外端口访问。
- **方案:** 外部命令超时改为终止整个进程组，防止 certbot 子进程占着管道让超时失效。
- **效果:** 证书申请期间调试与状态请求不再被全局锁拖住；入口切换失败可重试；
  重装后不需要额外开放 8899 才能进入面板。

### 6. Shadowrocket 订阅导入兼容 (v2.12.14)
- **问题:** Hysteria 2 分享链接把 `30001,31001,32001` 写进 URI authority 的端口位。
  Shadowrocket 请求订阅成功（HTTP 200），但解析节点时端口不是整数，导致整份订阅拒绝导入。
- **方案:** authority 只写主端口 `30001`，端口跳跃列表改放在 `mport` 查询参数。
- **效果:** 默认 Base64 订阅的 5 条 URI 均可被标准解析器读取；不支持跳跃的客户端
  仍可通过主端口连接。

---

## 文件变更

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `backend/zeroproxy/routes.py` | +新增/~修改 | `_dash_fingerprint()` + `_dashboard_body` 返回 fingerprint；setup 短事务、可重试入口、标准 443 交接 |
| `backend/zeroproxy/services.py` | +新增/~修改 | `_stats_cache` 流量统计短时缓存；外部命令超时终止进程组 |
| `backend/zeroproxy/nginx_config.py` | ~修改 | `/panel/`、`/api/`、`/static/` 标准 443 反代 |
| `backend/zeroproxy/apply.py` | ~修改 | 初始化 nginx 配置与失败恢复 |
| `backend/zeroproxy/share_links.py` | ~修改 | 正式部署统一生成标准 `/panel/` 基址；Hysteria 2 authority 改单端口，跳跃列表移入 `mport` |
| `backend/static/app/lib/state.js` | ~修改 | 智能轮询逻辑 (基于后端 fingerprint) |
| `backend/static/app/lib/jobs.js` | ~修改 | 自适应轮询间隔 (100ms→400ms) |
| `backend/static/app/lib/raf.js` | +新增 | requestAnimationFrame 渲染调度器 |
| `backend/static/app/lib/dom.js` | 未变 | — |
| `backend/static/app/views/dashboard.js` | ~修改 | 集成智能轮询间隔 |
| `backend/static/app/style/tokens.css` | +扩展 | compact-mode 支持 |

## 测试
- 383 tests passed, 6 skipped — 全部通过
- Python 语法校验通过
- JavaScript 语法校验通过
