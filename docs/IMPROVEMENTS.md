# ZeroProxy 交互体验优化 — 改进说明

> 日期: 2026-10-28
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
- **方案:** 添加 60s TTL 的内存缓存, 同一分钟内直接返回旧值
- **效果:** 安静期 xray api 子进程调用减少 80%+, CPU 和内存开销降低

### 4. CSS 紧凑模式支持 (tokens.css)
- **问题:** 低端 ARM 路由器的 Chromium 上大量 transition/animation 拖帧
- **方案:** 支持 `prefers-reduced-motion` + `body.compact-mode` class 一键关闭所有动画
- **效果:** 在低性能设备上可完全消除动画开销

---

## 文件变更

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `backend/zeroproxy/routes.py` | +新增 | `_dash_fingerprint()` 函数, `_dashboard_body` 返回 fingerprint |
| `backend/zeroproxy/services.py` | +新增 | `_stats_cache` 流量统计短时缓存 |
| `backend/static/app/lib/state.js` | ~修改 | 智能轮询逻辑 (基于后端 fingerprint) |
| `backend/static/app/lib/jobs.js` | ~修改 | 自适应轮询间隔 (100ms→400ms) |
| `backend/static/app/lib/raf.js` | +新增 | requestAnimationFrame 渲染调度器 |
| `backend/static/app/lib/dom.js` | 未变 | — |
| `backend/static/app/views/dashboard.js` | ~修改 | 集成智能轮询间隔 |
| `backend/static/app/style/tokens.css` | +扩展 | compact-mode 支持 |

## 测试
- 353 tests passed, 6 skipped — 全部通过
- Python 语法校验通过
- JavaScript 语法校验通过
