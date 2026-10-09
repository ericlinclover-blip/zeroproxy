package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// serverEntry 是服务器清单里的一条 (与安装脚本 / CLI 写的 servers/*.json 对应)。
type serverEntry struct {
	Key  string `json:"key"`
	Base string `json:"base"`
	ID   string `json:"id"`
}

// statusResp 与原来的 cgi 契约**逐字段一致** —— 界面页 (index.html + app.js) 因此
// 一个字节都不用改。多出来的 mode / covered / why 是老字段的细化: 原来只有 mode,
// 而且那个 mode 是按 "/dev/net/tun 在不在" 报的 (原厂 5.4 上就是这么骗人的)。
type statusResp struct {
	OK      bool   `json:"ok"`
	Core    string `json:"core"`
	Mode    string `json:"mode"`
	Covered string `json:"covered"`
	Why     string `json:"why"`
	IPv6    string `json:"ipv6"`
	//: 数据面上真的过了多少包。规则在但 0 包 = 没人被接管 (多半是接口名不对),
	//: 这个数字是界面上唯一能一眼看出来的"真的接管了"的证据。
	Packets int           `json:"packets"`
	//: WAN 口的收+发字节数。界面那块性能模式表盘的转速就是它算出来的 (真流量才有转速)。
	//: 与原 cgi 同一个字段名, 老页面拿到它也不会用坏 (它只读自己认识的键)。
	WAN     int64         `json:"wan"`
	Client  string        `json:"client"`
	//: 性能模式 (内核态 eBPF / dae) 那几个值 —— 表盘按它们画。与原 cgi 逐字段一致。
	Perf    perfResp      `json:"perf"`
	Servers []serverEntry `json:"servers"`
}

// perfResp 是性能模式那几张牌。字段名与 cgi 里那一份**必须一样** (两个入口, 一套语义):
// cap=能不能开 / state=意图 / live=现场 / why=上一次的结论 / exit_ip=验证过的出口 /
// busy=正在切换 / progress=切换到了哪一步 (CLI 写下的原话)。
type perfResp struct {
	Cap      string `json:"cap"`
	State    string `json:"state"`
	Live     string `json:"live"`
	Why      string `json:"why"`
	ExitIP   string `json:"exit_ip"`
	Busy     string `json:"busy"`
	Progress string `json:"progress"`
}

type simpleResp struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Log     string `json:"log,omitempty"`
}

// : 请求体上限。这是个只收一个 URL / 一个键的接口, 64 KB 已经宽到离谱了。
const maxBody = 64 << 10

// : 静态文件的**白名单**。写成白名单而不是"从 docroot 里按路径取", 是因为取错一个字节
// : 就是给面板开了个任意文件读取 —— 这里根本没有可穿越的路径。
var staticFiles = map[string]string{
	"index.html": "text/html; charset=utf-8",
	"app.js":     "text/javascript; charset=utf-8",
	// 性能模式那块表盘 (仪表盘 + 动画)。与 app.js 同一条分发路径: 面板下发、路由器只落盘。
	"perf.js": "text/javascript; charset=utf-8",
}

func serve(cfg serveConfig) error {
	if !cfg.allowWAN && !isLANIP(cfg.bind) {
		return fmt.Errorf("拒绝绑定 %s: 不是局域网地址 (确实需要就加 --allow-wan)", cfg.bind)
	}
	addr := net.JoinHostPort(cfg.bind, strconv.Itoa(cfg.port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { route(w, r, cfg) }),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// 手动动作 (add / refresh) 会同步等 CLI 跑完, 写超时必须比它松
		WriteTimeout: actionTimeout + 20*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	logf("本地管理界面: http://%s (运行目录 %s)", addr, cfg.dir)
	err := srv.ListenAndServe()
	if err != nil {
		return err
	}
	return nil
}

func route(w http.ResponseWriter, r *http.Request, cfg serveConfig) {
	switch r.URL.Path {
	case "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	case "/", "/index.html":
		serveStatic(w, cfg, "index.html")
	case "/app.js":
		serveStatic(w, cfg, "app.js")
	case "/perf.js":
		serveStatic(w, cfg, "perf.js")
	case "/cgi-bin/zeroproxy":
		// 页面与脚本本身**不需要授权** (代码里不含任何机密, 授权只在数据接口上),
		// 这与原来的 cgi 完全一致 —— 否则用户第一眼看到的是浏览器弹的登录框。
		query := r.URL.Query()
		// 脚本名走白名单 (与原 cgi 一致): 这个分支不需要授权, 拼路径等于开任意文件读取。
		if want := query.Get("file"); want == "app.js" || want == "perf.js" {
			serveStatic(w, cfg, want)
			return
		}
		action := query.Get("a")
		if action == "" {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				serveStatic(w, cfg, "index.html")
				return
			}
			writeJSON(w, http.StatusMethodNotAllowed, simpleResp{Error: "缺少 a= 参数"})
			return
		}
		if !authorized(w, r, cfg) {
			writeJSON(w, http.StatusForbidden, simpleResp{
				Error: "未授权 — 在路由器上执行 zeroproxy ui 拿到带令牌的地址",
			})
			return
		}
		handleAction(w, r, cfg, action)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// authorized 认三样东西: 地址里的 ?k= (顺手种成一年期的 cookie)、已种下的 cookie、
// 或 Authorization: Bearer。三者与原来的 cgi 是同一套语义 —— 用户看到的地址形状不变。
func authorized(w http.ResponseWriter, r *http.Request, cfg serveConfig) bool {
	if given := r.URL.Query().Get("k"); given != "" {
		if !constantEq(given, cfg.token) {
			return false
		}
		http.SetCookie(w, &http.Cookie{
			Name: "zp_ui", Value: cfg.token, Path: "/",
			MaxAge: 31536000, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		return true
	}
	if cookie, err := r.Cookie("zp_ui"); err == nil && cookie.Value != "" {
		if constantEq(cookie.Value, cfg.token) {
			return true
		}
	}
	if head := r.Header.Get("Authorization"); strings.HasPrefix(head, "Bearer ") {
		if constantEq(strings.TrimPrefix(head, "Bearer "), cfg.token) {
			return true
		}
	}
	// 第四样: 一个有效的 **LuCI 会话**。为什么 zpcore 也要认它 —— 从 LuCI 菜单点进来的
	// 那个 iframe 是浏览器自己发的请求, **带不上令牌**; 用户能做的只有"先登录路由器后台"。
	// 只认令牌的话, LuCI 固件上这一页永远显示未授权 (真机 GL-MT3000 / OpenWrt 24.10 实测)。
	return luciSession(r)
}

// luciSession 拿 `sysauth*` cookie 去问 ubus: 有效会话返回 JSON, 无效会话打印
// "Command failed … (Not found)"。**两种情况退出码都是 0**, 所以只能看文本。
func luciSession(r *http.Request) bool {
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, "sysauth") {
			continue
		}
		sid := strings.TrimSpace(cookie.Value)
		if !isSessionID(sid) {
			continue
		}
		out, _ := run(probeTimeout, "ubus", "call", "session", "get",
			fmt.Sprintf(`{"ubus_rpc_session":%q}`, sid))
		if out != "" && !strings.Contains(out, "Command failed") {
			return true
		}
	}
	return false
}

// 会话 id 是 32 位十六进制。先自己卡一道再拼进 JSON —— 它是从 cookie 里来的。
func isSessionID(sid string) bool {
	if len(sid) != 32 {
		return false
	}
	for i := 0; i < len(sid); i++ {
		c := sid[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func constantEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func serveStatic(w http.ResponseWriter, cfg serveConfig, name string) {
	media, allowed := staticFiles[name]
	if !allowed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(cfg.dir, "www", "zeroproxy", name))
	if err != nil {
		http.Error(w, "界面文件缺失 —— 重跑一次安装命令会重新下发", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func handleAction(w http.ResponseWriter, r *http.Request, cfg serveConfig, action string) {
	switch action {
	case "status":
		writeJSON(w, http.StatusOK, currentStatus(cfg))
	case "log":
		out, good := run(probeTimeout, "logread", "-e", "zeroproxy")
		if !good && trimSpace(out) == "" {
			writeJSON(w, http.StatusOK, simpleResp{OK: true, Log: "（这台固件上没有 logread, 看不到日志）"})
			return
		}
		writeJSON(w, http.StatusOK, simpleResp{OK: true, Log: tailLines(out, 60)})
	// update / update-log 也走 CLI: 一处实现、两个入口 (SSH 与网页)。
	// perf-on / perf-off 是页面上那块性能模式表盘的两个动作 —— 同样转发给 CLI (切数据面
	// 的规矩全在 perf.sh 里: 校验配置 → 换 → 验证出口 → 失败退回)。
	case "add", "drop", "toggle", "refresh", "update", "update-log", "perf-on", "perf-off":
		payload, err := readBody(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, simpleResp{Error: err.Error()})
			return
		}
		args, err := cliArgs(action, payload)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, simpleResp{Error: err.Error()})
			return
		}
		out, good := run(actionTimeout, cfg.cli, args...)
		if !good {
			msg := trimSpace(out)
			if msg == "" {
				msg = "执行失败: " + cfg.cli + " " + strings.Join(args, " ")
			}
			writeJSON(w, http.StatusOK, simpleResp{Error: msg})
			return
		}
		writeJSON(w, http.StatusOK, simpleResp{OK: true, Message: out})
	default:
		writeJSON(w, http.StatusBadRequest, simpleResp{Error: "未知操作: " + action})
	}
}

// cliArgs 把界面上的动作翻成 CLI 参数。**动作本身在 CLI 里实现, 这里只做转发** ——
// 一处实现、两处入口 (SSH 与网页), 不会出现"界面能做的和命令行能做的不是一回事"。
func cliArgs(action string, payload map[string]any) ([]string, error) {
	switch action {
	case "add":
		url := strings.TrimSpace(asString(payload["url"]))
		if url == "" {
			return nil, fmt.Errorf("没有收到服务器链接")
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("这看起来不是一个面板链接")
		}
		if !strings.Contains(url, "/c/") {
			return nil, fmt.Errorf("这看起来不是一个面板链接 (要 /c/<配对码> 那一段)")
		}
		return []string{"add", url}, nil
	case "drop":
		key := strings.TrimSpace(asString(payload["key"]))
		if key == "" {
			return nil, fmt.Errorf("没有指定要移除的服务器")
		}
		// 键会进 shell 参数, 而且 CLI 用它拼文件名 —— 收紧到清单里出现过的那套字符。
		if strings.ContainsAny(key, " /\\$`'\"*?[]") {
			return nil, fmt.Errorf("服务器键不合法")
		}
		return []string{"drop", key}, nil
	case "toggle":
		if asBool(payload["on"]) {
			return []string{"on"}, nil
		}
		return []string{"off"}, nil
	case "refresh":
		return []string{"refresh"}, nil
	case "update":
		return []string{"update"}, nil
	case "update-log":
		return []string{"update-log"}, nil
	// 表盘上的那个按钮: 进 = perf on, 出 = perf off。CLI 里没有 TTY 时会**后台跑**并把
	// 进度写进 perf/progress, 界面轮询状态就能把"进入中"那段动画一气画完。
	case "perf-on":
		return []string{"perf", "on"}, nil
	case "perf-off":
		return []string{"perf", "off"}, nil
	}
	return nil, fmt.Errorf("未知操作")
}

func currentStatus(cfg serveConfig) statusResp {
	core := "stopped"
	if ok(probeTimeout, cfg.initd, "running") {
		core = "running"
	}
	mode, covered := liveMode()
	caps := readCaps(cfg.dir)
	why := ""
	if mode == "none" {
		// 一级都没接管时把**每一级为什么不行**都带上: 只报"选中的那一级"会漏掉关键信息
		// (真机截图里选的是 tun, 屏幕上却只有 tproxy 的原因, 于是没人知道 iptables 那条路
		//  到底为什么也没用上)。与 agent.sh 的心跳报的是同一份。
		var parts []string
		for _, level := range []string{"tun", "tproxy", "redirect"} {
			if v := caps["why."+level]; v != "" {
				parts = append(parts, level+": "+v)
			}
		}
		why = strings.Join(parts, " · ")
	}
	return statusResp{
		OK:      true,
		Core:    core,
		Mode:    mode,
		Covered: covered,
		Why:     why,
		// IPv6 是泄漏面: 探不到就必须显示出来 (目标网站会看到真实的 v6 地址)
		IPv6:    caps["ipv6"],
		Packets: datapathPackets(mode),
		WAN:     wanBytes(),
		Client:  readTrimmed(filepath.Join(cfg.dir, "version")),
		Perf:    currentPerf(cfg),
		Servers: readServers(cfg.dir),
	}
}

// currentPerf 把性能模式的状态汇总成界面上那几张牌。
//
// "正在切换"的判据: 进度文件存在且还没有终态行 (DONE=…)。CLI 是这么写的 (见安装在
// perf.sh 里的 zp_perf_enter), 这里只是把它读出来 —— 前端不猜, 后端也不编。
func currentPerf(cfg serveConfig) perfResp {
	progress := perfFile(cfg.dir, "progress")
	busy := "0"
	if progress != "" && !strings.Contains(progress, "DONE=") {
		busy = "1"
	}
	live := "0"
	if daeRunning() {
		live = "1"
	}
	caps := readCaps(cfg.dir)
	// 进度只取最后几行: 界面上的标题栏放不下整份日志, 而且前面那几行是"取内核"的旧闻。
	tail := progress
	if lines := strings.Split(progress, "\n"); len(lines) > 3 {
		tail = strings.Join(lines[len(lines)-3:], "|")
	} else {
		tail = strings.ReplaceAll(progress, "\n", "|")
	}
	return perfResp{
		Cap:      caps["perf_cap"],
		State:    perfFile(cfg.dir, "state"),
		Live:     live,
		Why:      perfFile(cfg.dir, "why"),
		ExitIP:   perfFile(cfg.dir, "exit_ip"),
		Busy:     busy,
		Progress: tail,
	}
}

func readBody(r *http.Request) (map[string]any, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("读请求失败")
	}
	if len(body) == 0 {
		return map[string]any{}, nil
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("请求体不是 JSON")
	}
	return payload, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	// 面板那边回的中文话里可能有 < > (比如 "<配对码>"), 转义了不好看也不好查
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func asString(v any) string {
	if s, isString := v.(string); isString {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes" || t == "on"
	case float64:
		return t != 0
	}
	return false
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return trimSpace(string(data))
}
