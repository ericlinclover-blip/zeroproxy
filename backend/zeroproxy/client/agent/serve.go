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
	OK      bool          `json:"ok"`
	Core    string        `json:"core"`
	Mode    string        `json:"mode"`
	Covered string        `json:"covered"`
	Why     string        `json:"why"`
	IPv6    string        `json:"ipv6"`
	Client  string        `json:"client"`
	Servers []serverEntry `json:"servers"`
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
	case "/cgi-bin/zeroproxy":
		// 页面与脚本本身**不需要授权** (代码里不含任何机密, 授权只在数据接口上),
		// 这与原来的 cgi 完全一致 —— 否则用户第一眼看到的是浏览器弹的登录框。
		query := r.URL.Query()
		if query.Get("file") == "app.js" {
			serveStatic(w, cfg, "app.js")
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
	return false
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
	case "add", "drop", "toggle", "refresh":
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
		for _, level := range []string{"tun", "tproxy", "redirect"} {
			if v := caps["why."+level]; v != "" {
				why = v
				break
			}
		}
	}
	return statusResp{
		OK:      true,
		Core:    core,
		Mode:    mode,
		Covered: covered,
		Why:     why,
		// IPv6 是泄漏面: 探不到就必须显示出来 (目标网站会看到真实的 v6 地址)
		IPv6:    caps["ipv6"],
		Client:  readTrimmed(filepath.Join(cfg.dir, "version")),
		Servers: readServers(cfg.dir),
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
