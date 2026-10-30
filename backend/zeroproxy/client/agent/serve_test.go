package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLuciSessionAcceptsTheShapeReturnedByRealUbus(t *testing.T) {
	// 真实的 ubus session get 一定带 values.username —— 1.3.2 起除了"会话有效", 还要
	// 校验身份是 root (或该会话的 ACL 放行本应用), 见 P2-8。
	bin := t.TempDir()
	fakeExecutable(t, bin, "ubus", "printf '%s\\n' '{\"values\":{\"username\":\"root\"}}'\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "sysauth",
		Value: "0123456789abcdef0123456789abcdef",
	})
	if !luciSession(req) {
		t.Fatal("valid LuCI session of root was rejected")
	}
}

// 非 root 的会话只有在 ACL 明确放行本应用时才认 —— 默认拒绝 (fail closed)。
// 多账号 + ACL 的固件上, 一个被限制的账号以前能借这个入口跑 update (root 级)。
func TestLuciSessionRequiresRootOrAppACL(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"root", "printf '%s\\n' '{\"values\":{\"username\":\"root\"}}'\n", true},
		{"guest without acl", "printf '%s\\n' '{\"values\":{\"username\":\"guest\"}}'\n", false},
		{"guest with app acl", "printf '%s\\n' '{\"values\":{\"username\":\"guest\",\"access\":{\"luci-app-zeroproxy\":true}}}'\n", true},
		{"guest with other acl", "printf '%s\\n' '{\"values\":{\"username\":\"guest\",\"access\":{\"luci-app-other\":true}}}'\n", false},
		{"empty values", "printf '%s\\n' '{\"values\":{}}'\n", false},
	}
	for _, tc := range cases {
		bin := t.TempDir()
		fakeExecutable(t, bin, "ubus", tc.body)
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "sysauth",
			Value: "0123456789abcdef0123456789abcdef",
		})
		if got := luciSession(req); got != tc.want {
			t.Fatalf("%s: luciSession = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// 两个入口都补了安全头 (P2-8): 只允许同源 iframe、不许 MIME 嗅探、不带 Referer 出去。
func TestRouteSetsSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	cfg := serveConfig{
		commonConfig: commonConfig{dir: dir, cli: filepath.Join(dir, "cli")},
		token:        "test-token",
	}
	for _, path := range []string{"/", "/cgi-bin/zeroproxy?a=status&k=test-token"} {
		rec := httptest.NewRecorder()
		route(rec, httptest.NewRequest(http.MethodGet, path, nil), cfg)
		want := map[string]string{
			"X-Frame-Options":         "SAMEORIGIN",
			"Content-Security-Policy": "frame-ancestors 'self'",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "no-referrer",
		}
		for key, value := range want {
			if got := rec.Header().Get(key); got != value {
				t.Fatalf("%s: header %s = %q, want %q", path, key, got, value)
			}
		}
	}
}

// 动作名有两个来源: `?a=` 与 PATH_INFO (`/cgi-bin/zeroproxy/status`)。页面只发 ?a=,
// 但外部脚本/手工路径走 PATH_INFO —— 以前 zpcore 只认 ?a=, 契约与 cgi 不一致。
func TestRouteAcceptsPathInfoAction(t *testing.T) {
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	cli := fakeExecutable(t, dir, "cli", "printf '%s\\n' \"$*\" >> \""+called+"\"\n")
	cfg := serveConfig{
		commonConfig: commonConfig{dir: dir, cli: cli},
		token:        "test-token",
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/cgi-bin/zeroproxy/toggle?k=test-token",
		strings.NewReader(`{"on":true}`),
	)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	route(rec, req, cfg)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATH_INFO toggle status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(called)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "on" {
		t.Fatalf("PATH_INFO toggle invoked CLI with %q, want on", strings.TrimSpace(string(got)))
	}
}

// 布尔解析与 cgi 对齐: yes/on/大写 也算"开" (以前 cgi 只认 true|1)。
func TestAsBoolMatchesCgiSemantics(t *testing.T) {
	for _, value := range []any{true, "true", "1", "yes", "on", "ON", " Yes "} {
		if !asBool(value) {
			t.Fatalf("asBool(%#v) = false, want true", value)
		}
	}
	for _, value := range []any{false, "false", "0", "no", "off", "", nil, float64(0)} {
		if asBool(value) {
			t.Fatalf("asBool(%#v) = true, want false", value)
		}
	}
}

func TestLuciSessionRejectsErrorsAndMalformedJSON(t *testing.T) {
	cases := []string{
		"printf '%s\\n' 'Command failed: Not found'\n",
		"printf '%s\\n' 'not json'\n",
		"printf '%s\\n' '{\"error\":\"not found\"}'\n",
		"printf '%s\\n' '{\"values\":{}}'\nexit 1\n",
	}
	for _, body := range cases {
		bin := t.TempDir()
		fakeExecutable(t, bin, "ubus", body)
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "sysauth",
			Value: "0123456789abcdef0123456789abcdef",
		})
		if luciSession(req) {
			t.Fatalf("invalid ubus result was accepted: %q", body)
		}
	}
}

func TestRouteRejectsGETAndAcceptsPOSTForToggle(t *testing.T) {
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	cli := fakeExecutable(t, dir, "cli", "printf '%s\\n' \"$*\" >> \""+called+"\"\n")
	cfg := serveConfig{
		commonConfig: commonConfig{dir: dir, cli: cli},
		token:        "test-token",
	}

	getReq := httptest.NewRequest(
		http.MethodGet,
		"/cgi-bin/zeroproxy?a=toggle&k=test-token",
		nil,
	)
	getResp := httptest.NewRecorder()
	route(getResp, getReq, cfg)
	if getResp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET toggle status = %d, want 405; body=%s", getResp.Code, getResp.Body.String())
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatal("GET toggle invoked the CLI")
	}

	postReq := httptest.NewRequest(
		http.MethodPost,
		"/cgi-bin/zeroproxy?a=toggle&k=test-token",
		strings.NewReader(`{"on":false}`),
	)
	postReq.Header.Set("Content-Type", "application/json")
	postResp := httptest.NewRecorder()
	route(postResp, postReq, cfg)
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST toggle status = %d, want 200; body=%s", postResp.Code, postResp.Body.String())
	}
	got, err := os.ReadFile(called)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "off" {
		t.Fatalf("POST toggle invoked CLI with %q, want off", strings.TrimSpace(string(got)))
	}
}
