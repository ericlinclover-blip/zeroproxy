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
	bin := t.TempDir()
	fakeExecutable(t, bin, "ubus", "printf '%s\\n' '{\"values\":{}}'\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "sysauth",
		Value: "0123456789abcdef0123456789abcdef",
	})
	if !luciSession(req) {
		t.Fatal("valid LuCI session was rejected")
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
