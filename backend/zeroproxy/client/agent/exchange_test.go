package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func panelFixture(t *testing.T, servers, spool, name, base string) {
	t.Helper()
	cred, _ := json.Marshal(panelCredential{Base: base, ID: "dv-test", Secret: "private-secret"})
	if err := os.WriteFile(filepath.Join(servers, name+".json"), cred, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, name+".json.request"), []byte(`{"device":"dv-test","actual":true}`), 0600); err != nil {
		t.Fatal(err)
	}
}
func runRound(t *testing.T, ctx context.Context, servers, spool string, legacy bool) {
	t.Helper()
	entries, err := os.ReadDir(servers)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeRound(ctx, servers, spool, entries, legacy); err != nil {
		t.Fatal(err)
	}
}
func TestExchangePanelsAreIndependentAndBounded(t *testing.T) {
	servers, spool := t.TempDir(), t.TempDir()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-secret" {
			t.Error("missing bearer")
		}
		w.Write([]byte(`{"desired":false,"rev":"0123456789abcdef"}`))
	}))
	defer fast.Close()
	panelFixture(t, servers, spool, "a-slow", slow.URL)
	panelFixture(t, servers, spool, "b-fast", fast.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	start := time.Now()
	runRound(t, ctx, servers, spool, false)
	if time.Since(start) > time.Second {
		t.Fatal("round exceeded budget")
	}
	if _, err := os.Stat(filepath.Join(spool, "b-fast.json.response")); err != nil {
		t.Fatal("healthy panel blocked by failed panel:", err)
	}
	if _, err := os.Stat(filepath.Join(spool, "a-slow.json.response")); !os.IsNotExist(err) {
		t.Fatal("failed panel produced success")
	}
}
func TestExchangeRejectsInvalidRepliesAndRedirects(t *testing.T) {
	for _, tc := range []struct {
		name, body, kind string
		status           int
	}{
		{"html", "<html>login</html>", "protocol", 200},
		{"missing-desired", `{"rev":"0123456789abcdef"}`, "protocol", 200},
		{"invalid-revision", `{"desired":true,"rev":"wrong"}`, "protocol", 200},
		{"bad-type", `{"desired":"false","rev":"0123456789abcdef"}`, "protocol", 200},
		{"oversized", strings.Repeat("x", exchangeLimit+1), "protocol", 200},
		{"revoked", `{}`, "auth", 403},
		{"redirect", `{}`, "http", 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/other")
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			servers, spool := t.TempDir(), t.TempDir()
			panelFixture(t, servers, spool, "panel", srv.URL)
			// A stale success must not survive a failed round.
			os.WriteFile(filepath.Join(spool, "panel.json.response"), []byte(`{}`), 0600)
			runRound(t, context.Background(), servers, spool, false)
			if _, err := os.Stat(filepath.Join(spool, "panel.json.response")); !os.IsNotExist(err) {
				t.Fatal("invalid reply accepted")
			}
			b, err := os.ReadFile(filepath.Join(spool, "panel.json.error"))
			if err != nil {
				t.Fatal(err)
			}
			var failure exchangeError
			json.Unmarshal(b, &failure)
			if failure.Kind != tc.kind {
				t.Fatalf("%s: %s", failure.Kind, b)
			}
			if calls.Load() != 1 {
				t.Fatal("terminal error retried or redirect followed")
			}
			if strings.Contains(string(b), "private-secret") {
				t.Fatal("credential leaked")
			}
		})
	}
}
func TestExchangeRetriesTransientFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"desired":true,"rev":"0123456789abcdef"}`))
	}))
	defer srv.Close()
	servers, spool := t.TempDir(), t.TempDir()
	panelFixture(t, servers, spool, "panel", srv.URL)
	runRound(t, context.Background(), servers, spool, false)
	if calls.Load() != 2 {
		t.Fatal("transient failure not retried")
	}
	if _, err := os.Stat(filepath.Join(spool, "panel.json.response")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(spool, "panel.json.error")); !os.IsNotExist(err) {
		t.Fatal("successful retry retained old error")
	}
}
func TestExchangeCertificateFallbackIsExplicit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"desired":true,"rev":"0123456789abcdef"}`))
	}))
	defer srv.Close()
	servers, spool := t.TempDir(), t.TempDir()
	panelFixture(t, servers, spool, "panel", srv.URL)
	runRound(t, context.Background(), servers, spool, false)
	if _, err := os.Stat(filepath.Join(spool, "panel.json.response")); !os.IsNotExist(err) {
		t.Fatal("strict mode bypassed certificate verification")
	}
	runRound(t, context.Background(), servers, spool, true)
	if _, err := os.Stat(filepath.Join(spool, "panel.json.response")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(spool, "panel.json.tls")); err != nil {
		t.Fatal("legacy fallback not recorded")
	}
}
