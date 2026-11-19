package main

// The shell owns reconciliation; this module owns the bounded network round.
// Requests and replies live in a private tmpfs spool, never in process arguments.
import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const exchangeLimit = 64 << 10

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type panelCredential struct {
	Base   string `json:"base"`
	ID     string `json:"id"`
	Secret string `json:"secret"`
}
type exchangeError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func exchangeCommand(args []string) error {
	fs := flag.NewFlagSet("exchange", flag.ContinueOnError)
	servers := fs.String("servers", "/etc/zeroproxy/servers", "panel credential directory")
	spool := fs.String("spool", "", "private request/reply directory on tmpfs")
	legacyTLS := fs.Bool("legacy-tls", false, "allow existing certificate-error fallback; record warning")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *spool == "" || fs.NArg() != 0 {
		return fmt.Errorf("exchange requires --spool")
	}
	entries, err := os.ReadDir(*servers)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return exchangeRound(ctx, *servers, *spool, entries, *legacyTLS)
}

func exchangeRound(ctx context.Context, servers, spool string, entries []os.DirEntry, legacyTLS bool) error {
	// A shared transport reuses DNS/TLS connections across retries within this round.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // router control traffic must not inherit a proxy environment
	transport.MaxConnsPerHost = 4
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	insecureTransport := transport.Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // explicit legacy compatibility only
	defer insecureTransport.CloseIdleConnections()
	insecureClient := &http.Client{Transport: insecureTransport, CheckRedirect: client.CheckRedirect}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := entry.Name()
		requestPath := filepath.Join(spool, name+".request")
		if _, err := os.Stat(requestPath); err != nil {
			continue
		}
		count++
		if count > 32 {
			wg.Wait()
			return fmt.Errorf("too many panel requests")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			responsePath := filepath.Join(spool, name+".response")
			errorPath := filepath.Join(spool, name+".error")
			os.Remove(responsePath)
			os.Remove(errorPath)
			os.Remove(filepath.Join(spool, name+".tls"))
			fail := func(kind, message string) {
				blob, _ := json.Marshal(exchangeError{kind, message})
				_ = os.WriteFile(errorPath, blob, 0600)
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				fail("timeout", "control round deadline")
				return
			}
			credBytes, err := os.ReadFile(filepath.Join(servers, name))
			if err != nil {
				fail("credentials", "cannot read panel credentials")
				return
			}
			var cred panelCredential
			if json.Unmarshal(credBytes, &cred) != nil || cred.ID == "" || cred.Secret == "" {
				fail("credentials", "invalid panel credentials")
				return
			}
			endpoint, err := url.Parse(strings.TrimRight(cred.Base, "/") + "/c/report")
			if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
				fail("credentials", "invalid panel address")
				return
			}
			body, err := readBoundedFile(requestPath)
			if err != nil || !json.Valid(body) {
				fail("request", "invalid heartbeat request")
				return
			}
			activeClient := client
			for attempt := 0; attempt < 3; attempt++ {
				attemptCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
				reply, kind := exchangeOnce(attemptCtx, activeClient, endpoint.String(), cred.Secret, body)
				cancel()
				if kind == "tls" && legacyTLS && activeClient == client {
					activeClient = insecureClient
					_ = os.WriteFile(filepath.Join(spool, name+".tls"), []byte("certificate verification bypassed (legacy compatibility)\n"), 0600)
					// Certificate fallback consumes an attempt and shares the round deadline.
					continue
				}
				if kind == "" {
					os.Remove(errorPath)
					tmp := responsePath + ".tmp"
					if os.WriteFile(tmp, reply, 0600) != nil || os.Rename(tmp, responsePath) != nil {
						fail("storage", "cannot publish heartbeat reply")
					}
					return
				}
				fail(kind, "panel heartbeat failed") // never include URL, body, or credentials
				if kind != "network" && kind != "server" {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(100+rand.Intn(250)) * time.Millisecond):
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func readBoundedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, exchangeLimit+1))
	if len(b) > exchangeLimit {
		return nil, fmt.Errorf("request too large")
	}
	return b, err
}

func exchangeOnce(ctx context.Context, client *http.Client, endpoint, secret string, body []byte) ([]byte, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "request"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &certErr) || errors.As(err, &unknown) {
			return nil, "tls"
		}
		return nil, "network"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, "auth"
	}
	if resp.StatusCode >= 500 || resp.StatusCode == 429 {
		return nil, "server"
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "http"
	}
	reply, err := io.ReadAll(io.LimitReader(resp.Body, exchangeLimit+1))
	if err != nil {
		return nil, "network"
	}
	if len(reply) > exchangeLimit {
		return nil, "protocol"
	}
	var ack struct {
		Desired *bool  `json:"desired"`
		Rev     string `json:"rev"`
	}
	if json.Unmarshal(reply, &ack) != nil || ack.Desired == nil || !revisionPattern.MatchString(ack.Rev) {
		return nil, "protocol"
	}
	return reply, ""
}
