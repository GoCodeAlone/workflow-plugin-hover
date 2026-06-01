package hoverclient

// browser_backend_test.go — TDD tests for Task 3: browserBackend.Login,
// cookie handoff, and typed error surface.
//
// All tests that exercise go-rod drive it against a local httptest server
// (no real Hover connection). Tests run headless with an isolated temp
// profile dir so they never interfere with a real browser session.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

// newBrowserTestOpts returns headless BrowserOptions pointing at a temp profile
// and with a short timeout suitable for local tests. It skips the test if no
// Chrome binary is available and opts.Download is false.
func newBrowserTestOpts(t *testing.T) BrowserOptions {
	t.Helper()
	dir := t.TempDir()
	opts := BrowserOptions{
		Download:   false,
		Headless:   true,
		ProfileDir: dir,
		Timeout:    60 * time.Second,
	}
	// If a Chrome binary exists, use it; otherwise skip (we don't download in CI).
	if _, ok := findChromeBinary(); !ok {
		t.Skip("no Chrome binary found; skipping browser backend test (install Chrome to run)")
	}
	return opts
}

// fakeSigninMux returns an http.ServeMux that simulates Hover's signin flow.
// authResponse is what /signin/auth.json returns.
// auth2Response is what /signin/auth2.json returns (ignored if authResponse
// does not contain status=need_2fa).
// It also serves a minimal /signin page with fake __uzma clearance cookies.
func fakeSigninMux(authResponse, auth2Response map[string]any) *http.ServeMux {
	mux := http.NewServeMux()

	// Signin page — set clearance cookies so waitForClearanceCookies is satisfied.
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "__uzma",
			Value: "fake-clearance",
			Path:  "/",
		})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})

	// Step 1 auth endpoint.
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authResponse)
	})

	// Step 2 auth endpoint (TOTP).
	mux.HandleFunc("/signin/auth2.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auth2Response)
	})

	return mux
}

// newBrowserClient creates a *Client wired with a browserBackend whose opts
// point at the given test server URL.  The http.Client jar is already set up
// (by NewClientWithOptions) and will receive copied cookies after login.
//
// The overrideHost param wires the backend so it navigates to srv.URL rather
// than the live hoverHost constant.  This is test-only; production always uses
// hoverHost.
func newBrowserClient(t *testing.T, opts BrowserOptions, overrideHost string, creds Credentials) *Client {
	t.Helper()
	c, err := NewClientWithOptions(creds, nil, ClientOptions{Browser: opts})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}
	// Wire the override host for local testing.
	bb := c.backend.(*browserBackend)
	bb.overrideHost = overrideHost
	return c
}

// --------------------------------------------------------------------------
// TestBrowserBackend_ChromeMissingDownloadDisabled
// --------------------------------------------------------------------------

// TestBrowserBackend_ChromeMissingDownloadDisabled verifies that when no
// system Chrome is present and Download is false, Login returns ErrChromeUnavailable
// with an actionable message — before any navigation.
func TestBrowserBackend_ChromeMissingDownloadDisabled(t *testing.T) {
	opts := BrowserOptions{
		Download:   false,
		Headless:   true,
		ProfileDir: t.TempDir(),
		Path:       "/nonexistent/chrome/binary",
		Timeout:    10 * time.Second,
	}
	creds := Credentials{Username: "alice", Password: "pw"}
	c, err := NewClientWithOptions(creds, nil, ClientOptions{Browser: opts})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}
	bb := c.backend.(*browserBackend)
	bb.overrideHost = "http://127.0.0.1:9" // unreachable; error must be before navigate

	err = c.Login(context.Background())
	if err == nil {
		t.Fatal("expected error when Chrome binary is missing")
	}
	if !errors.Is(err, ErrChromeUnavailable) {
		t.Errorf("expected ErrChromeUnavailable, got: %v", err)
	}
	// Message must be actionable.
	msg := err.Error()
	if !strings.Contains(msg, "Chrome") && !strings.Contains(msg, "chrome") {
		t.Errorf("error message not actionable (no Chrome mention): %q", msg)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_LoginLocalNoMFA
// --------------------------------------------------------------------------

// TestBrowserBackend_LoginLocalNoMFA drives a full browser login against a
// local fake Hover signin server (no real Hover connection). Verifies that:
//   - loggedAt is set on the Client after successful login
//   - clearance cookies are copied into c.http.Jar
func TestBrowserBackend_LoginLocalNoMFA(t *testing.T) {
	opts := newBrowserTestOpts(t)

	auth := map[string]any{"succeeded": true, "status": "completed"}
	mux := fakeSigninMux(auth, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// loggedAt must be set.
	c.mu.Lock()
	loggedAt := c.loggedAt
	c.mu.Unlock()
	if loggedAt.IsZero() {
		t.Fatal("loggedAt not set after successful login")
	}
	if time.Since(loggedAt) > 30*time.Second {
		t.Errorf("loggedAt too stale: %v", loggedAt)
	}

	// Clearance cookies must be in the jar.
	srvURL, _ := url.Parse(srv.URL)
	cookies := c.http.Jar.Cookies(srvURL)
	found := false
	for _, ck := range cookies {
		if isClearanceCookie(ck.Name) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("clearance cookies not copied into c.http.Jar; jar cookies: %v", cookies)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_LoginLocalTOTPRequired
// --------------------------------------------------------------------------

// TestBrowserBackend_LoginLocalTOTPRequired verifies that when /signin/auth.json
// returns need_2fa and a TOTP secret is configured, the backend posts a generated
// code to /signin/auth2.json and succeeds.
func TestBrowserBackend_LoginLocalTOTPRequired(t *testing.T) {
	opts := newBrowserTestOpts(t)

	// Build a fresh mux (don't use fakeSigninMux which already registers auth2).
	var auth2Code string
	mux := http.NewServeMux()
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__uzma", Value: "fake-clearance", Path: "/"})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": false, "status": "need_2fa"})
	})
	mux.HandleFunc("/signin/auth2.json", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if code, ok := body["code"].(string); ok {
			auth2Code = code
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "status": "completed"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	totp := mustParse(t, rfc6238Secret)
	creds := Credentials{Username: "alice", Password: "pw", TOTPSecret: totp}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login with TOTP: %v", err)
	}

	c.mu.Lock()
	loggedAt := c.loggedAt
	c.mu.Unlock()
	if loggedAt.IsZero() {
		t.Fatal("loggedAt not set after TOTP login")
	}

	// auth2 code must be a 6-digit string.
	if len(auth2Code) != 6 {
		t.Errorf("TOTP code posted to auth2 = %q, want 6 digits", auth2Code)
	}
	for _, r := range auth2Code {
		if r < '0' || r > '9' {
			t.Errorf("non-digit in auth2 code: %q", auth2Code)
		}
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_LoginEmail2FAWithoutTOTP
// --------------------------------------------------------------------------

// TestBrowserBackend_LoginEmail2FAWithoutTOTP verifies that when /signin/auth.json
// returns need_2fa but no TOTP secret is configured, Login returns ErrEmail2FARequired
// (not ErrBotChallenge, not a generic error). The message must be actionable.
func TestBrowserBackend_LoginEmail2FAWithoutTOTP(t *testing.T) {
	opts := newBrowserTestOpts(t)

	auth := map[string]any{"succeeded": false, "status": "need_2fa"}
	mux := fakeSigninMux(auth, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// No TOTP secret configured.
	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	err := c.Login(ctx)
	if err == nil {
		t.Fatal("expected error when need_2fa without TOTP secret")
	}
	if !errors.Is(err, ErrEmail2FARequired) {
		t.Errorf("expected ErrEmail2FARequired, got: %T %v", err, err)
	}
	// Must NOT be ErrBotChallenge.
	if errors.Is(err, ErrBotChallenge) {
		t.Errorf("got ErrBotChallenge; should be ErrEmail2FARequired")
	}
	// Message must mention TOTP/authenticator.
	msg := err.Error()
	if !strings.Contains(strings.ToLower(msg), "totp") && !strings.Contains(strings.ToLower(msg), "authenticator") {
		t.Errorf("error message not actionable (no TOTP/authenticator mention): %q", msg)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_LoginDetectsBotChallenge
// --------------------------------------------------------------------------

// TestBrowserBackend_LoginDetectsBotChallenge verifies that when /signin/auth.json
// returns an HTTP 401/403 or an Imperva-style block, Login returns ErrBotChallenge.
func TestBrowserBackend_LoginDetectsBotChallenge(t *testing.T) {
	opts := newBrowserTestOpts(t)

	mux := http.NewServeMux()
	// Signin page — no clearance cookies set, simulating persistent Imperva block.
	// We'll serve a page that blocks permanently.
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		// Imperva challenge page — no clearance cookies.
		// The page content simulates a bot-challenge block page.
		_, _ = w.Write([]byte(`<html><body>
			<div id="main-iframe"></div>
			<script>document.getElementById('main-iframe').innerHTML='blocked';</script>
		</body></html>`))
	})
	// auth.json returns 401 (bot blocked before login even possible).
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"blocked"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	creds := Credentials{Username: "alice", Password: "pw"}
	// Short timeout so the clearance-wait gives up quickly.
	opts.Timeout = 8 * time.Second
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := c.Login(ctx)
	if err == nil {
		t.Fatal("expected error from bot-challenge server")
	}
	if !errors.Is(err, ErrBotChallenge) {
		t.Errorf("expected ErrBotChallenge, got: %T %v", err, err)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_ReadsDelegateToHTTP
// --------------------------------------------------------------------------

// TestBrowserBackend_ReadsDelegateToHTTP verifies that after a successful
// browser login, ListDomains delegates to the HTTP path using the jar-backed
// http.Client — confirming the hybrid architecture handoff.
func TestBrowserBackend_ReadsDelegateToHTTP(t *testing.T) {
	opts := newBrowserTestOpts(t)

	auth := map[string]any{"succeeded": true, "status": "completed"}
	mux := fakeSigninMux(auth, nil)

	// Also serve /api/domains for the HTTP read delegation.
	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"succeeded": true,
			"domains": []map[string]any{
				{"id": "dom1", "domain_name": "example.com"},
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	// Wire the HTTP client to point at the test server too.
	c.http.Transport = rewriteTransport{base: srv.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	// Login first so loggedAt is set.
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// ListDomains should delegate to the HTTP backend (which hits /api/domains).
	domains, err := c.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(domains) != 1 || domains[0].Name != "example.com" {
		t.Errorf("unexpected domains: %v", domains)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_WritesReturnUnavailable
// --------------------------------------------------------------------------

// TestBrowserBackend_WritesReturnUnavailable verifies that write operations
// still return ErrBrowserBackendUnavailable (Task 4 territory).
func TestBrowserBackend_WritesReturnUnavailable(t *testing.T) {
	opts := BrowserOptions{
		Download:   false,
		Headless:   true,
		ProfileDir: t.TempDir(),
		Timeout:    10 * time.Second,
	}
	bb := newBrowserBackend(opts)

	// Fake a logged-in client (loggedAt set, so ensureLogin won't fire).
	c, err := NewClientWithOptions(Credentials{Username: "u", Password: "p"}, nil, ClientOptions{Browser: opts})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}
	c.mu.Lock()
	c.loggedAt = time.Now()
	c.mu.Unlock()
	_ = bb // ensure the backend is the right type

	ctx := context.Background()
	if err := bb.SetNameservers(ctx, c, "example.com", []string{"ns1.com"}); !errors.Is(err, ErrBrowserBackendUnavailable) {
		t.Errorf("SetNameservers: want ErrBrowserBackendUnavailable, got %v", err)
	}
	if _, err := bb.CreateRecord(ctx, c, "dom1", DNSRecord{}); !errors.Is(err, ErrBrowserBackendUnavailable) {
		t.Errorf("CreateRecord: want ErrBrowserBackendUnavailable, got %v", err)
	}
	if err := bb.UpdateRecord(ctx, c, "r1", DNSRecord{}); !errors.Is(err, ErrBrowserBackendUnavailable) {
		t.Errorf("UpdateRecord: want ErrBrowserBackendUnavailable, got %v", err)
	}
	if err := bb.DeleteRecord(ctx, c, "r1"); !errors.Is(err, ErrBrowserBackendUnavailable) {
		t.Errorf("DeleteRecord: want ErrBrowserBackendUnavailable, got %v", err)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_CloseIsIdempotent
// --------------------------------------------------------------------------

// TestBrowserBackend_CloseIsIdempotent verifies Close() doesn't panic when
// called on a backend that was never used to launch a browser.
func TestBrowserBackend_CloseIsIdempotent(t *testing.T) {
	opts := BrowserOptions{
		Download:   false,
		Headless:   true,
		ProfileDir: t.TempDir(),
		Timeout:    5 * time.Second,
	}
	bb := newBrowserBackend(opts)
	if err := bb.Close(); err != nil {
		t.Errorf("Close on unused backend: %v", err)
	}
	if err := bb.Close(); err != nil {
		t.Errorf("second Close on unused backend: %v", err)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_LoginSkipsWhenFresh
// --------------------------------------------------------------------------

// TestBrowserBackend_LoginSkipsWhenFresh verifies that a second Login call
// within sessionStaleAfter does not re-launch the browser.
func TestBrowserBackend_LoginSkipsWhenFresh(t *testing.T) {
	opts := newBrowserTestOpts(t)

	// Count how many times the signin page is hit.
	signinHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		signinHits++
		http.SetCookie(w, &http.Cookie{Name: "__uzma", Value: "fake", Path: "/"})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "status": "completed"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("first Login: %v", err)
	}
	firstHits := signinHits

	// Second login: session is fresh — should not re-navigate.
	if err := c.Login(ctx); err != nil {
		t.Fatalf("second Login: %v", err)
	}

	// Signin page must not have been hit again.
	if signinHits != firstHits {
		t.Errorf("browser re-launched on second Login; signin page hit count went from %d to %d", firstHits, signinHits)
	}
}

// TestBrowserBackend_OverrideHostRespected is a compile-time check that
// overrideHost field exists on browserBackend (used by all local tests above).
func TestBrowserBackend_OverrideHostRespected(_ *testing.T) {
	bb := &browserBackend{}
	_ = bb.overrideHost
	_ = os.DevNull // suppress unused import warning
}
