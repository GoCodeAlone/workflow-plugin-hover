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
	"sync/atomic"
	"testing"
	"time"

	"github.com/GoCodeAlone/rod/lib/proto"
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

func TestBrowserBackend_LoginRetriesSignin429(t *testing.T) {
	opts := newBrowserTestOpts(t)
	var authHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__uzma", Value: "fake", Path: "/"})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		hit := authHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if hit == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`<html><head><title>429 Too Many Requests</title></head><body>try later</body></html>`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "status": "completed"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	oldDelay := retryBaseDelay
	retryBaseDelay = time.Millisecond
	t.Cleanup(func() { retryBaseDelay = oldDelay })

	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login after retryable 429: %v", err)
	}
	if got := authHits.Load(); got != 2 {
		t.Fatalf("auth hits = %d, want 2", got)
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

// TestBrowserBackend_WritesRequireBrowserSession verifies that write operations
// on a browserBackend whose browser has not been initialised (no successful
// Login that launched Chrome) return a clear "not initialised" error rather
// than panicking or returning a misleading result. This covers the case where
// callers fake loggedAt but never actually ran Login (unit-test-only pattern).
func TestBrowserBackend_WritesRequireBrowserSession(t *testing.T) {
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

	ctx := context.Background()
	// Each write operation must return a non-nil error mentioning "not initialised"
	// (not a panic, not a nil error, not ErrBrowserBackendUnavailable).
	checkWriteErr := func(t *testing.T, label string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: want error for uninitialised browser, got nil", label)
			return
		}
		if !strings.Contains(err.Error(), "not initialised") {
			t.Errorf("%s: error = %q; want message containing 'not initialised'", label, err.Error())
		}
	}

	err = bb.SetNameservers(ctx, c, "example.com", []string{"ns1.com"})
	checkWriteErr(t, "SetNameservers", err)

	_, err = bb.CreateRecord(ctx, c, "dom1", DNSRecord{})
	checkWriteErr(t, "CreateRecord", err)

	err = bb.UpdateRecord(ctx, c, "r1", DNSRecord{})
	checkWriteErr(t, "UpdateRecord", err)

	err = bb.DeleteRecord(ctx, c, "r1")
	checkWriteErr(t, "DeleteRecord", err)
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
	var signinHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		signinHits.Add(1)
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
	firstHits := signinHits.Load()

	// Second login: session is fresh — should not re-navigate.
	if err := c.Login(ctx); err != nil {
		t.Fatalf("second Login: %v", err)
	}

	// Signin page must not have been hit again.
	if got := signinHits.Load(); got != firstHits {
		t.Errorf("browser re-launched on second Login; signin page hit count went from %d to %d", firstHits, got)
	}
}

func TestBrowserBackend_LoginReusesWarmBrowserProfileSession(t *testing.T) {
	opts := newBrowserTestOpts(t)

	var signinHits, authHits, domainsHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		domainsHits.Add(1)
		if _, err := r.Cookie("__uzma"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"succeeded":false,"error_code":"login"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "domains": []map[string]any{}})
	})
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		signinHits.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "__uzma", Value: "fresh-from-signin", Path: "/"})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		authHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "status": "completed"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	seedBrowserProfileCookie(t, opts, srv.URL, "__uzma", "warm-session")

	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login with warm profile: %v", err)
	}
	if gotSignin, gotAuth := signinHits.Load(), authHits.Load(); gotSignin != 0 || gotAuth != 0 {
		t.Fatalf("warm profile should skip credential login; signinHits=%d authHits=%d", gotSignin, gotAuth)
	}
	if domainsHits.Load() == 0 {
		t.Fatal("warm profile login did not probe /api/domains")
	}
	c.mu.Lock()
	loggedAt := c.loggedAt
	c.mu.Unlock()
	if loggedAt.IsZero() {
		t.Fatal("loggedAt not set after warm profile reuse")
	}
}

func TestBrowserBackend_ProbeExistingSessionReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bb := newBrowserBackend(BrowserOptions{})
	bb.overrideHost = "http://127.0.0.1:1"
	c := &Client{
		http:      &http.Client{},
		UserAgent: defaultUserAgent,
	}

	ok, err := bb.probeExistingSession(ctx, c)
	if ok {
		t.Fatal("probeExistingSession unexpectedly reused a canceled session")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probeExistingSession error = %v, want context.Canceled", err)
	}
}

func TestBrowserBackend_ProbeExistingSessionReturnsContextCancellationFromBodyRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	bb := newBrowserBackend(BrowserOptions{})
	bb.overrideHost = "https://example.test"
	c := &Client{
		http: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       &cancelAfterPartialJSONBody{cancel: cancel},
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
		UserAgent: defaultUserAgent,
	}

	ok, err := bb.probeExistingSession(ctx, c)
	if ok {
		t.Fatal("probeExistingSession unexpectedly reused a canceled session")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probeExistingSession error = %v, want context.Canceled", err)
	}
}

func TestBrowserBackend_LoginFallsBackWhenWarmProfileUnauthenticated(t *testing.T) {
	opts := newBrowserTestOpts(t)

	var signinHits, authHits, domainsHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		domainsHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"succeeded":false,"error_code":"login"}`))
	})
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		signinHits.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "__uzma", Value: "fresh-from-signin", Path: "/"})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		authHits.Add(1)
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
		t.Fatalf("Login after stale warm profile probe: %v", err)
	}
	if domainsHits.Load() == 0 {
		t.Fatal("stale profile login did not probe /api/domains before fallback")
	}
	if gotSignin, gotAuth := signinHits.Load(), authHits.Load(); gotSignin == 0 || gotAuth == 0 {
		t.Fatalf("stale profile should fall back to credential login; signinHits=%d authHits=%d", gotSignin, gotAuth)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type cancelAfterPartialJSONBody struct {
	cancel context.CancelFunc
	sent   bool
}

func (b *cancelAfterPartialJSONBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, `{"succeeded":`), nil
	}
	b.cancel()
	return 0, context.Canceled
}

func (b *cancelAfterPartialJSONBody) Close() error {
	return nil
}

func seedBrowserProfileCookie(t *testing.T, opts BrowserOptions, baseURL, name, value string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	browser, launcher, err := launchBrowserWithHandles(ctx, opts)
	if err != nil {
		t.Fatalf("launch browser to seed profile cookie: %v", err)
	}
	defer launcher.Kill()
	defer func() { _ = browser.Close() }()

	if err := browser.Context(ctx).SetCookies([]*proto.NetworkCookieParam{{
		Name:    name,
		Value:   value,
		URL:     baseURL,
		Path:    "/",
		Expires: proto.TimeSinceEpoch(time.Now().Add(2 * time.Hour).Unix()),
	}}); err != nil {
		t.Fatalf("seed browser profile cookie: %v", err)
	}
}

// TestBrowserBackend_OverrideHostRespected is a compile-time check that
// overrideHost field exists on browserBackend (used by all local tests above).
func TestBrowserBackend_OverrideHostRespected(_ *testing.T) {
	bb := &browserBackend{}
	_ = bb.overrideHost
	_ = os.DevNull // suppress unused import warning
}
