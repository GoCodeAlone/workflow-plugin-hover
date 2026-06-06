package hoverclient

// browser_backend_write_test.go — TDD tests for Task 4: browserBackend
// in-browser DNS write operations (hybrid write path).
//
// All tests drive real go-rod against a local httptest server (no real Hover
// connection). Chrome is required; tests are skipped via newBrowserTestOpts
// when no binary is found (CI-safe).
//
// Test names: TestBrowserBackend_CreateRecordInBrowser,
// TestBrowserBackend_UpdateRecordInBrowser,
// TestBrowserBackend_DeleteRecordInBrowser,
// TestBrowserBackend_SetNameserversInBrowser,
// TestBrowserBackend_SetNameserversRejectsEmpty.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWriteMux returns an http.ServeMux that handles:
//   - /signin, /signin/auth.json (fake successful login + clearance cookie)
//   - DNS write endpoints recording the last received request
//
// The recordedReqs map (method → recorded request info) is populated by the
// handlers. The control_panel page returns a fixed CSRF token.
func fakeWriteMux(t *testing.T) (*http.ServeMux, *writeRequestLog) {
	return fakeWriteMuxWithControlPanelHTML(t, `<html><head><meta name="csrf-token" content="test-csrf-abc"></head></html>`)
}

func fakeWriteMuxWithControlPanelHTML(t *testing.T, controlPanelHTML string) (*http.ServeMux, *writeRequestLog) {
	t.Helper()
	log := &writeRequestLog{}
	mux := http.NewServeMux()

	// Signin page — set clearance cookie so waitForClearanceCookies passes.
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__uzma", Value: "fake-clearance", Path: "/"})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "status": "completed"})
	})

	// CreateRecord: POST /api/dns
	mux.HandleFunc("/api/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			log.record(r)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dns_record": map[string]any{
					"id":      "newid123",
					"type":    "A",
					"name":    "sub",
					"content": "5.5.5.5",
					"ttl":     300,
				},
			})
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// UpdateRecord + DeleteRecord: PUT/DELETE /api/dns/<recordID>
	mux.HandleFunc("/api/dns/", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	// SetNameservers CSRF page: GET /control_panel/domain/<name>
	mux.HandleFunc("/control_panel/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(controlPanelHTML))
	})

	// SetNameservers PUT: /api/control_panel/domains/<domain>
	mux.HandleFunc("/api/control_panel/", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	return mux, log
}

func fakeWriteMuxRequiringCookie(t *testing.T, controlPanelHTML, cookieName string) (*http.ServeMux, *writeRequestLog) {
	t.Helper()
	log := &writeRequestLog{}
	mux := http.NewServeMux()

	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "fake-session", Path: "/", HttpOnly: true})
		_, _ = w.Write([]byte(`<html><body>signin</body></html>`))
	})
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": true, "status": "completed"})
	})
	mux.HandleFunc("/control_panel/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(controlPanelHTML))
	})
	mux.HandleFunc("/api/control_panel/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(cookieName); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"succeeded":false,"error_code":"login","error":"You must login first"}`))
			return
		}
		log.record(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	return mux, log
}

// writeRequestLog captures the last recorded HTTP request (method, path, body,
// headers) across all write endpoints. Thread-safe.
type writeRequestLog struct {
	mu      sync.Mutex
	entries []capturedRequest
}

type capturedRequest struct {
	Method string
	Path   string
	Body   []byte
	Header http.Header
}

func (l *writeRequestLog) record(r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, capturedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   body,
		Header: r.Header.Clone(),
	})
}

// last returns the last captured request, or zero if none.
func (l *writeRequestLog) last() (capturedRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return capturedRequest{}, false
	}
	return l.entries[len(l.entries)-1], true
}

// firstMatching returns the first captured request whose Method matches, or
// zero if none. Useful when multiple requests are captured (e.g. login + write).
func (l *writeRequestLog) firstMatching(method, pathSuffix string) (capturedRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.Method == method && strings.HasSuffix(e.Path, pathSuffix) {
			return e, true
		}
	}
	return capturedRequest{}, false
}

// newWriteBrowserClient creates a logged-in browser client wired to srv.
// It performs a Login so the browser page is ready and loggedAt is set.
func newWriteBrowserClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	opts := newBrowserTestOpts(t)
	creds := Credentials{Username: "alice", Password: "pw"}
	c := newBrowserClient(t, opts, srv.URL, creds)
	t.Cleanup(func() { _ = c.backend.(interface{ Close() error }).Close() })

	// Wire the HTTP client transport so HTTP-path calls (reads) also reach srv.
	c.http.Transport = rewriteTransport{base: srv.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return c
}

// --------------------------------------------------------------------------
// TestBrowserBackend_CreateRecordInBrowser
// --------------------------------------------------------------------------

// TestBrowserBackend_CreateRecordInBrowser verifies that CreateRecord on the
// browser backend sends a POST to /api/dns in-page (not via Go http.Client),
// with the correct form-encoded payload, and returns the parsed DNSRecord.
func TestBrowserBackend_CreateRecordInBrowser(t *testing.T) {
	mux, log := fakeWriteMux(t)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newWriteBrowserClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rec := DNSRecord{Type: "A", Name: "sub", Content: "5.5.5.5", TTL: 300}
	created, err := c.CreateRecord(ctx, "dom1", rec)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if created.ID != "newid123" {
		t.Errorf("created.ID = %q, want %q", created.ID, "newid123")
	}
	if created.Content != "5.5.5.5" {
		t.Errorf("created.Content = %q, want %q", created.Content, "5.5.5.5")
	}

	// Verify the in-page fetch reached the server.
	req, ok := log.firstMatching(http.MethodPost, "/api/dns")
	if !ok {
		t.Fatal("POST /api/dns not observed by server")
	}

	// Body must contain the form fields (application/x-www-form-urlencoded or
	// a JSON-encoded object from in-page fetch — check both shapes).
	bodyStr := string(req.Body)
	if strings.Contains(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		vals, _ := url.ParseQuery(bodyStr)
		if vals.Get("domain_id") != "dom1" {
			t.Errorf("form domain_id = %q, want %q", vals.Get("domain_id"), "dom1")
		}
		if vals.Get("type") != "A" {
			t.Errorf("form type = %q, want A", vals.Get("type"))
		}
		if vals.Get("name") != "sub" {
			t.Errorf("form name = %q, want sub", vals.Get("name"))
		}
		if vals.Get("content") != "5.5.5.5" {
			t.Errorf("form content = %q, want 5.5.5.5", vals.Get("content"))
		}
	} else {
		// JSON body: allow both shapes for test robustness.
		if !strings.Contains(bodyStr, "dom1") {
			t.Errorf("body missing domain_id: %q", bodyStr)
		}
		if !strings.Contains(bodyStr, "5.5.5.5") {
			t.Errorf("body missing content: %q", bodyStr)
		}
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_UpdateRecordInBrowser
// --------------------------------------------------------------------------

// TestBrowserBackend_UpdateRecordInBrowser verifies that UpdateRecord on the
// browser backend sends a PUT to /api/dns/<recordID> in-page, with content
// (and optionally ttl) in the body.
func TestBrowserBackend_UpdateRecordInBrowser(t *testing.T) {
	mux, log := fakeWriteMux(t)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newWriteBrowserClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := c.UpdateRecord(ctx, "rec456", DNSRecord{Content: "9.9.9.9", TTL: 600})
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	req, ok := log.firstMatching(http.MethodPut, "/api/dns/rec456")
	if !ok {
		t.Fatal("PUT /api/dns/rec456 not observed by server")
	}

	bodyStr := string(req.Body)
	if strings.Contains(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		vals, _ := url.ParseQuery(bodyStr)
		if vals.Get("content") != "9.9.9.9" {
			t.Errorf("form content = %q, want 9.9.9.9", vals.Get("content"))
		}
	} else {
		if !strings.Contains(bodyStr, "9.9.9.9") {
			t.Errorf("body missing content 9.9.9.9: %q", bodyStr)
		}
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_DeleteRecordInBrowser
// --------------------------------------------------------------------------

// TestBrowserBackend_DeleteRecordInBrowser verifies that DeleteRecord on the
// browser backend sends a DELETE to /api/dns/<recordID> in-page.
func TestBrowserBackend_DeleteRecordInBrowser(t *testing.T) {
	mux, log := fakeWriteMux(t)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newWriteBrowserClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := c.DeleteRecord(ctx, "rec789")
	if err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	req, ok := log.firstMatching(http.MethodDelete, "/api/dns/rec789")
	if !ok {
		t.Fatal("DELETE /api/dns/rec789 not observed by server")
	}
	if req.Method != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", req.Method)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_SetNameserversInBrowser
// --------------------------------------------------------------------------

// TestBrowserBackend_SetNameserversInBrowser verifies that SetNameservers on
// the browser backend:
//  1. Fetches the CSRF token in-browser from /control_panel/domain/<name>.
//  2. PUTs to /api/control_panel/domains/domain-<name> with the nameservers
//     payload and X-CSRF-Token header.
func TestBrowserBackend_SetNameserversInBrowser(t *testing.T) {
	mux, log := fakeWriteMux(t)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newWriteBrowserClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := []string{"ns1.example.com", "ns2.example.com"}
	err := c.SetNameservers(ctx, "example.com", ns)
	if err != nil {
		t.Fatalf("SetNameservers: %v", err)
	}

	req, ok := log.firstMatching(http.MethodPut, "/api/control_panel/domains/domain-example.com")
	if !ok {
		t.Fatal("PUT /api/control_panel/domains/domain-example.com not observed by server")
	}

	// Must carry X-CSRF-Token from the control_panel page.
	csrfToken := req.Header.Get("X-CSRF-Token")
	if csrfToken != "test-csrf-abc" {
		t.Errorf("X-CSRF-Token = %q, want test-csrf-abc", csrfToken)
	}

	// Payload must contain field=nameservers + value=[ns1, ns2].
	var payload map[string]any
	if err := json.Unmarshal(req.Body, &payload); err != nil {
		t.Fatalf("decode PUT body: %v (raw: %q)", err, req.Body)
	}
	if payload["field"] != "nameservers" {
		t.Errorf("field = %v, want nameservers", payload["field"])
	}
	valSlice, ok := payload["value"].([]any)
	if !ok {
		t.Fatalf("value not []any: %T %v", payload["value"], payload["value"])
	}
	if len(valSlice) != 2 {
		t.Fatalf("value len = %d, want 2", len(valSlice))
	}
	if valSlice[0] != "ns1.example.com" || valSlice[1] != "ns2.example.com" {
		t.Errorf("value = %v, want [ns1.example.com ns2.example.com]", valSlice)
	}
}

func TestBrowserBackend_SetNameserversInBrowserWithoutCSRFMeta(t *testing.T) {
	mux, log := fakeWriteMuxWithControlPanelHTML(t, `<html><head><title>domain</title></head><body>no csrf meta</body></html>`)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newWriteBrowserClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := []string{"ns1.example.com", "ns2.example.com"}
	if err := c.SetNameservers(ctx, "example.com", ns); err != nil {
		t.Fatalf("SetNameservers without CSRF meta: %v", err)
	}

	req, ok := log.firstMatching(http.MethodPut, "/api/control_panel/domains/domain-example.com")
	if !ok {
		t.Fatal("PUT /api/control_panel/domains/domain-example.com not observed by server")
	}
	if got := req.Header.Get("X-CSRF-Token"); got != "" {
		t.Errorf("X-CSRF-Token = %q, want empty when control panel has no CSRF meta", got)
	}
}

func TestBrowserBackend_SetNameserversSyncsJarCookiesToBrowser(t *testing.T) {
	const sessionCookie = "__uzma"
	mux, log := fakeWriteMuxRequiringCookie(t, `<html><head><title>domain</title></head><body>no csrf meta</body></html>`, sessionCookie)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newWriteBrowserClient(t, srv)
	bb := c.backend.(*browserBackend)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := bb.browser.Context(ctx).SetCookies(nil); err != nil {
		t.Fatalf("clear browser cookies: %v", err)
	}

	ns := []string{"ns1.example.com", "ns2.example.com"}
	if err := c.SetNameservers(ctx, "example.com", ns); err != nil {
		t.Fatalf("SetNameservers after browser cookie loss: %v", err)
	}

	req, ok := log.firstMatching(http.MethodPut, "/api/control_panel/domains/domain-example.com")
	if !ok {
		t.Fatal("PUT /api/control_panel/domains/domain-example.com not observed by server")
	}
	if _, err := (&http.Request{Header: req.Header}).Cookie(sessionCookie); err != nil {
		t.Fatalf("PUT missing synced %s cookie: %v", sessionCookie, err)
	}
}

// --------------------------------------------------------------------------
// TestBrowserBackend_SetNameserversRejectsEmpty
// --------------------------------------------------------------------------

// TestBrowserBackend_SetNameserversRejectsEmpty verifies that SetNameservers
// with an empty slice returns ErrEmptyNameservers before touching the network.
func TestBrowserBackend_SetNameserversRejectsEmpty(t *testing.T) {
	// No Chrome needed — this must fail before any network call.
	opts := BrowserOptions{
		Download:   false,
		Headless:   true,
		ProfileDir: t.TempDir(),
		Timeout:    10 * time.Second,
	}
	bb := newBrowserBackend(opts)
	// Mark as logged in so ensureLogin doesn't try to launch Chrome.
	c, err := NewClientWithOptions(Credentials{Username: "u", Password: "p"}, nil, ClientOptions{Browser: opts})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}
	c.mu.Lock()
	c.loggedAt = time.Now()
	c.mu.Unlock()

	ctx := context.Background()
	err = bb.SetNameservers(ctx, c, "example.com", []string{})
	if err == nil {
		t.Fatal("expected error for empty nameservers")
	}
	if !errors.Is(err, ErrEmptyNameservers) {
		t.Errorf("expected ErrEmptyNameservers, got: %v", err)
	}
}
