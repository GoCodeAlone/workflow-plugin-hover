package hover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newStubClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	jar, _ := cookiejar.New(nil)
	httpc := &http.Client{
		Jar:       jar,
		Transport: rewriteTransport{base: srv.URL},
	}
	creds := Credentials{
		Username:   "alice",
		Password:   "pw",
		TOTPSecret: mustParse(t, rfc6238Secret),
	}
	c, err := NewClient(creds, httpc)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

type rewriteTransport struct{ base string }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = r.base[len("http://"):]
	return http.DefaultTransport.RoundTrip(clone)
}

func TestClient_Login_TwoStep_WithMFA(t *testing.T) {
	var hits []string
	var totpBody map[string]any
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/signin/auth.json":
			if r.Method != http.MethodPost {
				t.Errorf("auth method = %s, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "need_2fa", "type": "app"})
		case "/signin/auth2.json":
			if r.Method != http.MethodPost {
				t.Errorf("auth2 method = %s, want POST", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&totpBody); err != nil {
				t.Errorf("decode auth2 body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed"})
		default:
			t.Errorf("unexpected hit: %s %s", r.Method, r.URL.Path)
		}
	})
	defer srv.Close()

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	wantHits := []string{
		"POST /signin/auth.json",
		"POST /signin/auth2.json",
	}
	if len(hits) != len(wantHits) {
		t.Fatalf("hits = %v; want %v", hits, wantHits)
	}
	for i, want := range wantHits {
		if hits[i] != want {
			t.Errorf("hits[%d] = %q want %q", i, hits[i], want)
		}
	}

	if _, ok := totpBody["code"].(string); !ok {
		t.Errorf("TOTP POST missing code: %#v", totpBody)
	}
	if totpBody["remember"] != false {
		t.Errorf("TOTP POST remember = %#v, want false", totpBody["remember"])
	}
}

func TestClient_Login_NoMFA(t *testing.T) {
	var hits []string
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/signin/auth.json":
			if r.Method != http.MethodPost {
				t.Errorf("auth method = %s, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed"})
		case "/signin/auth2.json":
			t.Errorf("unexpected TOTP POST — account has no MFA")
		default:
			t.Errorf("unexpected hit: %s %s", r.Method, r.URL.Path)
		}
	})
	defer srv.Close()

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login (no-MFA): %v", err)
	}

	wantHits := []string{
		"POST /signin/auth.json",
	}
	if len(hits) != len(wantHits) {
		t.Fatalf("hits = %v; want %v", hits, wantHits)
	}
}

func TestClient_Login_UsesBrowserSigninShape(t *testing.T) {
	var authBody map[string]any
	var headers http.Header
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/signin/auth.json" {
			t.Errorf("unexpected hit: %s %s", r.Method, r.URL.Path)
			return
		}
		headers = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&authBody); err != nil {
			t.Errorf("decode auth body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed"})
	})
	defer srv.Close()

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, ok := authBody["token"]; !ok {
		t.Fatalf("auth body missing token field: %#v", authBody)
	}
	if got := headers.Get("Origin"); got != hoverHost {
		t.Errorf("Origin = %q, want %q", got, hoverHost)
	}
	if got := headers.Get("Referer"); got != hoverHost+"/signin" {
		t.Errorf("Referer = %q, want %q", got, hoverHost+"/signin")
	}
	if got := headers.Get("X-Requested-With"); got != "XMLHttpRequest" {
		t.Errorf("X-Requested-With = %q, want XMLHttpRequest", got)
	}
	if got := headers.Get("User-Agent"); !strings.Contains(got, "Mozilla/5.0") {
		t.Errorf("User-Agent = %q, want browser-like UA", got)
	}
}

func TestNewClient_NormalizesPastedSecretNewlines(t *testing.T) {
	c, err := NewClient(Credentials{
		Username: " alice@example.com \r\n",
		Password: "pw\r\n",
	}, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.creds.Username != "alice@example.com" {
		t.Errorf("username = %q, want trimmed address", c.creds.Username)
	}
	if c.creds.Password != "pw" {
		t.Errorf("password = %q, want newline-trimmed password", c.creds.Password)
	}
}

func TestClient_Login_SkipsWhenFresh(t *testing.T) {
	var hits int
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/signin/auth.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed"})
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	defer srv.Close()

	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstRound := hits
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits != firstRound {
		t.Errorf("second Login hit network; want cache hit. first=%d second=%d", firstRound, hits)
	}
}

func TestClient_LoginFailure_RaisesClearError(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"succeeded": false, "error": "Invalid username or password."})
	})
	defer srv.Close()

	err := c.Login(context.Background())
	if err == nil {
		t.Fatal("expected login error")
	}
	if !strings.Contains(err.Error(), "Invalid username or password") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestNewClient_RequiresCredentials(t *testing.T) {
	_, err := NewClient(Credentials{}, nil)
	if err == nil {
		t.Fatal("expected error on empty creds")
	}
}

// ── record API tests ──────────────────────────────────────────────────────────
//
// These tests share a single mux that handles both the login flow (no-MFA
// path) and the DNS record API endpoints.

// newRecordStub returns a stub server that handles the login flow (no-MFA)
// and invokes apiHandler for any path that starts with /api/.
func newRecordStub(t *testing.T, apiHandler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()

	// Login flow
	mux.HandleFunc("/signin/auth.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed"})
	})

	// API endpoints — delegate to caller.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiHandler(w, r)
	})

	srv := httptest.NewServer(mux)
	jar, _ := cookiejar.New(nil)
	httpc := &http.Client{
		Jar:       jar,
		Transport: rewriteTransport{base: srv.URL},
	}
	creds := Credentials{Username: "alice", Password: "pw"}
	c, err := NewClient(creds, httpc)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Force login eagerly so subsequent calls skip the login hit count.
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return c, srv
}

func TestClient_ListRecords(t *testing.T) {
	// Hover GET /api/domains/<domain>/dns response shape.
	// The client wraps the response in a {domains:[{domain_name, entries:[...]}]} envelope.
	respBody := `{
		"domains": [{
			"id": "dom1",
			"domain_name": "example.com",
			"entries": [
				{"id": "r1", "type": "A", "name": "@", "content": "1.2.3.4", "ttl": 300}
			]
		}]
	}`
	c, srv := newRecordStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/dns") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	defer srv.Close()

	recs, err := c.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].ID != "r1" || recs[0].Type != "A" || recs[0].Content != "1.2.3.4" {
		t.Errorf("unexpected record: %+v", recs[0])
	}
}

func TestClient_CreateRecord(t *testing.T) {
	var received map[string]string
	respBody := `{"dns_record": {"id": "newid", "type": "A", "name": "sub", "content": "5.5.5.5", "ttl": 300}}`
	c, srv := newRecordStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		_ = r.ParseForm()
		received = map[string]string{
			"domain_id": r.FormValue("domain_id"),
			"type":      r.FormValue("type"),
			"name":      r.FormValue("name"),
			"content":   r.FormValue("content"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	defer srv.Close()

	rec := DNSRecord{Type: "A", Name: "sub", Content: "5.5.5.5", TTL: 300}
	created, err := c.CreateRecord(context.Background(), "dom1", rec)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if created.ID != "newid" {
		t.Errorf("created.ID = %q want %q", created.ID, "newid")
	}
	if received["domain_id"] != "dom1" {
		t.Errorf("form domain_id = %q want %q", received["domain_id"], "dom1")
	}
	if received["content"] != "5.5.5.5" {
		t.Errorf("form content = %q want %q", received["content"], "5.5.5.5")
	}
}

func TestClient_UpdateRecord(t *testing.T) {
	var receivedContent string
	c, srv := newRecordStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		_ = r.ParseForm()
		receivedContent = r.FormValue("content")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	defer srv.Close()

	err := c.UpdateRecord(context.Background(), "r1", DNSRecord{Content: "9.9.9.9"})
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	if receivedContent != "9.9.9.9" {
		t.Errorf("content = %q want %q", receivedContent, "9.9.9.9")
	}
}

func TestClient_DeleteRecord(t *testing.T) {
	var deletedPath string
	c, srv := newRecordStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	defer srv.Close()

	err := c.DeleteRecord(context.Background(), "r1")
	if err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if !strings.HasSuffix(deletedPath, "/r1") {
		t.Errorf("deletedPath = %q; want suffix /r1", deletedPath)
	}
}

func TestEnsureLoginLocked_CallableUnderHeldLock(t *testing.T) {
	// Build a Client with a fresh loggedAt so ensureLoginLocked
	// short-circuits without making HTTP calls.
	c, err := NewClient(Credentials{Username: "u", Password: "p"}, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.loggedAt = time.Now() // skip the actual login
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureLoginLocked(context.Background()); err != nil {
		t.Errorf("ensureLoginLocked under held mu: %v", err)
	}
}

func TestFetchControlPanelCSRFLocked_ExtractsMetaToken(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control_panel/domain/example.com" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`<html><head>
<meta name="csrf-token" content="abc123xyz">
</head></html>`))
	})
	defer srv.Close()
	c.loggedAt = time.Now() // skip login

	c.mu.Lock()
	defer c.mu.Unlock()
	token, err := c.fetchControlPanelCSRFLocked(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("fetchControlPanelCSRFLocked: %v", err)
	}
	if token != "abc123xyz" {
		t.Errorf("token = %q, want abc123xyz", token)
	}
}

func TestFetchControlPanelCSRFLocked_MissingMetaTag(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head></head></html>`))
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.fetchControlPanelCSRFLocked(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error when meta tag absent")
	}
}

func TestFetchControlPanelCSRFLocked_Non2xx(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.fetchControlPanelCSRFLocked(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error on 403")
	}
}

func TestGetDomainDelegation_HappyPath(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/control_panel/domains/domain-example.com" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":"domain-example.com","domain_name":"example.com","nameservers":["ns1.do.com","ns2.do.com"]}`))
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	dom, err := c.GetDomainDelegation(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetDomainDelegation: %v", err)
	}
	if dom.ID != "domain-example.com" {
		t.Errorf("ID = %q", dom.ID)
	}
	if len(dom.Nameservers) != 2 {
		t.Errorf("Nameservers len = %d, want 2", len(dom.Nameservers))
	}
}

func TestGetDomainDelegation_EmptyNameserversReturnsSentinel(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"domain-example.com","domain_name":"example.com","nameservers":[]}`))
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	_, err := c.GetDomainDelegation(context.Background(), "example.com")
	if !errors.Is(err, ErrEmptyNameservers) {
		t.Fatalf("want ErrEmptyNameservers, got %v", err)
	}
}

func TestGetDomainDelegation_Non2xx(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	_, err := c.GetDomainDelegation(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error on 404")
	}
}

func TestSetNameservers_PUTShape(t *testing.T) {
	var capturedURL, capturedToken, capturedCT string
	var capturedBody []byte
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control_panel/domain/example.com":
			_, _ = w.Write([]byte(`<meta name="csrf-token" content="test-csrf-token">`))
		case "/api/control_panel/domains/domain-example.com":
			capturedURL = r.URL.Path
			capturedToken = r.Header.Get("X-CSRF-Token")
			capturedCT = r.Header.Get("Content-Type")
			capturedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	err := c.SetNameservers(context.Background(), "example.com", []string{"a.com", "b.com"})
	if err != nil {
		t.Fatalf("SetNameservers: %v", err)
	}
	if capturedURL != "/api/control_panel/domains/domain-example.com" {
		t.Errorf("URL = %q", capturedURL)
	}
	if capturedToken != "test-csrf-token" {
		t.Errorf("X-CSRF-Token = %q", capturedToken)
	}
	if !strings.HasPrefix(capturedCT, "application/json") {
		t.Errorf("Content-Type = %q", capturedCT)
	}
	var payload map[string]any
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("body decode: %v", err)
	}
	if payload["field"] != "nameservers" {
		t.Errorf("field = %v", payload["field"])
	}
	val, _ := payload["value"].([]any)
	if len(val) != 2 || val[0] != "a.com" || val[1] != "b.com" {
		t.Errorf("value = %v, want [a.com b.com]", payload["value"])
	}
}

func TestSetNameservers_Non2xxPUT(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/control_panel/domain/") {
			_, _ = w.Write([]byte(`<meta name="csrf-token" content="t">`))
			return
		}
		http.Error(w, "bad token", http.StatusUnprocessableEntity)
	})
	defer srv.Close()
	c.loggedAt = time.Now()

	err := c.SetNameservers(context.Background(), "example.com", []string{"a.com"})
	if err == nil {
		t.Fatal("expected error on 422")
	}
}

func TestDomainDelegation_JSONShape(t *testing.T) {
	// Tentative envelope per design A6: flat object, not wrapped.
	body := `{"id":"domain-example.com","domain_name":"example.com","nameservers":["a.com","b.com"]}`
	var d DomainDelegation
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.ID != "domain-example.com" {
		t.Errorf("ID = %q, want domain-example.com", d.ID)
	}
	if d.Name != "example.com" {
		t.Errorf("Name = %q, want example.com", d.Name)
	}
	if len(d.Nameservers) != 2 || d.Nameservers[0] != "a.com" || d.Nameservers[1] != "b.com" {
		t.Errorf("Nameservers = %v, want [a.com b.com]", d.Nameservers)
	}
}

func TestErrEmptyNameservers_IsSentinel(t *testing.T) {
	wrapped := fmt.Errorf("hover GetDomainDelegation: %w", ErrEmptyNameservers)
	if !errors.Is(wrapped, ErrEmptyNameservers) {
		t.Error("errors.Is should match ErrEmptyNameservers when wrapped")
	}
}

func TestClient_ListRecords_DomainNotFound(t *testing.T) {
	// API returns empty domains list — our client must return a clear error.
	respBody := `{"domains": []}`
	c, srv := newRecordStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	defer srv.Close()

	_, err := c.ListRecords(context.Background(), "notinaccount.com")
	if err == nil {
		t.Fatal("expected error for domain not in account")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractCSRFMeta_AttributeOrders(t *testing.T) {
	cases := []struct{ name, html, want string }{
		{"name-first double quotes", `<meta name="csrf-token" content="abc">`, "abc"},
		{"content-first double quotes", `<meta content="xyz" name="csrf-token">`, "xyz"},
		{"name-first single quotes", `<meta name='csrf-token' content='qqq'>`, "qqq"},
		{"content-first single quotes", `<meta content='zzz' name='csrf-token'>`, "zzz"},
		{"missing", `<meta name="other" content="nope">`, ""},
	}
	for _, tc := range cases {
		if got := extractCSRFMeta([]byte(tc.html)); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
