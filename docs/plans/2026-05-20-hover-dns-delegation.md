# Hover DNS Delegation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `infra.dns_delegation` resource type to workflow-plugin-hover so wfctl can set a domain's registrar-level nameservers via the Hover control-panel API.

**Architecture:** New `DelegationDriver` in `internal/drivers/delegation.go`, registered alongside the existing `DNSDriver` in `internal/provider.go`. Adds three control-panel methods to `internal/hover/client.go` (`GetDomainDelegation`, `SetNameservers`, plus the `fetchControlPanelCSRFLocked` helper). A new `DomainDelegation` type isolates the control-panel response shape from the existing `Domain`. Lock discipline: `SetNameservers` holds `c.mu` across the entire auth → CSRF → PUT sequence to eliminate the round-2 TOCTOU window.

**Tech Stack:** Go 1.21+; standard library only (no new third-party deps); reuses existing `regexp`, `net/http`, `encoding/json`, `sync`. gRPC plugin SDK via `github.com/GoCodeAlone/workflow`.

**Base branch:** main (working branch: `feat/dns-delegation` — already created)

**Design reference:** `docs/plans/2026-05-20-hover-dns-delegation-design.md` (PASSed 3 adversarial review rounds; round-3 doc clarifications applied inline).

---

## Scope Manifest

**PR Count:** 1
**Tasks:** 13
**Estimated Lines of Change:** ~600 (client extensions + new driver + tests + provider wiring + plugin.json)

**Out of scope:**
- workflow-registry manifest bump for v0.2.0 (deferred session; cannot author until goreleaser publishes asset SHAs).
- gocodealone-multisite `config/dns.wfctl.yaml` + `.github/workflows/dns-delegation.yml` (deferred session; gated on registry manifest carrying v0.2.0).
- Live field-test against gocodealone.tech via `workflow_dispatch` (deferred session; gated on the two artifacts above).
- The other domain-level fields the Hover endpoint accepts (`whois_privacy`, `auto_renew`, `locked`) — YAGNI; only `nameservers` is in scope.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | feat: infra.dns_delegation resource type (v0.2.0) | Task 1, Task 2, Task 3, Task 4, Task 5, Task 6, Task 7, Task 8, Task 9, Task 10, Task 11, Task 12, Task 13 | feat/dns-delegation |

**Status:** Draft

---

### Task 1: Add `DomainDelegation` type and `ErrEmptyNameservers` sentinel

**Files:**
- Modify: `internal/hover/client.go` — extend with type + var declarations

**Step 1: Write the failing test**

Add to `internal/hover/client_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jon/workspace/workflow-plugin-hover && GOWORK=off go test ./internal/hover -run "TestDomainDelegation_JSONShape|TestErrEmptyNameservers_IsSentinel" -v`
Expected: FAIL with `undefined: DomainDelegation` and `undefined: ErrEmptyNameservers`.

**Step 3: Write minimal implementation**

Add to `internal/hover/client.go` (near the existing `Domain` struct):

```go
// DomainDelegation is the response shape of GET /api/control_panel/domains/domain-<name>.
// Distinct from Domain (which represents the /api/domains/<name>/dns shape with Records)
// to avoid ambiguity over which fields are populated by which endpoint.
//
// Tentative envelope per design A6: flat object, not wrapped in {"domains":[...]}.
// First field-test call must confirm this shape; if Hover returns a different envelope
// the implementer pauses and amends the design before proceeding.
type DomainDelegation struct {
	ID          string   `json:"id"`
	Name        string   `json:"domain_name"`
	Nameservers []string `json:"nameservers"`
}

// ErrEmptyNameservers is returned by GetDomainDelegation when the parsed
// response has zero nameservers. Converts the silent-thrash failure mode
// (empty → Diff says NeedsUpdate forever → re-PUT loop) into a loud,
// single-iteration error visible at the first wfctl plan.
var ErrEmptyNameservers = errors.New("hover: delegation read returned 0 nameservers (verify field shape)")
```

**Step 4: Run test to verify it passes**

Run: `GOWORK=off go test ./internal/hover -run "TestDomainDelegation_JSONShape|TestErrEmptyNameservers_IsSentinel" -v`
Expected: PASS for both tests.

**Step 5: Commit**

```bash
git add internal/hover/client.go internal/hover/client_test.go
git commit -m "feat(hover): DomainDelegation type + ErrEmptyNameservers sentinel"
```

---

### Task 2: Refactor `ensureLogin` into `ensureLogin` + `ensureLoginLocked`

**Files:**
- Modify: `internal/hover/client.go:82-133` — split lock-acquisition from body

**Step 1: Write the failing test**

Add to `internal/hover/client_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/hover -run TestEnsureLoginLocked_CallableUnderHeldLock -v`
Expected: FAIL with `undefined: ensureLoginLocked`.

**Step 3: Write minimal implementation**

Refactor `internal/hover/client.go`:

```go
// ensureLogin re-authenticates iff the session is stale. Safe to call
// before every API hit; idempotent within sessionStaleAfter.
//
// Acquires c.mu internally. Callers that already hold the lock must
// call ensureLoginLocked instead.
func (c *Client) ensureLogin(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureLoginLocked(ctx)
}

// ensureLoginLocked is the implementation of ensureLogin without the lock
// acquisition. Caller MUST hold c.mu. Used by SetNameservers which holds
// c.mu across the full auth → CSRF → PUT sequence to eliminate the
// TOCTOU window between auth-check and PUT.
func (c *Client) ensureLoginLocked(ctx context.Context) error {
	if !c.loggedAt.IsZero() && time.Since(c.loggedAt) < sessionStaleAfter {
		return nil
	}
	// (existing body of ensureLogin, minus the lock acquisition)
	csrf, err := c.fetchSignInCSRF(ctx)
	// ... (rest of the existing login flow)
}
```

Move every line currently inside `ensureLogin` after `c.mu.Lock()` into `ensureLoginLocked`. The public `ensureLogin` becomes a 3-line wrapper.

**Step 4: Run all hover tests to verify no regression**

Run: `GOWORK=off go test ./internal/hover -count=1 -v`
Expected: PASS for all existing tests + `TestEnsureLoginLocked_CallableUnderHeldLock`.

**Step 5: Commit**

```bash
git add internal/hover/client.go internal/hover/client_test.go
git commit -m "refactor(hover): split ensureLogin into Locked variant"
```

---

### Task 3: Add `csrfMetaRe` regex + `fetchControlPanelCSRFLocked` helper

**Files:**
- Modify: `internal/hover/client.go` — add regex var + method

**Step 1: Write the failing test**

Add to `internal/hover/client_test.go`:

```go
func TestFetchControlPanelCSRFLocked_ExtractsMetaToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control_panel/domain/example.com" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`<html><head>
<meta name="csrf-token" content="abc123xyz">
</head></html>`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head></head></html>`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.fetchControlPanelCSRFLocked(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error when meta tag absent")
	}
}

func TestFetchControlPanelCSRFLocked_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.fetchControlPanelCSRFLocked(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error on 403")
	}
}
```

If `newTestClient` doesn't exist yet, add a helper (still in `client_test.go`):

```go
// newTestClient builds a Client that points at a httptest server URL by
// monkey-patching hoverHost via a package-level test override.
func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	// Use a fresh Client and point its http.Client at the test server via
	// a custom transport that rewrites the request URL host.
	c, err := NewClient(Credentials{Username: "u", Password: "p"}, &http.Client{
		Transport: &rewritingTransport{base: baseURL},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.loggedAt = time.Now() // skip login
	return c
}

type rewritingTransport struct{ base string }

func (rt *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(rt.base + req.URL.Path)
	if err != nil {
		return nil, err
	}
	target.RawQuery = req.URL.RawQuery
	req.URL = target
	req.Host = target.Host
	return http.DefaultTransport.RoundTrip(req)
}
```

If a similar helper already exists in `internal/hover/client_test.go` (likely — check existing tests), reuse it.

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/hover -run "TestFetchControlPanelCSRFLocked" -v`
Expected: FAIL — `undefined: fetchControlPanelCSRFLocked`.

**Step 3: Write minimal implementation**

Add to `internal/hover/client.go`:

```go
// csrfMetaRe extracts the Rails CSRF meta token from a control-panel HTML
// page. Distinct from csrfRe (form-token regex used by the /signin flow)
// because the control-panel pages embed the token as a meta tag for the
// SPA layer to read, while /signin embeds it as a hidden input.
//
// Both shapes coexist in the Hover-served HTML; we match each from the
// page where it's authoritative.
var csrfMetaRe = regexp.MustCompile(`<meta\s+name="csrf-token"\s+content="([^"]+)"`)

// fetchControlPanelCSRFLocked retrieves the meta-tag CSRF token from
// /control_panel/domain/<name>. Caller MUST hold c.mu (so the HTTP GET
// and any subsequent PUT execute against the same session-cookie state).
func (c *Client) fetchControlPanelCSRFLocked(ctx context.Context, domainName string) (string, error) {
	endpoint := fmt.Sprintf("%s/control_panel/domain/%s", hoverHost, url.PathEscape(domainName))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("hover: fetch control_panel CSRF for %q: %w", domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("hover: fetch control_panel CSRF for %q: HTTP %d: %s", domainName, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("hover: fetch control_panel CSRF for %q: read body: %w", domainName, err)
	}
	m := csrfMetaRe.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("hover: CSRF meta tag not found at /control_panel/domain/%s (control_panel UI changed?)", domainName)
	}
	return string(m[1]), nil
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/hover -run "TestFetchControlPanelCSRFLocked" -v`
Expected: PASS for all three subtests.

**Step 5: Commit**

```bash
git add internal/hover/client.go internal/hover/client_test.go
git commit -m "feat(hover): fetchControlPanelCSRFLocked + csrfMetaRe regex"
```

---

### Task 4: Add `GetDomainDelegation` method

**Files:**
- Modify: `internal/hover/client.go` — add method

**Step 1: Write the failing test**

```go
func TestGetDomainDelegation_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/control_panel/domains/domain-example.com" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":"domain-example.com","domain_name":"example.com","nameservers":["ns1.do.com","ns2.do.com"]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"domain-example.com","domain_name":"example.com","nameservers":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.GetDomainDelegation(context.Background(), "example.com")
	if !errors.Is(err, ErrEmptyNameservers) {
		t.Fatalf("want ErrEmptyNameservers, got %v", err)
	}
}

func TestGetDomainDelegation_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.GetDomainDelegation(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error on 404")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/hover -run TestGetDomainDelegation -v`
Expected: FAIL — `undefined: GetDomainDelegation`.

**Step 3: Write minimal implementation**

Add to `internal/hover/client.go`:

```go
// GetDomainDelegation fetches the registrar-level nameserver delegation for
// the named domain via the control-panel API (same endpoint family as the
// PUT used by SetNameservers — more likely to surface nameservers reliably
// than the DNS-records-oriented /api/domains/<name>/dns endpoint).
//
// Returns ErrEmptyNameservers if the parsed response has zero nameservers.
// This loud-on-empty behavior is intentional: it converts the silent
// re-apply thrash failure mode (empty → Diff says NeedsUpdate forever)
// into a single-iteration error visible at first wfctl plan.
func (c *Client) GetDomainDelegation(ctx context.Context, domainName string) (*DomainDelegation, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/control_panel/domains/domain-%s", hoverHost, url.PathEscape(domainName))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: %w", domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: HTTP %d: %s", domainName, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var d DomainDelegation
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: decode: %w", domainName, err)
	}
	if len(d.Nameservers) == 0 {
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: %w", domainName, ErrEmptyNameservers)
	}
	return &d, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/hover -run TestGetDomainDelegation -v`
Expected: PASS for all three subtests.

**Step 5: Commit**

```bash
git add internal/hover/client.go internal/hover/client_test.go
git commit -m "feat(hover): GetDomainDelegation method (loud on empty)"
```

---

### Task 5: Add `SetNameservers` method (lock-held across full sequence)

**Files:**
- Modify: `internal/hover/client.go` — add method + putNameserversLocked helper

**Step 1: Write the failing test**

```go
func TestSetNameservers_PUTShape(t *testing.T) {
	var capturedURL, capturedToken, capturedCT string
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/control_panel/domain/") {
			_, _ = w.Write([]byte(`<meta name="csrf-token" content="t">`))
			return
		}
		http.Error(w, "bad token", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	err := c.SetNameservers(context.Background(), "example.com", []string{"a.com"})
	if err == nil {
		t.Fatal("expected error on 422")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/hover -run TestSetNameservers -v`
Expected: FAIL — `undefined: SetNameservers`.

**Step 3: Write minimal implementation**

Add to `internal/hover/client.go`:

```go
// SetNameservers updates the registrar-level nameservers for a domain via
// Hover's control-panel API.
//
// Lock discipline: holds c.mu for the entire auth → CSRF fetch → PUT
// sequence. This eliminates the TOCTOU window between auth-check and
// PUT (another goroutine cannot re-auth and invalidate the CSRF token
// between the two requests).
//
// Trade-off: any concurrent caller using the same *Client blocks for
// up to ~60s (two HTTP round-trips under the 30s default client timeout).
// Acceptable for the field-test scope (single goroutine, one delegation
// resource). Future: cache CSRF at session granularity if mixed-resource
// throughput becomes a concern.
func (c *Client) SetNameservers(ctx context.Context, domainName string, ns []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureLoginLocked(ctx); err != nil {
		return err
	}
	csrf, err := c.fetchControlPanelCSRFLocked(ctx, domainName)
	if err != nil {
		return err
	}
	return c.putNameserversLocked(ctx, domainName, ns, csrf)
}

// putNameserversLocked PUTs the nameservers list. Caller MUST hold c.mu.
func (c *Client) putNameserversLocked(ctx context.Context, domainName string, ns []string, csrf string) error {
	endpoint := fmt.Sprintf("%s/api/control_panel/domains/domain-%s", hoverHost, url.PathEscape(domainName))
	payload := map[string]any{"field": "nameservers", "value": ns}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("hover: SetNameservers %q: marshal: %w", domainName, err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hover: SetNameservers %q: %w", domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hover: SetNameservers %q: HTTP %d: %s", domainName, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
```

Add `"bytes"` to imports if not already present.

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/hover -run TestSetNameservers -count=1 -v`
Expected: PASS.

Then re-run the full hover suite to confirm no regression:
Run: `GOWORK=off go test ./internal/hover -count=1`
Expected: ok (all tests pass).

**Step 5: Commit**

```bash
git add internal/hover/client.go internal/hover/client_test.go
git commit -m "feat(hover): SetNameservers + putNameserversLocked"
```

---

### Task 6: Create `DelegationDriver` skeleton + `HoverDelegationClient` interface

**Files:**
- Create: `internal/drivers/delegation.go`

**Step 1: Write the failing test**

Create `internal/drivers/delegation_test.go`:

```go
package drivers

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
)

type fakeDelegationClient struct {
	getResult *hover.DomainDelegation
	getErr    error
	setErr    error
	lastSetNS []string
}

func (f *fakeDelegationClient) GetDomainDelegation(_ context.Context, _ string) (*hover.DomainDelegation, error) {
	return f.getResult, f.getErr
}

func (f *fakeDelegationClient) SetNameservers(_ context.Context, _ string, ns []string) error {
	f.lastSetNS = append([]string(nil), ns...)
	return f.setErr
}

func TestDelegationDriver_TypeAndProviderIDFormat(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	if got := d.Type(); got != "infra.dns_delegation" {
		t.Errorf("Type() = %q, want infra.dns_delegation", got)
	}
	if got := d.ProviderIDFormat(); got != interfaces.IDFormatDomainName {
		t.Errorf("ProviderIDFormat() = %v, want IDFormatDomainName", got)
	}
	if d.SensitiveKeys() != nil {
		t.Errorf("SensitiveKeys() = %v, want nil", d.SensitiveKeys())
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/drivers -run TestDelegationDriver_TypeAndProviderIDFormat -v`
Expected: FAIL — `undefined: NewDelegationDriverWithClient`.

**Step 3: Write minimal implementation**

Create `internal/drivers/delegation.go`:

```go
// Package-doc additions in this file are scoped to the dns_delegation
// driver. See dns.go for the prior infra.dns driver.
package drivers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
)

// HoverDelegationClient is the subset of *hover.Client that DelegationDriver
// depends on. Injectable for tests.
type HoverDelegationClient interface {
	GetDomainDelegation(ctx context.Context, domain string) (*hover.DomainDelegation, error)
	SetNameservers(ctx context.Context, domain string, ns []string) error
}

// DelegationDriver manages registrar-level nameserver delegation
// (infra.dns_delegation) for Hover-registered domains.
//
// ProviderID = apex domain name (e.g. "example.com"). One resource = one
// domain. Outputs include the desired nameservers as []any (structpb-safe)
// and a stashed previous_nameservers list captured at Create time for
// Delete-restoration.
type DelegationDriver struct {
	client HoverDelegationClient
}

// NewDelegationDriver returns a DelegationDriver bound to a real *hover.Client.
func NewDelegationDriver(c *hover.Client) *DelegationDriver {
	return &DelegationDriver{client: c}
}

// NewDelegationDriverWithClient returns a DelegationDriver bound to an
// injected client; used by tests.
func NewDelegationDriverWithClient(c HoverDelegationClient) *DelegationDriver {
	return &DelegationDriver{client: c}
}

func (d *DelegationDriver) Type() string { return "infra.dns_delegation" }

func (d *DelegationDriver) SensitiveKeys() []string { return nil }

func (d *DelegationDriver) ProviderIDFormat() interfaces.ProviderIDFormat {
	return interfaces.IDFormatDomainName
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/drivers -run TestDelegationDriver_TypeAndProviderIDFormat -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/drivers/delegation.go internal/drivers/delegation_test.go
git commit -m "feat(drivers): DelegationDriver skeleton + interface"
```

---

### Task 7: Implement `DelegationDriver.Create` + `parseDelegationSpec` + `nameserversToAny`

**Files:**
- Modify: `internal/drivers/delegation.go`

**Step 1: Write the failing test**

Append to `internal/drivers/delegation_test.go`:

```go
func TestDelegationDriver_Create_CallsSetNameservers(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID:          "domain-example.com",
			Name:        "example.com",
			Nameservers: []string{"ns1.hover.com", "ns2.hover.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"ns1.do.com", "ns2.do.com", "ns3.do.com"},
		},
	}
	out, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if fc.lastSetNS == nil || len(fc.lastSetNS) != 3 {
		t.Errorf("client.SetNameservers not called with 3 NS; got %v", fc.lastSetNS)
	}
	if out.ProviderID != "example.com" {
		t.Errorf("ProviderID = %q", out.ProviderID)
	}
	// Outputs.nameservers MUST be []any, not []string (structpb-safe).
	nsRaw, ok := out.Outputs["nameservers"]
	if !ok {
		t.Fatal("Outputs.nameservers missing")
	}
	nsAny, ok := nsRaw.([]any)
	if !ok {
		t.Fatalf("Outputs.nameservers = %T, want []any", nsRaw)
	}
	if len(nsAny) != 3 {
		t.Errorf("Outputs.nameservers len = %d, want 3", len(nsAny))
	}
	// previous_nameservers stashed from Hover defaults
	prevRaw, ok := out.Outputs["previous_nameservers"]
	if !ok {
		t.Fatal("Outputs.previous_nameservers missing")
	}
	prevAny, _ := prevRaw.([]any)
	if len(prevAny) != 2 {
		t.Errorf("previous_nameservers len = %d, want 2", len(prevAny))
	}
}

func TestDelegationDriver_Create_MissingDomain_Rejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestDelegationDriver_Create_MissingNameservers_Rejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{"domain": "example.com"},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for missing nameservers")
	}
}

func TestDelegationDriver_Create_DuplicateNameservers_Rejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "a.com"},
		},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for duplicate nameservers")
	}
}

func TestDelegationDriver_Create_PreviousReadFails_Continues(t *testing.T) {
	// Best-effort pre-change read: failure is non-fatal.
	fc := &fakeDelegationClient{
		getErr: errors.New("read flaked"),
	}
	d := NewDelegationDriverWithClient(fc)
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	out, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create with read failure should still succeed: %v", err)
	}
	// previous_nameservers should be empty []any when read failed.
	prev, _ := out.Outputs["previous_nameservers"].([]any)
	if len(prev) != 0 {
		t.Errorf("previous_nameservers = %v, want empty when pre-read failed", prev)
	}
}
```

Add `"errors"` to the test imports if needed.

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/drivers -run TestDelegationDriver_Create -v`
Expected: FAIL — `undefined: d.Create` (or undefined parseDelegationSpec).

**Step 3: Write minimal implementation**

Append to `internal/drivers/delegation.go`:

```go
// dnsDelegationSpec is the parsed config view.
type dnsDelegationSpec struct {
	domain      string
	nameservers []string
}

// parseDelegationSpec validates config and produces a typed view.
func parseDelegationSpec(spec interfaces.ResourceSpec) (dnsDelegationSpec, error) {
	domain, _ := spec.Config["domain"].(string)
	if domain == "" {
		domain = spec.Name
	}
	if domain == "" {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation: config missing required key 'domain' (or spec.Name)")
	}
	rawNS, present := spec.Config["nameservers"]
	if !present {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: config missing required key 'nameservers'", domain)
	}
	nsList, ok := rawNS.([]any)
	if !ok {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: config 'nameservers' must be an array, got %T", domain, rawNS)
	}
	if len(nsList) < 1 {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: config 'nameservers' must have ≥1 entry", domain)
	}
	seen := make(map[string]struct{}, len(nsList))
	parsed := make([]string, 0, len(nsList))
	for i, item := range nsList {
		s, ok := item.(string)
		if !ok {
			return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: nameservers[%d] must be a string, got %T", domain, i, item)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: nameservers[%d] must be non-empty", domain, i)
		}
		if _, dup := seen[s]; dup {
			return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: nameservers[%d] = %q is a duplicate", domain, i, s)
		}
		seen[s] = struct{}{}
		parsed = append(parsed, s)
	}
	return dnsDelegationSpec{domain: domain, nameservers: parsed}, nil
}

// nameserversToAny converts []string to []any. Required for Outputs values
// to round-trip through structpb (typed slices are rejected; see iacserver.go
// package doc and the workspace structpb-boundary feedback memory).
func nameserversToAny(ns []string) []any {
	out := make([]any, len(ns))
	for i, s := range ns {
		out[i] = s
	}
	return out
}

// delegationOutput builds the ResourceOutput for a Create/Update result.
// previous_nameservers may be nil; the helper converts to empty []any.
func delegationOutput(name, domain string, ns, previous []string) *interfaces.ResourceOutput {
	if previous == nil {
		previous = []string{}
	}
	return &interfaces.ResourceOutput{
		Name:       name,
		Type:       "infra.dns_delegation",
		ProviderID: domain,
		Outputs: map[string]any{
			"domain":               domain,
			"nameservers":          nameserversToAny(ns),
			"previous_nameservers": nameserversToAny(previous),
		},
		Status: "active",
	}
}

// Create stashes the current upstream nameservers (best-effort) as
// previous_nameservers, then PUTs the desired set.
func (d *DelegationDriver) Create(ctx context.Context, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation create: %w", err)
	}
	s, err := parseDelegationSpec(spec)
	if err != nil {
		return nil, err
	}
	var previous []string
	if dom, err := d.client.GetDomainDelegation(ctx, s.domain); err == nil && dom != nil {
		previous = append([]string(nil), dom.Nameservers...)
	}
	// Best-effort: if GetDomainDelegation failed, previous remains nil → empty []any in output.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation create %q: %w", s.domain, err)
	}
	if err := d.client.SetNameservers(ctx, s.domain, s.nameservers); err != nil {
		return nil, fmt.Errorf("dns_delegation create %q: %w", s.domain, err)
	}
	return delegationOutput(spec.Name, s.domain, s.nameservers, previous), nil
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/drivers -run TestDelegationDriver_Create -v`
Expected: PASS for all four Create subtests.

**Step 5: Commit**

```bash
git add internal/drivers/delegation.go internal/drivers/delegation_test.go
git commit -m "feat(drivers): DelegationDriver.Create + spec validation"
```

---

### Task 8: Implement `DelegationDriver.Read` + `Update` + `Delete`

**Files:**
- Modify: `internal/drivers/delegation.go`

**Step 1: Write the failing test**

Append to `internal/drivers/delegation_test.go`:

```go
func TestDelegationDriver_Read_HappyPath(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID:          "domain-example.com",
			Name:        "example.com",
			Nameservers: []string{"ns1.do.com", "ns2.do.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	out, err := d.Read(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.ProviderID != "example.com" {
		t.Errorf("ProviderID = %q", out.ProviderID)
	}
	ns, _ := out.Outputs["nameservers"].([]any)
	if len(ns) != 2 {
		t.Errorf("nameservers len = %d", len(ns))
	}
}

func TestDelegationDriver_Read_PropagatesError(t *testing.T) {
	fc := &fakeDelegationClient{getErr: errors.New("API down")}
	d := NewDelegationDriverWithClient(fc)
	_, err := d.Read(context.Background(), interfaces.ResourceRef{Name: "x.com", ProviderID: "x.com"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDelegationDriver_Update_HappyPath(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID: "domain-example.com", Name: "example.com",
			Nameservers: []string{"ns1.do.com", "ns2.do.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	ref := interfaces.ResourceRef{Name: "example.com", Type: "infra.dns_delegation", ProviderID: "example.com"}
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"ns3.do.com", "ns4.do.com"},
		},
	}
	out, err := d.Update(context.Background(), ref, spec)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if fc.lastSetNS[0] != "ns3.do.com" {
		t.Errorf("first NS = %q", fc.lastSetNS[0])
	}
	_ = out
}

func TestDelegationDriver_Update_DomainRenameRejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	ref := interfaces.ResourceRef{Name: "old.com", ProviderID: "old.com"}
	spec := interfaces.ResourceSpec{
		Name: "new.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "new.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	if _, err := d.Update(context.Background(), ref, spec); err == nil {
		t.Fatal("expected error rejecting domain rename")
	}
}

func TestDelegationDriver_Delete_RestoresPreviousNameservers(t *testing.T) {
	fc := &fakeDelegationClient{}
	d := NewDelegationDriverWithClient(fc)
	ref := interfaces.ResourceRef{
		Name: "example.com", ProviderID: "example.com",
		InputSnapshot: map[string]any{
			"previous_nameservers": []any{"old1.com", "old2.com"},
		},
	}
	if err := d.Delete(context.Background(), ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fc.lastSetNS) != 2 || fc.lastSetNS[0] != "old1.com" {
		t.Errorf("Delete set NS = %v, want [old1.com old2.com]", fc.lastSetNS)
	}
}

func TestDelegationDriver_Delete_FallbackHoverDefaults(t *testing.T) {
	fc := &fakeDelegationClient{}
	d := NewDelegationDriverWithClient(fc)
	// No previous_nameservers in InputSnapshot.
	ref := interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"}
	if err := d.Delete(context.Background(), ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fc.lastSetNS) != 2 || fc.lastSetNS[0] != "ns1.hover.com" || fc.lastSetNS[1] != "ns2.hover.com" {
		t.Errorf("Delete set NS = %v, want [ns1.hover.com ns2.hover.com] fallback", fc.lastSetNS)
	}
}
```

Note: `interfaces.ResourceRef.InputSnapshot` may not exist on all versions of the workflow interface — check existing tests for the canonical way to pass state to Delete. If `InputSnapshot` isn't a field on `ResourceRef`, the test should use whatever channel the existing `DNSDriver.Delete` uses (likely the state file resolved by the engine before Delete is called).

If `ResourceRef` doesn't have `InputSnapshot`, adjust the design: stash previous_nameservers in the resource's State backing rather than the ref. Inspect `/Users/jon/workspace/workflow/interfaces/iac_resource_driver.go` to confirm.

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/drivers -run "TestDelegationDriver_Read|TestDelegationDriver_Update|TestDelegationDriver_Delete" -v`
Expected: FAIL — methods not defined.

**Step 3: Write minimal implementation**

Append to `internal/drivers/delegation.go`:

```go
// Read fetches the current registrar nameservers.
func (d *DelegationDriver) Read(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation read %q: %w", ref.Name, err)
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	dom, err := d.client.GetDomainDelegation(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns_delegation read %q: %w", ref.Name, err)
	}
	// Read does not populate previous_nameservers (state-only field
	// captured at Create time). Leave as empty []any.
	return delegationOutput(ref.Name, domain, dom.Nameservers, nil), nil
}

// Update replaces the registrar nameservers. Rejects in-place domain
// renames (those must route through Diff → NeedsReplace → Delete-then-Create).
func (d *DelegationDriver) Update(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation update %q: %w", ref.Name, err)
	}
	s, err := parseDelegationSpec(spec)
	if err != nil {
		return nil, err
	}
	currentDomain := ref.ProviderID
	if currentDomain == "" {
		currentDomain = ref.Name
	}
	if !strings.EqualFold(s.domain, currentDomain) {
		return nil, fmt.Errorf("dns_delegation update %q: spec.domain %q does not match current %q — domain change requires resource replace, not update", ref.Name, s.domain, currentDomain)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation update %q: %w", ref.Name, err)
	}
	if err := d.client.SetNameservers(ctx, currentDomain, s.nameservers); err != nil {
		return nil, fmt.Errorf("dns_delegation update %q: %w", ref.Name, err)
	}
	return delegationOutput(ref.Name, currentDomain, s.nameservers, nil), nil
}

// hoverDefaultNameservers is the fallback for Delete when previous_nameservers
// is not in the resource's input snapshot. Documented as best-effort in the
// design (assumption A5).
var hoverDefaultNameservers = []string{"ns1.hover.com", "ns2.hover.com"}

// Delete restores the stashed previous_nameservers (or the Hover-default
// fallback). Caller's state must surface previous_nameservers via
// ref.InputSnapshot for the restore path to fire.
func (d *DelegationDriver) Delete(ctx context.Context, ref interfaces.ResourceRef) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("dns_delegation delete %q: %w", ref.Name, err)
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	ns := hoverDefaultNameservers
	if ref.InputSnapshot != nil {
		if raw, ok := ref.InputSnapshot["previous_nameservers"]; ok {
			if list, ok := raw.([]any); ok && len(list) > 0 {
				restored := make([]string, 0, len(list))
				for _, item := range list {
					if s, ok := item.(string); ok && s != "" {
						restored = append(restored, s)
					}
				}
				if len(restored) > 0 {
					ns = restored
				}
			}
		}
	}
	if err := d.client.SetNameservers(ctx, domain, ns); err != nil {
		return fmt.Errorf("dns_delegation delete %q: %w", ref.Name, err)
	}
	return nil
}
```

If `interfaces.ResourceRef` does NOT have `InputSnapshot` (verify via `cat /Users/jon/workspace/workflow/interfaces/iac_resource_driver.go | grep -A5 "type ResourceRef"`), substitute the correct field name and adjust both the test and impl. If no such field exists at all, the implementer MUST pause and surface this as a design amendment — Delete cannot restore previous_nameservers without a state channel.

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/drivers -run "TestDelegationDriver_Read|TestDelegationDriver_Update|TestDelegationDriver_Delete" -v`
Expected: PASS for all six subtests.

**Step 5: Commit**

```bash
git add internal/drivers/delegation.go internal/drivers/delegation_test.go
git commit -m "feat(drivers): DelegationDriver.Read/Update/Delete"
```

---

### Task 9: Implement `DelegationDriver.Diff` (multiset compare + domain-rename Replace)

**Files:**
- Modify: `internal/drivers/delegation.go`

**Step 1: Write the failing test**

Append to `internal/drivers/delegation_test.go`:

```go
func TestDelegationDriver_Diff_NilCurrent(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain": "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	res, err := d.Diff(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsUpdate {
		t.Error("expected NeedsUpdate=true for nil current")
	}
}

func TestDelegationDriver_Diff_UpToDate_OrderIndependent(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com", "c.com"},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"c.com", "a.com", "b.com"}, // reversed
		},
	}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.NeedsUpdate {
		t.Error("expected NeedsUpdate=false for same multiset")
	}
}

func TestDelegationDriver_Diff_Changed(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"new.com", "b.com"},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsUpdate {
		t.Error("expected NeedsUpdate=true")
	}
}

func TestDelegationDriver_Diff_DomainChange_NeedsReplace(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "new.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "new.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	current := &interfaces.ResourceOutput{ProviderID: "old.com"}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsReplace {
		t.Error("expected NeedsReplace=true on domain change")
	}
	if len(res.Changes) != 1 || res.Changes[0].Path != "domain" || !res.Changes[0].ForceNew {
		t.Errorf("expected ForceNew domain change, got %+v", res.Changes)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/drivers -run TestDelegationDriver_Diff -v`
Expected: FAIL — `d.Diff` not defined.

**Step 3: Write minimal implementation**

Append to `internal/drivers/delegation.go`:

```go
// Diff compares desired vs current. Multiset semantics on nameservers
// (order-independent — Hover accepts any order on PUT). Domain rename
// (desired vs current.ProviderID) forces Replace.
func (d *DelegationDriver) Diff(_ context.Context, desired interfaces.ResourceSpec, current *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	s, err := parseDelegationSpec(desired)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return &interfaces.DiffResult{NeedsUpdate: true}, nil
	}
	if current.ProviderID != "" && !strings.EqualFold(s.domain, current.ProviderID) {
		return &interfaces.DiffResult{
			NeedsReplace: true,
			Changes: []interfaces.FieldChange{{
				Path:     "domain",
				Old:      current.ProviderID,
				New:      s.domain,
				ForceNew: true,
			}},
		}, nil
	}
	currentNS := nameserversFromOutputs(current.Outputs)
	if !sameNameserverSet(currentNS, s.nameservers) {
		return &interfaces.DiffResult{
			NeedsUpdate: true,
			Changes: []interfaces.FieldChange{{
				Path: "nameservers",
				Old:  nameserversToAny(currentNS),
				New:  nameserversToAny(s.nameservers),
			}},
		}, nil
	}
	return &interfaces.DiffResult{NeedsUpdate: false}, nil
}

// nameserversFromOutputs reconstructs []string from Outputs["nameservers"]
// (which is stored as []any).
func nameserversFromOutputs(outputs map[string]any) []string {
	raw, ok := outputs["nameservers"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sameNameserverSet returns true iff a and b are multiset-equal.
func sameNameserverSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if !strings.EqualFold(sa[i], sb[i]) {
			return false
		}
	}
	return true
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/drivers -run TestDelegationDriver_Diff -v`
Expected: PASS for all four subtests.

**Step 5: Commit**

```bash
git add internal/drivers/delegation.go internal/drivers/delegation_test.go
git commit -m "feat(drivers): DelegationDriver.Diff (multiset + Replace)"
```

---

### Task 10: Implement `DelegationDriver.HealthCheck` + `Scale`

**Files:**
- Modify: `internal/drivers/delegation.go`

**Step 1: Write the failing test**

Append to `internal/drivers/delegation_test.go`:

```go
func TestDelegationDriver_HealthCheck_Healthy(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID: "domain-example.com", Name: "example.com",
			Nameservers: []string{"a.com", "b.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	res, err := d.HealthCheck(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if !res.Healthy {
		t.Errorf("Healthy = false, want true")
	}
}

func TestDelegationDriver_HealthCheck_Unhealthy(t *testing.T) {
	fc := &fakeDelegationClient{getErr: errors.New("boom")}
	d := NewDelegationDriverWithClient(fc)
	res, err := d.HealthCheck(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("HealthCheck should not return err; got %v", err)
	}
	if res.Healthy {
		t.Error("Healthy = true, want false")
	}
}

func TestDelegationDriver_Scale_NotSupported(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	_, err := d.Scale(context.Background(), interfaces.ResourceRef{Name: "x"}, 3)
	if err == nil {
		t.Fatal("expected error from Scale")
	}
}

func TestDelegationDriver_CtxCanceled_AllMethods(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	ref := interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"}
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Create(ctx, spec); err == nil {
		t.Error("Create: expected error for canceled ctx")
	}
	if _, err := d.Read(ctx, ref); err == nil {
		t.Error("Read: expected error for canceled ctx")
	}
	if _, err := d.Update(ctx, ref, spec); err == nil {
		t.Error("Update: expected error for canceled ctx")
	}
	if err := d.Delete(ctx, ref); err == nil {
		t.Error("Delete: expected error for canceled ctx")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal/drivers -run "TestDelegationDriver_HealthCheck|TestDelegationDriver_Scale|TestDelegationDriver_CtxCanceled" -v`
Expected: FAIL — methods not defined.

**Step 3: Write minimal implementation**

Append to `internal/drivers/delegation.go`:

```go
// HealthCheck probes connectivity to the domain by fetching its delegation.
func (d *DelegationDriver) HealthCheck(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	if err := ctx.Err(); err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	if _, err := d.client.GetDomainDelegation(ctx, domain); err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	return &interfaces.HealthResult{Healthy: true, Message: "ok"}, nil
}

// Scale is not supported for DNS delegation (no replica concept).
func (d *DelegationDriver) Scale(_ context.Context, _ interfaces.ResourceRef, _ int) (*interfaces.ResourceOutput, error) {
	return nil, fmt.Errorf("dns_delegation: scale is not supported")
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/drivers -count=1 -v 2>&1 | tail -10`
Expected: ALL delegation tests pass.

**Step 5: Commit**

```bash
git add internal/drivers/delegation.go internal/drivers/delegation_test.go
git commit -m "feat(drivers): DelegationDriver.HealthCheck + Scale + ctx tests"
```

---

### Task 11: Wire `DelegationDriver` into `HoverProvider`

**Files:**
- Modify: `internal/provider.go:22` (type comment) + `:84-87` (drivers map) + `:90-100` (Capabilities)

**Step 1: Write the failing test**

Add to `internal/iacserver_test.go` (or wherever iacserver-level capability assertions live; check existing tests for the canonical place):

```go
func TestHoverIaCServer_Capabilities_IncludesDelegation(t *testing.T) {
	// Smoke: Capabilities() must list both infra.dns and infra.dns_delegation.
	// Tests should bring up the iacserver via the existing test harness;
	// see iacserver_test.go for the canonical setup.
	// Pseudocode (adapt to existing test harness):
	caps := newTestIaCServerInitialized(t).Capabilities()
	wantTypes := map[string]bool{"infra.dns": false, "infra.dns_delegation": false}
	for _, c := range caps.Capabilities {
		if _, ok := wantTypes[c.ResourceType]; ok {
			wantTypes[c.ResourceType] = true
		}
	}
	for rt, found := range wantTypes {
		if !found {
			t.Errorf("Capabilities missing %q", rt)
		}
	}
}
```

(The implementer must adapt this to the actual existing `iacserver_test.go` harness pattern. Check the existing capabilities test there for the canonical assertion shape.)

**Step 2: Run tests to verify they fail**

Run: `GOWORK=off go test ./internal -count=1 -run "Capabilities" -v`
Expected: FAIL or PASS-without-new-type — the new resource type is not yet registered.

**Step 3: Write minimal implementation**

Edit `internal/provider.go`:

1. Update the type comment at line 21-22:

```go
// HoverProvider implements interfaces.IaCProvider for Hover.
// Supports two resource types:
//   - infra.dns           — DNS records within Hover's nameservers.
//   - infra.dns_delegation — registrar-level nameserver delegation.
```

2. In `Initialize` (line 84), add the delegation driver to the map:

```go
	p.drivers = map[string]interfaces.ResourceDriver{
		"infra.dns":            drivers.NewDNSDriver(c),
		"infra.dns_delegation": drivers.NewDelegationDriver(c),
	}
```

3. In `Capabilities` (line 90-100), append the second capability:

```go
func (p *HoverProvider) Capabilities() []interfaces.IaCCapabilityDeclaration {
	return []interfaces.IaCCapabilityDeclaration{
		{
			ResourceType: "infra.dns",
			Tier:         1,
			Operations:   []string{"create", "read", "update", "delete"},
		},
		{
			ResourceType: "infra.dns_delegation",
			Tier:         1,
			Operations:   []string{"create", "read", "update", "delete"},
		},
	}
}
```

**Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal -count=1`
Expected: PASS for capabilities + all existing tests.

**Step 5: Commit**

```bash
git add internal/provider.go internal/iacserver_test.go
git commit -m "feat(provider): register DelegationDriver + update Capabilities"
```

---

### Task 12: Update `plugin.json` to declare `infra.dns_delegation`

**Files:**
- Modify: `plugin.json`

**Step 1: Read current state**

```bash
cat plugin.json
```

**Step 2: Edit**

Update `plugin.json` so `iacProvider.resourceTypes` lists both:

```json
{
  ...
  "iacProvider": {
    "computePlanVersion": "v2",
    "resourceTypes": ["infra.dns", "infra.dns_delegation"]
  },
  ...
}
```

If `resourceTypes` is missing entirely, add it. Otherwise extend the array.

**Step 3: Verify JSON parses**

Run: `jq . plugin.json > /dev/null && echo "OK"`
Expected: `OK` (no JSON syntax errors).

**Step 4: Run full build + test**

Run: `GOWORK=off go build ./... && GOWORK=off go test ./... -count=1 -timeout 120s 2>&1 | tail -5`
Expected: all packages PASS.

**Step 5: Commit**

```bash
git add plugin.json
git commit -m "feat: plugin.json declares infra.dns_delegation"
```

---

### Task 13: Run full validation + open PR

**Files:** none (verification + PR open)

**Step 1: Full validation gate**

```bash
gofmt -l . 2>&1 | head     # expect empty
GOWORK=off go vet ./... 2>&1 | head  # expect empty
GOWORK=off go build ./... 2>&1 | head  # expect empty
GOWORK=off go test ./... -count=1 -timeout 120s 2>&1 | tail -10  # expect all OK
```

Expected: every command emits no errors. If any fail, fix before proceeding.

**Step 2: Push + open PR**

```bash
git push -u origin feat/dns-delegation
gh pr create --title "feat: infra.dns_delegation resource type (v0.2.0)" --body "$(cat <<'BODY'
## Summary

Adds the `infra.dns_delegation` resource type so wfctl can set a domain's registrar-level nameservers via the Hover control-panel API. Field-test target: gocodealone.tech → ns1/2/3.digitalocean.com.

Design + 3-round adversarial review history: \`docs/plans/2026-05-20-hover-dns-delegation-design.md\`.
Implementation plan: \`docs/plans/2026-05-20-hover-dns-delegation.md\`.

## Endpoint

Captured from the Hover web UI (2026-05-20):

\`\`\`
PUT /api/control_panel/domains/domain-<name>
Content-Type: application/json
X-CSRF-Token: <rails-csrf>

{"field":"nameservers","value":["ns1.digitalocean.com",...]}
\`\`\`

## What changed

- New \`DomainDelegation\` type (distinct from \`Domain\` to avoid endpoint-shape ambiguity).
- New \`ErrEmptyNameservers\` sentinel — loud failure on empty Read instead of silent re-apply thrash.
- \`SetNameservers\` holds \`c.mu\` across the full auth → CSRF → PUT sequence (no TOCTOU).
- New \`GetDomainDelegation\` using the same API family as the PUT (control-panel endpoint).
- New \`DelegationDriver\` registered as \`infra.dns_delegation\` alongside the existing \`infra.dns\` driver.
- \`plugin.json\` declares the new resource type.
- Outputs structpb-safe (\`[]any\` not \`[]string\`).
- Delete stashes \`previous_nameservers\` at Create for restore; falls back to \`[ns1.hover.com, ns2.hover.com]\` for state-less resources.

## Follow-ups (deferred to a separate session)

1. workflow-registry manifest bump to v0.2.0 (cannot author until goreleaser publishes asset SHAs after this PR merges + the v0.2.0 tag fires).
2. gocodealone-multisite: \`config/dns.wfctl.yaml\` + \`.github/workflows/dns-delegation.yml\` (manual workflow_dispatch); operator runs apply against gocodealone.tech.

## Test plan

- [x] \`gofmt -l .\` clean
- [x] \`GOWORK=off go vet ./...\` clean
- [x] \`GOWORK=off go build ./...\` clean
- [x] \`GOWORK=off go test ./... -count=1\` all PASS
- [ ] Field test: \`wfctl apply\` in GHA against gocodealone.tech; verify Hover UI shows DO nameservers post-apply.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
BODY
)" 2>&1 | tail -2
```

**Step 3: Request Copilot review**

```bash
gh pr edit $(gh pr view --json number -q .number) --repo GoCodeAlone/workflow-plugin-hover --add-reviewer @copilot
```

**Step 4: Verify PR open + Copilot triggered**

Run: `gh pr view --repo GoCodeAlone/workflow-plugin-hover --json state,number,reviewRequests`
Expected: `state: OPEN`; `reviewRequests` contains the Copilot bot (or `reviews` will populate it within ~60s).

**Step 5: Commit if any final cleanup needed**

If the PR creation requires any last-minute fix (e.g., a forgotten file), commit + push. Otherwise no commit needed.

---

## Rollback notes

Per the design's Rollback section. Per-task rollback:

- **Task 1-5 (client extensions)**: Revert commit; restores original `client.go`. Backwards-compatible additive changes; no consumer depends on the new symbols yet.
- **Task 6-10 (driver)**: Revert commits. No external consumers reference `DelegationDriver`.
- **Task 11 (provider wiring)**: Revert commit; restores single-driver map. wfctl that previously loaded the plugin sees only `infra.dns` again.
- **Task 12 (plugin.json)**: Revert; `iacProvider.resourceTypes` returns to single-type. wfctl's manifest validation flips back to passing.
- **Task 13 (PR)**: `gh pr close <N>` if needed. Branch deletion via `--delete-branch` on close.

Full revert pre-merge = `git push origin --delete feat/dns-delegation`.

Post-merge rollback = revert PR + cherry-pick the revert + new v0.2.1 tag.
