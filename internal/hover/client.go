package hover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	hoverHost         = "https://www.hover.com"
	defaultUserAgent  = "wfctl-hover-plugin/0.1 (+https://github.com/GoCodeAlone/workflow-plugin-hover)"
	sessionStaleAfter = 1 * time.Hour
)

// Credentials carries the operator-provided login material.
type Credentials struct {
	Username   string
	Password   string
	TOTPSecret TOTPSecret
}

// Client is a Hover account-portal client. Concurrency-safe; the
// underlying cookie jar serialises across goroutines via mu.
type Client struct {
	mu        sync.Mutex
	http      *http.Client
	creds     Credentials
	loggedAt  time.Time
	UserAgent string
}

// NewClient returns a fresh Client. Pass http=nil for an internal
// jar-backed http.Client. Tests inject a stub to redirect requests.
func NewClient(creds Credentials, httpClient *http.Client) (*Client, error) {
	if creds.Username == "" || creds.Password == "" {
		return nil, errors.New("hover: username + password required")
	}
	if httpClient == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("hover: cookie jar: %w", err)
		}
		httpClient = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	}
	if httpClient.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		httpClient.Jar = jar
	}
	return &Client{http: httpClient, creds: creds, UserAgent: defaultUserAgent}, nil
}

// Login performs a full authentication cycle against Hover's control panel.
// It is safe to call when already authenticated — it re-authenticates only
// when the session is older than sessionStaleAfter (1 hour). Safe for
// concurrent use; the internal mutex serialises calls.
//
// The underlying auth flow (derived from pjslauta/hover-dyn-dns):
//  1. GET https://www.hover.com/signin  →  extract CSRF _token
//  2. POST https://www.hover.com/signin  (username + password + _token)
//  3. Probe https://www.hover.com/signin/totp for a TOTP form.
//     If a _token is present → account has MFA enabled → submit TOTP code.
//     If the CSRF token is absent → MFA is not enabled → skip.
//  4. Session cookies are stored in the jar for subsequent API calls.
func (c *Client) Login(ctx context.Context) error {
	return c.ensureLogin(ctx)
}

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

	csrf, err := c.fetchSignInCSRF(ctx)
	if err != nil {
		return err
	}

	// Step 1 — submit credentials.
	form := url.Values{
		"username": {c.creds.Username},
		"password": {c.creds.Password},
		"_token":   {csrf},
	}
	if err := c.postForm(ctx, hoverHost+"/signin", form); err != nil {
		return fmt.Errorf("hover signin step 1: %w", err)
	}

	// Step 2 — TOTP (conditional). Probe the TOTP page for a _token.
	// If a token is found the account has MFA enabled and we must submit
	// a 6-digit code. If the page contains no _token the account has MFA
	// disabled and we skip this step — no TOTP submission required.
	//
	// This matches the pjslauta/hover-dyn-dns behaviour: it checks the
	// response `status == 'need_2fa'` before posting to auth2.json.
	// The form-based portal equivalent is the presence of _token on the
	// TOTP page.
	csrf2, totpEnabled, err := c.probeTOTPPage(ctx)
	if err != nil {
		return err
	}
	if totpEnabled {
		if c.creds.TOTPSecret.key == nil {
			return fmt.Errorf("hover: account has MFA enabled but no totp_secret was provided")
		}
		code := c.creds.TOTPSecret.Code()
		form = url.Values{
			"code":   {code},
			"_token": {csrf2},
		}
		if err := c.postForm(ctx, hoverHost+"/signin/totp", form); err != nil {
			return fmt.Errorf("hover signin step 2 (totp): %w", err)
		}
	}

	c.loggedAt = time.Now()
	return nil
}

var csrfRe = regexp.MustCompile(`<input[^>]+name="_token"[^>]+value="([^"]+)"`)

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

func (c *Client) fetchSignInCSRF(ctx context.Context) (string, error) {
	return c.fetchCSRF(ctx, hoverHost+"/signin")
}

// probeTOTPPage fetches /signin/totp and returns:
//   - (token, true, nil)  — page contains a _token → MFA is enabled.
//   - ("", false, nil)    — page loaded but no _token → MFA is not enabled.
//   - ("", false, err)    — network error, non-2xx status, or body read failure.
//
// Treating a non-200 response (redirect, login failure, Cloudflare gate)
// as "MFA not enabled" would silently misclassify these errors and let
// login appear to succeed before failing on the first API call. Status
// + body errors are now surfaced rather than swallowed.
func (c *Client) probeTOTPPage(ctx context.Context) (string, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, hoverHost+"/signin/totp", nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("hover: probe TOTP page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("hover: probe TOTP page: unexpected HTTP %d", resp.StatusCode)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return "", false, fmt.Errorf("hover: probe TOTP page: read body: %w", readErr)
	}
	m := csrfRe.FindSubmatch(body)
	if len(m) < 2 {
		// Page loaded successfully but no CSRF token present —
		// account does not have MFA enabled.
		return "", false, nil
	}
	return string(m[1]), true, nil
}

func (c *Client) fetchCSRF(ctx context.Context, urlStr string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := csrfRe.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("hover: CSRF token not found at %s (login UI changed?)", urlStr)
	}
	return string(m[1]), nil
}

func (c *Client) postForm(ctx context.Context, urlStr string, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

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

// DNSRecord mirrors Hover's internal API record shape.
type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

// Domain is the API shape returned by GET /api/domains.
type Domain struct {
	ID      string      `json:"id"`
	Name    string      `json:"domain_name"`
	Records []DNSRecord `json:"entries"`
}

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
//
// Note: the wire payload uses []string directly — encoding/json serializes
// it as a JSON array, which is what Hover expects. This is distinct from
// the []any requirement in ResourceOutput.Outputs (which crosses the
// structpb gRPC boundary); typed slices are fine here because the wire
// format is plain JSON, not structpb.
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

// GetDomain returns the full Domain struct (including the
// hover-assigned ID) for the named zone. The ID is required when
// creating new records via CreateRecord; the human-readable name is
// not accepted by the POST /api/dns endpoint.
func (c *Client) GetDomain(ctx context.Context, domain string) (*Domain, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/domains/%s/dns", hoverHost, url.PathEscape(domain))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover get domain %q: HTTP %d: %s", domain, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var wrap struct {
		Domains []Domain `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return nil, fmt.Errorf("hover get domain parse: %w", err)
	}
	for i := range wrap.Domains {
		if strings.EqualFold(wrap.Domains[i].Name, domain) {
			return &wrap.Domains[i], nil
		}
	}
	return nil, fmt.Errorf("hover: domain %q not found in account", domain)
}

// ListRecords returns records for the named zone. Caller MUST pass
// the apex domain (e.g. "example.com").
func (c *Client) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/domains/%s/dns", hoverHost, url.PathEscape(domain))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover list records %q: HTTP %d: %s", domain, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var wrap struct {
		Domains []Domain `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return nil, fmt.Errorf("hover list records parse: %w", err)
	}
	for _, d := range wrap.Domains {
		if strings.EqualFold(d.Name, domain) {
			return d.Records, nil
		}
	}
	return nil, fmt.Errorf("hover: domain %q not found in account", domain)
}

// CreateRecord adds a new DNS record for the domain.
func (c *Client) CreateRecord(ctx context.Context, domainID string, rec DNSRecord) (*DNSRecord, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	form := url.Values{
		"domain_id": {domainID},
		"name":      {rec.Name},
		"type":      {rec.Type},
		"content":   {rec.Content},
	}
	if rec.TTL > 0 {
		form.Set("ttl", fmt.Sprintf("%d", rec.TTL))
	}
	endpoint := hoverHost + "/api/dns"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover create record: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		DNSRecord DNSRecord `json:"dns_record"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hover create record parse: %w", err)
	}
	return &out.DNSRecord, nil
}

// UpdateRecord PATCHes an existing record's content (and TTL when > 0).
func (c *Client) UpdateRecord(ctx context.Context, recordID string, rec DNSRecord) error {
	if err := c.ensureLogin(ctx); err != nil {
		return err
	}
	form := url.Values{"content": {rec.Content}}
	if rec.TTL > 0 {
		form.Set("ttl", fmt.Sprintf("%d", rec.TTL))
	}
	endpoint := fmt.Sprintf("%s/api/dns/%s", hoverHost, url.PathEscape(recordID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hover update %q: HTTP %d: %s", recordID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// DeleteRecord removes a record by ID.
func (c *Client) DeleteRecord(ctx context.Context, recordID string) error {
	if err := c.ensureLogin(ctx); err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/dns/%s", hoverHost, url.PathEscape(recordID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hover delete %q: HTTP %d: %s", recordID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
