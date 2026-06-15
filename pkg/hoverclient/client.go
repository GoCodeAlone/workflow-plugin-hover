package hoverclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	hoverHost         = "https://www.hover.com"
	defaultUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	sessionStaleAfter = 1 * time.Hour
	maxBackoffCap     = 30 * time.Second
)

// retryBaseDelay is the initial backoff duration for 429/503 retries.
// Overridable in tests (set to a small value to keep tests fast).
var retryBaseDelay = 1 * time.Second

// maxRetries is the maximum number of retry attempts after a 429/503.
// Overridable in tests.
var maxRetries = 5

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
	backend   executionBackend
	// domainNS caches nameservers keyed by domain name. Populated by
	// listDomainsHTTP so GetDomainDelegation can short-circuit the
	// per-domain GET when a prior ListDomains call has already fetched them.
	// Guarded by mu.
	domainNS map[string][]string
}

// NewClient returns a fresh Client. Pass httpClient=nil for the browser
// backend (production path — Chrome drives Imperva clearance + login).
// Pass a non-nil *http.Client to select the HTTP backend; tests inject
// a stub to redirect requests without launching Chrome.
func NewClient(creds Credentials, httpClient *http.Client) (*Client, error) {
	return NewClientWithOptions(creds, httpClient, ClientOptions{})
}

// NewClientWithOptions returns a Client with explicit runtime options.
// opts.Browser is used when httpClient is nil (browser backend); it is
// ignored when httpClient is non-nil (HTTP backend selected).
func NewClientWithOptions(creds Credentials, httpClient *http.Client, opts ClientOptions) (*Client, error) {
	creds.Username = strings.TrimSpace(creds.Username)
	creds.Password = strings.TrimRight(creds.Password, "\r\n")
	if creds.Username == "" || creds.Password == "" {
		return nil, errors.New("hover: username + password required")
	}

	var backend executionBackend
	if httpClient != nil {
		// Injected HTTP client: use HTTP backend (test path).
		if httpClient.Jar == nil {
			jar, err := cookiejar.New(nil)
			if err != nil {
				return nil, err
			}
			httpClient.Jar = jar
		}
		backend = &httpBackend{}
	} else {
		// nil HTTP client: use browser backend (production path).
		browserOpts := opts.Browser
		if browserOpts.ProfileDir == "" {
			browserOpts.ProfileDir = defaultBrowserProfileDir()
		}
		if browserOpts.Timeout == 0 {
			browserOpts.Timeout = defaultBrowserTimeout
		}
		backend = newBrowserBackend(browserOpts)

		// Provide a jar-backed http.Client for the cookie-reuse path
		// (Task 3 will populate this jar from browser cookies).
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("hover: cookie jar: %w", err)
		}
		httpClient = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	}

	return &Client{
		http:      httpClient,
		creds:     creds,
		UserAgent: defaultUserAgent,
		backend:   backend,
	}, nil
}

// do executes req via c.http.Do, retrying on HTTP 429 (Too Many Requests) and
// 503 (Service Unavailable) with exponential back-off.
//
// Back-off: if the response includes a numeric Retry-After header its value is
// used directly; otherwise the wait is retryBaseDelay * 2^attempt with ±10 %
// jitter, capped at maxBackoffCap (30 s).
//
// Safety: do only retries when req.Body is nil or re-readable (GetBody != nil).
// One-shot bodies (e.g. POST with a streaming body) are returned as-is after
// the first response so the caller's body is never consumed twice.
//
// Context cancellation during a back-off sleep is honoured: do returns
// ctx.Err() immediately when the context is done.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	// Don't retry requests with a one-shot body.
	bodyRetryable := req.Body == nil || req.GetBody != nil

	for attempt := 0; ; attempt++ {
		// Re-create the body for retries when possible.
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("hover: re-create request body for retry: %w", err)
			}
			req.Body = body
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}

		// Non-retryable status or body is one-shot → return immediately.
		if (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) ||
			!bodyRetryable {
			return resp, nil
		}

		// Drain and close so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if attempt >= maxRetries {
			return nil, fmt.Errorf("hover: request to %s failed after %d retries: HTTP %d",
				req.URL.Path, maxRetries, resp.StatusCode)
		}

		// Compute wait duration.
		wait := retryBaseDelay * time.Duration(math.Pow(2, float64(attempt)))
		if wait > maxBackoffCap {
			wait = maxBackoffCap
		}
		// Honor Retry-After header if present and numeric.
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, parseErr := strconv.Atoi(ra); parseErr == nil && secs >= 0 {
				wait = time.Duration(secs) * time.Second
			}
		}
		// Add ±10 % jitter to spread concurrent retries.
		// Non-security use: jitter is for load spreading, not randomness quality.
		jitter := time.Duration(float64(wait) * (rand.Float64()*0.2 - 0.1)) //nolint:gosec
		wait += jitter
		if wait < 0 {
			wait = 0
		}

		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(wait):
		}
	}
}

// Login performs a full authentication cycle against Hover's control panel.
// It is safe to call when already authenticated — it re-authenticates only
// when the session is older than sessionStaleAfter (1 hour). Safe for
// concurrent use; the internal mutex serialises calls.
//
// On the HTTP backend the underlying auth flow follows Hover's current React
// signin UI:
//  1. POST https://www.hover.com/signin/auth.json with username + password.
//  2. If the response status is "need_2fa", POST /signin/auth2.json with the
//     current TOTP code.
//  3. Session cookies are stored in the jar for subsequent API calls.
func (c *Client) Login(ctx context.Context) error {
	return c.backend.Login(ctx, c)
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

	auth, err := c.postLoginJSON(ctx, hoverHost+"/signin/auth.json", map[string]any{
		"username": c.creds.Username,
		"password": c.creds.Password,
		"remember": false,
		// token MUST be JSON null, not "". Hover's signin branches on this
		// field for its "magic token" sign-in: a non-null token (even "")
		// routes to magic-token validation, which fails an empty token with
		// a generic "Invalid username or password." The browser sends null
		// for password sign-in; match it exactly (verified via DevTools).
		"token": nil,
	})
	if err != nil {
		return fmt.Errorf("hover signin step 1: %w", err)
	}
	if auth.Status == "need_2fa" {
		if c.creds.TOTPSecret.key == nil {
			return fmt.Errorf("hover: account has MFA enabled but no totp_secret was provided")
		}
		if _, err := c.postLoginJSON(ctx, hoverHost+"/signin/auth2.json", map[string]any{
			"code":     c.creds.TOTPSecret.Code(),
			"remember": false,
		}); err != nil {
			return fmt.Errorf("hover signin step 2 (totp): %w", err)
		}
	}

	c.loggedAt = time.Now()
	return nil
}

var csrfRe = regexp.MustCompile(`<input[^>]+name="_token"[^>]+value="([^"]+)"`)

// CSRF meta-tag extraction. Distinct from csrfRe (form-token regex used
// by the /signin flow) because the control-panel pages embed the token
// as a meta tag for the SPA layer to read, while /signin embeds it as a
// hidden input. Both shapes coexist in the Hover-served HTML; each is
// matched from the page where it's authoritative.
//
// Two patterns to handle both HTML attribute orderings + single/double
// quotes. Rails+SPA codebases routinely emit either; assuming a single
// ordering means a Hover UI update could silently break CSRF extraction.
var (
	csrfMetaReNameFirst    = regexp.MustCompile(`<meta\s+name\s*=\s*['"]csrf-token['"]\s+content\s*=\s*['"]([^'"]+)['"]`)
	csrfMetaReContentFirst = regexp.MustCompile(`<meta\s+content\s*=\s*['"]([^'"]+)['"]\s+name\s*=\s*['"]csrf-token['"]`)
)

// ErrForwardNotFound is returned when Hover has no root forward configured.
var ErrForwardNotFound = errors.New("hover: forward not found")

// extractCSRFMeta returns the CSRF meta token regardless of attribute
// order or quote style. Returns "" if no match.
func extractCSRFMeta(body []byte) string {
	if m := csrfMetaReNameFirst.FindSubmatch(body); len(m) >= 2 {
		return string(m[1])
	}
	if m := csrfMetaReContentFirst.FindSubmatch(body); len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

// fetchControlPanelCSRFLocked retrieves the meta-tag CSRF token from
// /control_panel/domain/<name>. Caller MUST hold c.mu (so the HTTP GET
// and any subsequent PUT execute against the same session-cookie state).
func (c *Client) fetchControlPanelCSRFLocked(ctx context.Context, domainName string) (string, error) {
	endpoint := fmt.Sprintf("%s/control_panel/domain/%s", hoverHost, url.PathEscape(domainName))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
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
	token := extractCSRFMeta(body)
	if token == "" {
		return "", fmt.Errorf("hover: CSRF meta tag not found at /control_panel/domain/%s (control_panel UI changed?)", domainName)
	}
	return token, nil
}

type signinResponse struct {
	Succeeded bool   `json:"succeeded"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

func (c *Client) postLoginJSON(ctx context.Context, urlStr string, payload map[string]any) (signinResponse, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return signinResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, &buf)
	if err != nil {
		return signinResponse{}, err
	}
	// Browser-consistent headers. A bare UA + Referer reads as a bot to
	// Hover's signin protection; match what Chrome actually sends for a
	// same-origin XHR — client hints (sec-ch-ua) + fetch metadata
	// (Sec-Fetch-*) + Accept-Language — kept consistent with the macOS
	// Chrome UA in defaultUserAgent.
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Origin", hoverHost)
	req.Header.Set("Referer", hoverHost+"/signin")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	resp, err := c.http.Do(req)
	if err != nil {
		return signinResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return signinResponse{}, err
	}
	var parsed signinResponse
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &parsed); err != nil {
			return signinResponse{}, fmt.Errorf("HTTP %d: parse signin JSON: %w", resp.StatusCode, err)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if parsed.Error != "" {
			return signinResponse{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, parsed.Error)
		}
		return signinResponse{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if parsed.Error != "" {
		return signinResponse{}, errors.New(parsed.Error)
	}
	return parsed, nil
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

// hoverLockState accepts the lock formats Hover has returned from /api/domains:
// string values such as "on"/"off" and booleans such as true/false.
type hoverLockState string

func (s *hoverLockState) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*s = hoverLockState(text)
		return nil
	}
	var locked bool
	if err := json.Unmarshal(data, &locked); err == nil {
		*s = hoverLockState(strconv.FormatBool(locked))
		return nil
	}
	if string(bytes.TrimSpace(data)) == "null" {
		*s = ""
		return nil
	}
	return fmt.Errorf("hover lock state: expected string, boolean, or null")
}

// Domain is the API shape returned by GET /api/domains.
type Domain struct {
	ID          string      `json:"id"`
	Name        string      `json:"domain_name"`
	Records     []DNSRecord `json:"entries"`
	Nameservers []string    `json:"nameservers"`
	Locked      string      `json:"locked"`
}

func (d *Domain) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID          string         `json:"id"`
		Name        string         `json:"domain_name"`
		Records     []DNSRecord    `json:"entries"`
		Nameservers []string       `json:"nameservers"`
		Locked      hoverLockState `json:"locked"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.ID = raw.ID
	d.Name = raw.Name
	d.Records = raw.Records
	d.Nameservers = raw.Nameservers
	d.Locked = string(raw.Locked)
	return nil
}

// DomainForward is Hover's account-level web forwarding state for a domain.
type DomainForward struct {
	Domain  string `json:"domain"`
	URL     string `json:"url"`
	Stealth bool   `json:"stealth"`
}

// GetTransferLock returns the registrar transfer-lock state for a domain.
func (c *Client) GetTransferLock(ctx context.Context, domainName string) (bool, error) {
	return c.backend.GetTransferLock(ctx, c, domainName)
}

func (c *Client) getTransferLockHTTP(ctx context.Context, domainName string) (bool, error) {
	domains, err := c.ListDomains(ctx)
	if err != nil {
		return false, fmt.Errorf("hover: GetTransferLock %q: %w", domainName, err)
	}
	for _, domain := range domains {
		if strings.EqualFold(domain.Name, domainName) {
			locked, ok := parseHoverLock(domain.Locked)
			if !ok {
				return false, fmt.Errorf("hover: GetTransferLock %q: lock state missing from /api/domains response", domainName)
			}
			return locked, nil
		}
	}
	return false, fmt.Errorf("hover: GetTransferLock %q: domain not found", domainName)
}

func parseHoverLock(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true", "locked", "1", "yes":
		return true, true
	case "off", "false", "unlocked", "0", "no":
		return false, true
	default:
		return false, false
	}
}

// GetForward returns Hover's root web-forwarding target for a domain.
func (c *Client) GetForward(ctx context.Context, domainName string) (*DomainForward, error) {
	return c.backend.GetForward(ctx, c, domainName)
}

func (c *Client) getForwardHTTP(ctx context.Context, domainName string) (*DomainForward, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/control_panel/forwards/%s", hoverHost, url.PathEscape(domainName))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("hover: GetForward %q: %w", domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover: GetForward %q: HTTP %d: %s", domainName, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var body struct {
		Succeeded bool `json:"succeeded"`
		Domain    struct {
			Name                string `json:"name"`
			Forward             string `json:"forward"`
			HasStealthRedirects bool   `json:"has_stealth_redirects"`
		} `json:"domain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("hover: GetForward %q: decode: %w", domainName, err)
	}
	if !body.Succeeded {
		return nil, fmt.Errorf("hover: GetForward %q: API returned succeeded=false", domainName)
	}
	if strings.TrimSpace(body.Domain.Forward) == "" {
		return nil, fmt.Errorf("%w: hover: GetForward %q: no root forward configured", ErrForwardNotFound, domainName)
	}
	name := body.Domain.Name
	if name == "" {
		name = domainName
	}
	return &DomainForward{
		Domain:  name,
		URL:     body.Domain.Forward,
		Stealth: body.Domain.HasStealthRedirects,
	}, nil
}

// SetForward updates Hover's root web-forwarding target for a domain.
func (c *Client) SetForward(ctx context.Context, domainName string, forward DomainForward) error {
	return c.backend.SetForward(ctx, c, domainName, forward)
}

func (c *Client) setForwardHTTP(ctx context.Context, domainName string, forward DomainForward) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureLoginLocked(ctx); err != nil {
		return err
	}
	csrf, err := c.fetchControlPanelCSRFLocked(ctx, domainName)
	if err != nil {
		return err
	}
	return c.putForwardLocked(ctx, domainName, forward, csrf)
}

func (c *Client) putForwardLocked(ctx context.Context, domainName string, forward DomainForward, csrf string) error {
	endpoint := hoverHost + "/api/control_panel/forwards"
	forwardID := fmt.Sprintf("hpr-domain-%s", domainName)
	payload := map[string]any{
		"domains": []map[string]any{{
			"id":       fmt.Sprintf("domain-%s", domainName),
			"forwards": []string{forwardID},
		}},
		"fields": map[string]any{
			"path":    domainName,
			"url":     forward.URL,
			"stealth": forward.Stealth,
			"type":    "root",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("hover: SetForward %q: marshal: %w", domainName, err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hover: SetForward %q: %w", domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hover: SetForward %q: HTTP %d: %s", domainName, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
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
	return c.backend.GetDomainDelegation(ctx, c, domainName)
}

// getDomainDelegationHTTP is the HTTP-backend implementation of GetDomainDelegation.
//
// Read path (in priority order):
//  1. NS cache (populated by listDomainsHTTP from GET /api/domains).
//     A non-empty cache hit short-circuits the network call entirely.
//  2. Per-domain fallback: GET /api/domains/<name>
//     Used when no prior ListDomains call has populated the cache.
//
// The old GET /api/control_panel/domains/domain-<name> is PUT-only on live
// Hover (returns 404 on GET). It is never used for reads.
func (c *Client) getDomainDelegationHTTP(ctx context.Context, domainName string) (*DomainDelegation, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}

	// 1. Check NS cache (populated by ListDomains).
	c.mu.Lock()
	cached, ok := c.domainNS[domainName]
	if ok {
		ns := make([]string, len(cached))
		copy(ns, cached)
		c.mu.Unlock()
		if len(ns) == 0 {
			return nil, fmt.Errorf("hover: GetDomainDelegation %q: %w", domainName, ErrEmptyNameservers)
		}
		return &DomainDelegation{Name: domainName, Nameservers: ns}, nil
	}
	c.mu.Unlock()

	// 2. Cache miss — fall back to per-domain GET /api/domains/<name>.
	endpoint := fmt.Sprintf("%s/api/domains/%s", hoverHost, url.PathEscape(domainName))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: %w", domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: HTTP %d: %s", domainName, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// The per-domain endpoint wraps the domain in {"succeeded":...,"domain":{...}}.
	var wrap struct {
		Succeeded bool   `json:"succeeded"`
		Domain    Domain `json:"domain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: decode: %w", domainName, err)
	}
	if len(wrap.Domain.Nameservers) == 0 {
		return nil, fmt.Errorf("hover: GetDomainDelegation %q: %w", domainName, ErrEmptyNameservers)
	}
	return &DomainDelegation{
		ID:          wrap.Domain.ID,
		Name:        wrap.Domain.Name,
		Nameservers: wrap.Domain.Nameservers,
	}, nil
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
// the full duration of the held-lock sequence. Worst case (session is
// stale and re-auth fires inside ensureLoginLocked):
//   - POST /signin/auth.json (credentials)
//   - POST /signin/auth2.json (TOTP code, only if MFA enabled)
//   - GET /control_panel/domain/<name> (CSRF for the API write)
//   - PUT /api/control_panel/domains/domain-<name>
//
// Up to ~180s at the 30s default per-request timeout when re-auth is
// needed; ~60s on the warm-session path (CSRF GET + PUT). Acceptable
// for the field-test scope (single goroutine, one delegation
// resource). Future: cache CSRF at session granularity if
// mixed-resource throughput becomes a concern.
func (c *Client) SetNameservers(ctx context.Context, domainName string, ns []string) error {
	return c.backend.SetNameservers(ctx, c, domainName, ns)
}

// SetTransferLock updates Hover's registrar transfer-lock setting.
func (c *Client) SetTransferLock(ctx context.Context, domainName string, locked bool) error {
	return c.backend.SetTransferLock(ctx, c, domainName, locked)
}

// setNameserversHTTP is the HTTP-backend implementation of SetNameservers.
func (c *Client) setNameserversHTTP(ctx context.Context, domainName string, ns []string) error {
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

func (c *Client) setTransferLockHTTP(ctx context.Context, domainName string, locked bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureLoginLocked(ctx); err != nil {
		return err
	}
	csrf, err := c.fetchControlPanelCSRFLocked(ctx, domainName)
	if err != nil {
		return err
	}
	return c.putControlPanelFieldLocked(ctx, domainName, "locked", locked, csrf)
}

// putNameserversLocked PUTs the nameservers list. Caller MUST hold c.mu.
//
// Note: the wire payload uses []string directly — encoding/json serializes
// it as a JSON array, which is what Hover expects. This is distinct from
// the []any requirement in ResourceOutput.Outputs (which crosses the
// structpb gRPC boundary); typed slices are fine here because the wire
// format is plain JSON, not structpb.
func (c *Client) putNameserversLocked(ctx context.Context, domainName string, ns []string, csrf string) error {
	return c.putControlPanelFieldLocked(ctx, domainName, "nameservers", ns, csrf)
}

func (c *Client) putControlPanelFieldLocked(ctx context.Context, domainName, field string, value any, csrf string) error {
	endpoint := fmt.Sprintf("%s/api/control_panel/domains/domain-%s", hoverHost, url.PathEscape(domainName))
	payload := map[string]any{"field": field, "value": value}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("hover: set control_panel field %q for %q: marshal: %w", field, domainName, err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hover: set control_panel field %q for %q: %w", field, domainName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hover: set control_panel field %q for %q: HTTP %d: %s", field, domainName, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// ListDomains fetches every domain in the authenticated account via the
// account-level GET /api/domains endpoint. The returned slice is the
// inverse-key of the SetNameservers / GetDomainDelegation / GetDomain
// surface (which all operate on a single named zone) — callers iterate
// the list to drive cross-zone operations like
// IaCProviderEnumerator.EnumerateAll("infra.dns").
//
// CSRF is not required for GET requests under Hover's API; ensureLogin
// is still called so the session cookie is fresh.
func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	return c.backend.ListDomains(ctx, c)
}

// listDomainsHTTP is the HTTP-backend implementation of ListDomains.
func (c *Client) listDomainsHTTP(ctx context.Context) ([]Domain, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, fmt.Errorf("hover: ListDomains: login: %w", err)
	}
	endpoint := hoverHost + "/api/domains"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("hover: ListDomains: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("hover: ListDomains: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hover: ListDomains: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var body struct {
		Succeeded bool     `json:"succeeded"`
		Domains   []Domain `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("hover: ListDomains: decode: %w", err)
	}
	if !body.Succeeded {
		return nil, fmt.Errorf("hover: ListDomains: API returned succeeded=false")
	}
	// Populate the NS cache so subsequent GetDomainDelegation calls can
	// short-circuit the per-domain GET (the list endpoint already includes
	// nameservers for every domain in one call).
	c.mu.Lock()
	if c.domainNS == nil {
		c.domainNS = make(map[string][]string, len(body.Domains))
	}
	for _, d := range body.Domains {
		if d.Name == "" {
			continue
		}
		ns := make([]string, len(d.Nameservers))
		copy(ns, d.Nameservers)
		c.domainNS[d.Name] = ns
	}
	c.mu.Unlock()
	return body.Domains, nil
}

// GetDomain returns the full Domain struct (including the
// hover-assigned ID) for the named zone. The ID is required when
// creating new records via CreateRecord; the human-readable name is
// not accepted by the POST /api/dns endpoint.
func (c *Client) GetDomain(ctx context.Context, domain string) (*Domain, error) {
	return c.backend.GetDomain(ctx, c, domain)
}

// getDomainHTTP is the HTTP-backend implementation of GetDomain.
func (c *Client) getDomainHTTP(ctx context.Context, domain string) (*Domain, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/domains/%s/dns", hoverHost, url.PathEscape(domain))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
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
	return c.backend.ListRecords(ctx, c, domain)
}

// listRecordsHTTP is the HTTP-backend implementation of ListRecords.
func (c *Client) listRecordsHTTP(ctx context.Context, domain string) ([]DNSRecord, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/domains/%s/dns", hoverHost, url.PathEscape(domain))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
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
	return c.backend.CreateRecord(ctx, c, domainID, rec)
}

// createRecordHTTP is the HTTP-backend implementation of CreateRecord.
func (c *Client) createRecordHTTP(ctx context.Context, domainID string, rec DNSRecord) (*DNSRecord, error) {
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
	return c.backend.UpdateRecord(ctx, c, recordID, rec)
}

// updateRecordHTTP is the HTTP-backend implementation of UpdateRecord.
func (c *Client) updateRecordHTTP(ctx context.Context, recordID string, rec DNSRecord) error {
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
	return c.backend.DeleteRecord(ctx, c, recordID)
}

// deleteRecordHTTP is the HTTP-backend implementation of DeleteRecord.
func (c *Client) deleteRecordHTTP(ctx context.Context, recordID string) error {
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
