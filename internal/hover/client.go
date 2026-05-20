package hover

import (
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

// ensureLogin re-authenticates iff the session is stale. Safe to call
// before every API hit; idempotent within sessionStaleAfter.
func (c *Client) ensureLogin(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
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

	// Step 2 — submit TOTP. Hover re-issues a fresh `_token` on the
	// TOTP page; refetch.
	csrf2, err := c.fetchTOTPCSRF(ctx)
	if err != nil {
		return err
	}
	code := c.creds.TOTPSecret.Code()
	form = url.Values{
		"code":   {code},
		"_token": {csrf2},
	}
	if err := c.postForm(ctx, hoverHost+"/signin/totp", form); err != nil {
		return fmt.Errorf("hover signin step 2 (totp): %w", err)
	}

	c.loggedAt = time.Now()
	return nil
}

var csrfRe = regexp.MustCompile(`<input[^>]+name="_token"[^>]+value="([^"]+)"`)

func (c *Client) fetchSignInCSRF(ctx context.Context) (string, error) {
	return c.fetchCSRF(ctx, hoverHost+"/signin")
}

func (c *Client) fetchTOTPCSRF(ctx context.Context) (string, error) {
	return c.fetchCSRF(ctx, hoverHost+"/signin/totp")
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
