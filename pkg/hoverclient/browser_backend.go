package hoverclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoCodeAlone/rod"
	rodlauncher "github.com/GoCodeAlone/rod/lib/launcher"
	"github.com/GoCodeAlone/rod/lib/proto"
)

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

// ErrBrowserBackendUnavailable is returned by browserBackend write operations
// that are not yet implemented (Task 4). Callers should treat this as a
// "not yet implemented via browser" signal.
var ErrBrowserBackendUnavailable = errors.New("hover: browser backend not yet available for this operation (Task 4)")

// ErrBotChallenge is returned when Imperva (or another bot-protection layer)
// blocks the browser session: clearance cookies never arrive, or the login
// endpoint returns a persistent access-denied response. Operators should
// check network egress rules or rotate the browser profile.
var ErrBotChallenge = errors.New("hover: Imperva/bot challenge blocked the browser session — check network or rotate browser profile")

// ErrChromeUnavailable is returned when no Chrome binary can be found and
// BrowserOptions.Download is false. Install Chrome or set
// HOVER_BROWSER_DOWNLOAD=true to enable automatic download.
var ErrChromeUnavailable = errors.New("hover: no Chrome binary found; install Chrome or set HOVER_BROWSER_DOWNLOAD=true")

// ErrEmail2FARequired is returned when Hover reports need_2fa but no TOTP
// secret is configured on the Credentials. This means the account uses
// email-OTP or another non-TOTP second factor. Configure a TOTP authenticator
// app on the account and supply the base32 seed as totp_secret.
var ErrEmail2FARequired = errors.New("hover: account uses email/non-TOTP 2FA — configure an authenticator app (TOTP) on the account and supply totp_secret, or pre-trust this browser profile")

// ErrSigninThrottled is returned internally when Hover starts rate-limiting
// credential signin. Callers see it wrapped in ErrBotChallenge with an
// operator-facing cooldown message.
var ErrSigninThrottled = errors.New("hover: signin throttled")

const (
	signinThrottleCooldown = 30 * time.Minute
	signinCooldownFile     = ".hover-signin-cooldown.json"
)

// ---------------------------------------------------------------------------
// browserBackend
// ---------------------------------------------------------------------------

// browserBackend implements executionBackend using a Chrome instance driven
// via the GoCodeAlone/rod CDP library. Login mints Imperva clearance cookies
// and completes TOTP 2FA in-browser; subsequent read operations reuse those
// cookies via the Go http.Client (hybrid architecture).
//
// The browser and launcher handles are kept alive after Login so that Task 4
// can reuse the same page for in-browser writes. Close() tears them down.
type browserBackend struct {
	opts BrowserOptions

	// overrideHost replaces hoverHost for local tests. Empty means production
	// (uses hoverHost). Never set in production code.
	overrideHost string

	// Live handles, set by Login and torn down by Close.
	browser  *rod.Browser
	launcher *rodlauncher.Launcher
}

func newBrowserBackend(opts BrowserOptions) *browserBackend {
	return &browserBackend{opts: opts}
}

// signinHost returns the host to navigate to. In production this is hoverHost;
// in tests it is overrideHost.
func (b *browserBackend) signinHost() string {
	if b.overrideHost != "" {
		return b.overrideHost
	}
	return hoverHost
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// Login drives Chrome to:
//  1. Launch Chrome with the configured persistent profile.
//  2. Copy existing profile cookies into c.http.Jar and probe /api/domains.
//  3. If the probe is authenticated, reuse the warm session without login.
//  4. Otherwise navigate to /signin (Imperva JS runs, clearance cookies are minted).
//  5. Wait for Imperva clearance cookies.
//  6. Submit credentials via in-page fetch (same-origin XHR path).
//  7. Handle TOTP 2FA if required.
//  8. Copy all browser cookies into c.http.Jar for the hybrid HTTP reads.
//  9. Set c.loggedAt.
func (b *browserBackend) Login(ctx context.Context, c *Client) error {
	return b.login(ctx, c, true)
}

func (b *browserBackend) forceLogin(ctx context.Context, c *Client) error {
	c.mu.Lock()
	c.loggedAt = time.Time{}
	c.mu.Unlock()
	_ = b.Close()
	return b.login(ctx, c, false)
}

func (b *browserBackend) login(ctx context.Context, c *Client, allowWarmReuse bool) error {
	if allowWarmReuse {
		c.mu.Lock()
		alreadyFresh := !c.loggedAt.IsZero() && time.Since(c.loggedAt) < sessionStaleAfter
		c.mu.Unlock()
		if alreadyFresh {
			return nil
		}
	}

	if b.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.opts.Timeout)
		defer cancel()
	}

	// Resolve Chrome binary. If not found and Download is false → typed error.
	if b.opts.Path == "" {
		if _, ok := findChromeBinary(); !ok && !b.opts.Download {
			return ErrChromeUnavailable
		}
	} else {
		// Explicit path provided: validate it exists (unless Download would
		// handle it, but an explicit path means the operator chose a specific
		// binary — honor it literally).
		if _, err := os.Stat(b.opts.Path); err != nil && !b.opts.Download {
			return fmt.Errorf("%w: %s: %v", ErrChromeUnavailable, b.opts.Path, err)
		}
	}

	browser, l, err := b.launchBrowser(ctx)
	if err != nil {
		// launchBrowserWithHandles returns a plain error when Chrome isn't found;
		// wrap as ErrChromeUnavailable if it mentions Chrome.
		msg := err.Error()
		if strings.Contains(msg, "no Chrome") || strings.Contains(msg, "launch Chrome") || strings.Contains(msg, "connect Chrome") {
			return fmt.Errorf("%w: %v", ErrChromeUnavailable, err)
		}
		return err
	}
	// Keep handles for Close() and Task 4 page reuse.
	b.browser = browser
	b.launcher = l

	if err := b.handOffCookies(browser, c); err != nil {
		return fmt.Errorf("hover browser login: warm cookie handoff: %w", err)
	}
	if allowWarmReuse {
		if ok, err := b.probeExistingSession(ctx, c); err != nil {
			return fmt.Errorf("hover browser login: warm session probe: %w", err)
		} else if ok {
			_ = b.clearSigninCooldown()
			c.mu.Lock()
			c.loggedAt = time.Now()
			c.mu.Unlock()
			return nil
		}
	}
	if err := b.checkSigninCooldown(time.Now()); err != nil {
		return err
	}

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return fmt.Errorf("hover browser login: new page: %w", err)
	}
	defer func() { _ = page.Close() }()
	page = page.Context(ctx)

	// Strip navigator.webdriver fingerprint.
	_, _ = page.EvalOnNewDocument(`() => {
		Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
	}`)

	// Set a consistent UA + Accept-Language (matching the Chrome build we launched).
	_ = page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent:      defaultUserAgent,
		AcceptLanguage: "en-US,en;q=0.9",
		Platform:       "macOS",
	})

	// Navigate to signin.
	signinURL := b.signinHost() + "/signin"
	if err := page.Navigate(signinURL); err != nil {
		return fmt.Errorf("hover browser login: navigate signin: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		return fmt.Errorf("hover browser login: wait signin load: %w", err)
	}

	// Wait for Imperva clearance cookies. A timeout/cancel means clearance was
	// never minted → treat as a bot challenge. A genuine cookie-read failure is
	// a browser malfunction, not a challenge — surface it as-is.
	if _, err := waitForClearanceCookies(ctx, browser); err != nil {
		if isContextErr(err) {
			return fmt.Errorf("%w: clearance cookies not minted: %v", ErrBotChallenge, err)
		}
		return fmt.Errorf("hover browser login: read clearance cookies: %w", err)
	}

	// Submit credentials via in-page fetch. The probe helper handles need_2fa
	// detection and TOTP; we post-process its errors to surface typed variants.
	if err := submitBrowserSignin(ctx, page, c.creds); err != nil {
		if errors.Is(err, ErrSigninThrottled) {
			_ = b.markSigninCooldown(time.Now(), err.Error())
		}
		return b.classifySigninError(err)
	}

	// Copy all browser cookies into the Go http.Client jar so HTTP reads reuse
	// the Imperva clearance + session cookies (hybrid architecture).
	if err := b.handOffCookies(browser, c); err != nil {
		return fmt.Errorf("hover browser login: cookie handoff: %w", err)
	}

	c.mu.Lock()
	c.loggedAt = time.Now()
	c.mu.Unlock()
	_ = b.clearSigninCooldown()
	return nil
}

// classifySigninError maps submitBrowserSignin errors to typed errors where
// appropriate. The probe helper already returns clear English strings; we
// wrap them into the appropriate sentinel so callers can errors.Is them.
func (b *browserBackend) classifySigninError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// need_2fa without TOTP secret — emit the dedicated typed error.
	if strings.Contains(msg, "no totp_secret") || strings.Contains(msg, "totp_secret was provided") {
		return fmt.Errorf("%w: %v", ErrEmail2FARequired, err)
	}
	if errors.Is(err, ErrSigninThrottled) {
		return fmt.Errorf("%w: Hover signin is throttled; cached profile cooldown is active for %s: %v", ErrBotChallenge, signinThrottleCooldown, err)
	}
	// HTTP 401/403/429 from auth endpoint → bot/rate challenge.
	if strings.Contains(msg, "HTTP 401") || strings.Contains(msg, "HTTP 403") || strings.Contains(msg, "HTTP 429") {
		return fmt.Errorf("%w: %v", ErrBotChallenge, err)
	}
	return err
}

type signinCooldownMarker struct {
	Until  time.Time `json:"until"`
	Reason string    `json:"reason,omitempty"`
}

func (b *browserBackend) signinCooldownPath() string {
	if b.opts.ProfileDir == "" {
		return ""
	}
	return filepath.Join(b.opts.ProfileDir, signinCooldownFile)
}

func (b *browserBackend) checkSigninCooldown(now time.Time) error {
	path := b.signinCooldownPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hover browser login: read signin cooldown marker: %w", err)
	}
	var marker signinCooldownMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		_ = os.Remove(path)
		return nil
	}
	if marker.Until.IsZero() || !now.Before(marker.Until) {
		_ = os.Remove(path)
		return nil
	}
	return fmt.Errorf("%w: Hover signin was throttled recently; retry after %s or reuse a valid cached browser session", ErrBotChallenge, marker.Until.Format(time.RFC3339))
}

func (b *browserBackend) markSigninCooldown(now time.Time, reason string) error {
	path := b.signinCooldownPath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	marker := signinCooldownMarker{
		Until:  now.Add(signinThrottleCooldown).UTC(),
		Reason: reason,
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (b *browserBackend) clearSigninCooldown() error {
	path := b.signinCooldownPath()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// launchBrowser launches Chrome and returns the browser + launcher handles.
// It honours HOVER_BROWSER_NO_SANDBOX when set. --no-sandbox is intentionally
// not on by default (it weakens sandbox security); it is only applied when an
// operator explicitly sets the env var.
func (b *browserBackend) launchBrowser(ctx context.Context) (*rod.Browser, *rodlauncher.Launcher, error) {
	return launchBrowserWithHandles(ctx, b.opts)
}

// handOffCookies copies every cookie the browser holds into c.http.Jar for
// the signinHost. This lets the Go http.Client reuse Imperva clearance
// and session cookies for all subsequent read operations.
func (b *browserBackend) handOffCookies(browser *rod.Browser, c *Client) error {
	cookies, err := browser.GetCookies()
	if err != nil {
		return fmt.Errorf("get browser cookies: %w", err)
	}
	// Determine the jar target URL. In production this is hoverHost; in tests
	// it is overrideHost (the fake httptest server).
	targetURLStr := b.signinHost()
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		return fmt.Errorf("parse host URL %q: %w", targetURLStr, err)
	}

	var httpCookies []*http.Cookie
	for _, cookie := range cookies {
		httpCookies = append(httpCookies, &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
		})
	}
	if c.http.Jar != nil {
		c.http.Jar.SetCookies(targetURL, httpCookies)
	}
	return nil
}

func (b *browserBackend) syncJarCookiesToBrowser(ctx context.Context, c *Client) error {
	if b.browser == nil || c.http.Jar == nil {
		return nil
	}
	targetURL, err := url.Parse(b.signinHost())
	if err != nil {
		return fmt.Errorf("parse host URL %q: %w", b.signinHost(), err)
	}
	cookies := c.http.Jar.Cookies(targetURL)
	if len(cookies) == 0 {
		return nil
	}
	cookieURL := targetURL.String()
	var params []*proto.NetworkCookieParam
	for _, cookie := range cookies {
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		params = append(params, &proto.NetworkCookieParam{
			Name:     cookie.Name,
			Value:    cookie.Value,
			URL:      cookieURL,
			Path:     path,
			Secure:   cookie.Secure || targetURL.Scheme == "https",
			HTTPOnly: cookie.HttpOnly,
		})
	}
	if err := b.browser.Context(ctx).SetCookies(params); err != nil {
		return fmt.Errorf("set browser cookies from jar: %w", err)
	}
	return nil
}

func (b *browserBackend) probeExistingSession(ctx context.Context, c *Client) (bool, error) {
	endpoint := b.signinHost() + "/api/domains"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, nil
	}
	var body struct {
		Succeeded bool `json:"succeeded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, nil
	}
	return body.Succeeded, nil
}

// ---------------------------------------------------------------------------
// READ operations — delegate to the HTTP backend after ensuring login.
// ---------------------------------------------------------------------------

func (b *browserBackend) ensureLoggedIn(ctx context.Context, c *Client) error {
	return b.Login(ctx, c)
}

func (b *browserBackend) ListDomains(ctx context.Context, c *Client) ([]Domain, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return nil, err
	}
	return c.listDomainsHTTP(ctx)
}

func (b *browserBackend) GetDomain(ctx context.Context, c *Client, domain string) (*Domain, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return nil, err
	}
	return c.getDomainHTTP(ctx, domain)
}

func (b *browserBackend) ListRecords(ctx context.Context, c *Client, domain string) ([]DNSRecord, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return nil, err
	}
	return c.listRecordsHTTP(ctx, domain)
}

func (b *browserBackend) GetDomainDelegation(ctx context.Context, c *Client, domainName string) (*DomainDelegation, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return nil, err
	}
	return c.getDomainDelegationHTTP(ctx, domainName)
}

func (b *browserBackend) GetTransferLock(ctx context.Context, c *Client, domainName string) (bool, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return false, err
	}
	return c.getTransferLockHTTP(ctx, domainName)
}

func (b *browserBackend) GetForward(ctx context.Context, c *Client, domainName string) (*DomainForward, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return nil, err
	}
	return c.getForwardHTTP(ctx, domainName)
}

// ---------------------------------------------------------------------------
// WRITE operations — Task 4: in-browser DNS writes (hybrid write path).
//
// All four methods run the HTTP request in-page inside an authenticated Chrome
// page (credentials:'include'). This ensures the request carries Chrome's TLS
// fingerprint and the live Imperva clearance cookies — necessary for Hover's
// bot-protection layer to accept mutations.
//
// Pattern per method:
//  1. Ensure logged in (b.Login re-uses the fresh session when < sessionStaleAfter).
//  2. Open a fresh page on the live browser (pages are cheap; closing them is safe).
//  3. Navigate to a Hover page so the origin matches (required for same-origin
//     credentials:'include' fetch to be accepted by the browser security model).
//  4. Execute the HTTP request via browserFetchWithHeaders / browserFetchJSON.
//  5. Parse the response on the Go side and return typed errors.
// ---------------------------------------------------------------------------

// openWritePage opens a new browser page on the live browser, navigates it to
// base+"/api/dns" to establish the same-origin context required for
// credentials:'include' fetch calls. The caller is responsible for closing the
// page via the returned cleanup func.
//
// b.browser.Context(ctx) returns a temporary clone of the browser that uses ctx
// rather than the browser's internal (potentially-expired login-timeout) context,
// so new page creation honours the caller's deadline rather than the login one.
func (b *browserBackend) openWritePage(ctx context.Context, base string) (*rod.Page, func(), error) {
	if b.browser == nil {
		return nil, nil, fmt.Errorf("hover browser write: browser not initialised (Login must succeed before write operations)")
	}
	page, err := b.browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, nil, fmt.Errorf("hover browser write: new page: %w", err)
	}
	page = page.Context(ctx)
	// Navigate to any Hover page so `fetch` calls in-page are treated as
	// same-origin requests (credentials:'include' requires matching origins).
	// We use /api/dns because it's a stable, lightweight JSON endpoint.
	if err := page.Navigate(base + "/api/dns"); err != nil {
		_ = page.Close()
		return nil, nil, fmt.Errorf("hover browser write: navigate: %w", err)
	}
	_ = page.WaitLoad()
	cleanup := func() { _ = page.Close() }
	return page, cleanup, nil
}

// CreateRecord adds a new DNS record for the domain. Executes POST /api/dns
// in-page with application/x-www-form-urlencoded payload, matching the HTTP
// backend exactly but running inside Chrome's TLS session.
func (b *browserBackend) CreateRecord(ctx context.Context, c *Client, domainID string, rec DNSRecord) (*DNSRecord, error) {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return nil, err
	}
	base := b.signinHost()
	page, cleanup, err := b.openWritePage(ctx, base)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	form := map[string]any{
		"domain_id": domainID,
		"name":      rec.Name,
		"type":      rec.Type,
		"content":   rec.Content,
	}
	if rec.TTL > 0 {
		form["ttl"] = fmt.Sprintf("%d", rec.TTL)
	}

	rawBody, code, err := browserFetchJSON(ctx, page, "POST", base+"/api/dns",
		"application/x-www-form-urlencoded", form)
	if err != nil {
		return nil, fmt.Errorf("hover browser CreateRecord: fetch: %w", err)
	}
	if code >= 400 {
		return nil, fmt.Errorf("hover browser CreateRecord: HTTP %d: %s", code, strings.TrimSpace(rawBody))
	}
	var out struct {
		DNSRecord DNSRecord `json:"dns_record"`
	}
	if err := json.Unmarshal([]byte(rawBody), &out); err != nil {
		return nil, fmt.Errorf("hover browser CreateRecord: parse response: %w", err)
	}
	return &out.DNSRecord, nil
}

// UpdateRecord updates an existing DNS record. Executes PUT /api/dns/<recordID>
// in-page with application/x-www-form-urlencoded payload.
func (b *browserBackend) UpdateRecord(ctx context.Context, c *Client, recordID string, rec DNSRecord) error {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return err
	}
	base := b.signinHost()
	page, cleanup, err := b.openWritePage(ctx, base)
	if err != nil {
		return err
	}
	defer cleanup()

	form := map[string]any{"content": rec.Content}
	if rec.TTL > 0 {
		form["ttl"] = fmt.Sprintf("%d", rec.TTL)
	}
	endpoint := fmt.Sprintf("%s/api/dns/%s", base, url.PathEscape(recordID))
	rawBody, code, err := browserFetchJSON(ctx, page, "PUT", endpoint,
		"application/x-www-form-urlencoded", form)
	if err != nil {
		return fmt.Errorf("hover browser UpdateRecord %q: fetch: %w", recordID, err)
	}
	if code >= 400 {
		return fmt.Errorf("hover browser UpdateRecord %q: HTTP %d: %s", recordID, code, strings.TrimSpace(rawBody))
	}
	return nil
}

// DeleteRecord removes a DNS record by ID. Executes DELETE /api/dns/<recordID>
// in-page (no body).
func (b *browserBackend) DeleteRecord(ctx context.Context, c *Client, recordID string) error {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return err
	}
	base := b.signinHost()
	page, cleanup, err := b.openWritePage(ctx, base)
	if err != nil {
		return err
	}
	defer cleanup()

	endpoint := fmt.Sprintf("%s/api/dns/%s", base, url.PathEscape(recordID))
	rawBody, code, err := browserFetchJSON(ctx, page, "DELETE", endpoint, "", nil)
	if err != nil {
		return fmt.Errorf("hover browser DeleteRecord %q: fetch: %w", recordID, err)
	}
	if code >= 400 {
		return fmt.Errorf("hover browser DeleteRecord %q: HTTP %d: %s", recordID, code, strings.TrimSpace(rawBody))
	}
	return nil
}

// SetNameservers updates the registrar-level nameservers for a domain.
// Rejects empty ns immediately (same invariant as the HTTP backend).
// CSRF token is extracted in-browser from the control_panel domain page, then
// a PUT is issued in-page with the CSRF token in X-CSRF-Token.
func (b *browserBackend) SetNameservers(ctx context.Context, c *Client, domainName string, ns []string) error {
	if len(ns) == 0 {
		return fmt.Errorf("hover: SetNameservers %q: %w", domainName, ErrEmptyNameservers)
	}
	return b.setControlPanelField(ctx, c, "SetNameservers", domainName, "nameservers", ns)
}

func (b *browserBackend) SetTransferLock(ctx context.Context, c *Client, domainName string, locked bool) error {
	return b.setControlPanelField(ctx, c, "SetTransferLock", domainName, "locked", locked)
}

func (b *browserBackend) SetForward(ctx context.Context, c *Client, domainName string, forward DomainForward) error {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return err
	}
	rawBody, code, err := b.setForwardOnce(ctx, c, domainName, forward)
	if err != nil {
		return err
	}
	if isHoverLoginResponse(code, rawBody) {
		fmt.Fprintf(os.Stderr, "hover browser SetForward %q: session rejected by Hover; revalidating cached browser session\n", domainName)
		if ok, probeErr := b.revalidateBrowserSession(ctx, c); probeErr != nil {
			return fmt.Errorf("hover browser SetForward %q: revalidate browser session after HTTP %d: %w", domainName, code, probeErr)
		} else if ok {
			rawBody, code, err = b.setForwardOnce(ctx, c, domainName, forward)
			if err != nil {
				return err
			}
		}
	}
	if isHoverLoginResponse(code, rawBody) {
		fmt.Fprintf(os.Stderr, "hover browser SetForward %q: cached browser session still rejected; refreshing login and retrying once\n", domainName)
		if err := b.forceLogin(ctx, c); err != nil {
			return fmt.Errorf("hover browser SetForward %q: refresh login after HTTP %d: %w", domainName, code, err)
		}
		rawBody, code, err = b.setForwardOnce(ctx, c, domainName, forward)
		if err != nil {
			return err
		}
	}
	if code >= 400 {
		return fmt.Errorf("hover browser SetForward %q: HTTP %d: %s", domainName, code, strings.TrimSpace(rawBody))
	}
	return nil
}

func (b *browserBackend) setControlPanelField(ctx context.Context, c *Client, operation, domainName, field string, value any) error {
	if err := b.ensureLoggedIn(ctx, c); err != nil {
		return err
	}
	rawBody, code, err := b.setControlPanelFieldOnce(ctx, c, operation, domainName, field, value)
	if err != nil {
		return err
	}
	if isHoverLoginResponse(code, rawBody) {
		fmt.Fprintf(os.Stderr, "hover browser %s %q: session rejected by Hover; revalidating cached browser session\n", operation, domainName)
		if ok, probeErr := b.revalidateBrowserSession(ctx, c); probeErr != nil {
			return fmt.Errorf("hover browser %s %q: revalidate browser session after HTTP %d: %w", operation, domainName, code, probeErr)
		} else if ok {
			rawBody, code, err = b.setControlPanelFieldOnce(ctx, c, operation, domainName, field, value)
			if err != nil {
				return err
			}
		}
	}
	if isHoverLoginResponse(code, rawBody) {
		fmt.Fprintf(os.Stderr, "hover browser %s %q: cached browser session still rejected; refreshing login and retrying once\n", operation, domainName)
		if err := b.forceLogin(ctx, c); err != nil {
			return fmt.Errorf("hover browser %s %q: refresh login after HTTP %d: %w", operation, domainName, code, err)
		}
		rawBody, code, err = b.setControlPanelFieldOnce(ctx, c, operation, domainName, field, value)
		if err != nil {
			return err
		}
	}
	if code >= 400 {
		return fmt.Errorf("hover browser %s %q: HTTP %d: %s", operation, domainName, code, strings.TrimSpace(rawBody))
	}
	return nil
}

func (b *browserBackend) revalidateBrowserSession(ctx context.Context, c *Client) (bool, error) {
	if b.browser == nil {
		return false, nil
	}
	base := b.signinHost()
	if err := b.syncJarCookiesToBrowser(ctx, c); err != nil {
		return false, fmt.Errorf("cookie sync: %w", err)
	}
	page, cleanup, err := b.openWritePage(ctx, base)
	if err != nil {
		return false, err
	}
	defer cleanup()

	rawBody, code, err := browserFetchJSON(ctx, page, "GET", base+"/api/domains", "", nil)
	if err != nil {
		return false, fmt.Errorf("probe /api/domains: %w", err)
	}
	if code < 200 || code >= 300 {
		return false, nil
	}
	var body struct {
		Succeeded bool `json:"succeeded"`
	}
	if err := json.Unmarshal([]byte(rawBody), &body); err != nil {
		return false, nil
	}
	if !body.Succeeded {
		return false, nil
	}
	if err := b.handOffCookies(b.browser.Context(ctx), c); err != nil {
		return false, fmt.Errorf("cookie handoff: %w", err)
	}
	c.mu.Lock()
	c.loggedAt = time.Now()
	c.mu.Unlock()
	return true, nil
}

func (b *browserBackend) setNameserversOnce(ctx context.Context, c *Client, domainName string, ns []string) (string, int, error) {
	return b.setControlPanelFieldOnce(ctx, c, "SetNameservers", domainName, "nameservers", ns)
}

func (b *browserBackend) setForwardOnce(ctx context.Context, c *Client, domainName string, forward DomainForward) (string, int, error) {
	if b.browser == nil {
		return "", 0, fmt.Errorf("hover browser SetForward: browser not initialised (Login must succeed before write operations)")
	}
	base := b.signinHost()
	if err := b.syncJarCookiesToBrowser(ctx, c); err != nil {
		return "", 0, fmt.Errorf("hover browser SetForward: cookie sync: %w", err)
	}

	page, err := b.browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return "", 0, fmt.Errorf("hover browser SetForward: new page: %w", err)
	}
	page = page.Context(ctx)
	defer func() { _ = page.Close() }()

	cpURL := fmt.Sprintf("%s/control_panel/domain/%s/forwards", base, url.PathEscape(domainName))
	if err := page.Navigate(cpURL); err != nil {
		return "", 0, fmt.Errorf("hover browser SetForward: navigate forwards: %w", err)
	}
	_ = page.WaitLoad()

	obj, err := page.Context(ctx).Eval(`() => {
		const m = document.querySelector('meta[name="csrf-token"]');
		return m ? m.getAttribute('content') : '';
	}`)
	if err != nil {
		return "", 0, fmt.Errorf("hover browser SetForward: eval CSRF: %w", err)
	}
	csrf := obj.Value.String()

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
	headers := map[string]string{}
	if csrf != "" {
		headers["X-CSRF-Token"] = csrf
	}
	rawBody, code, err := browserFetchWithHeaders(ctx, page, "PUT", base+"/api/control_panel/forwards",
		"application/json;charset=UTF-8", payload, headers)
	if err != nil {
		return "", 0, fmt.Errorf("hover browser SetForward %q: fetch: %w", domainName, err)
	}
	return rawBody, code, nil
}

func (b *browserBackend) setControlPanelFieldOnce(ctx context.Context, c *Client, operation, domainName, field string, value any) (string, int, error) {
	if b.browser == nil {
		return "", 0, fmt.Errorf("hover browser %s: browser not initialised (Login must succeed before write operations)", operation)
	}
	base := b.signinHost()
	if err := b.syncJarCookiesToBrowser(ctx, c); err != nil {
		return "", 0, fmt.Errorf("hover browser %s: cookie sync: %w", operation, err)
	}

	// Open a page and navigate to the control_panel domain page to read the CSRF.
	// Use browser.Context(ctx) to override the browser's stored (login-timeout)
	// context so new page creation honours the caller's deadline.
	page, err := b.browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return "", 0, fmt.Errorf("hover browser %s: new page: %w", operation, err)
	}
	page = page.Context(ctx)
	defer func() { _ = page.Close() }()

	cpURL := fmt.Sprintf("%s/control_panel/domain/%s", base, url.PathEscape(domainName))
	if err := page.Navigate(cpURL); err != nil {
		return "", 0, fmt.Errorf("hover browser %s: navigate control_panel: %w", operation, err)
	}
	_ = page.WaitLoad()

	// Extract the CSRF meta tag via JavaScript DOM access.
	obj, err := page.Context(ctx).Eval(`() => {
		const m = document.querySelector('meta[name="csrf-token"]');
		return m ? m.getAttribute('content') : '';
	}`)
	if err != nil {
		return "", 0, fmt.Errorf("hover browser %s: eval CSRF: %w", operation, err)
	}
	csrf := obj.Value.String()

	// Build PUT endpoint + payload (same as HTTP backend).
	putEndpoint := fmt.Sprintf("%s/api/control_panel/domains/domain-%s", base, url.PathEscape(domainName))
	payload := map[string]any{"field": field, "value": value}
	headers := map[string]string{}
	if csrf != "" {
		headers["X-CSRF-Token"] = csrf
	}

	rawBody, code, err := browserFetchWithHeaders(ctx, page, "PUT", putEndpoint,
		"application/json", payload, headers)
	if err != nil {
		return "", 0, fmt.Errorf("hover browser %s %q: fetch: %w", operation, domainName, err)
	}
	return rawBody, code, nil
}

func isHoverLoginResponse(code int, rawBody string) bool {
	body := strings.ToLower(rawBody)
	return code == http.StatusUnauthorized &&
		(strings.Contains(body, `"error_code":"login"`) ||
			strings.Contains(body, `"error_code": "login"`) ||
			strings.Contains(body, "you must login first"))
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

// Close tears down the browser process and CDP launcher. The profile directory
// is preserved (Kill, not Cleanup) so Imperva clearance cookies persist across
// calls. Safe to call multiple times.
func (b *browserBackend) Close() error {
	if b.browser != nil {
		_ = b.browser.Close()
		b.browser = nil
	}
	if b.launcher != nil {
		b.launcher.Kill()
		b.launcher = nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// isContextErr returns true when the error is a context cancellation or
// deadline exceeded.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// launchBrowserWithHandles launches Chrome and returns the rod.Browser and
// *rodlauncher.Launcher so the caller can manage the full lifecycle (including
// Kill on teardown without deleting the profile dir).
//
// We re-implement the launch sequence rather than delegating to
// launchProbeBrowser because that function encapsulates the launcher handle
// inside the cleanup closure, giving callers no way to store it.
func launchBrowserWithHandles(ctx context.Context, opts BrowserOptions) (*rod.Browser, *rodlauncher.Launcher, error) {
	if err := os.MkdirAll(opts.ProfileDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("hover browser: create profile dir: %w", err)
	}

	noSandbox := os.Getenv("HOVER_BROWSER_NO_SANDBOX") == "true"

	l := rodlauncher.New().
		Context(ctx).
		HeadlessNew(opts.Headless).
		UserDataDir(opts.ProfileDir)

	if noSandbox {
		l = l.Set("no-sandbox")
	}

	if opts.Path != "" {
		l = l.Bin(opts.Path)
	} else if path, ok := findChromeBinary(); ok {
		l = l.Bin(path)
	} else if !opts.Download {
		return nil, nil, fmt.Errorf("hover browser: no Chrome found; install Chrome or set HOVER_BROWSER_DOWNLOAD=true")
	}

	controlURL, err := l.Launch()
	if err != nil {
		return nil, nil, fmt.Errorf("hover browser: launch Chrome: %w", err)
	}
	browser := rod.New().Context(ctx).ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		l.Kill()
		return nil, nil, fmt.Errorf("hover browser: connect Chrome: %w", err)
	}
	return browser, l, nil
}
