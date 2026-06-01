package hoverclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
//  1. Navigate to /signin (Imperva JS runs, clearance cookies are minted).
//  2. Wait for Imperva clearance cookies.
//  3. Submit credentials via in-page fetch (same-origin XHR path).
//  4. Handle TOTP 2FA if required.
//  5. Copy all browser cookies into c.http.Jar for the hybrid HTTP reads.
//  6. Set c.loggedAt.
func (b *browserBackend) Login(ctx context.Context, c *Client) error {
	c.mu.Lock()
	alreadyFresh := !c.loggedAt.IsZero() && time.Since(c.loggedAt) < sessionStaleAfter
	c.mu.Unlock()
	if alreadyFresh {
		return nil
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

	// Wait for Imperva clearance cookies. If they never arrive → bot challenge.
	if _, err := waitForClearanceCookies(ctx, browser); err != nil {
		if isContextErr(err) {
			return fmt.Errorf("%w: %v", ErrBotChallenge, err)
		}
		return fmt.Errorf("%w: %v", ErrBotChallenge, err)
	}

	// Submit credentials via in-page fetch. The probe helper handles need_2fa
	// detection and TOTP; we post-process its errors to surface typed variants.
	if err := submitBrowserSignin(ctx, page, c.creds); err != nil {
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
	// HTTP 401/403 from auth endpoint → bot challenge.
	if strings.Contains(msg, "HTTP 401") || strings.Contains(msg, "HTTP 403") {
		return fmt.Errorf("%w: %v", ErrBotChallenge, err)
	}
	return err
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

// ---------------------------------------------------------------------------
// WRITE operations — Task 4 (not yet implemented, return sentinel).
// ---------------------------------------------------------------------------

func (b *browserBackend) CreateRecord(_ context.Context, _ *Client, _ string, _ DNSRecord) (*DNSRecord, error) {
	return nil, ErrBrowserBackendUnavailable
}

func (b *browserBackend) UpdateRecord(_ context.Context, _ *Client, _ string, _ DNSRecord) error {
	return ErrBrowserBackendUnavailable
}

func (b *browserBackend) DeleteRecord(_ context.Context, _ *Client, _ string) error {
	return ErrBrowserBackendUnavailable
}

func (b *browserBackend) SetNameservers(_ context.Context, _ *Client, _ string, _ []string) error {
	return ErrBrowserBackendUnavailable
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
