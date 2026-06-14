package hoverclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoCodeAlone/rod"
	"github.com/GoCodeAlone/rod/lib/launcher"
	"github.com/GoCodeAlone/rod/lib/proto"
)

// LiveAuthProbeResult captures the live Hover browser-auth viability signal.
type LiveAuthProbeResult struct {
	LoginSucceeded    bool
	ClearanceCookies  []string
	GoHTTPReuseViable bool
	DomainCount       int
}

func (r LiveAuthProbeResult) ClearanceCookieNames() []string {
	out := append([]string(nil), r.ClearanceCookies...)
	return out
}

// ProbeLiveBrowserAuth exercises real Chrome against Hover. It is intended for
// opt-in live tests only; it never logs credentials or TOTP material.
func ProbeLiveBrowserAuth(ctx context.Context, creds Credentials, opts BrowserOptions) (LiveAuthProbeResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultBrowserTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	browser, cleanup, err := launchProbeBrowser(ctx, opts)
	if err != nil {
		return LiveAuthProbeResult{}, err
	}
	defer cleanup()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return LiveAuthProbeResult{}, fmt.Errorf("hover browser probe: new page: %w", err)
	}
	defer func() { _ = page.Close() }()
	page = page.Context(ctx)
	_, _ = page.EvalOnNewDocument(`() => {
		Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
	}`)
	_ = page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent:      defaultUserAgent,
		AcceptLanguage: "en-US,en;q=0.9",
		Platform:       "macOS",
	})
	if err := page.Navigate(hoverHost + "/signin"); err != nil {
		return LiveAuthProbeResult{}, fmt.Errorf("hover browser probe: navigate signin: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		return LiveAuthProbeResult{}, fmt.Errorf("hover browser probe: wait signin load: %w", err)
	}

	clearance, err := waitForClearanceCookies(ctx, browser)
	if err != nil {
		return LiveAuthProbeResult{}, err
	}
	if err := submitBrowserSignin(ctx, page, creds); err != nil {
		return LiveAuthProbeResult{}, err
	}
	domains, httpReuse := probeGoHTTPReuse(ctx, browser)
	return LiveAuthProbeResult{
		LoginSucceeded:    true,
		ClearanceCookies:  clearance,
		GoHTTPReuseViable: httpReuse,
		DomainCount:       domains,
	}, nil
}

func launchProbeBrowser(ctx context.Context, opts BrowserOptions) (*rod.Browser, func(), error) {
	if err := os.MkdirAll(opts.ProfileDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("hover browser probe: create profile dir: %w", err)
	}
	// Local launcher: UserDataDir persists by default; Cleanup() would delete it
	// (and KeepUserDataDir() panics on a non-managed launcher), so keep the
	// profile dir and use Kill() in cleanup to tear down only the process. This
	// preserves the Imperva clearance/cookie state across calls.
	launcher := launcher.New().
		Context(ctx).
		HeadlessNew(opts.Headless).
		UserDataDir(opts.ProfileDir)

	if opts.Path != "" {
		launcher = launcher.Bin(opts.Path)
	} else if path, ok := findChromeBinary(); ok {
		launcher = launcher.Bin(path)
	} else if !opts.Download {
		return nil, nil, fmt.Errorf("hover browser probe: no Chrome found; install Chrome or set HOVER_BROWSER_DOWNLOAD=true")
	}
	controlURL, err := launcher.Launch()
	if err != nil {
		return nil, nil, fmt.Errorf("hover browser probe: launch Chrome: %w", err)
	}
	browser := rod.New().Context(ctx).ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		launcher.Kill()
		return nil, nil, fmt.Errorf("hover browser probe: connect Chrome: %w", err)
	}
	cleanup := func() {
		_ = browser.Close()
		launcher.Kill()
	}
	return browser, cleanup, nil
}

func findChromeBinary() (string, bool) {
	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}
	for _, candidate := range candidates {
		if filepath.IsAbs(candidate) {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate, true
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, true
		}
	}
	return "", false
}

func waitForClearanceCookies(ctx context.Context, browser *rod.Browser) ([]string, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		names, err := clearanceCookieNames(browser)
		if err != nil {
			return nil, fmt.Errorf("hover browser probe: read cookies: %w", err)
		}
		if len(names) > 0 {
			return names, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("hover browser probe: wait for Imperva clearance cookies: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func clearanceCookieNames(browser *rod.Browser) ([]string, error) {
	cookies, err := browser.GetCookies()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, cookie := range cookies {
		if isClearanceCookie(cookie.Name) && !seen[cookie.Name] {
			seen[cookie.Name] = true
			names = append(names, cookie.Name)
		}
	}
	return names, nil
}

func isClearanceCookie(name string) bool {
	switch name {
	case "__uzma", "__uzmb", "__uzmc", "__uzmd", "__uzme", "uzmx":
		return true
	default:
		return strings.HasPrefix(name, "__ss")
	}
}

type browserSigninResult struct {
	OK            bool   `json:"ok"`
	HTTPCode      int    `json:"httpCode"`
	RetryableSeen bool   `json:"-"`
	Succeeded     *bool  `json:"succeeded"`
	Status        string `json:"status"`
	Error         string `json:"error"`
	Raw           string `json:"raw"`
}

func submitBrowserSignin(ctx context.Context, page *rod.Page, creds Credentials) error {
	result, err := browserSigninFetchWithRetry(ctx, page, "/signin/auth.json", map[string]any{
		"username": creds.Username,
		"password": creds.Password,
		"remember": false,
		"token":    nil,
	})
	if err != nil {
		return err
	}
	if result.Status == "need_2fa" {
		if creds.TOTPSecret.key == nil {
			return fmt.Errorf("hover: account has MFA enabled but no totp_secret was provided")
		}
		result, err = browserSigninFetchWithRetry(ctx, page, "/signin/auth2.json", map[string]any{
			"code":     creds.TOTPSecret.Code(),
			"remember": false,
		})
		if err != nil {
			return err
		}
	}
	if !result.OK {
		if result.RetryableSeen {
			return fmt.Errorf("%w: HTTP %d: %s", ErrSigninThrottled, result.HTTPCode, summarizeSigninRaw(result.Raw))
		}
		if result.Error != "" {
			return fmt.Errorf("hover browser signin: HTTP %d: %s", result.HTTPCode, result.Error)
		}
		return fmt.Errorf("hover browser signin: HTTP %d: %s", result.HTTPCode, summarizeSigninRaw(result.Raw))
	}
	if result.Error != "" {
		return fmt.Errorf("hover browser signin: %s", result.Error)
	}
	if result.Succeeded != nil && !*result.Succeeded {
		return fmt.Errorf("hover browser signin: did not complete: %s", summarizeSigninRaw(result.Raw))
	}
	if result.Status != "" && result.Status != "completed" {
		return fmt.Errorf("hover browser signin: unexpected status %q: %s", result.Status, summarizeSigninRaw(result.Raw))
	}
	return nil
}

func browserSigninFetchWithRetry(ctx context.Context, page *rod.Page, endpoint string, payload map[string]any) (browserSigninResult, error) {
	var result browserSigninResult
	var err error
	retryableSeen := false
	for attempt := 0; ; attempt++ {
		result, err = browserSigninFetch(ctx, page, endpoint, payload)
		if err != nil {
			return browserSigninResult{}, err
		}
		if isRetryableBrowserSigninStatus(result.HTTPCode) {
			retryableSeen = true
		}
		result.RetryableSeen = retryableSeen
		if !isRetryableBrowserSigninStatus(result.HTTPCode) || attempt >= maxRetries {
			return result, nil
		}
		wait := retryBaseDelay << attempt
		if wait > maxBackoffCap {
			wait = maxBackoffCap
		}
		fmt.Fprintf(os.Stderr, "hover browser signin: HTTP %d from %s; retrying in %s\n", result.HTTPCode, endpoint, wait)
		select {
		case <-ctx.Done():
			return browserSigninResult{}, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func isRetryableBrowserSigninStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

func summarizeSigninRaw(raw string) string {
	summary := strings.TrimSpace(raw)
	if len(summary) > 300 {
		summary = summary[:300] + "...(truncated)"
	}
	return summary
}

func browserSigninFetch(ctx context.Context, page *rod.Page, endpoint string, payload map[string]any) (browserSigninResult, error) {
	raw, code, err := browserFetchJSON(ctx, page, "POST", endpoint, "application/json;charset=UTF-8", payload)
	if err != nil {
		return browserSigninResult{}, fmt.Errorf("hover browser signin: fetch %s: %w", endpoint, err)
	}
	var parsed struct {
		Succeeded *bool  `json:"succeeded"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	_ = json.Unmarshal([]byte(raw), &parsed)
	ok := code >= 200 && code < 300
	return browserSigninResult{
		OK:        ok,
		HTTPCode:  code,
		Succeeded: parsed.Succeeded,
		Status:    parsed.Status,
		Error:     parsed.Error,
		Raw:       raw,
	}, nil
}

// browserFetchResult is the raw result of a browserFetchJSON call.
type browserFetchResult struct {
	OK      bool   `json:"ok"`
	Code    int    `json:"code"`
	RawBody string `json:"rawBody"`
}

// browserFetchJSON executes an in-page fetch inside page with the given method,
// endpoint (path or full URL), contentType, and payload. The payload is
// serialized to either JSON (when contentType contains "application/json") or
// application/x-www-form-urlencoded (when it contains "form-urlencoded") using
// the values passed as a map[string]any. The function returns the response body
// as a string, the HTTP status code, and any JavaScript-level error.
//
// credentials:'include' is always set so Chrome's session cookies accompany the
// request — this is the key property that makes the hybrid write path work.
//
// extraHeaders is a map of additional headers to set (e.g. X-CSRF-Token).
// Pass nil when no extra headers are needed.
func browserFetchJSON(ctx context.Context, page *rod.Page, method, endpoint, contentType string, payload any) (rawBody string, code int, err error) {
	return browserFetchWithHeaders(ctx, page, method, endpoint, contentType, payload, nil)
}

// browserFetchWithHeaders is like browserFetchJSON but also accepts an
// extraHeaders map (may be nil). Each entry is set as a request header.
func browserFetchWithHeaders(ctx context.Context, page *rod.Page, method, endpoint, contentType string, payload any, extraHeaders map[string]string) (rawBody string, code int, err error) {
	// Serialize the payload to the wire body on the Go side so we don't have to
	// pass a complex encoding function to JS.
	var bodyStr string
	if payload != nil {
		switch {
		case strings.Contains(contentType, "application/x-www-form-urlencoded"):
			// Encode map[string]any as URL-encoded form string.
			m, ok := payload.(map[string]any)
			if !ok {
				return "", 0, fmt.Errorf("browserFetchWithHeaders: form-urlencoded payload must be map[string]any")
			}
			vals := url.Values{}
			for k, v := range m {
				vals.Set(k, fmt.Sprintf("%v", v))
			}
			bodyStr = vals.Encode()
		default:
			// JSON-encode the payload.
			b, jerr := json.Marshal(payload)
			if jerr != nil {
				return "", 0, fmt.Errorf("browserFetchWithHeaders: marshal payload: %w", jerr)
			}
			bodyStr = string(b)
		}
	}

	// Encode extraHeaders as a JSON object string so JS can parse it.
	extraJSON := "{}"
	if len(extraHeaders) > 0 {
		b, jerr := json.Marshal(extraHeaders)
		if jerr != nil {
			return "", 0, fmt.Errorf("browserFetchWithHeaders: marshal extraHeaders: %w", jerr)
		}
		extraJSON = string(b)
	}

	obj, evalErr := page.Context(ctx).Evaluate(&rod.EvalOptions{
		ByValue:      true,
		AwaitPromise: true,
		JS: `async (method, endpoint, contentType, body, extraHeadersJSON) => {
			const headers = {
				'Accept': 'application/json, text/plain, */*',
				'X-Requested-With': 'XMLHttpRequest'
			};
			if (contentType) headers['Content-Type'] = contentType;
			const extra = JSON.parse(extraHeadersJSON);
			Object.assign(headers, extra);
			const opts = { method, credentials: 'include', headers };
			if (body) opts.body = body;
			const resp = await fetch(endpoint, opts);
			const rawBody = await resp.text();
			return { ok: resp.ok, code: resp.status, rawBody };
		}`,
		JSArgs: []any{method, endpoint, contentType, bodyStr, extraJSON},
	})
	if evalErr != nil {
		return "", 0, evalErr
	}
	var result browserFetchResult
	if err := obj.Value.Unmarshal(&result); err != nil {
		return "", 0, fmt.Errorf("browserFetchWithHeaders: decode result: %w", err)
	}
	return result.RawBody, result.Code, nil
}

func probeGoHTTPReuse(ctx context.Context, browser *rod.Browser) (int, bool) {
	cookies, err := browser.GetCookies()
	if err != nil {
		return 0, false
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return 0, false
	}
	hoverURL, _ := url.Parse(hoverHost)
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
	jar.SetCookies(hoverURL, httpCookies)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hoverHost+"/api/domains", nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, false
	}
	var body struct {
		Succeeded bool     `json:"succeeded"`
		Domains   []Domain `json:"domains"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return 0, false
	}
	return len(body.Domains), body.Succeeded
}
