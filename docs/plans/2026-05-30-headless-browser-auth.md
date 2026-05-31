# Headless-browser Hover auth Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Replace Hover's broken cold-HTTP signin with a real Chrome/go-rod execution path that can pass Imperva and operate the Hover account portal through the existing Workflow plugin/provider contract.

**Architecture:** Keep `hoverclient.Client`, `internal/provider.go`, and the IaC driver interfaces stable; add private backend/config seams so production uses a browser backend and tests may keep the current local HTTP backend. Validate live Hover first, then implement full-browser DNS/delegation calls, provider runtime options, docs, and release proof.

**Tech Stack:** Go 1.26, go-rod CDP browser driver, existing Workflow IaC provider interfaces, existing `httptest` unit tests, opt-in live tests against Hover.

**Base branch:** main

---

## Scope Manifest

**PR Count:** 1
**Tasks:** 6
**Estimated Lines of Change:** ~1800 (informational; not enforced)

**Out of scope:**
- Managed CAPTCHA/solver services or any third-party credential proxy.
- Python/Playwright harnesses, standalone tools, or non-Workflow demos.
- Public API/contract break for `hoverclient.Client`, plugin gRPC surface, or Workflow IaC resource types.
- New cloud resources or production DNS mutation outside explicit live-test/import validation.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Browser-backed Hover auth for Imperva-protected control panel | Task 1, Task 2, Task 3, Task 4, Task 5, Task 6 | feat/headless-browser-auth-2026-05-30T2030 |

**Status:** Locked 2026-05-31T00:45:26Z

### Task 1: Live Browser Viability Gate

**Files:**
- Create: `pkg/hoverclient/browser_options.go`
- Create: `pkg/hoverclient/browser_live_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Write the opt-in live test**

Create `TestLiveBrowserLoginAndHTTPReuseProbe` with these invariants:

```go
func TestLiveBrowserLoginAndHTTPReuseProbe(t *testing.T) {
	if os.Getenv("HOVER_LIVE_TEST") != "1" {
		t.Skip("set HOVER_LIVE_TEST=1 to run live Hover browser auth probe")
	}
	creds := liveCredentialsFromEnv(t)
	opts := liveBrowserOptionsFromEnv(t)
	result, err := ProbeLiveBrowserAuth(context.Background(), creds, opts)
	if err != nil {
		t.Fatalf("live browser auth probe: %v", err)
	}
	if !result.LoginSucceeded {
		t.Fatalf("login did not complete")
	}
	if len(result.ClearanceCookies) == 0 {
		t.Fatalf("Imperva clearance cookies not observed")
	}
	t.Logf("go_http_reuse_viable=%t domains=%d clearance_cookies=%v", result.GoHTTPReuseViable, result.DomainCount, result.ClearanceCookieNames())
}
```

`liveCredentialsFromEnv` reads `HOVER_USERNAME`, `HOVER_PASSWORD`, optional `HOVER_TOTP_SECRET`; it must not log secret values. If live env is absent while `HOVER_LIVE_TEST=1`, fail with a missing-env list.

**Step 2: Run test to verify it fails before implementation**

Run: `HOVER_LIVE_TEST=1 GOWORK=off go test ./pkg/hoverclient -run TestLiveBrowserLoginAndHTTPReuseProbe -count=1 -v`

Expected: FAIL at compile time because `ProbeLiveBrowserAuth` / browser options do not exist, or FAIL with explicit missing live env. If verified Hover test-account credentials are unavailable, mark the locked plan blocked after this task; do not continue to stub-only browser implementation.

**Step 3: Add minimal browser probe implementation**

Add `BrowserOptions`, env parsing, and `ProbeLiveBrowserAuth`:

```go
type BrowserOptions struct {
	Path       string
	Download   bool
	Headless   bool
	ProfileDir string
	Timeout    time.Duration
}

type LiveAuthProbeResult struct {
	LoginSucceeded    bool
	ClearanceCookies  []string
	GoHTTPReuseViable bool
	DomainCount       int
}
```

Use go-rod to launch/attach Chrome, navigate to `https://www.hover.com/signin`, wait for Imperva clearance cookies (`__uzma`, `__uzmb`, `__uzmc`, `__uzmd`, `__uzme`, `uzmx`, `__ss*` prefixes), submit username/password and TOTP when required, and then probe whether a plain Go `http.Client` with copied cookies can call `GET /api/domains`.

**Step 4: Run live viability**

Run with the verified test-account environment loaded:

```bash
HOVER_LIVE_TEST=1 \
HOVER_BROWSER_HEADLESS=true \
GOWORK=off go test ./pkg/hoverclient -run TestLiveBrowserLoginAndHTTPReuseProbe -count=1 -v
```

Expected: PASS with log containing `go_http_reuse_viable=` and `clearance_cookies=[...]`; no password/TOTP secret in output. If go-rod cannot pass Imperva while the same account works in a normal browser, stop and backport the design instead of continuing.

**Step 5: Commit**

```bash
git add go.mod go.sum pkg/hoverclient/browser_options.go pkg/hoverclient/browser_live_test.go
git commit -m "test(hoverclient): add live browser auth viability gate"
```

Rollback: revert commit; no runtime behavior changed unless the opt-in live test is run.

### Task 2: Client Backend Seam and Provider Browser Config

**Files:**
- Create: `pkg/hoverclient/backend.go`
- Create: `pkg/hoverclient/browser_backend.go`
- Create: `pkg/hoverclient/options.go`
- Modify: `pkg/hoverclient/client.go`
- Modify: `pkg/hoverclient/client_test.go`
- Modify: `internal/provider.go`
- Modify: `internal/provider_test.go`

**Step 1: Write failing unit tests**

Add tests for:
- `NewClient(creds, injectedHTTPClient)` uses the HTTP backend so existing `httptest` tests do not launch Chrome.
- `NewClient(creds, nil)` defaults to browser backend options.
- `NewClientWithOptions(creds, nil, ClientOptions{Browser: BrowserOptions{...}})` preserves explicit runtime config.
- Provider config maps `browser_path`, `browser_download`, `browser_headless`, `browser_profile_dir` plus `HOVER_BROWSER_*` env aliases into `hoverclient.ClientOptions`.

Expected test names:

```go
func TestNewClient_DefaultsToBrowserBackendWithoutInjectedHTTP(t *testing.T)
func TestNewClient_InjectedHTTPUsesHTTPBackendForTests(t *testing.T)
func TestInitialize_ParsesBrowserConfig(t *testing.T)
func TestInitialize_EnvBrowserConfigAliases(t *testing.T)
```

**Step 2: Run tests to verify failure**

Run: `GOWORK=off go test ./pkg/hoverclient ./internal -run 'TestNewClient_|TestInitialize_.*Browser' -count=1 -v`

Expected: FAIL because options/backend seam and provider parsing are absent.

**Step 3: Implement backend seam**

Add private interface:

```go
type executionBackend interface {
	Login(context.Context, *Client) error
	ListDomains(context.Context, *Client) ([]Domain, error)
	GetDomain(context.Context, *Client, string) (*Domain, error)
	CreateRecord(context.Context, *Client, string, Record) (*Record, error)
	UpdateRecord(context.Context, *Client, string, Record) (*Record, error)
	DeleteRecord(context.Context, *Client, string, string) error
	GetDomainDelegation(context.Context, *Client, string) (*DomainDelegation, error)
	SetNameservers(context.Context, *Client, string, []string) error
	Close() error
}
```

Move current HTTP logic behind `httpBackend`. Add a compile-valid `browserBackend` skeleton in `browser_backend.go` that stores `BrowserOptions` and returns `ErrBrowserBackendUnavailable` for live operations until Task 3 replaces the login implementation. `Client` keeps `NewClient(creds, httpClient)` for compatibility; `httpClient != nil` selects `httpBackend`; production `httpClient == nil` selects `browserBackend`.

**Step 4: Implement provider config**

Parse explicit provider config first, env aliases second, defaults last:
- `browser_path` / `HOVER_BROWSER_PATH`
- `browser_download` / `HOVER_BROWSER_DOWNLOAD`
- `browser_headless` / `HOVER_BROWSER_HEADLESS`
- `browser_profile_dir` / `HOVER_BROWSER_PROFILE_DIR`

Do not log values. Default profile dir must be under `${XDG_STATE_HOME:-$HOME/.local/state}/wfctl/plugins/hover/browser-profile`.

**Step 5: Run tests to verify pass**

Run: `GOWORK=off go test ./pkg/hoverclient ./internal -run 'TestNewClient_|TestInitialize_.*Browser' -count=1 -v`

Expected: PASS.

**Step 6: Commit**

```bash
git add pkg/hoverclient/backend.go pkg/hoverclient/browser_backend.go pkg/hoverclient/options.go pkg/hoverclient/client.go pkg/hoverclient/client_test.go internal/provider.go internal/provider_test.go
git commit -m "refactor(hoverclient): add browser backend configuration seam"
```

Rollback: revert commit; re-run `GOWORK=off go test ./pkg/hoverclient ./internal`.

### Task 3: Browser Backend Login, Stealth, and Typed Errors

**Files:**
- Modify: `pkg/hoverclient/browser_backend.go`
- Create: `pkg/hoverclient/browser_backend_test.go`
- Modify: `pkg/hoverclient/client.go`
- Modify: `pkg/hoverclient/backend.go`
- Modify: `.gitignore`

**Step 1: Write failing browser-backend tests**

Use local `httptest` pages exercised through go-rod where feasible. Tests:
- login form happy path sets `loggedAt` and handles no-MFA JSON completion.
- TOTP-required path posts a generated code and errors clearly when no `totp_secret`.
- challenge page detection returns typed `ErrBotChallenge`.
- Chrome missing with downloads disabled returns an actionable Chrome acquisition error.
- profile dir under repo is gitignored when local test override uses `.hover-browser-profile/`.

Expected test names:

```go
func TestBrowserBackend_LoginLocalNoMFA(t *testing.T)
func TestBrowserBackend_LoginLocalTOTPRequired(t *testing.T)
func TestBrowserBackend_LoginDetectsBotChallenge(t *testing.T)
func TestBrowserBackend_ChromeMissingDownloadDisabled(t *testing.T)
```

**Step 2: Run tests to verify failure**

Run: `GOWORK=off go test ./pkg/hoverclient -run 'TestBrowserBackend_' -count=1 -v`

Expected: FAIL because browser backend is absent.

**Step 3: Implement browser launch and login**

Implement `browserBackend` with:
- system Chrome lookup: `BrowserOptions.Path`, `HOVER_BROWSER_PATH`, `ROD_BROWSER_PATH`, `google-chrome`, `chromium`, Chrome app paths where appropriate.
- download control: if no Chrome found and `Download=false`, return `ErrChromeUnavailable`.
- launcher flags: new headless when `Headless=true`, persistent user data dir, no `--no-sandbox` unless explicitly required by environment/test hook.
- init scripts: remove `navigator.webdriver`, align UA/client hints with launched Chrome, set locale/timezone stable enough for Hover.
- human-like field interactions and waits for clearance cookie presence before auth submit.
- bounded relaunch retry once after browser crash.
- typed errors: `ErrBotChallenge`, `ErrChromeUnavailable`.

**Step 4: Run tests to verify pass**

Run: `GOWORK=off go test ./pkg/hoverclient -run 'TestBrowserBackend_' -count=1 -v`

Expected: PASS.

**Step 5: Run live login regression**

Run with verified test-account environment:

```bash
HOVER_LIVE_TEST=1 \
HOVER_BROWSER_HEADLESS=true \
GOWORK=off go test ./pkg/hoverclient -run TestLiveBrowserLoginAndHTTPReuseProbe -count=1 -v
```

Expected: PASS; no secret output; if `ErrBotChallenge`, stop and backport design.

**Step 6: Commit**

```bash
git add .gitignore pkg/hoverclient/browser_backend.go pkg/hoverclient/browser_backend_test.go pkg/hoverclient/client.go pkg/hoverclient/backend.go
git commit -m "feat(hoverclient): authenticate hover through chrome"
```

Rollback: revert commit; delete any local `.hover-browser-profile/`; re-run package tests.

### Task 4: Full-Browser DNS and Delegation Operations

**Files:**
- Modify: `pkg/hoverclient/browser_backend.go`
- Modify: `pkg/hoverclient/browser_backend_test.go`
- Modify: `pkg/hoverclient/client.go`
- Modify: `pkg/hoverclient/client_test.go`
- Modify: `internal/drivers/dns_test.go`
- Modify: `internal/drivers/delegation_test.go`

**Step 1: Write failing API operation tests**

Add tests that verify `Client` delegates these operations to the selected backend:
- `ListDomains`
- `GetDomain`
- `ListRecords`
- `CreateRecord`
- `UpdateRecord`
- `DeleteRecord`
- `GetDomainDelegation`
- `SetNameservers`

For browser backend local tests, use in-page `fetch` against a local server and parse JSON from the page context so network requests originate from Chrome. Include CSRF meta extraction for `SetNameservers`.

**Step 2: Run tests to verify failure**

Run: `GOWORK=off go test ./pkg/hoverclient ./internal/drivers -run 'Test(Client|BrowserBackend|DNS|Delegation)' -count=1 -v`

Expected: FAIL for browser backend API methods not implemented or not delegated.

**Step 3: Implement full-browser operations**

Move live production calls into browser context:
- Use `page.Eval` / in-page `fetch` for `/api/domains`, `/api/domains/<domain>/dns`, `/api/dns`, `/api/dns/<id>`, `/api/control_panel/domains/domain-<name>`.
- Fetch CSRF token from `/control_panel/domain/<name>` inside Chrome before nameserver PUT.
- Preserve current JSON structs/errors, including `ErrEmptyNameservers` and existing record parsing semantics.
- Keep `httpBackend` behavior for injected-HTTP tests.
- If Task 1 proved plain Go HTTP reuse viable, document the evidence in a comment and leave browser as default; do not switch default back to HTTP without amending the design.

**Step 4: Run focused tests**

Run: `GOWORK=off go test ./pkg/hoverclient ./internal/drivers -count=1 -v`

Expected: PASS.

**Step 5: Run all unit tests**

Run: `GOWORK=off go test ./... -count=1`

Expected: PASS.

**Step 6: Commit**

```bash
git add pkg/hoverclient/browser_backend.go pkg/hoverclient/browser_backend_test.go pkg/hoverclient/client.go pkg/hoverclient/client_test.go internal/drivers/dns_test.go internal/drivers/delegation_test.go
git commit -m "feat(hoverclient): execute hover dns operations in browser"
```

Rollback: revert commit; re-run `GOWORK=off go test ./... -count=1`.

### Task 5: Workflow Plugin Runtime Validation With Real Consumer

**Files:**
- Modify: `internal/iacserver_live_test.go`
- Modify: `cmd/workflow-plugin-hover/plugin.json`
- Modify: `plugin.json`
- Modify: `README.md`

**Step 1: Write/adjust live plugin validation**

Ensure the existing live server/import test can run with browser options:
- `HOVER_LIVE_TEST=1`
- `HOVER_USERNAME`
- `HOVER_PASSWORD`
- optional `HOVER_TOTP_SECRET`
- `HOVER_BROWSER_*`

The test must load the real plugin/provider path and exercise Workflow IaC import/status behavior, not call the client directly only.

**Step 2: Run live plugin validation**

Run:

```bash
HOVER_LIVE_TEST=1 \
HOVER_BROWSER_HEADLESS=true \
GOWORK=off go test ./internal -run 'Test.*Live' -count=1 -v
```

Expected: PASS with evidence that at least one Hover domain or delegation object is read/imported; no secret output. If the test account has zero domains, expected output may be an explicit "login succeeded; zero domains" assertion plus one non-mutating status/read path against a configured test domain if available.

**Step 3: Validate real Workflow consumer path**

From `/Users/jon/workspace/gocodealone-dns` or the current real consumer repo if renamed, run the smallest available Workflow/wfctl import or validation command that loads this local plugin build and uses the Hover provider.

Expected: command reaches the real Hover provider and returns imported/read Hover state rather than `401 Invalid username or password` or `ErrBotChallenge`.

**Step 4: Update manifest version/runtime docs**

Set plugin manifests to `0.5.0` for the browser-auth behavioral release. README must describe:
- real Chrome/go-rod auth, not old CSRF form signin.
- Chrome install/download/profile config.
- sensitive profile directory.
- bot challenge typed failure and manual remediation.
- unchanged IaC usage.

**Step 5: Run runtime/build validation**

Run:

```bash
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off go test ./... -count=1
```

Expected: all commands exit 0.

**Step 6: Commit**

```bash
git add internal/iacserver_live_test.go cmd/workflow-plugin-hover/plugin.json plugin.json README.md
git commit -m "docs(hover): document browser auth runtime and release"
```

Rollback: revert commit; plugin remains at prior manifest version/docs.

### Task 6: Final Security Review, Release Prep, and PR

**Files:**
- Create: `docs/plans/2026-05-30-headless-browser-auth.security-review.md`
- Modify: `docs/plans/2026-05-30-headless-browser-auth-design.md` if execution disproves an assumption

**Step 1: Run adversarial security review**

Review final diff for:
- secret leakage in logs/errors/tests.
- browser profile path safety and gitignore coverage.
- no third-party credential/CAPTCHA service.
- Chrome download/path trust boundary.
- no public contract break.
- no mock-only claim for Imperva pass.

Save findings in `docs/plans/2026-05-30-headless-browser-auth.security-review.md`.

**Step 2: Run full verification**

Run:

```bash
GOWORK=off go test ./... -count=1
GOWORK=off go vet ./...
GOWORK=off go build ./...
HOVER_LIVE_TEST=1 HOVER_BROWSER_HEADLESS=true GOWORK=off go test ./pkg/hoverclient ./internal -run 'TestLive|Test.*Live' -count=1 -v
```

Expected: all non-live commands PASS; live command PASS with real Hover evidence or the plan is blocked before PR. No secrets printed.

**Step 3: Run scope verification**

Run:

```bash
/Users/jon/.codex/plugins/cache/autodev-marketplace/autodev/6.2.0/tests/plan-scope-check.sh --verify-lock docs/plans/2026-05-30-headless-browser-auth.md
```

Expected: PASS.

**Step 4: Commit security review**

```bash
git add docs/plans/2026-05-30-headless-browser-auth.security-review.md docs/plans/2026-05-30-headless-browser-auth-design.md
git commit -m "docs(hover): record browser auth security review"
```

**Step 5: Create PR**

Push branch and open one PR:

```bash
git push -u origin feat/headless-browser-auth-2026-05-30T2030
gh pr create --fill --base main --head feat/headless-browser-auth-2026-05-30T2030
```

Expected: one PR covering Tasks 1-6; PR body includes live Hover evidence and rollback note.

Rollback: close PR or revert merged PR; pin consumers back to v0.4.2 knowing live Hover automation returns to known-broken HTTP behavior.
