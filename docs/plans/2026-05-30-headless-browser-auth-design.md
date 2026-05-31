# Headless-browser Hover auth (defeat Imperva ABP) — Design

**Date:** 2026-05-30
**Status:** Design (autonomous pipeline; user-approved direction)
**Guidance:** `/Users/jon/workspace/docs/design-guidance.md` (workspace rev 4)
**Repo:** workflow-plugin-hover

## Problem

Hover has no public API; `pkg/hoverclient` scrapes the React signin flow (`POST /signin/auth.json`). Hover sits behind **Imperva Advanced Bot Protection** (ex-Distil): a JS *sensor* POSTed to `/c<uuid>` mints clearance cookies (`__uzma/b/c/d/e`, `uzmx`, `__ss*`) that `auth.json` then requires. A cold Go `http.Client` never runs the sensor → Imperva rejects it → generic `401 "Invalid username or password"` even with valid creds (root-caused live 2026-05-30 via playwright: dummy-cred probe returned the normal JSON error; real browser login from the same IP succeeds; the `__uzm*`+`/c<uuid>` handshake is the difference). Token/header fixes (v0.4.1/v0.4.2) were correct hardening but cannot pass Imperva — the clearance is a JS-computed, server-validated, rotating fingerprint. **The HTTP-scrape login never worked against live Imperva-protected Hover; it only ever passed the test stub.**

## Decision (approved)

Replace the cold-HTTP login with a **real-Chrome session driver** (CDP via **go-rod**) that runs Imperva's JS, mints clearance, and drives the **full** Hover flow in-browser.

### Architecture

`hoverclient.Client.Login()` (+ the API methods) swap their HTTP impl for a go-rod browser session behind the **unchanged** `hoverclient` interface — so `internal/provider.go` + the `infra.dns` / `infra.dns_delegation` drivers are untouched.

```
Login(): launch/attach Chrome → goto /signin (Imperva sensor runs, clearance minted)
       → type username/password (human-like delays) → submit auth.json
       → if need_2fa: type TOTP code → auth2.json → authenticated control panel
ListDomains()/SetNameservers(): performed IN-BROWSER (navigate control-panel pages /
       in-page fetch with the live clearance), NOT via a separate Go http.Client.
```

### Browser scope: full-browser (default)

All Hover requests run inside Chrome, not just login. **Why:** TLS/JA3 is a documented Imperva signal; handing cookies to Go's `http.Client` for the API calls exposes a non-Chrome TLS fingerprint — a tell even *with* valid cookies. In-browser keeps TLS + JS + cookies consistent end-to-end.

**Deferred empirical confirmation (plan's FIRST validation task):** with the verified test account, log in via the browser, then attempt a same-session `ListDomains` via plain Go HTTP reusing the clearance cookies. If Imperva does NOT re-challenge (clears the session, not per-request), the login-only optimization (browser→cookies→HTTP) is viable + lighter; adopt it. Until proven, full-browser is the safe default.

### Chrome acquisition (resolution order)

1. **System/PATH Chrome** if present (`google-chrome`, `chromium`, `$ROD_BROWSER_PATH`).
2. Else **go-rod launcher auto-downloads + caches** a pinned Chromium (`~/.cache/rod`).
3. **Container image** with Chrome baked, for CI (the gocodealone-dns import workflow runs in it).

The browser cannot compile into the Go binary (~150MB); this is the "bundle what we can + external OK" middle path. A `HOVER_BROWSER_PATH` / `HOVER_BROWSER_DOWNLOAD=false` config lets operators pin behavior.

### Stealth (must not read as automated)

- New-headless (`--headless=new`) or headful; never old headless-shell.
- Strip `navigator.webdriver`; consistent UA + `sec-ch-ua` client-hints matching the launched Chrome's real version (no UA/version skew).
- Human-like input: per-key delays, a mouse move/click into fields before typing, small randomized waits.
- Persistent profile / cookie jar so the Imperva clearance survives across calls within `sessionStaleAfter`.
- go-rod/stealth has known gaps (webdriver leaks on new pages); apply manual page-init JS patches on top.

### Error handling / failure modes

- **Chrome missing + download disabled** → clear error: "no Chrome found; install Chrome or set HOVER_BROWSER_DOWNLOAD=true".
- **Imperva block / challenge page** (not the normal login form) → detect (challenge HTML / unexpected redirect / persistent 401) → return a typed `ErrBotChallenge` with guidance, NOT a misleading auth error.
- **TOTP missing when 2FA required** → existing behavior (clear error).
- **Browser launch/crash** → bounded retries (1 relaunch), then fail with the launch error.
- **Slow Imperva sensor** → explicit waits for clearance cookie presence before submitting, with timeout.

## Global Design Guidance

Source: `docs/design-guidance.md` (rev 4)

| guidance | response |
|---|---|
| Primary Go, stdlib-first, deps justified | go-rod is a justified external dep (only viable Go CDP driver with stealth ecosystem); no alternative passes Imperva |
| No new standalone binaries | extends the existing plugin; browser is a runtime dependency, not a new wfctl binary |
| Plugin contracts unchanged | `hoverclient` interface + gRPC surface unchanged; swap is internal |
| Secrets never logged | creds typed into a local browser; never logged; `(creds redacted)` preserved; profile dir is local + gitignored |
| Goreleaser + release workflow | new minor release (v0.5.0 — behavioral change); plugin.json minEngineVersion unchanged |
| Cross-driver parity / e2e via real consumer | validate via the gocodealone-dns import workflow (real Hover) + the test account |

## Security Review

- **Auth/secrets**: Hover username/password/TOTP typed into a locally-launched Chrome on the runner; never transmitted to any third party (no managed solver). Profile/cookie cache is local + gitignored; treat as sensitive (clears on stale).
- **Trust boundary / new deps**: adds go-rod + a Chrome binary (downloaded-and-checksummed by go-rod, or system). Chrome is a large attack surface but standard. Pin the Chromium revision; rely on go-rod's checksum on download.
- **Abuse / ToS**: deliberately passes Imperva bot-protection — Hover ToS gray area. Shipped best-effort with a README disclaimer; Hover has no API alternative. Public MIT plugin: documented, not hidden.
- **Least privilege**: browser runs sandboxed by default; `--no-sandbox` only where the CI container requires it (documented).

## Infrastructure Impact

- **CI weight**: the import workflow gains a Chrome dependency — either a cached download (~150MB first run, cached after) or a container image with Chrome. Slower than the old HTTP path (seconds → tens of seconds per login). Self-hosted Linux runner must allow Chrome (deps/sandbox).
- **No cloud resources created**; read-only DNS enumeration + (migration) NS writes unchanged in effect.
- **Rollback**: see below.

## Multi-Component Validation

- **Plugin + real Hover**: the gocodealone-dns `import-dns.yml` run against live Hover (Imperva) is the end-to-end proof — `imported N infra.dns zones via provider "hover"` instead of the 401.
- **Test account**: `hover-dns-test@gocodealone.com` (recorded in gocodealone-dns/.hover-test-account.local.md) for repeatable login validation without risking the production Hover account's lockout.
- Not mock-only: go-rod tests can stub a local server for unit logic, but the Imperva-pass is validated against real Hover.

## Assumptions

1. **A real Chrome (go-rod, stealthed) can pass Imperva for Hover login.** Most fragile. Evidence: playwright (real Chromium) passed Imperva for signup; go-rod drives the same engine. Risk: go-rod's CDP/stealth gaps vs Imperva behavioral/ML. **Gated by the plan's first task** (live login with the test account); if go-rod can't pass where playwright did, reconsider driver (e.g. a more stealth-focused approach) before building the rest.
2. **The verified test account is available** for validation. Currently pending email verification (catch-all lag); not a design blocker, but a validation-task dependency.
3. **Imperva clearance is session-scoped** (one clearance covers the session) — drives whether login-only is viable; tested in the deferred scope task. Full-browser is safe regardless.
4. **go-rod's launcher can fetch a working Chromium on the runner OS** (Linux X64); else system Chrome / container.
5. **Hover's signin flow shape is stable** (`/signin/auth.json` + `/signin/auth2.json` + TOTP); already used by the current client.

## Rollback

Runtime-affecting (auth path + new browser dependency + CI). Rollback path:
- Revert to the previous release (v0.4.2) — the HTTP-only client. NOTE: v0.4.2 cannot actually authenticate against live Imperva, so rollback = "Hover automation disabled" not "working old behavior". The gocodealone-dns hover pin reverts to v0.4.2 + Hover import returns to known-manual (workflow already isolates Hover failure: continue-on-error + honest-red).
- Feature is additive behind the unchanged interface; reverting the plugin version is the rollback.

## Re-evaluation cadence

Per user: re-check for maintained Imperva-bypass solutions periodically (next: ~2026-05-30 search done — no maintained Go lib; revisit if go-rod stealth proves insufficient or breaks). Record findings in the retro.

## ADR

- **ADR 0001** — Drive Hover auth with a real browser (go-rod) to defeat Imperva ABP; reject HTTP-scrape (cannot pass), managed solvers (cred-leak), and Python tooling (wrong language).
