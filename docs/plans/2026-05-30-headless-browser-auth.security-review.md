# Security Review — Headless-browser Hover auth (v0.5.0)

**Date:** 2026-06-01
**Reviewer:** Claude (Opus 4.8), lead
**Scope:** diff `origin/main...feat/headless-browser-auth-2026-05-30T2030` (28 files, +3418/−118)
**Plan:** docs/plans/2026-05-30-headless-browser-auth.md (scope-lock verified PASS)

## Review items (plan Task 6 Step 1)

| Item | Verdict | Evidence |
|---|---|---|
| Secret leakage in logs/errors/tests | **CLEAN** | grep of `pkg/hoverclient` + `internal` for log/print of pass/totp/secret/cred → 0 hits (one match was a comment in `totp.go`). Login submits creds via in-page `fetch`; errors carry endpoint + HTTP code, never the body's secret fields. Live test logs `clearance_cookies` names + domain count only. CI run showed `HOVER_USERNAME: ***` (masked). |
| Browser profile path safety + gitignore | **CLEAN** | Default profile dir is `${XDG_STATE_HOME:-$HOME/.local/state}/wfctl/plugins/hover/browser-profile` — **outside the repo**. Local test profile `.hover-browser-profile/` is gitignored (`git check-ignore` confirms). Profile holds session/clearance cookies → treated as sensitive; `Close()` uses `launcher.Kill()` (not `Cleanup()`) to preserve it across calls but never commits it. |
| No third-party credential/CAPTCHA solver | **CLEAN** | grep for captcha/2captcha/scrapfly/zenrows/anticaptcha/solver → 0 (the "resolver" hits are DNS-NS lookups). Credentials are typed only into a locally-launched Chrome on the operator's own runner; never sent to any third party. |
| Chrome download/path trust boundary | **CLEAN (standard)** | Chrome is resolved from system PATH/`browser_path` first; else go-rod's launcher downloads + checksum-verifies a pinned Chromium to `~/.cache/rod`. Driver is our maintained fork `github.com/GoCodeAlone/rod` (ADR 0002) — `govulncheck`-clean + Dependabot-clean + CodeQL-green. `--no-sandbox` is OFF by default; only enabled via explicit `HOVER_BROWSER_NO_SANDBOX=true`. |
| No public contract break | **CLEAN** | `hoverclient.Client` exported methods + signatures unchanged; `NewClient(creds, httpClient)` preserved; the browser/HTTP split is behind the private `executionBackend` seam. gRPC/IaC provider surface unchanged. |
| Not mock-only for the Imperva claim | **CLEAN** | Imperva-pass + TOTP login + 30-domain read validated against **real production Hover** via the gocodealone-dns CI probe on the self-hosted runner (`go_http_reuse_viable=true`, run 26784365604). Unit tests drive **real go-rod** against local httptest servers (not mocked-away); they `t.Skip` when no Chrome is present (CI-safe). |

## Findings

- **(Minor, fixed)** `Login` mislabeled a cookie-read failure as `ErrBotChallenge`; now only a clearance timeout maps to `ErrBotChallenge`, other read errors surface as-is.
- **(Important — tracked follow-up, NOT blocking)** **UA/platform/version skew.** `defaultUserAgent` is a fixed macOS Chrome 131 string and `Sec-Ch-Ua-Platform`/`SetUserAgent.Platform` are hardcoded `macOS`, while the CI runner's Chrome is Linux (and may differ in version). The presented identity is internally self-consistent (UA + client-hints both say macOS) but skews vs the real `navigator.platform`/version. **This configuration passed production**, so it ships as-is; deriving the UA + platform + version from the actually-launched Chrome (and stripping `HeadlessChrome`) is a resilience improvement to make + re-validate via the prod-run probe before relying on it. Tracked for a follow-up release.

## Abuse / ToS

Deliberately passes Imperva bot-protection — Hover ToS gray area. Hover has no API alternative. Shipped best-effort with a README disclaimer; public MIT plugin, documented not hidden. Re-evaluation cadence recorded in the design (2026-05-30 re-check: no maintained Go-native alternative; SOTA stealth tools are Python/Node).

## Verdict

**PASS.** No Critical/High findings. One Important resilience follow-up (UA derivation) accepted-and-tracked because the current config is production-proven. Secret handling, trust boundary, contract stability, and real-Hover validation all clean.
