# Headless-browser Hover auth — Adversarial Design Review 1

**Date:** 2026-05-30
**Phase:** design
**Design:** `docs/plans/2026-05-30-headless-browser-auth-design.md`
**Status:** PASS after design corrections

## Findings

| sev | class | loc | issue | resolution |
|---|---|---|---|---|
| Critical | validation | `Multi-Component Validation` | Browser implementation could proceed against local stubs even if the verified Hover account or go-rod Imperva pass failed. | Design now requires live viability as the plan's first task and blocks stub-only implementation when the test account is unavailable. |
| Important | testability | `Architecture` | Replacing the HTTP path outright would destroy existing `httptest` coverage or force every unit test to launch Chrome. | Design now requires an internal execution-backend seam: production browser backend, tests may keep local HTTP backend. |
| Important | config | `Chrome acquisition` | Runtime knobs were named inconsistently and not clearly exposed at provider config/env level. | Design now requires `browser_path`, `browser_download`, `browser_headless`, `browser_profile_dir` plus `HOVER_*` env aliases and `ROD_BROWSER_PATH` compatibility. |
| Important | secrets | `Stealth` | Persistent browser profile could be created inside repo and accidentally committed; profile contains auth cookies. | Design now requires sensitive default under `${XDG_STATE_HOME:-$HOME/.local/state}/wfctl/plugins/hover/browser-profile` and gitignore coverage for local test paths. |
| Important | docs drift | `Multi-Component Validation` | README still documents obsolete CSRF form login, causing operators to debug the wrong failure mode. | Design now requires README update for browser auth, Chrome/runtime config, bot challenge behavior, and sensitive profile handling. |
| Minor | optimization | `Browser scope` | Browser-login + Go HTTP API reuse may be viable, but adopting it before evidence would reintroduce TLS/JA3 risk. | Design keeps full-browser as default and makes login-only optimization evidence-gated. |

## Clean Checks

| area | result |
|---|---|
| Public contract | unchanged `hoverclient` + provider surface preserved. |
| Ecosystem fit | Go plugin implementation; no Python harness or standalone demo tool. |
| Security posture | no managed CAPTCHA/solver service; secrets redacted; profile treated as sensitive state. |
| Rollback | rollback is honest: v0.4.2 disables live Hover automation, not a working fallback. |

## Verdict

PASS. Remaining risk is empirical, not design-structural: go-rod may still fail Imperva where Playwright succeeds. The implementation plan must make that the first executable gate and stop if it fails.
