# Retro — Browser-driven Hover auth (v0.5.0)

**Date:** 2026-06-01
**Scope:** workflow-plugin-hover v0.5.0 + GoCodeAlone/rod fork v0.116.3 + gocodealone-dns hover pin v0.5.0
**Artifacts:** design `docs/plans/2026-05-30-headless-browser-auth-design.md` (5 backports) · plan `...auth.md` (scope-locked) · security review `...security-review.md` · ADR 0001/0002 · issue #31

## Outcome

Hover IaC auth fixed end-to-end. `imported 30 infra.dns zones via provider "hover"` in production (gocodealone-dns import-dns.yml, self-hosted runner) — was a hard 401 behind Imperva ABP. Catalog PR #12 (46 zones = 16 DO + 30 Hover).

## What worked

- **Spike before commit.** "Spike both drivers, pick the winner" → empirically confirmed go-rod clears Imperva (pure-Go, beat playwright-go on runtime) BEFORE building. De-risked the design's most-fragile assumption cheaply.
- **Live gate first (plan Task 1).** The viability probe caught a real bug (`KeepUserDataDir()` panics on a non-managed launcher) the instant it ran live — exactly the "don't build a driver that only passes stubs" guard working.
- **Production proof via CI, not local.** HOVER_* are org PRIVATE secrets; running the probe in the private consumer repo (gocodealone-dns) on the self-hosted runner proved Imperva-clear + TOTP + 30-domain read + `go_http_reuse_viable=true` against the real account — no creds ever left the org.
- **Hybrid emerged from evidence.** `go_http_reuse_viable=true` (Imperva clears the session, not per-request) turned the deferred login-only optimization into the chosen read transport; full-browser kept for writes.
- **Per-task lead verification.** Every subagent task was lead-verified (clean build/test) before acceptance; false LSP "undefined" diagnostics (a sibling repo's go.work hijacking the editor workspace) were correctly ignored because the CLI build was the truth.

## What slipped

- **Tagged v0.5.0 on the feature-branch HEAD, not the squash-merge commit.** `git checkout main` failed silently (a worktree held `main`) and I tagged without confirming I was on the merge commit. Squash preserves the tree so the release is byte-identical/correct, but it reinforces the prior lesson: **verify `git rev-parse HEAD` == merge commit before tagging** (same class as the v0.66.0 burn).
- **Two implementer subagents needed lead course-correction** on the rod go.work false-diagnostics noise — mitigated by always prefixing `GOWORK=off`.

## Follow-ups (issue #31)

1. Derive UA/platform/version from the launched Chrome + re-validate (resilience — current macOS-on-Linux skew passed but is the likely Imperva-break vector under JA4/UA-CH checks).
2. Live-validate the in-browser write path (only httptest-tested; migration needs it).
3. Bump `setup-go@v5` (Node-20 cutoff 2026-06-16).
4. Email-default 2FA accounts are not CI-viable (need TOTP or pre-trusted profile) — documented, no code action.

Still deferred from prior DNS work: CF+NC import (creds pending), provider migration execution, .tech→.com redirect, DNS UI.
