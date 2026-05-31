# 0001. Drive Hover auth with a real browser (go-rod) to defeat Imperva ABP

**Status:** Accepted
**Date:** 2026-05-30
**Decision-makers:** codingsloth@pm.me (approved), Claude (Opus 4.8)
**Related:** docs/plans/2026-05-30-headless-browser-auth-design.md

## Context

Hover has no public API; the plugin scrapes the React signin (`/signin/auth.json`). Hover is behind **Imperva Advanced Bot Protection** (ex-Distil): a JS sensor (`/c<uuid>`) mints clearance cookies (`__uzma/b/c/d/e`, `uzmx`) that the auth endpoint requires. A cold Go `http.Client` never runs the sensor → Imperva returns a generic 401 even with valid credentials (root-caused live 2026-05-30). No header/token tweak can pass it: the clearance is a JS-computed, server-validated, rotating fingerprint, additionally backed by TLS/JA3 + behavioral signals. The prior HTTP login never actually worked against live Hover — only against the test stub.

## Decision

We will authenticate by **driving a real Chrome via go-rod** (CDP) so Imperva's JS executes and mints clearance, performing the **full** Hover flow in-browser (login + API calls) to keep TLS/JS/cookies consistent.

Alternatives rejected:
- **Keep HTTP-scrape** — cannot pass Imperva; proven non-functional against live Hover.
- **Managed solver services (Scrapfly/ZenRows/2captcha)** — would route Hover *login credentials* through a third party; unacceptable for auth.
- **Python tooling (nodriver/zendriver/SeleniumBase-UC)** — the 2026 SOTA, but wrong language for a Go gRPC plugin; would bolt a Python runtime onto the plugin.
- **Reverse-engineer the Imperva sensor** in Go — fragile, breaks on every Imperva update, unmaintainable, more ToS-hostile than driving a real browser.

## Consequences

- Defeats Imperva on a **best-effort** basis (arms race): works today; Imperva updates may break it. Mitigated by full-browser (max longevity) + periodic re-evaluation of maintained solutions.
- Adds a **Chrome runtime dependency** (system / go-rod-cached / container) — cannot compile into the Go binary; heavier CI (download/cache or container; tens of seconds per login vs the old sub-second HTTP).
- ToS gray area (passing bot-protection); shipped best-effort with a README disclaimer; public MIT plugin, documented not hidden.
- The `hoverclient` interface + gRPC surface are unchanged — drivers/provider untouched; the change is internal + revertible by version pin (rollback = Hover automation disabled, since v0.4.2 can't auth live).
- Negative: go-rod's CDP + stealth has known gaps vs Imperva's behavioral/ML; viability is gated by a live login test before the full build.
