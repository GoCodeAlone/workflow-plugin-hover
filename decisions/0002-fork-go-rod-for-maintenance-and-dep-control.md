# 0002. Fork go-rod to GoCodeAlone/rod for maintenance + dep control

**Status:** Accepted
**Date:** 2026-05-31
**Decision-makers:** codingsloth@pm.me (directed), Claude (Opus 4.8)
**Related:** decisions/0001-real-browser-auth-for-imperva.md (amends the driver source), docs/plans/2026-05-30-headless-browser-auth-design.md

## Context

ADR 0001 chose go-rod (CDP) to defeat Imperva. But `github.com/go-rod/rod` is **stale**: no release since 2024, 179 open issues, 27 open PRs, 425 forks. The Imperva arms race means we will eventually need our own patches and dep bumps, and upstream has no active fix channel. `govulncheck` on the pinned tree is clean (no *called* vulns), but GitHub Dependabot flags 2 moderate `golang.org/x/sys` advisories, and we cannot get upstream to act. We need durable control over the browser driver our DNS automation depends on.

## Decision

Fork to **`github.com/GoCodeAlone/rod`** and maintain it ourselves. We **rename the module path** (not just a filesystem replace) so consumers can `require`/`replace` the fork with a matching module path in CI — a versioned `replace` to a differently-pathed module fails Go's module-path check. Bump the go directive 1.21 → 1.26.3. Keep divergence from upstream **minimal** to preserve mergeability: do NOT bleeding-edge-bump deps that break the API for no vuln benefit (fetchup 0.5.x breaks the launcher), and do NOT run whole-repo `modernize` (it churns 2600+ lines of generated proto). Address Dependabot (x/sys). `workflow-plugin-hover` imports `github.com/GoCodeAlone/rod` directly.

Alternatives rejected:
- **Stay on go-rod/rod** — stale, no fix channel, no control; the original problem.
- **Filesystem/replace without rename** — `replace ... => GoCodeAlone/rod vX` fails the module-path match; filesystem replace isn't CI-portable.
- **Switch driver (chromedp / playwright-go)** — chromedp is not stealth-focused; playwright-go drags a Node-driven Playwright runtime onto a Go gRPC plugin (rejected in ADR 0001). The driver spike already picked go-rod.

## Consequences

- We own go-rod maintenance: periodically merge upstream, apply our patches/dep bumps, run our own vuln gate (CodeQL on the fork + `govulncheck` + Dependabot).
- Divergence kept small → upstream merges stay feasible; the rename is the one large mechanical delta (104 files).
- Vuln posture: `govulncheck` clean + Dependabot x/sys addressed.
- The 3 nested example/tooling modules stay on the upstream path (not maintained surface; not in hover's dep graph).
- Undo cost: low — revert hover's import/require back to `github.com/go-rod/rod`.
- Negative: a maintained fork is ongoing work; if upstream revives, re-evaluate whether to drop the fork.
