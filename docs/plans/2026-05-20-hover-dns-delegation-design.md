# Hover DNS Delegation — `infra.dns_delegation` Design

**Date:** 2026-05-20
**Status:** Revised after adversarial review round 2
**Scope:** workflow-plugin-hover v0.2.0 — new resource type for registrar-level nameserver delegation
**Field-test target:** gocodealone.tech → ns1/2/3.digitalocean.com

## Goal

Let wfctl set a domain's nameservers at the registrar layer via the Hover plugin. The existing `infra.dns` resource manages DNS *records* within Hover's nameservers. This new resource type manages the upstream nameserver delegation itself — i.e., "who is authoritative DNS for this domain", which is a different API surface and lifecycle.

Concrete first use: point gocodealone.tech at DigitalOcean's nameservers via `wfctl apply` triggered by a manual `workflow_dispatch` GitHub Actions job inside the gocodealone-multisite repo.

## Endpoint

Captured from the Hover web UI (browser DevTools, 2026-05-20):

```
PUT https://www.hover.com/api/control_panel/domains/domain-<domain_name>
Content-Type: application/json
X-CSRF-Token: <rails-csrf>
Cookie: hoverauth=...; hover_session=...

{"field":"nameservers","value":["ns1.digitalocean.com","ns3.digitalocean.com","ns2.digitalocean.com"]}
```

ID convention: `domain-<domain_name>` (different from the `dom<N>` numeric IDs the DNS-record API uses).

The generic `{"field": ..., "value": ...}` body suggests Hover uses this endpoint for several domain-level fields (whois_privacy, locked, auto_renew, nameservers). We only model `nameservers` here — YAGNI on the rest.

The CSRF token is a Rails `authenticity_token`. The existing login flow extracts a *form* token via `<input name="_token" value="...">` from `/signin`. The control-panel pages serve the *meta* form via `<meta name="csrf-token" content="...">` (verified from the captured browser session — same session emitted both shapes simultaneously). Both ultimately resolve to the same Rails CSRF authenticity-token secret per session; the meta-tag form is what JavaScript-driven fetches in Hover's SPA layer consume, and that's the form the API gateway validates against.

We fetch fresh per PUT (user decision).

## Architecture

Three artifacts, **shipped as three async-gated PRs across two sessions**:

| # | Artifact | Session | Gate |
|---|---|---|---|
| 1 | workflow-plugin-hover v0.2.0 (this PR) | Now | Copilot + CI green → merge → tag v0.2.0 → goreleaser publishes assets |
| 2 | workflow-registry manifest bump | **Separate later session** | Post-goreleaser; cannot be PRed until v0.2.0 asset SHAs exist |
| 3 | gocodealone-multisite field-test YAML + workflow | Same separate session as #2 OR after #2 merges | Gated on registry manifest carrying v0.2.0 so `wfctl plugin install` resolves |

The plugin PR (#1) is the entire scope of the current autonomous pass. #2 and #3 are explicitly out-of-scope for the current session — a follow-up note in the merged PR description will trigger them in a fresh session.

## Components

### `internal/hover/client.go` extensions

- `type DomainDelegation struct { ID string; Name string; Nameservers []string }` — **distinct new type** for the control-panel detail endpoint. Avoids polluting the existing `Domain` (which represents the `/api/domains/<name>/dns` shape with `Records []DNSRecord`). Two endpoints → two types → no ambiguity over which fields are populated by which path. (Per adversarial review round 2 finding #2.)
- `csrfMetaRe = regexp.MustCompile(\`<meta\s+name="csrf-token"\s+content="([^"]+)"\`)` — new regex distinct from the existing `csrfRe` (form-token regex used for `/signin`). Comment cites both, names the page each is fetched from, and notes that an empty match on either regex is treated as "page UI changed".
- `fetchControlPanelCSRF(ctx context.Context, domainName string) (string, error)` — `GET /control_panel/domain/<name>`, parses meta token via `csrfMetaRe`. Non-2xx → typed error "hover: fetch control_panel CSRF: HTTP %d"; missing meta → typed error "hover: CSRF meta tag not found at /control_panel/domain/%s (control_panel UI changed?)". Caller must hold `c.mu` (see Concurrency section).
- `GetDomainDelegation(ctx context.Context, domainName string) (*DomainDelegation, error)` — **new method**. `GET /api/control_panel/domains/domain-<name>`. Same API family as the PUT; far more likely to surface the `nameservers` field reliably. Returns a `*DomainDelegation`. **If the parsed response yields zero nameservers, returns a typed error `ErrEmptyNameservers`** rather than a zero-length slice. This converts the silent-thrash failure mode (empty → Diff says NeedsUpdate forever → re-PUT loop) into a loud, single-iteration error visible at the first `wfctl plan`. (Per adversarial review round 2 finding #3.) This is the **primary Read source** for `DelegationDriver`.
- `SetNameservers(ctx context.Context, domainName string, ns []string) error` — see Concurrency section below for lock discipline. Eager `ensureLogin`, `fetchControlPanelCSRF`, `PUT /api/control_panel/domains/domain-<name>` with JSON body + `X-CSRF-Token` header. PUT non-2xx → surface Hover's body as error.

### Concurrency: `SetNameservers` holds `c.mu` across the entire critical section

Adversarial review round 2 identified a TOCTOU window in the round-1 design: calling `ensureLogin` (which acquires+releases `c.mu`) BEFORE acquiring the lock for the CSRF+PUT phase still allowed another goroutine to re-auth in the gap between the two lock-acquisitions.

Round-2 fix: add a private `ensureLoginLocked(ctx)` helper that checks `loggedAt` and re-auths without acquiring `c.mu` (caller must already hold it). Refactor existing `ensureLogin` to acquire-lock-then-call-Locked. `SetNameservers` holds the lock for the entire auth → CSRF → PUT sequence:

```go
func (c *Client) SetNameservers(ctx context.Context, domainName string, ns []string) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    if err := c.ensureLoginLocked(ctx); err != nil {
        return err
    }
    csrf, err := c.fetchControlPanelCSRFLocked(ctx, domainName)
    if err != nil {
        return err
    }
    return c.putNameserversLocked(ctx, domainName, ns, csrf)
}
```

Three `*Locked` helpers added: `ensureLoginLocked`, `fetchControlPanelCSRFLocked`, `putNameserversLocked`. The existing public `ensureLogin` becomes a thin wrapper that acquires-then-calls-Locked, preserving its existing call sites' lock semantics (no behavior change to existing callers).

This genuinely eliminates the race window: no other goroutine can interleave between auth-check and PUT, because the lock is held throughout. The pattern follows standard Go mutex discipline (Locked variants for callers already holding the lock).

### `internal/drivers/delegation.go` (new, ~150 LoC)

- `type DelegationDriver struct { client HoverDelegationClient }` where the test-injectable interface is:
  ```go
  type HoverDelegationClient interface {
      GetDomainDelegation(ctx context.Context, domain string) (*hover.DomainDelegation, error)
      SetNameservers(ctx context.Context, domain string, ns []string) error
  }
  ```
- `infra.dns_delegation` resource type.
- Config schema:
  ```yaml
  config:
    domain: string                # required; apex zone (e.g. example.com)
    nameservers: [string]         # required; ≥1 hostname, distinct entries
  ```
  Validation: `≥1 nameserver` (Hover may accept single-NS setups; not the plugin's place to over-validate). Duplicates rejected as a config-author bug. Each nameserver string non-empty.
- **Outputs encoding (structpb-safe)**: `Outputs["nameservers"]` is stored as `[]any` of `string`, NOT `[]string`. Per the structpb boundary invariant (see `iacserver.go` package doc; `feedback_workflow_plugin_structpb_boundary` workspace memory). Helper `nameserversToAny(ns []string) []any` converts. Round-trip test through `json.Marshal` + `json.Unmarshal` into `map[string]any` confirms the type survives.
- Lifecycle:
  - **Create** — validate, capture pre-change nameservers via `client.GetDomainDelegation` (best-effort; non-fatal if it fails) and stash them in `Outputs["previous_nameservers"]`, then `client.SetNameservers`. Return outputs `{domain, nameservers, previous_nameservers}`.
  - **Update** — validate, call `client.SetNameservers`. Returns outputs from desired (no read-after-write, per namecheap round-4 pattern). Preserves any existing `previous_nameservers` from prior state if available.
  - **Read** — `client.GetDomainDelegation(ctx, domain)` → return `{domain, nameservers}` as `ResourceOutput`. Does NOT populate `previous_nameservers` from upstream (it's a state-only field captured at Create).
  - **Delete** — read `previous_nameservers` from the resource's input snapshot if present; otherwise fall back to `[ns1.hover.com, ns2.hover.com]` with a logged warning. PUT via `client.SetNameservers`. This is the rollback path: the resource owns the registrar state it took over and restores what was there before, with a documented hardcoded fallback for state-less or pre-v0.2.0 resources.
  - **Diff** — multiset comparison of `current.Outputs["nameservers"]` (`[]any` decoded back to `[]string`) vs desired. Order-independent. Domain rename (desired vs `current.ProviderID`) → `NeedsReplace=true` with a `ForceNew` change.
  - **HealthCheck** — `GetDomainDelegation` success/failure.
  - **Scale** — no-op error (DNS delegation has no replicas).
  - **SensitiveKeys** — nil; nameservers are public.
  - **ProviderIDFormat** — `IDFormatDomainName`.
- Ctx.Err() check before every API-touching method (mirrors PR #4 round-6 namecheap hardening).

### `internal/provider.go`

- Add `"infra.dns_delegation": drivers.NewDelegationDriver(c)` to the drivers map.
- Append `IaCCapabilityDeclaration{ResourceType: "infra.dns_delegation", Tier: 1, Operations: []string{"create","read","update","delete"}}` to `Capabilities()`.

### `internal/iacserver.go`

- No structural change. The provider's `Capabilities()` + `ResourceDriver()` dispatch already drive the gRPC surface.

### `plugin.json`

- Add `"infra.dns_delegation"` to `iacProvider.resourceTypes`.

### Workflow-registry manifest + gocodealone-multisite field-test artifact

Both deferred to a separate session per the Architecture table above. The current PR's description will explicitly call out:
- Tag v0.2.0 expected post-merge.
- Follow-up registry manifest PR required (cannot be authored until goreleaser publishes SHAs).
- Follow-up gocodealone-multisite PR adds `config/dns.wfctl.yaml` + `.github/workflows/dns-delegation.yml`.

## Data flow

```
Operator clicks "Run workflow" (workflow_dispatch on gocodealone-multisite)
  ↓
GHA: wfctl plugin install workflow-plugin-hover@v0.2.0
GHA: wfctl apply config/dns.wfctl.yaml
  ↓
wfctl loads hover plugin (gRPC), Initialize() → eager Login (session cookies + optional TOTP)
  ↓
wfctl Plan → DelegationDriver.Diff(desired, current)
   ├── current == nil               → NeedsUpdate=true (first apply)
   ├── desired.domain != current.PID → NeedsReplace=true
   ├── multiset(desired.ns) != multiset(current.Outputs.ns) → NeedsUpdate=true
   └── else                         → NeedsUpdate=false
  ↓
wfctl Apply → DelegationDriver.Create or Update
   ├── ctx.Err check
   ├── Create only: GetDomainDelegation → stash current NS as previous_nameservers (best-effort)
   ├── client.SetNameservers (under c.mu, both CSRF GET + PUT inside the lock)
   │   ├── ensureLogin
   │   ├── lock c.mu
   │   ├── fetchControlPanelCSRFLocked → token
   │   └── PUT /api/control_panel/domains/domain-<name>
   │         Body:   {"field":"nameservers","value":[...]}
   │         Header: X-CSRF-Token: <token>
   └── 200 → return dnsDelegationOutputFromDesired(domain, ns, previous_ns)
  ↓
wfctl persists state. Subsequent Plans no-op until config changes.
```

## Error handling

| Failure | Behavior |
|---|---|
| CSRF-fetch non-2xx | Typed error "hover: fetch control_panel CSRF: HTTP %d"; PUT not attempted. |
| CSRF meta tag missing | Typed error "hover: CSRF meta tag not found at /control_panel/domain/%s (control_panel UI changed?)". |
| Login expired between CSRF fetch and PUT | Cannot happen: both run under the same `c.mu` lock-hold; no re-auth can interleave. |
| Pre-change `GetDomainDelegation` fails during Create | Logged warning; Create proceeds with empty `previous_nameservers`. Not blocking. |
| PUT non-2xx | Surface Hover's response body: "hover SetNameservers %q: HTTP %d: %s". |
| Cloudflare challenge on PUT | Manifests as non-2xx → same path. Operator must allowlist the runner IP. README documents. |
| Domain rename via Update | Typed error "domain change requires resource replace, not update". |
| Delete: PUT to previous_nameservers (or default) fails | Propagate; IaC state retained. |
| Read endpoint returns empty `nameservers` field | `GetDomainDelegation` returns typed `ErrEmptyNameservers`. `Read` propagates as error; `Diff` propagates; `wfctl plan` fails loudly with "hover: delegation read returned 0 nameservers; verify field shape" — converts the previous silent re-apply thrash into a single-iteration loud failure. |

## Testing

| Layer | Coverage |
|---|---|
| `internal/hover/client_test.go` | httptest stub: `/control_panel/domain/<name>` returns HTML with meta csrf-token → `SetNameservers` PUT asserts URL + body shape + `X-CSRF-Token` header. `/api/control_panel/domains/domain-<name>` GET stub returns JSON with `nameservers` populated → `GetDomainDelegation` parses it. Failure paths: non-2xx CSRF fetch, missing meta tag, non-2xx PUT, non-2xx GET. Existing MFA-on / MFA-off login paths re-verified. |
| `internal/drivers/delegation_test.go` | Fake client implementing `HoverDelegationClient`. Create/Update/Read/Delete/Diff happy paths. Diff multiset order-independence (`[a,b,c]` vs `[c,b,a]` → NeedsUpdate=false). Domain rename → NeedsReplace=true + ForceNew. ctx-cancellation propagates from every method. Delete with previous_nameservers in state → PUTs those. Delete without previous_nameservers → PUTs `[ns1.hover.com,ns2.hover.com]` fallback. Outputs round-trip through `json.Marshal`+`Unmarshal` confirms `[]any` (not `[]string`) is what crosses the boundary. Config validation: missing domain, missing nameservers, zero-length nameservers, duplicate nameservers, empty-string nameservers. |
| `internal/iacserver_test.go` | Capabilities lists both `infra.dns` and `infra.dns_delegation`. gRPC bufconn smoke for the new type. |
| Field test (deferred session) | `wfctl apply` in GHA against gocodealone.tech. Pass criterion: Hover control panel UI shows the three DigitalOcean nameservers post-apply. `dig +short NS gocodealone.tech` is a propagation check, not a plugin check — verify separately after TTL expiry. |

## Assumptions

| # | Claim | Risk if false | Evidence / verification status |
|---|---|---|---|
| A1 | Captured PUT endpoint shape is stable across Hover releases. | Plugin breaks; need re-capture. | OSS clients show 5+ years of stability on the related `/api/dns` endpoints; same control panel codebase. |
| A2 | The meta-tag CSRF token fetched from `/control_panel/domain/<name>` is the value Hover's API gateway validates against the `X-CSRF-Token` header on PUTs to `/api/control_panel/domains/<id>`. | PUT rejects with 422; need a different token source. | The captured browser session emitted exactly this combination — meta token in the page, same token replayed as `X-CSRF-Token` header. Adversarial-review-1 finding addressed: documented the exact source page + header mapping. |
| A3 | No Cloudflare/CAPTCHA gate on the PUT path from a fresh GH-runner IP. | Field test fails; mitigation = self-hosted runner OR document a stable egress IP. | README already documents this as a CAPTCHA caveat on the existing DNS flow; same risk model. |
| A4 | Hover idempotently accepts "set to same nameservers" (no-op success). | Only matters on Create-after-state-loss; Diff prevents the re-PUT in normal flow. | Inferred from typical PUT-idempotency conventions; not verified. |
| A5 | When `previous_nameservers` is missing from state, the fallback `[ns1.hover.com, ns2.hover.com]` is a reasonable Hover default. | Delete writes wrong values for an account whose original NS set was different. User manually fixes once. | chickenandpork/hoverdnsapi test fixtures show this pair on most domains; `ns3.hover.com` exists in some fixtures. Mitigated by the primary path (stashed previous_nameservers) capturing the actual prior state. The hardcoded fallback is the last-resort path only. |
| A6 | `GET /api/control_panel/domains/domain-<name>` returns `nameservers: [...]` in the response body. | Read returns empty; Diff false-positives on every Plan. | The PUT is on the same endpoint — same API family. Assumed to surface the field on GET, but NOT yet curl-verified. **First implementation task: live-verify this with a single curl against the captured session before writing the driver.** If it returns a different shape than expected, the implementation pauses for a design amendment. Tracking-issue placeholder. |
| A7 | GH-hosted runners can reach hover.com without IP-based blocking. | Workflow fails at first request; mitigation = self-hosted runner. | No known IP-based block. |

## Rollback

The change touches runtime (plugin loading + a live registrar PUT), so rollback is in scope.

- **Plugin (workflow-plugin-hover v0.2.0)**: `wfctl plugin install workflow-plugin-hover@v0.1.0` reverts the install on any consumer.
- **Registry**: revert the manifest PR; `wfctl plugin search` falls back to v0.1.0.
- **gocodealone-multisite**: two paths:
  - **State-still-active**: delete the `infra.dns_delegation` resource block. `wfctl apply` will Delete the resource, which PUTs the stashed `previous_nameservers` back via the captured pre-Create state.
  - **State-already-cleared** (resource removed without a Delete pass): manually re-add the resource with `nameservers: [<original NS list from Hover's UI>]` and apply. OR set them via Hover's UI directly.
- **DNS itself**: the PUT is reversible — set whatever NS list you want via another apply. DNS propagation can take up to 24h, but the registrar state flips immediately.

## Surfaced doubts after adversarial review round 1

(Original three doubts retained; new ones from adversarial review escalated to assumptions A2/A6 + the Concurrency section.)

1. **CSRF-per-PUT cost**: per-PUT control_panel page fetch doubles the request count. If Hover throttles these GETs we may need to fall back to cached-with-1h-TTL CSRF. User-chosen "fetch fresh" is the safer default.
2. **Cloudflare on GHA**: shared-IP runners can trip bot challenges. Fallback: self-hosted runner with a stable egress IP that's been allowlisted via a manual login from that IP.
3. **A6 — Read endpoint coverage**: now mitigated by switching primary Read from `/api/domains/<name>/dns` to `/api/control_panel/domains/domain-<name>` (same API family as the PUT). Still needs live curl verification as the first implementation step.

## Adversarial review round 2 — findings addressed

| Finding | Severity | Resolution |
|---|---|---|
| TOCTOU between `ensureLogin` and `c.mu.Lock()` in `SetNameservers` | Critical | Refactored: new `ensureLoginLocked` helper; `SetNameservers` holds `c.mu` for the entire auth → CSRF → PUT sequence. No interleaving window. |
| `Domain` struct dual-population ambiguity | Important | Introduced distinct `DomainDelegation` type returned by `GetDomainDelegation`. Existing `Domain` struct unchanged. |
| Silent Apply thrash if Read returns empty nameservers | Important | `GetDomainDelegation` returns typed `ErrEmptyNameservers` on zero-entries. Loud failure at first plan instead of silent loop. |
| `HoverProvider` struct comment not updated | Minor | Implementation will update both the type comment and Initialize. |
| Field-test YAML shape not communicated to follow-up session | Minor | PR #1 description will include the draft `dns.wfctl.yaml` shape. |
| ForceNew Replace codepath unjustified vs requirements | Minor | Kept for symmetry with namecheap pattern + future-proofing; explicit test case added to driver_test for documentation, not because the user asked for cross-domain rename. |

## Adversarial review round 1 — findings addressed

| Finding | Severity | Resolution |
|---|---|---|
| Read endpoint uncertainty (A6) | Critical | Switched primary Read to `/api/control_panel/domains/domain-<name>` (same API family as the PUT). First implementation task is curl-verifying the response shape. |
| `Outputs["nameservers"]` encoding unspecified | Critical | Explicitly spec'd as `[]any` (not `[]string`) with helper `nameserversToAny` + round-trip JSON test. References structpb boundary invariant in `iacserver.go` + workspace memory. |
| CSRF token source ambiguity | Important | Documented the two distinct regexes (`csrfRe` for form token on `/signin`; new `csrfMetaRe` for meta tag on `/control_panel/`). Cited that both shapes coexist in the captured browser session. |
| `ensureLogin` + `fetchControlPanelCSRF` concurrency | Important | New `*Locked` helpers; `SetNameservers` holds `c.mu` across both the CSRF GET and the PUT. Eliminates the race window. |
| Delete hardcodes Hover defaults | Important | Primary path stashes `previous_nameservers` at Create; Delete restores from state. Hardcoded `[ns1.hover.com, ns2.hover.com]` only as a last-resort fallback for state-less / pre-v0.2.0 resources. |
| Registry + multisite sequenced in same session | Minor | Architecture table now explicitly defers #2 and #3 to a separate session post-goreleaser. |
| `≥2 nameservers` validation policy | Minor | Relaxed to `≥1` with distinct + non-empty constraints. |
| Field test success criterion under propagation delay | Minor | Tightened: pass = Hover UI shows new NS; `dig` is a separate post-TTL verification. |

## Sequencing (revised)

**Current session (this PR):**

1. workflow-plugin-hover v0.2.0 plugin PR opens → CI green → Copilot review rounds → merge → tag v0.2.0 → goreleaser publishes assets.

**Separate later session:**

2. workflow-registry manifest update PR with v0.2.0 SHAs → CI green → merge.
3. gocodealone-multisite PR adds `config/dns.wfctl.yaml` + `.github/workflows/dns-delegation.yml` → merge.
4. Operator (Jon) runs the workflow_dispatch → DNS delegation flips to DO.
5. Validate via Hover UI; separately verify propagation via `dig +short NS gocodealone.tech` after TTL expiry.

## References

- Captured curl from the Hover web UI session (2026-05-20).
- workflow-plugin-namecheap PR #4 round-6 hardening pattern (ctx propagation across all driver methods).
- workflow-plugin-namecheap PR #4 round-4 lesson (build outputs from desired set, no read-after-write).
- chickenandpork/hoverdnsapi `Domain.NameServers` field + fixtures.
- jmhodges/hover `Domain.Nameservers` field (alternate read endpoint).
- `feedback_workflow_plugin_structpb_boundary` workspace memory (typed slices reject structpb marshal).
- Adversarial review round 1 (2026-05-20) — 2 Critical / 3 Important / 3 Minor findings addressed inline in this revision.
