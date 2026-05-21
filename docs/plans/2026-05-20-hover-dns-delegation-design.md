# Hover DNS Delegation — `infra.dns_delegation` Design

**Date:** 2026-05-20
**Status:** Draft → adversarial review → writing-plans
**Scope:** workflow-plugin-hover v0.2.0 — new resource type for registrar-level nameserver delegation
**Field-test target:** gocodealone.tech → ns1/2/3.digitalocean.com

## Goal

Let wfctl set a domain's nameservers at the registrar layer via the Hover plugin. The existing `infra.dns` resource manages DNS *records* within Hover's nameservers. This new resource type manages the upstream nameserver delegation itself — i.e., "who is authoritative DNS for this domain", which is a different API surface and lifecycle.

Concrete first use: point gocodealone.tech at DigitalOcean's nameservers via `wfctl apply` triggered by a manual `workflow_dispatch` GitHub Actions job inside the gocodealone-multisite repo.

## Endpoint

Captured from the Hover web UI (browser DevTools):

```
PUT https://www.hover.com/api/control_panel/domains/domain-<domain_name>
Content-Type: application/json
X-CSRF-Token: <rails-csrf>
Cookie: hoverauth=...; hover_session=...

{"field":"nameservers","value":["ns1.digitalocean.com","ns3.digitalocean.com","ns2.digitalocean.com"]}
```

ID convention: `domain-<domain_name>` (different from the `dom<N>` numeric IDs the DNS-record API uses).

The generic `{"field": ..., "value": ...}` body suggests Hover uses this endpoint for several domain-level fields (whois_privacy, locked, auto_renew, nameservers). We only model `nameservers` here — YAGNI on the rest.

The CSRF token is a Rails `authenticity_token` exposed as `<meta name="csrf-token" content="...">` in any control_panel HTML page. Fetch fresh per PUT (user decision).

## Architecture

Three artifacts:

1. **workflow-plugin-hover v0.2.0** — adds `infra.dns_delegation` driver alongside the existing `infra.dns` driver. Shared `*hover.Client`. Additive change; v0.1.0 consumers continue to work.
2. **workflow-registry manifest bump** — capability list + v0.2.0 download SHAs (post-release).
3. **gocodealone-multisite/config/dns.wfctl.yaml + .github/workflows/dns-delegation.yml** — field-test artifact; manual `workflow_dispatch`.

## Components

### `internal/hover/client.go` extensions

- `Domain.Nameservers []string \`json:"nameservers,omitempty"\`` — Hover already returns this field in `GET /api/domains/<name>/dns` per the chickenandpork/hoverdnsapi fixtures; we just need to parse it.
- `fetchControlPanelCSRF(ctx context.Context, domainName string) (string, error)` — `GET /control_panel/domain/<name>`, parse `<meta name="csrf-token" content="...">` with a new regex `csrfMetaRe`. Returns typed error on non-2xx or missing token (mirrors the existing `probeTOTPPage` error semantics).
- `SetNameservers(ctx context.Context, domainName string, ns []string) error` — eager `ensureLogin`, then `fetchControlPanelCSRF`, then `PUT /api/control_panel/domains/domain-<name>` with the JSON body + `X-CSRF-Token` header. Surface PUT non-2xx response body as the error.

### `internal/drivers/delegation.go` (new, ~120 LoC)

- `type DelegationDriver struct { client HoverDelegationClient }` where the test-injectable interface is:
  ```go
  type HoverDelegationClient interface {
      GetDomain(ctx context.Context, domain string) (*hover.Domain, error)
      SetNameservers(ctx context.Context, domain string, ns []string) error
  }
  ```
- `infra.dns_delegation` resource type.
- Config schema:
  ```yaml
  config:
    domain: string                # required; apex zone (e.g. example.com)
    nameservers: [string]         # required; ≥2 distinct hostnames
  ```
- Lifecycle:
  - **Create / Update** — validate (domain non-empty; nameservers ≥2 distinct), call `client.SetNameservers`, return `dnsDelegationOutputFromDesired(domain, nameservers)` (build outputs from the desired set without read-after-write — same pattern as the namecheap round-4 fix).
  - **Read** — `client.GetDomain(ctx, domain)` → return `{domain, nameservers}` as ResourceOutput.
  - **Delete** — `client.SetNameservers(ctx, domain, []string{"ns1.hover.com","ns2.hover.com"})` — resets to Hover defaults (user choice; comment cites this design doc).
  - **Diff** — multiset comparison of `current.Outputs["nameservers"]` vs desired (order-independent — Hover's PUT accepts any order). Domain rename (desired vs `current.ProviderID`) → `NeedsReplace=true` with `ForceNew` change.
  - **HealthCheck** — `GetDomain` success/failure.
  - **Scale** — no-op error (DNS delegation has no replicas).
  - **SensitiveKeys** — nil; nameservers are public.
  - **ProviderIDFormat** — `IDFormatDomainName`.
- Ctx.Err() check before every API call (mirrors PR #4 round-6 namecheap hardening).

### `internal/provider.go`

- Add `"infra.dns_delegation": drivers.NewDelegationDriver(c)` to the drivers map.
- Append `IaCCapabilityDeclaration{ResourceType: "infra.dns_delegation", Tier: 1, Operations: []string{"create","read","update","delete"}}` to `Capabilities()`.

### `internal/iacserver.go`

- No structural change. The provider's `Capabilities()` + `ResourceDriver()` dispatch already drive the gRPC surface.

### `plugin.json`

- Add `"infra.dns_delegation"` to `iacProvider.resourceTypes`.

### `workflow-registry/plugins/hover/manifest.json`

- Add `"infra.dns_delegation"` to `capabilities.iacProvider.resourceTypes`.
- Bump `version` to `0.2.0`.
- Repopulate `downloads` with v0.2.0 SHA256s post-release (separate PR, gated on tag publish).

### `gocodealone-multisite/.github/workflows/dns-delegation.yml`

- `on: workflow_dispatch`
- Steps: checkout → setup-go → install wfctl (from `GoCodeAlone/setup-wfctl@v1`) → `wfctl plugin install workflow-plugin-hover@v0.2.0` → `wfctl apply config/dns.wfctl.yaml`
- Secrets sourced from repo or env: `HOVER_USERNAME`, `HOVER_PASSWORD`, `HOVER_TOTP_SECRET` (the existing required_secrets manifested by the plugin).

### `gocodealone-multisite/config/dns.wfctl.yaml`

```yaml
modules:
  - name: hover
    type: iac.provider.hover
    config:
      username:    ${HOVER_USERNAME}
      password:    ${HOVER_PASSWORD}
      totp_secret: ${HOVER_TOTP_SECRET}

resources:
  - name: gocodealone-tech-delegation
    type: infra.dns_delegation
    config:
      provider: hover
      domain:   gocodealone.tech
      nameservers:
        - ns1.digitalocean.com
        - ns2.digitalocean.com
        - ns3.digitalocean.com
```

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
   ├── client.fetchControlPanelCSRF(ctx, "gocodealone.tech") → token
   ├── ctx.Err check
   ├── PUT /api/control_panel/domains/domain-gocodealone.tech
   │      Body:   {"field":"nameservers","value":["ns1.digitalocean.com",...]}
   │      Header: X-CSRF-Token: <token>
   └── 200 → return dnsDelegationOutputFromDesired
  ↓
wfctl persists state. Subsequent Plans no-op until config changes.
```

## Error handling

| Failure | Behavior |
|---|---|
| CSRF-fetch non-2xx | Typed error "hover: fetch control_panel CSRF: HTTP %d"; PUT not attempted. |
| CSRF token missing in meta | Typed error "hover: CSRF token not found at /control_panel/domain/%s (control_panel UI changed?)". |
| Login expired between CSRF fetch and PUT | `ensureLogin` re-fetches inside SetNameservers; covered. |
| PUT non-2xx | Surface Hover's response body as the error message ("hover SetNameservers %q: HTTP %d: %s"). |
| Cloudflare challenge on PUT | Manifests as non-2xx → same path. Operator must allowlist the runner IP. README documents. |
| Domain rename via Update | Typed error "domain change requires resource replace, not update" (mirrors namecheap pattern). |
| Delete: PUT to Hover-default NS fails | Propagate; IaC state retained. |

## Testing

| Layer | Coverage |
|---|---|
| `internal/hover/client_test.go` | httptest stub: `/control_panel/domain/<name>` returns HTML with meta csrf-token → `SetNameservers` PUT asserts URL + body shape + `X-CSRF-Token` header. Failure paths: non-2xx CSRF fetch, missing meta tag, non-2xx PUT. Existing MFA-on / MFA-off login paths re-verified. |
| `internal/drivers/delegation_test.go` | Fake client: Create/Update/Read/Delete/Diff happy paths. Diff multiset order-independence (`[a,b,c]` vs `[c,b,a]` → NeedsUpdate=false). Domain rename → NeedsReplace=true + ForceNew. ctx-cancellation propagates from every method. Delete writes `[ns1.hover.com,ns2.hover.com]`. Config validation: missing domain, missing nameservers, fewer than 2 nameservers, duplicate nameservers. |
| `internal/iacserver_test.go` | Capabilities lists both `infra.dns` and `infra.dns_delegation`. gRPC bufconn smoke for the new type. |
| Field test | `wfctl apply` in GHA against gocodealone.tech. Verify Hover UI shows the three DigitalOcean nameservers post-apply. |

## Assumptions

| # | Claim | Risk if false | Evidence |
|---|---|---|---|
| A1 | Captured PUT endpoint shape is stable across Hover releases. | Plugin breaks; need re-capture. | OSS clients show 5+ years of stability on the related `/api/dns` endpoints; same control panel codebase. |
| A2 | CSRF tokens from `/control_panel/domain/<name>` are valid for `/api/control_panel/domains/<id>` PUTs (Rails per-session, not per-action). | PUT rejects with 422; retry-with-fresh-fetch loop required. | Rails default behavior; the captured curl used a token fetched from an arbitrary control_panel page. |
| A3 | No Cloudflare/CAPTCHA gate on the PUT path from a fresh GH-runner IP. | Field test fails; mitigation = self-hosted runner OR document a stable egress IP. | README already documents this as a CAPTCHA caveat on the existing DNS flow; same risk model. |
| A4 | Hover idempotently accepts "set to same nameservers" (no-op success). | Only matters on Create-after-state-loss; Diff prevents the re-PUT in normal flow. | Inferred from typical PUT-idempotency conventions; not verified. |
| A5 | Hover's default nameservers are `ns1.hover.com` + `ns2.hover.com`. | Delete writes wrong values; user manually fixes once. | chickenandpork/hoverdnsapi test fixtures show this pair on multiple domains. |
| A6 | `GET /api/domains/<name>/dns` returns `nameservers: [...]` in the response. | Read returns empty; Diff reports perpetual drift. Fallback: `GET /api/domains/<id>` (different endpoint per jmhodges/hover). | chickenandpork fixtures include the field; not verified against accounts with externally-set nameservers. |
| A7 | GH-hosted runners can reach hover.com. | Workflow fails at first request; mitigation = self-hosted runner. | No known IP-based block. |

## Rollback

The change touches runtime (plugin loading + a live registrar PUT), so rollback is in scope.

- **Plugin (workflow-plugin-hover v0.2.0)**: `wfctl plugin install workflow-plugin-hover@v0.1.0` reverts the install on any consumer.
- **Registry**: revert the manifest PR; `wfctl plugin search` falls back to v0.1.0.
- **gocodealone-multisite**: delete the `infra.dns_delegation` resource block; future `wfctl apply` no-ops. To reset gocodealone.tech back to Hover's nameservers: re-run the workflow with `nameservers: [ns1.hover.com, ns2.hover.com]` declared, OR set them manually in Hover's UI.
- **DNS itself**: the PUT is reversible — set whatever NS list you want via another apply. DNS propagation can take up to 24h, but the registrar state flips immediately.

## Top 3 surfaced doubts (from self-challenge)

1. **CSRF-per-PUT cost**: per-PUT control_panel page fetch doubles the request count. If Hover throttles these GETs we may need to fall back to cached-with-1h-TTL CSRF (matching the login session). User-chosen "fetch fresh" is the safer default; field test will validate.
2. **Cloudflare on GHA**: shared-IP runners can trip bot challenges. Fallback: self-hosted runner with a stable egress IP that's been allowlisted via a manual login from that IP. Already a caveat in the README for the DNS-records flow.
3. **Read endpoint coverage of arbitrary external NS**: fixtures show Hover-defaults + Tucows alt only. If `GET /api/domains/<name>/dns` doesn't echo back `ns1.digitalocean.com` etc. post-set, Diff false-positives on every Plan. Mitigation: add a fallback to `GET /api/domains/<id>` if observed in field test.

## Sequencing

1. Plugin PR opens → CI green → Copilot review rounds → merge → tag v0.2.0 → goreleaser publishes assets.
2. Registry manifest update PR with v0.2.0 SHAs → CI green → merge.
3. gocodealone-multisite PR adds `config/dns.wfctl.yaml` + `.github/workflows/dns-delegation.yml` → merge.
4. Operator (Jon) runs the workflow_dispatch → DNS delegation flips to DO.
5. Validate via Hover UI + `dig +short NS gocodealone.tech` post-propagation.

## References

- Captured curl from the Hover web UI session (2026-05-20).
- workflow-plugin-namecheap PR #4 round-6 hardening pattern (ctx propagation across all driver methods).
- chickenandpork/hoverdnsapi `Domain.NameServers` field + fixtures.
- jmhodges/hover `Domain.Nameservers` field (alternate read endpoint).
