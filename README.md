# workflow-plugin-hover

[![CI](https://github.com/GoCodeAlone/workflow-plugin-hover/actions/workflows/ci.yml/badge.svg)](https://github.com/GoCodeAlone/workflow-plugin-hover/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Experimental** — Hover DNS provider for the GoCodeAlone/workflow IaC surface.
> Hover has no official API. This plugin drives a real Chrome browser to
> authenticate, then reuses session cookies for read operations and runs writes
> in-browser.

## Why Chrome?

Hover's signin endpoint is protected by Imperva Advanced Bot Protection (ABP).
A cold Go `http.Client` receives a 401/block response because it cannot run
Imperva's JavaScript sensor to mint the clearance cookie. A real Chrome instance
runs the JS sensor, passes the Imperva challenge, and completes the full login
flow (including TOTP 2FA). The resulting session + clearance cookies are then
reused by a lightweight Go `http.Client` for all read operations; writes that
require an in-page flow run in the same browser instance.

## Hybrid architecture

1. **Browser login**: Chrome drives the Hover signin page, passes the Imperva
   challenge, and completes TOTP 2FA when configured.
2. **HTTP reads**: Session + Imperva clearance cookies are transferred to a Go
   `http.Client`; all read operations (`ListDomains`, `GetDomain`, `ListRecords`,
   `GetDomainDelegation`) use the cookie-reuse path.
3. **In-browser writes**: Mutations (`SetNameservers`, `CreateRecord`,
   `UpdateRecord`, `DeleteRecord`) run in the browser where the full Imperva
   context is live.

The session is considered stale after 1 hour; a fresh browser login fires
automatically on the next operation.

## Chrome acquisition

The plugin needs a Chrome binary. Resolution order:

1. `browser_path` config key (or `HOVER_BROWSER_PATH` / `ROD_BROWSER_PATH` env
   var) — absolute path to an existing Chrome/Chromium binary.
2. Auto-download: if no binary is found and `browser_download` is `true` (or
   `HOVER_BROWSER_DOWNLOAD=true`), go-rod downloads a compatible Chromium build
   to a local cache. **Default: `true`.**
3. If neither finds a binary, `ErrChromeUnavailable` is returned.

## Configuration

```yaml
modules:
  - name: hover
    type: iac.provider
    config:
      provider: hover
      username: ${HOVER_USERNAME}
      password: ${HOVER_PASSWORD}
      totp_secret: ${HOVER_TOTP_SECRET}   # omit if account has no MFA

      # Browser options (all optional; shown with their defaults)
      # browser_path:        ""            # absolute path to Chrome binary
      # browser_download:    true          # auto-download Chromium if not found
      # browser_headless:    true          # run Chrome headlessly
      # browser_profile_dir: ""            # persistent profile dir (see below)

  - name: example-com
    type: infra.dns
    config:
      provider: hover
      domain: example.com
      records:
        - { type: A,     name: '@',   content: 203.0.113.10, ttl: 900 }
        - { type: CNAME, name: 'www', content: example.com.,  ttl: 900 }
```

### Browser config env vars

| Config key           | Env alias                | Default                                    |
|----------------------|--------------------------|--------------------------------------------|
| `browser_path`       | `HOVER_BROWSER_PATH`, `ROD_BROWSER_PATH` | (none — auto-discover or download) |
| `browser_download`   | `HOVER_BROWSER_DOWNLOAD` | `true`                                     |
| `browser_headless`   | `HOVER_BROWSER_HEADLESS` | `true`                                     |
| `browser_profile_dir`| `HOVER_BROWSER_PROFILE_DIR` | `${XDG_STATE_HOME:-$HOME/.local/state}/wfctl/plugins/hover/browser-profile` |

Explicit config keys take precedence over env vars; env vars take precedence
over built-in defaults.

## 2FA / TOTP

Supply `HOVER_TOTP_SECRET` (base32-encoded seed from the Hover "Set up
authenticator" QR-code page) when your account has 2FA enabled. The plugin
computes RFC 6238 (SHA-1, 30 s step, 6 digits) codes in-process.

**Email / non-TOTP 2FA is not supported.** If Hover reports `need_2fa` and no
TOTP secret is configured, the plugin returns `ErrEmail2FARequired`. To resolve:
either switch the account to an authenticator-app 2FA method and supply the
base32 seed, or pre-trust a persistent browser profile (see below) so the
security checkpoint is skipped on subsequent runs.

## Browser profile directory

The profile dir stores Imperva clearance cookies, Hover session cookies, and
other browser state across runs. It is sensitive — treat it like a credential
file and keep it out of version control.

Default location:

```
${XDG_STATE_HOME:-$HOME/.local/state}/wfctl/plugins/hover/browser-profile
```

Override via `browser_profile_dir` or `HOVER_BROWSER_PROFILE_DIR`. A warm
profile skips re-authentication against Imperva on subsequent runs and allows
the plugin to work even after a TOTP secret is no longer available.

## Required secrets

| Name | Sensitive | Purpose |
|------|-----------|---------|
| `HOVER_USERNAME` | no | Hover account login (email) |
| `HOVER_PASSWORD` | **yes** | Hover account password |
| `HOVER_TOTP_SECRET` | **yes** | Base32 TOTP seed (required when account has authenticator 2FA) |

```sh
wfctl secrets setup --plugin workflow-plugin-hover
```

Sensitive fields are masked during interactive prompts.

## Typed errors

| Error | Meaning |
|-------|---------|
| `ErrBotChallenge` | Imperva blocked the browser session. Check network egress rules or rotate the browser profile. |
| `ErrChromeUnavailable` | No Chrome binary found and `browser_download=false`. Install Chrome or set `HOVER_BROWSER_DOWNLOAD=true`. |
| `ErrEmail2FARequired` | Account uses email/non-TOTP 2FA. Switch to an authenticator app or pre-trust a persistent browser profile. |

### Bot-challenge notice

Driving a real browser against Imperva-protected pages is a best-effort
approach. Imperva may update its JS sensor in ways that break the clearance
flow; this is a known gray area in Imperva's terms of service. The plugin
documents this honestly and makes no guarantees of perpetual bypass.

## Importing existing state

```sh
wfctl infra import --config infra.yaml --name example-com-dns --id example.com
wfctl infra import --config infra.yaml --name example-com-delegation --id example.com
```

Declare the target resource in config first so `wfctl` resolves the Hover
provider and resource type. `infra.dns` imports zone records; `infra.dns_delegation`
imports registrar nameservers. Imported state is adoption-shaped so follow-up
plans compare against live outputs.

## DNS record semantics

The `records` key is **required**. The plugin treats your declared list as
authoritative: records present upstream but absent from `records` are deleted;
records in `records` but absent upstream are created; records that differ are
updated. To drop every record from a zone, set `records: []`. Omitting `records`
entirely is rejected at Plan time to prevent accidental zone wipes.

## Limitations

- **No zone delete**: Hover exposes no API to drop a DNS zone. Resource `Delete`
  is a no-op — IaC state is cleared but upstream records remain. Drop the zone
  manually via Hover's UI if needed.
- **Rate limit**: Stick to small zones; Hover's account portal is not optimised
  for bulk DNS edits.

## Development

```sh
GOWORK=off GOTOOLCHAIN=auto go build ./...
GOWORK=off GOTOOLCHAIN=auto go test ./... -race -count=1
```

Browser unit tests in `pkg/hoverclient` launch real Chrome locally and may take
~20 s. They skip automatically when no Chrome binary is available and
`HOVER_BROWSER_DOWNLOAD` is not set.
