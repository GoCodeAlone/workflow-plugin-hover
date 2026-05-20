# workflow-plugin-hover

[![CI](https://github.com/GoCodeAlone/workflow-plugin-hover/actions/workflows/ci.yml/badge.svg)](https://github.com/GoCodeAlone/workflow-plugin-hover/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 🧪 **Experimental** — Hover DNS provider for the GoCodeAlone/workflow IaC surface.
> Hover has no official API; this plugin mimics the browser auth flow used by
> [pjslauta/hover-dyn-dns](https://github.com/pjslauta/hover-dyn-dns). Watch out
> for UI changes on hover.com that may break CSRF token parsing.

## Auth flow

1. GET `/signin` → parse `<input name="_token">` (CSRF token).
2. POST `/signin` with `username`, `password`, `_token`.
3. GET `/signin/totp` → parse fresh `_token`.
4. POST `/signin/totp` with `code` (TOTP RFC 6238) + `_token`.
5. Session cookie now carries subsequent `/api/dns` requests.

Re-auth fires whenever the in-memory session is older than 1h.

## Configuration

```yaml
modules:
  - name: hover
    type: iac.provider.hover
    config:
      username: ${HOVER_USERNAME}
      password: ${HOVER_PASSWORD}
      totp_secret: ${HOVER_TOTP_SECRET}

resources:
  - name: example-com
    type: infra.dns
    config:
      provider: hover
      domain: example.com
      records:
        - { type: A,     name: '@',   data: 203.0.113.10, ttl: 900 }
        - { type: CNAME, name: 'www', data: example.com., ttl: 900 }
```

## Required secrets

| Name | Sensitive | Source |
|------|-----------|--------|
| `HOVER_USERNAME` | no | Hover account login |
| `HOVER_PASSWORD` | **yes** | Hover account password |
| `HOVER_TOTP_SECRET` | **yes** | Base32 seed from Hover 2FA setup (the QR-code page shows a "Secret Key" field; copy that) |

`wfctl secrets setup --plugin workflow-plugin-hover` prompts for each;
sensitive fields are masked.

## TOTP

In-process RFC 6238 (SHA-1, 30s step, 6 digits). The seed is decoded
once at plugin start; codes are computed on each login. Tested
against [RFC 6238 Appendix B vectors](https://datatracker.ietf.org/doc/html/rfc6238#appendix-B).

## Caveats

- **UI brittleness**: Hover's signin page can change. The plugin
  fails loud with `CSRF token not found at /signin` when the regex
  no longer matches.
- **CAPTCHA**: Hover may serve a CAPTCHA challenge on suspicious
  logins. The plugin doesn't solve CAPTCHAs; you'll need to log
  in manually from the same IP to seed trust, OR use a static
  egress IP for the plugin runner.
- **Rate limit**: Stick to small zones; Hover's account portal
  isn't optimised for bulk DNS edits.

## Development

```sh
GOWORK=off go build ./...
GOWORK=off go test ./... -race -count=1
```
