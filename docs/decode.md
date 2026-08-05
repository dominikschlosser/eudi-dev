# Decode

Auto-detect and inspect credentials (SD-JWT, JWT VC, mDOC), OpenID4VCI/VP requests, and ETSI trust lists.

```bash
# Credentials
eudi decode credential.txt
eudi decode "eyJhbGci..."
eudi decode --json credential.txt
eudi decode -v credential.txt
cat credential.txt | eudi decode

# OpenID4VCI credential offers
eudi decode 'openid-credential-offer://?credential_offer_uri=...'
eudi decode 'https://issuer.example/offer?credential_offer=...'

# OpenID4VP authorization requests
eudi decode 'openid4vp://authorize?...'
eudi decode 'haip-vp://authorize?...'
eudi decode 'eudi-openid4vp://authorize?...'
eudi decode request.jwt
cat offer.json | eudi decode

# ETSI trust lists
eudi decode trust-list.jwt
eudi decode -f trustlist https://example.com/trust-list.jwt
```

## Auto-detection order

1. **OpenID URI schemes** — `openid-credential-offer://` / `haip-vci://` (VCI), `openid4vp://` / `haip-vp://` / `eudi-openid4vp://` (VP)
2. **HTTP(S) URL with OID4 query params** — `credential_offer` / `credential_offer_uri` (VCI), `client_id` / `response_type` / `request_uri` (VP)
3. **SD-JWT** — contains `~` separator
4. **mDOC** — hex or base64url encoded CBOR
5. **JSON** — inspected for OID4 marker keys (`credential_issuer` → VCI, `client_id` → VP)
6. **JWT** — 3 dot-separated parts; payload inspected for OID4 markers and trust list markers (`TrustedEntitiesList`)

## Format override

Use `--format` / `-f` to skip auto-detection when it gets it wrong (e.g. a credential JWT whose payload happens to contain `credential_issuer`):

```bash
eudi decode -f jwt "eyJhbGci..."
eudi decode -f sdjwt credential.txt
eudi decode -f mdoc credential.hex
eudi decode -f vci 'openid-credential-offer://...'
eudi decode -f vp request.jwt
```

Accepted values: `sdjwt` (or `sd-jwt`), `jwt`, `mdoc` (or `mso_mdoc`), `vci` (or `oid4vci`), `vp` (or `oid4vp`), `trustlist` (or `trust`).

## QR Code Scanning

Scan a QR code directly from an image file or a screen capture:

```bash
eudi decode --qr screenshot.png
eudi decode --screen
```

`--screen` uses the native macOS `screencapture` tool in interactive selection mode — a crosshair appears to let you select the region containing the QR code. On other platforms, take a screenshot and use `--qr screenshot.png` instead.

> **Note:** Screen capture permission on macOS is granted to the **terminal app** (Terminal.app, iTerm2, etc.), not to the `eudi` binary itself. If permission is missing, System Settings will be opened automatically to the Screen Recording pane — enable access for your terminal app there, then re-run the command.

## Flags

| Flag             | Description                                                  |
|------------------|--------------------------------------------------------------|
| `-f`, `--format` | Pin format: `sdjwt`, `jwt`, `mdoc`, `vci`, `vp`, `trustlist` |
| `--qr`           | Decode QR from a PNG or JPEG image file                      |
| `--screen`       | Open interactive screen region selector and decode a QR code from the selection (macOS only) |

`--qr`, `--screen`, and positional input arguments are mutually exclusive.

## Example output

```
SD-JWT Credential
──────────────────────────────────────────────────

┌ Header
  alg: ES256
  typ: dc+sd-jwt

┌ Payload (signed claims)
  _sd: ["77ofip...", "EyNwlR...", "X3X1zI..."]
  _sd_alg: sha-256
  iss: https://issuer.example
  vct: urn:eudi:pid:1

┌ Disclosed Claims (3)
  [1] given_name: Erika
  [2] family_name: Mustermann
  [3] birth_date: 1984-08-12
```

`decode` is primarily an inspection tool, but it can automatically verify JWT or SD-JWT signatures when issuer metadata can be resolved from `iss` and `kid`. Use `validate` when you need explicit trust inputs such as `--key`, `--trust-list`, or status-list checking.

Use `-v` for x5c chains, digest IDs, and device key info. Use `--json` for machine-readable output.
