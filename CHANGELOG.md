# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- removed the dedicated HAIP Keycloak example now that the combined issuer+verifier app covers the HAIP verifier flow

## [1.9.2] - 2026-04-18

### Fixed 

- Do not print traffic classified as "unknown" in the proxy by default

## [1.9.1] - 2026-04-18

### Fixed 

- Proxy grouping fixed/improved

## [1.9.0] - 2026-04-18

### Changed 

- Proxy now learns dynamic endpoints as the flow is going on, calls classified as 'unknown' are not logged by default

## [1.8.10] - 2026-04-12

### Fixed

- malformed custom-scheme credential offer links in the Keycloak demo apps by preserving the original `openid-credential-offer://` and `haip-vci://` URIs after scheme validation instead of normalizing them through `url.Parse(...).String()`
- wallet UI manual URI detection so `haip-vci://...` offers are routed to issuance instead of the presentation parser

## [1.8.9] - 2026-04-12

### Fixed

- lint and security issues in the wallet presentation port probing logic by binding temporary listeners to `127.0.0.1` and handling listener close errors explicitly
- Keycloak example offer-link rendering by validating allowed wallet URI schemes before passing them through to the HTML templates

## [1.8.8] - 2026-04-12

### Fixed

- interactive wallet issuance now defers `credential_offer_uri` fetches until after user consent instead of dereferencing remote offers just to render the modal
- interactive wallet issuance now shows imported credentials immediately after approval and surfaces issuance errors in the wallet UI instead of failing silently

## [1.8.7] - 2026-04-12

### Fixed

- interactive wallet issuance after UI approval now reuses the parsed credential offer instead of refetching one-shot `credential_offer_uri` endpoints
- wallet UI issuance approvals now surface errors correctly and refresh imported credentials immediately on success
- Keycloak example offer links now render as the correct custom wallet schemes instead of broken sanitized browser URLs

## [1.8.6] - 2026-04-12

### Changed

- aligned the dedicated HAIP Keycloak example structure and docs with the baseline issuer+verifier example so both are easier to compare as reference setups

### Fixed

- `wallet accept --auto-accept` now reuses an already running wallet server instead of conflicting on the local port
- `wallet accept` without an explicit port now probes the standard wallet port before falling back to a one-shot server
- HAIP example helper layout and related scripts/build wiring were cleaned up

## [1.8.5] - 2026-04-11

### Added

- a new dedicated HAIP Keycloak example covering HAIP-style authorization-code issuance and x509-based verifier authentication
- wallet support for interactive authorization-code issuance callbacks via the local `/callback` endpoint

### Changed

- simplified and cleaned up the Keycloak example set so the demo apps and bootstrap flows are easier to follow as reference implementations
- expanded the OIDF conformance runner coverage for Browser API and HAIP flows

### Fixed

- Browser API handling for multisigned OpenID4VP request objects
- mdoc Browser API session transcript generation for `dc_api` / `dc_api.jwt`
- multiple issuance and verification issues in the combined Keycloak demo flows

## [1.8.4] - 2026-04-11

### Added

- `wallet remove --all` for clearing the stored wallet more easily

### Fixed

- example setup and bootstrap issues in the combined Keycloak issuer/verifier demo
- interactive wallet issuance behavior so headed mode no longer behaves like silent auto-accept
- Keycloak demo support files so generated trust-list and signing material are handled correctly

## [1.8.3] - 2026-04-11

### Changed

- macOS wallet URL-handler behavior now distinguishes between interactive mode and explicit `--auto-accept` background import

### Fixed

- headed issuance flows now surface the wallet instead of silently importing like auto-accept mode
- the combined Keycloak demo app now logs out through Keycloak instead of only clearing the local session

## [1.8.2] - 2026-04-11

### Added

- Keycloak-based example setups for issuer-only, verifier-only, and combined issuance + verification flows
- a combined Keycloak demo app with smoke tests and bootstrap scripts for end-to-end issuance and wallet login flows

### Fixed

- credential-offer and issuer-metadata parsing for the new Keycloak issuance example flows

## [1.8.1] - 2026-04-09

### Fixed

- SIOPv2 only mode and require-encrypted-request was not enforced

## [1.8.0] - 2026-04-09

### Added

- Browser API presentation support at `/api/dc-api` for OpenID4VP `dc_api` and `dc_api.jwt` response modes, including `web-origin:` client binding and wallet-side Browser API result handling
- HAIP wallet conformance coverage for the current OID4VP 1.0 Final and OID4VCI 1.0 Final HAIP plans, including `dc_api.jwt` VP scenarios

### Changed

- the OIDF wallet conformance runner now targets the current OID4VP 1.0 Final, OID4VCI 1.0 Final, and HAIP wallet plans by default
- the wallet now requests `credential_response_encryption` when issuers advertise it and accepts encrypted JWE credential responses in the authorization code flow

### Fixed

- wallet-generated ETSI trust lists now use the required top-level `LoTE` JSON binding wrapper instead of the previously emitted unwrapped payload
- trust-list parsing and format detection now reject the old non-conformant unwrapped trust-list shape
- proxy JWE tests now match the current `EncryptJWE` API so the full suite builds cleanly again

## [1.7.4] - 2026-04-09

### Changed

- updated the conformance runner to target the current OpenID4VP / OID4VCI 1.0 variant names

## [1.7.3] - 2026-04-08

### Fixed

- compatibility with the then-current wallet conformance test suite

## [1.7.2] - 2026-04-08

### Fixed

- authorization errors are now returned to the verifier instead of being dropped locally
- `direct_post.jwt` responses now preserve `state`

## [1.7.1] - 2026-03-22

### Fixed

- trust-list parsing and decoded output now preserve and expose `ListAndSchemeInformation.NextUpdate`

## [1.7.0] - 2026-03-22

### Changed

- `/api/trustlists` now exposes a container-friendly relative `path` for each trust-list profile entry
- `/api/trustlists` now publishes `advertised_url` for the configured issuer URL and keeps `url` as a backward-compatible alias

### Documentation

- clarified that `/api/trustlists` is a local discovery endpoint while `/api/trustlists/{id}` serves the ETSI trust-list JWT
- documented how Docker and Testcontainers callers should resolve trust-list `path` values against the URL they actually used

## [1.6.0] - 2026-03-22

### Added

- multiple wallet trust-list profiles with `/api/trustlists`, `/api/trustlists/{id}`, and CLI selection via `wallet trust-list --id|--vct|--doctype`
- signed OpenID Credential Issuer metadata and registrar-style authorization responses for wallet-issued credential types
- trust-profile-specific credential-signing leaf certificates under the shared wallet CA

### Changed

- `issue --wallet` now issues with the wallet issuer context instead of generating externally and importing afterward
- wallet issuer and status-list URLs are now persisted and reused across commands so generated credentials, `wallet serve`, trust lists, and status lists stay aligned
- wallet trust lists remain ETSI-shaped and certificate-centric while issuer authorization data is published through issuer metadata and registrar responses

### Fixed

- `issue --wallet` credentials now validate against the wallet trust list and use wallet-managed status-list entries by default
- `wallet generate-pid`, `wallet serve`, `wallet trust-list`, `wallet ca-cert`, `wallet tls-cert`, and `validate --trust-list` now work coherently against the same persisted wallet issuer state
- trust-list parsing accepts current ETSI-style `ListIssueDateTime` payloads

### Documentation

- documented trust-list creation, profile IDs such as `pid` and `local`, wallet-native `issue --wallet` behavior, and the shared-CA/per-profile-leaf certificate model

## [1.5.3] - 2026-03-20

### Fixed

- `wallet tls-cert` now prints exactly one leaf PEM certificate; `wallet ca-cert` prints exactly one CA PEM certificate

## [1.5.2] - 2026-03-20

### Added

- `wallet ca-cert` to print or export the shared wallet CA certificate

### Changed

- wallets under the same wallet base directory now share one persisted CA
- the shared CA now anchors wallet trust lists, status-list `x5c` chains, issuer-metadata `x5c` chains, and HTTPS wallet certificates
- HTTPS wallet certificates are now signed by the shared CA instead of being self-signed
- no wallet API endpoint paths or response formats changed; only the trust model and certificate material changed

## [1.5.1] - 2026-03-20

### Changed

- wallet-generated PID credentials now use the HTTPS wallet status list endpoint on `port+1`
- `wallet issuer-tls-cert` was renamed to `wallet tls-cert` to reflect that the exported certificate covers all HTTPS wallet endpoints
- persisted HTTPS wallet certificate files were renamed to `wallet-tls-cert.pem` / `wallet-tls-key.pem` with legacy migration from the old issuer-prefixed names
- `wallet serve` now prints both HTTP and HTTPS endpoint URLs where both are available

### Documentation

- clarified that `/api/trustlist` and `/api/statuslist` are also exposed via HTTPS
- updated wallet, validate, docker, and README docs for `wallet tls-cert` and HTTPS status-list resolution

## [1.5.0] - 2026-03-20

### Added

- persistent wallet issuer HTTPS certificate files in the wallet directory
- `wallet issuer-tls-cert` to print or export the HTTPS issuer certificate used by `/.well-known/jwt-vc-issuer`

### Changed

- validate UI banner now prefers the status-list validation result when a status check ran

### Fixed

- local validation fetches now bypass proxies and correctly trust the wallet's self-signed local HTTPS endpoints for issuer metadata and status-list resolution

## [1.4.5] - 2026-03-20

### Fixed

- statuslist entries for generate-pid/validate checks statuslist

## [1.4.4] - 2026-03-20

### Fixed

- kid-based verification in validate ui

## [1.4.3] - 2026-03-20

### Fixed

- validate ui does kid-based resolution

## [1.4.2] - 2026-03-20

### Fixed

- `wallet generate-pid` now uses the correct local issuer `iss` instead of `https://issuer.example`

## [1.4.1] - 2026-03-20

### Fixed

- kid-based issuer metadata resolution issues

## [1.4.0] - 2026-03-20

### Added

- HTTPS issuer metadata endpoint for wallet-issued SD-JWT credentials
- kid-based issuer metadata resolution for SD-JWT verification

## [1.3.8] - 2026-03-19

### Fixed

- disclosure of nested values in SD-JWT credentials

## [1.3.7] - 2026-03-19

### Fixed

- further mock PID structural fixes
- multi-credential decoding in proxy

## [1.3.6] - 2026-03-19

### Fixed

- default mdoc PID `birth_place` claim shape
- render one decode link per credential for multi-credential proxy results

## [1.3.5] - 2026-03-19

### Fixed

- debug-mode wallet allows non-matching claims

## [1.3.4] - 2026-03-19

### Fixed

- update default pid mock credentials to better match reality

## [1.3.3] - 2026-03-18

### Fixed

- support browser back in decode ui and nested cred drilldown

## [1.3.2] - 2026-03-11

### Fixed

- enforce spec-compliant request object claims/values

## [1.3.1] - 2026-03-10

### Added

- add aki trusted_authorities support

## [1.3.0] - 2026-03-10

### Added

- add aki trusted_authorities support

## [1.2.1] - 2026-03-09

### Fixed

- include sub and ttl in statuslists

## [1.2.0] - 2026-03-07

### Changed

- Default OIDF runner to signed strict plan

## [1.1.0] - 2026-03-05

### Added

- `wallet show <id>` subcommand to inspect stored credentials (raw by default, `--decoded` for human-readable output)

## [1.0.4] - 2026-03-04

### Fixed

- `trusted_authorities` trust list fetch: fall back to `localhost` when `host.docker.internal` is unreachable (wallet running on host, verifier in Docker)

## [1.0.3] - 2026-03-04

### Added

- Display version in `wallet serve` and `proxy` startup banners

## [1.0.2] - 2026-03-04

### Fixed

- DCQL `trusted_authorities` now reads `values` (array) per OID4VP 1.0 spec instead of `value` (string)
- Codecov ignore patterns use regex syntax to match Go coverage paths

## [1.0.1] - 2026-03-04

### Added

- Version auto-detection from Go module info for `go install` builds (falls back to ldflags, then `dev`)

## [1.0.0] - 2026-03-04

First stable release of oid4vc-dev, a developer toolkit for debugging and testing
OID4VP, OID4VCI, SD-JWT, mDoc, and related SSI/eIDAS 2.0 protocols.

### Features

- **Credential Decoding** - Auto-detect and decode SD-JWT VC, JWT VC, and mDoc/mdoc credentials with selective disclosure resolution
- **Credential Validation** - Signature verification (ES256/384/512, RS256/384/512, PS256), certificate chain validation against ETSI trust lists, token status list (RFC 9596) checking
- **Credential Issuance** - Generate test SD-JWT, JWT VC, and mDoc credentials with configurable claims, key types, and certificate chains
- **DCQL Evaluation** - Parse and evaluate Digital Credentials Query Language queries with credential matching, claim_sets, and credential_sets support
- **Wallet** - Full OID4VP 1.0 wallet with consent UI, supporting:
  - All client_id schemes (x509_san_dns, x509_hash, redirect_uri, verifier_attestation, decentralized_identifier)
  - Response modes: direct_post, direct_post.jwt (JARM), fragment
  - Encrypted request objects (JWE with ECDH-ES)
  - HAIP 1.0 enforcement mode
  - SIOPv2 self-issued ID token (response_type "vp_token id_token")
  - OID4VCI pre-authorized code flow with tx_code support
  - DCQL `trusted_authorities` (`etsi_tl`) filtering
  - Session transcript generation (OID4VP and ISO 18013-7 modes)
- **Proxy** - Debugging reverse proxy that intercepts, classifies, and decodes OID4VP/VCI traffic with:
  - Live web dashboard with SSE streaming
  - HAR export
  - Automatic JWE decryption (key extraction from subprocess stdout)
  - Subprocess management for proxied services
- **Web UI** - Browser-based credential decoder and validator
- **QR Code** - Screen capture and decode support (macOS)
- **Docker** - Multi-arch Docker image with HTTP API for integration testing (Testcontainers support)
### Spec Compliance

- OID4VP 1.0 (Draft 28) - Authorization request parsing, DCQL, JAR, all response modes
- OID4VCI 1.0 - Pre-authorized code grant, credential endpoint, proof of possession
- HAIP 1.0 - Full enforcement of mandatory parameters and algorithms
- SD-JWT (RFC 9809) - Parsing, disclosure resolution, key binding JWT, SHA-256/384/512
- mDoc (ISO 18013-5) - CBOR parsing, COSE_Sign1 verification, MSO validation
- ETSI TS 119 612 - Trust list generation and certificate chain validation
- RFC 9596 - Token status list generation and checking
- SIOPv2 - Self-issued ID token with JWK thumbprint subject

## [0.22.0] - 2026-03-04

### Fixed

- build/linting

## [0.21.2] - 2026-03-04

### Fixed

- build

## [0.21.1] - 2026-03-04

### Fixed

- improve maintainability, tests, remaining spec deviations

## [0.21.0] - 2026-03-04

### Fixed

- improve maintainability, tests, remaining spec deviations

## [0.20.2] - 2026-03-03

### Fixed

- generate trust list correctly signed

## [0.20.1] - 2026-03-03

### Fixed

- build

## [0.20.0] - 2026-03-03

### Added

- add optional request obj enc

## [0.19.0] - 2026-03-03

### Fixed

- use cert chain to sign creds/trust list

## [0.18.5] - 2026-03-02

### Added

- add --docker shortcut

## [0.18.4] - 2026-03-02

### Fixed

- claim matching

## [0.18.3] - 2026-03-02

### Added

- warn if sig algorithm doesnt match header cert

## [0.18.2] - 2026-03-02

### Fixed

- clickable links in proxy

## [0.18.1] - 2026-03-02

### Fixed

- proxy credential detection and decryption

## [0.18.0] - 2026-03-02

### Fixed

- proxy credential scanning improved

## [0.17.2] - 2026-03-02

### Fixed

- wallet enforces OID4VP 1.0 enc args and dismisses invalid requests

## [0.17.1] - 2026-03-02

### Fixed

- windows build

## [0.17.0] - 2026-03-02

### Fixed

- use OID4VP 1.0 spec client_metadata scheme for enc alg/enc

## [0.16.1] - 2026-02-28

### Fixed

- flaky tests

## [0.16.0] - 2026-02-28

### Added

- add --nbf to add not-before claim to issued credentials

## [0.15.0] - 2026-02-28

### Added

- proxy detects credentials / keys from proxied service

## [0.14.2] - 2026-02-28

### Fixed

- use go 1.26.0 in dockerfile

## [0.14.1] - 2026-02-28

### Changed

- apply code review findings / improvements

## [0.14.0] - 2026-02-28

### Changed

- add issue jwt documentation and wallet tx-code/pre-auth notes

## [0.13.4] - 2026-02-28

### Changed

- apply code review findings / improvements

## [0.13.3] - 2026-02-27

### Fixed

- spec violation when building vp response with multiple creds

## [0.13.2] - 2026-02-27

### Fixed

- support JWT VC throughout the codebase

## [0.13.1] - 2026-02-27

### Fixed

- wallet now supports jwt_vc_json (plain jwt credentials)

## [0.13.0] - 2026-02-27

### Added

- add next-response manipulation and preferred format

## [0.12.1] - 2026-02-27

### Fixed

- missed renames

## [0.12.0] - 2026-02-27

### Changed

- rename to oid4vc-dev

## [0.11.1] - 2026-02-27

### Added

- build docker image, update docs

## [0.11.0] - 2026-02-27

### Added

- add mock wallet

## [0.10.0] - 2026-02-27

### Added

- allow to decode tokens from token response in proxy ui

## [0.9.1] - 2026-02-27

### Fixed

- decoder ui created errors when used with the proxy

## [0.9.0] - 2026-02-27

### Added

- merge openid into decode command

## [0.8.2] - 2026-02-26

### Fixed

- fix issue command issues

## [0.8.1] - 2026-02-26

### Fixed

- output mdoc as b64 encoded

## [0.8.0] - 2026-02-26

### Added

- issue mock credentials

## [0.7.1] - 2026-02-26

### Added

- add proxy features

## [0.7.0] - 2026-02-26

### Added

- add proxy features

## [0.6.3] - 2026-02-26

### Fixed

- proxy request classification, docs

## [0.6.2] - 2026-02-26

### Fixed

- proxy respect forwarded-for header

## [0.6.1] - 2026-02-26

### Fixed

- proxy filters out irrelevant requests

## [0.6.0] - 2026-02-26

### Added

- add proxy mode

## [0.5.0] - 2026-02-26

### Added

- add qr screen capture support for macos

## [0.4.1] - 2026-02-26

### Fixed

- fix web ui bugs

## [0.4.0] - 2026-02-26

### Added

- add validation to web ui

## [0.3.0] - 2026-02-26

### Added

- improve web ui highlighting and structure

## [0.2.0] - 2026-02-26

### Added

- add web ui

## [0.1.0] - 2026-02-26

### Fixed

- add Apache 2.0 license

[1.7.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.1
[1.7.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.0
[1.6.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.6.0
[1.5.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.3
[1.5.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.2
[1.5.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.1
[1.5.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.0
[1.4.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.5
[1.4.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.4
[1.4.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.3
[1.4.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.2
[1.4.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.1
[1.4.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.0
[1.3.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.8
[1.3.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.7
[1.3.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.6
[1.3.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.5
[1.3.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.4
[1.3.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.3
[1.3.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.2
[1.3.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.1
[1.3.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.0
[1.2.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.2.1
[1.2.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.2.0
[1.1.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.1.0
[1.0.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.4
[1.0.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.3
[1.0.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.2
[1.0.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.1
[1.0.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.0
[0.22.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.22.0
[0.21.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.2
[0.21.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.1
[0.21.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.0
[0.20.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.2
[0.20.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.1
[0.20.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.0
[0.19.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.19.0
[0.18.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.5
[0.18.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.4
[0.18.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.3
[0.18.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.2
[0.18.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.1
[0.18.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.0
[0.17.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.2
[0.17.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.1
[0.17.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.0
[0.16.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.16.1
[0.16.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.16.0
[0.15.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.15.0
[0.14.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.2
[0.14.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.1
[0.14.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.0
[0.13.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.4
[0.13.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.3
[0.13.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.2
[0.13.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.1
[0.13.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.0
[0.12.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.12.1
[0.12.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.12.0
[0.11.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.11.1
[0.11.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.11.0
[0.10.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.10.0
[0.9.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.9.1
[0.9.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.9.0
[0.8.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.2
[0.8.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.1
[0.8.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.0
[0.7.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.7.1
[0.7.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.7.0
[0.6.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.3
[0.6.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.2
[0.6.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.1
[0.6.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.0
[0.5.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.5.0
[0.4.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.4.1
[0.4.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.4.0
[0.3.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.3.0
[0.2.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.2.0
[0.1.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.1.0
