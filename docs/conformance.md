# OIDF Conformance

This repository runs the current OpenID Foundation plans for OID4VP 1.0 Final, OID4VCI 1.0 Final, and HAIP 1.0 Final variants against the local `eudi-dev` testing wallet, and the issuer and verifier plans against the demo issuer and verifier.

The docs are split by purpose:

- [How to run the wallet conformance suite](./conformance-run.md)
- [How to run the demo issuer and verifier plans](./conformance-run-demorp.md)
- [Current conformance results](./conformance-results.md)

## Current State

The harness targets a local OpenID Foundation conformance-suite server by default. The documented baseline is `release-v5.2.4`. When the server exposes `/api/server`, the wrapper checks that its tag matches the runner/templates tag and fails early on a mismatch.

Current local status:

- VCI Final SD-JWT and mDoc wallet plans pass in strict mode. The SD-JWT plans include the batch credential issuance module (the wallet sends multiple distinct proof keys and matches the reordered credentials by binding key). The mdoc plans use the key attestation configuration, where the wallet sends one proof whose attestation names every batch key (Appendix F.1, HAIP §4.5.1). The suite issues for the proof key only, so the module skips there (see [conformance results](conformance-results.md)).
- VCI HAIP SD-JWT and mDoc wallet plans pass in strict mode, including plain immediate issuance, deferred issuance, encrypted credential request variants, FAPI happy-path modules, and FAPI negative authorization-response modules, plus batch issuance for SD-JWT (the mdoc batch modules are the same skips).
- VP Final, VP HAIP `direct_post.jwt`, and VP HAIP `dc_api.jwt` selected modules pass in strict mode, including the unusable-encryption-key module (the wallet ignores JWKS keys it cannot use per RFC 7517 §5). Negative modules that finish as `REVIEW` count as pass-equivalent for the local harness when the runner reports zero condition failures.
- The wrapper passes explicit VP module lists for the alpha Final plans only, so suite-side not-applicable or broken modules appear as documented exclusions instead of red result boxes. The certifiable HAIP plans always run complete (the suite's plan definition decides what runs, and a certification run must not filter modules).

See [Current conformance results](./conformance-results.md) for the detailed plan matrix, artifact locations, result-page screenshots, and suite-side exclusions.

## Covered Plans

The wrapper runs the current Final wallet plans plus the current HAIP wallet plans:

- `oid4vp-1final-wallet-test-plan`
- `oid4vci-1_0-wallet-test-plan`
- `oid4vp-1final-wallet-haip-test-plan`
- `oid4vci-1_0-wallet-haip-test-plan`

Only the two HAIP plans are part of the OIDF certification program. The suite publishes the plain Final wallet plans as alpha tests, so their runs are evidence but not certifiable yet. The wrapper enforces the split: against the production certification service it runs only the HAIP plans (complete and unfiltered), while local and demo-service runs cover the whole matrix.

## Default Matrix

The default run covers every plan variant combination the wallet supports.

VP Final generates the cross product of credential format (SD-JWT, mDoc), response mode, and the supported prefix and request pairs (36 plans):

- `direct_post` and `direct_post.jwt` with `redirect_uri` (`url_query` and unsigned `request_uri`), `x509_hash` (signed), and `x509_san_dns` (signed)
- `dc_api` and `dc_api.jwt` with `web-origin` (unsigned), `x509_hash` and `x509_san_dns` (signed and multisigned)

VCI Final generates the cross product of credential format, grant type (authorization code, pre-authorized code), offer delivery (`by_value`, `by_reference`), issuance mode (immediate, deferred), and credential response encryption (plain, encrypted), always issuer initiated with client attestation, DPoP, and a plain scope request (32 plans).

The HAIP plans expose fewer selectable variants (they pin the rest per module entry internally):

- VP HAIP: SD-JWT and mDoc with `direct_post.jwt` and `dc_api.jwt`, the latter covering unsigned (no `client_id`), signed `x509_hash`, and multisigned `x509_hash` Browser API modules (4 plans)
- VCI HAIP: SD-JWT and mDoc with `by_value` and `by_reference` offers, each covering immediate plain, deferred plain, and immediate encrypted responses (4 plans)

The matrix leaves out the variants the wallet does not implement: the `pre_registered` and `decentralized_identifier` prefixes, the `wallet_initiated` and `issuer_initiated_dc_api` VCI flows (issuance starts from a credential offer), `rar` authorization requests (the wallet authorizes via scope), and mTLS or `private_key_jwt` client authentication.

The matrix is fixed in the wrapper. Use the official runner `--rerun` selector for targeted reruns of an already generated matrix, or `ONLY_SCENARIOS` (a comma separated list of slug substrings) to generate and run a subset.

## Harness Behavior

[`scripts/oidf-wallet-conformance.sh`](../scripts/oidf-wallet-conformance.sh):

- defaults to `CONFORMANCE_MODE=local`
- targets `https://localhost:8443/` and `https://localhost:8444/` for the local suite and mTLS endpoints
- downloads the latest upstream conformance-suite release tarball from GitLab, unless `OIDF_SUITE_DIR` or `OIDF_SUITE_URL` is set
- checks the local suite `/api/server` tag when available and fails early if the running server does not match the runner/templates release
- creates a Python virtualenv for the official runner
- starts `eudi wallet serve` in strict mode with default PID credentials
- configures the wallet's normal OID4VCI authorization-code client settings
- runs the official `run-test-plan.py` against the conformance-suite server
- forwards `--rerun` to the official runner for targeted plan/module reruns

[`scripts/oidf_wallet_conformance.py`](../scripts/oidf_wallet_conformance.py):

- verifies the extracted suite contains the current Final wallet plans and templates
- reads the wallet's holder binding key from `/api/credentials`
- reads the wallet's issuer signing JWK from `/.well-known/jwt-vc-issuer`
- uses the shared wallet CA as the attestation and trust anchor PEM
- generates per-scenario OIDF config files from the upstream templates
- keeps the VCI suite alias aligned with the configured `redirect_uri` and helper-page paths
- disables the suite's VCI browser helper page and drives the same offer URL directly through the wallet API
- drives Browser API `dc_api` / `dc_api.jwt` presentation requests through the wallet's `/api/dc-api` endpoint
- sets the wallet's conformance mode before each submission through `PUT /api/config/conformance`. Final modules run non-HAIP and HAIP modules run enforced, no matter how the wallet was started
- passes explicit VP module lists for the alpha Final scenarios so the suite runs executable coverage for that generated variant, and runs the certifiable HAIP plans complete without a filter
- monitors waiting modules and automatically submits presentation requests, Browser API requests, credential offers, verifier redirects, and negative-review screenshot placeholders
- prints the created local `plan-detail.html?plan=...` URLs

## Design Rule

The wallet runs a conformance test with its normal keys:

- its holder key for DPoP and proof binding
- its issuer signing key and certificate chain for client attestation and key attestation
- its shared wallet CA as the trust anchor

## What the Suite Does Not Cover

The suite plays the authorization server, and its authorization endpoint issues the code on the first request without a sign-in. So no plan reaches the branch where the wallet hands the authorization URL to a browser. The Playwright suite covers that branch against the demo issuer, which serves a real login page and gives the pushed `request_uri` one use (RFC 9126 section 4).

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
