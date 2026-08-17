# OIDF Conformance

This repository runs the current OpenID Foundation wallet plans for OID4VP 1.0 Final, OID4VCI 1.0 Final, and HAIP 1.0 Final variants against the local `eudi-dev` testing wallet.

The docs are split by purpose:

- [How to run the wallet conformance suite](./conformance-run.md)
- [Current conformance results](./conformance-results.md)

## Current State

The harness targets a local OpenID Foundation conformance-suite server by default. The documented baseline is `release-v5.2.2`. When the server exposes `/api/server`, the wrapper checks that its tag matches the runner/templates tag and fails early on a mismatch.

Current local status:

- VCI Final SD-JWT and mDoc wallet plans pass in strict mode, including the release-v5.2.1 batch credential issuance module (the wallet sends multiple distinct proof keys and matches the reordered credentials by binding key).
- VCI HAIP SD-JWT and mDoc wallet plans pass in strict mode, including plain immediate issuance, deferred issuance, encrypted credential request variants, batch issuance, FAPI happy-path modules, and FAPI negative authorization-response modules.
- VP Final, VP HAIP `direct_post.jwt`, and VP HAIP `dc_api.jwt` selected modules pass in strict mode, including the release-v5.2.1 unusable-encryption-key module (the wallet ignores JWKS keys it cannot use per RFC 7517 §5). Negative modules that finish as `REVIEW` count as pass-equivalent for the local harness when the runner reports zero condition failures.
- The wrapper passes explicit VP module lists per generated variant. Suite-side not-applicable or broken modules then appear as documented exclusions instead of red result boxes.

See [Current conformance results](./conformance-results.md) for the detailed plan matrix, artifact locations, result-page screenshots, and suite-side exclusions.

## Covered Plans

The wrapper runs the current Final wallet plans plus the current HAIP wallet plans:

- `oid4vp-1final-wallet-test-plan`
- `oid4vci-1_0-wallet-test-plan`
- `oid4vp-1final-wallet-haip-test-plan`
- `oid4vci-1_0-wallet-haip-test-plan`

It does not use the older ID3 wallet plan.

## Default Matrix

The default run covers these Final and HAIP scenarios:

- VP Final: SD-JWT `direct_post`, signed `request_uri`, `x509_hash`
- VP Final: SD-JWT `direct_post.jwt`, signed `request_uri`, `x509_hash`
- VP Final: SD-JWT `direct_post`, unsigned `request_uri`, `redirect_uri`
- VP Final: mDoc `direct_post.jwt`, signed `request_uri`, `x509_hash`
- VP HAIP: SD-JWT `direct_post.jwt`
- VP HAIP: mDoc `direct_post.jwt`
- VP HAIP: SD-JWT `dc_api.jwt`, covering unsigned (no `client_id`), signed `x509_hash`, and multisigned `x509_hash` Browser API modules
- VP HAIP: mDoc `dc_api.jwt`, covering unsigned (no `client_id`), signed `x509_hash`, and multisigned `x509_hash` Browser API modules
- VCI Final: SD-JWT authorization-code issuer-initiated flow with client attestation and DPoP
- VCI Final: mDoc authorization-code issuer-initiated flow with client attestation and DPoP
- VCI HAIP: SD-JWT, covering immediate plain, deferred plain, and immediate encrypted responses
- VCI HAIP: mDoc, covering immediate plain, deferred plain, and immediate encrypted responses

Those runs are fixed in the wrapper. There is no plan selector and no ID3 fallback. Use the official runner `--rerun` selector only for targeted reruns of an already generated matrix.

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
- sets the wallet's conformance mode before each submission through `PUT /api/config/conformance`. Final modules run non-HAIP and HAIP modules run enforced, no matter how the wallet was started. This works against a locally hosted wallet, which is what a conformance run targets
- passes explicit VP module lists for each scenario so the suite runs executable coverage for that generated variant
- monitors waiting modules and automatically submits presentation requests, Browser API requests, credential offers, verifier redirects, and negative-review screenshot placeholders
- prints the created local `plan-detail.html?plan=...` URLs

## Design Rule

There is no conformance-only wallet mode in this flow.

The wallet uses:

- its normal holder key for DPoP and proof binding
- its normal issuer signing key and certificate chain for client attestation and key attestation
- its normal shared wallet CA as the trust anchor

This keeps the run aligned with real wallet behavior. There are no suite-only signing paths.

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
