# Running OIDF Conformance Against the Demo Issuer and Verifier

This runbook runs the official OIDF issuer and verifier plans against the demo issuer and demo verifier that `wallet serve` mounts under `/issuer` and `/verifier`. It is the counterpart of [Running OIDF Wallet Conformance](./conformance-run.md). There the suite plays the issuer and the verifier and our wallet is under test. Here the suite plays the wallet and our demo counterparties are under test.

Certification is sought for the wallet alone. These issuer and verifier plans run locally (or on the hosted demo service) as quality checks, and the wrapper refuses the production certification service.

## What Runs

The wrapper starts one wallet server and drives these plans through the official `run-test-plan.py`:

- `oid4vci-1_0-issuer-test-plan` against the demo issuer, three times (authorization code wallet initiated, authorization code issuer initiated, pre-authorized code)
- `oid4vci-1_0-issuer-haip-test-plan` against the demo issuer (SD-JWT VC, authorization code, issuer initiated). Only the VCI modules run. The plan's appended FAPI2 Security Profile server suite exercises a full OAuth authorization server, and the demo issuer implements the minimal HAIP profile a wallet needs (PAR, PKCE S256, DPoP, attestation-based client authentication)
- `oid4vp-1final-verifier-test-plan` against the demo verifier, three times (SD-JWT VC signed request, SD-JWT VC unsigned request under the `redirect_uri` prefix, mdoc signed request)
- `oid4vp-1final-verifier-haip-test-plan` against the demo verifier (SD-JWT VC and mdoc, both `direct_post.jwt`)

Modules that test something the demo pair does not offer are left out, since they would skip themselves and `run-test-plan.py` counts a skip as a failure: the demo issuer serves unsigned metadata (`metadata-test-signed`), requires no key attestation (`fail-invalid-key-attestation-signature`), advertises no credential encryption (`fail-unsupported-encryption-algorithm`), and signs one credential per request unless an offer asked for a batch, so the batch module runs only in the offer driven scenarios. The demo verifier serves its request objects over GET, so `request-uri-method-post` is left out under signed requests.

The pre-authorized code scenario also leaves out the six client attestation negative modules. Suite release-v5.2.4 breaks them under that grant: after the expected token refusal their flow keeps going into the credential request and the suite interrupts the module with "Condition called when test status is 'WAITING'. This is a bug in the test module". The same modules complete under both authorization code scenarios, where the refusal happens at the PAR endpoint.

The harness stands in for the human tester the plans expect:

- it pushes a fresh demo credential offer to the suite's exposed `credential_offer` endpoint whenever an issuer-initiated module waits for one (by value, since a `credential_offer_uri` must be https)
- it signs in at the demo issuer's authorization page as the demo account (alice) and follows the redirect to the suite's callback
- it creates a demo verifier request per verifier module and delivers its query string to the suite's authorization endpoint, standing in for the wallet an `openid4vp://` link would invoke
- it uploads the screenshot placeholders the verifier plans end on

The suite cannot see whether the verifier under test verified the presentation (its verifier modules end in `REVIEW` either way), so the harness also reads the demo verifier's own verdict for every request. A module that presented a tampered credential must end `failed` at the demo verifier, everything else `verified`. A mismatch fails the run with exit code 3.

## Prerequisites

The same as [Running OIDF Wallet Conformance](./conformance-run.md): a local conformance-suite checkout at the documented baseline, and the suite server running on the host behind its nginx.

## Run

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.2.4 \
OIDF_RUN_DIR=/tmp/oidf-demorp-conformance \
  scripts/oidf-demorp-conformance.sh
```

Selected scenarios only (substring match on the scenario slug):

```bash
ONLY_SCENARIOS=vp-verifier-final-sdjwt,vci-issuer-preauth \
  scripts/oidf-demorp-conformance.sh
```

The `--rerun` selector passes through to the official runner exactly as in the wallet runbook.

## How the Demo Pair Is Served

The verifier plans require the `request_uri` and the `response_uri` to be https, and the HAIP issuer metadata checks require an https credential issuer. The wrapper starts the wallet with an https base URL and `--serve-tls`, so the wallet binds that origin itself with its own TLS certificate (the suite skips certificate verification on outbound calls, so the wallet CA does not need to be installed anywhere).

The suite signs the credentials it presents to the demo verifier under its own CAs (the `vp-signing` CA from `scripts/certs-keys` for SD-JWT VCs, a built-in mdoc IACA root for mdocs). The wrapper passes both to the wallet as `--demo-verifier-trust-anchor` files, so the demo verifier accepts those chains next to the wallet CA it always trusts. The IACA root is published by the suite server at `/mdoc-iaca-root.pem`. When that endpoint is unavailable the wrapper extracts the same certificate from the suite source.

For the issuer plans the suite is configured the other way around: the generated configs carry the wallet CA as `credential.trust_anchor_pem`, so the suite can validate the demo ticket's certificate chain, and as `client.request_object_trust_anchor_pem` in the verifier configs, so it can validate the demo verifier's signed request objects.

## Environment Overrides

The wallet runbook's suite and server overrides apply unchanged (`CONFORMANCE_MODE`, `CONFORMANCE_SERVER`, `OIDF_SUITE_DIR`, `OIDF_SUITE_TAG`, `OIDF_SUITE_URL`, `OIDF_RUN_DIR`, `OIDF_MODULE_IDLE_TIMEOUT`, `OIDF_KEEP_SUITE_DB`, `OIDF_REQUEST_TIMEOUT`, `PORT`). Set `OIDF_REQUEST_TIMEOUT=60` on a loaded machine, and leave `OIDF_KEEP_SUITE_DB` off for repeated runs (a suite database carrying several runs answers the monitor's reads so slowly that placeholder uploads miss and modules hang). Specific to this wrapper:

- `OIDF_DEMO_BASE_URL`: the https origin the demo issuer and verifier advertise. Defaults to `https://localhost:<port+1>`
- `ONLY_SCENARIOS`: comma separated scenario slug substrings to run a subset

`CONFORMANCE_MODE=hosted` needs a publicly reachable `OIDF_DEMO_BASE_URL` (a tunnel with its own TLS terminator), because the hosted suite fetches the demo endpoints itself. It refuses the production certification service. Local mode is the supported path.

## Result Artifacts

The wrapper prints the run directory and leaves the same artifacts as the wallet wrapper (`wallet.log`, `runner.log`, `results/` with the exported archives and the generated configs). The runner log additionally carries the `[verdicts]` block with the demo verifier's outcome per verifier module.
