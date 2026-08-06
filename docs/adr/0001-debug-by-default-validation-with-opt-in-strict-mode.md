# Debug-by-default validation with an opt-in strict mode

A wallet that rejects a malformed request tells you only that it was malformed, which is the least useful thing it could say to someone debugging a verifier. So validation runs in one of two modes (`internal/wallet/mode.go`). In `debug` (the default) every normative finding is recorded as a warning and the flow continues, so the failure surfaces further along where its effect is visible. In `strict` the same findings are fatal and the request is refused.

The split runs through the whole request path rather than sitting at the edge, because the point is to reach the later step, not to report earlier. `validatePresentationRequestCore` collects findings and only fails on them when the mode says so, and DCQL matching, JAR signature verification and `wallet_nonce` checking each behave differently per mode (see `docs/spec-compliance.md`, which states the two behaviours feature by feature).

## Consequences

The default configuration is deliberately not a conformant wallet. It will present credentials against a request whose JAR signature did not verify, and it says so in the activity log rather than refusing. Conformance runs and anything checking spec behaviour must pass `--mode strict`. Reversing the default would change the observable behaviour of every existing flow, which is why this is written down rather than treated as a flag.
