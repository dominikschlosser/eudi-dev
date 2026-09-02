# Debug-by-default validation with an opt-in strict mode

A wallet that rejects a malformed request tells the person debugging a verifier only that it was malformed. So validation runs in one of two modes (`internal/wallet/mode.go`). In `debug` (the default) every normative finding is recorded as a warning and the flow continues, so the failure surfaces further along where its effect is visible. In `strict` the same findings are fatal and the request is refused.

The split runs through the whole request path so the flow reaches the later step. `validatePresentationRequestCore` collects findings and only fails on them when the mode says so, and DCQL matching, JAR signature verification and `wallet_nonce` checking each behave differently per mode (see `docs/spec-compliance.md`, which states the two behaviours feature by feature).

Both modes run the checks and record what they find. The debug run is the one meant for watching what a counterparty gets wrong, so it is the run where naming each finding matters most.

`--haip` is a separate switch. It decides how many checks run, adding everything HAIP 1.0 asks of a counterparty on top of what the base specifications ask of any. What a violation then does follows the mode, the same as for every other finding: a HAIP run in debug mode names every profile violation and continues, and the same run in strict mode refuses the request.

## Consequences

The default configuration is deliberately not a conformant wallet. It will present credentials against a request whose JAR signature did not verify, and it says so in the activity log rather than refusing. Conformance runs and anything checking spec behaviour must pass `--mode strict`.
