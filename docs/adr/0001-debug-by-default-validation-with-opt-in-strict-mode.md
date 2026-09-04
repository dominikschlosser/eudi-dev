# Debug-by-default validation with an opt-in strict mode

A wallet that rejects a malformed request tells the person debugging a verifier only that it was malformed. So validation runs in one of two modes (`internal/wallet/mode.go`). In `debug` (the default) every normative finding is recorded as a warning and the flow continues, so the failure shows up where its effect is visible. In `strict` the same findings are fatal and the request is refused.

The split runs through the whole request path. `validatePresentationRequestCore` collects findings and only fails on them when the mode says so. DCQL matching, JAR signature verification and `wallet_nonce` checking each behave per mode (`docs/spec-compliance.md` lists both behaviours feature by feature).

`--haip` is a separate switch. It adds the HAIP 1.0 checks on top of the base specifications. What a violation does follows the mode. A HAIP run in debug mode names every profile violation and continues. The same run in strict mode refuses the request.

## Consequences

In the default mode the wallet presents credentials against a request whose JAR signature did not verify, and says so in the activity log. Conformance runs and anything checking spec behaviour must pass `--mode strict`.
