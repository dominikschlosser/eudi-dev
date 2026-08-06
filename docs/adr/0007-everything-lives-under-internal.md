---
status: accepted (expected to be revisited, see Direction)
---

# Everything lives under internal/

Only `main.go` sits outside `internal/` and `cmd/`, so nothing in this module can be imported by another project. That is deliberate. Several packages (`sdjwt`, `mdoc`, `dcql`, `statuslist`, `trustlist`) parse and verify formats that other Go projects would plausibly want, and making them importable now would turn every signature into a compatibility commitment while the tool is still moving quickly. Keeping the boundary closed means internals can be reshaped for whatever the CLI and the wallet server need next, without a deprecation cycle.

## Direction

A public API for the format packages (`sdjwt` and `mdoc` first) is wanted eventually. This ADR records why it has not happened yet, not that it should never happen. Revisit it when those packages stop changing shape, and supersede this ADR rather than quietly moving a directory.

## Consequences

Promotion is not a move. Today's package shapes are driven by what this toolkit needs, so their exported surfaces carry choices a library consumer would not want: verification results are returned as warning strings rather than errors in places (`VerifyClientID` and its neighbours in `internal/wallet/clientid.go`), because the debug mode in ADR-0001 needs a finding it can report and continue past. Anything promoted needs its interface designed for the caller who is not this tool, which is a separate exercise from relocating the files.
