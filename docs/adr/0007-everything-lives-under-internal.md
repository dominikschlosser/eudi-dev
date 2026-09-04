---
status: accepted (expected to be revisited, see Direction)
---

# Everything lives under internal/

Only `main.go` and the standalone programs under `examples/` sit outside `internal/` and `cmd/`, and those are all `package main`. Nothing in this module can be imported by another project (an example may reach into `internal/`, which is allowed within the module). Several packages (`sdjwt`, `mdoc`, `dcql`, `statuslist`, `trustlist`) parse and verify formats other Go projects would want. Making them importable now would turn every signature into a compatibility commitment while the tool still changes quickly. The closed boundary lets internals be reshaped for whatever the CLI and the wallet server need next, without a deprecation cycle.

## Direction

A public API for the format packages (`sdjwt` and `mdoc` first) is wanted eventually. Revisit this when those packages have stabilised, and supersede this ADR then.

## Consequences

Promotion is more than moving files. The packages are shaped by what this toolkit needs, so their exported functions carry choices a library consumer would not want. In places, verification results are warning strings instead of errors (`VerifyClientID` and its neighbours in `internal/wallet/clientid.go`), because the debug mode in ADR-0001 needs a finding it can report and continue past. Anything promoted needs its interface designed for an outside caller.
