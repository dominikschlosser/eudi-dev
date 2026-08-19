# Spec conformance is checked before and after every change

This tool exists to tell a developer whether their issuer, verifier or wallet follows the specifications. Every finding it reports, every check it runs and every sentence of its documentation is a claim about what a specification says. A wrong claim is worse than no claim, because it sends someone to fix conformant code.

So conformance comes before features, ergonomics and internal tidiness, and it is verified twice for every change: before the work, to establish what the specification requires, and after it, to confirm the change still matches.

## What checking means

Read the published document, fetched and searched. Not a memory of it, not a summary, and not what the surrounding code already claims.

A citation names the document, its version or date, and the section. Anything in quotation marks is verbatim from that section.

Specifications move, and a profile can defer a rule to another document that later drops it while the profile still points there. Following a citation one hop further is part of the check, and the citation names the document the rule is actually in.

## Before

Locate the exact section in the current document and confirm its requirement level, because a check may only be fatal where the specification says MUST. Where a profile defers, read what it defers to, at the version the profile references. Record the version in the change, so the next reader can tell when the ground was last checked.

## After

Confirm every citation the change touches is verbatim and correctly attributed, and that the tests state the requirement they encode, so a rule that later moves is found by reading them. `gofmt`, `golangci-lint run ./...` and `go test ./...` pass: a conformance claim that does not run is not a claim.

[ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md) covers what happens to a finding once it is raised. This decision is about the ground it stands on.

## Consequences

A check whose grounding cannot be produced is removed rather than kept on the chance it is useful, because an ungrounded check refuses conformant input, which is the failure this tool exists to prevent in others. Version 1.25.2 removed one: an `iss`-to-certificate binding attributed to HAIP 1.0 §6.1.1, which HAIP never stated. It came from SD-JWT VC draft-08 and was dropped by the draft-13 that HAIP 1.0 references, and in strict mode it had been refusing conformant credentials.

Behaviour kept for interoperability with implementations built against an older rule may stay, as long as the code says so and does not call it a requirement. The wallet still names the issuer in the subject alternative names of the leaves it signs with, for exactly that reason.

Documentation is held to the same standard as code. `docs/spec-compliance.md`, `docs/wallet.md` and `docs/validate.md` state what is checked and why, so a rule that changes is corrected in all of them at once.
