# Spec conformance is checked before and after every change

This tool exists to tell a developer whether their issuer, verifier or wallet follows the specifications. Every finding it reports, every check it runs and every sentence of its documentation is a claim about what a specification says. A wrong claim makes someone fix code that was conformant.

So conformance comes before features, ergonomics and internal tidiness. It is verified twice for every change: before the work, to establish what the specification requires, and after it, to confirm the change still matches.

## What checking means

Read the published document. A summary or a claim in the surrounding code does not count.

A citation names the document, its version or date, and the section. Anything in quotation marks is verbatim from that section.

Specifications change. A profile can defer a rule to another document that later drops it while the profile still points there. Follow such a citation to the document that holds the rule, and cite that one.

## Before

Locate the exact section in the current document and confirm its requirement level. A check may only be fatal where the specification says MUST. Where a profile defers, read what it defers to, at the version the profile references. Record the version in the change.

## After

Confirm every citation the change touches is verbatim and correctly attributed, and that the tests state the requirement they encode. `gofmt`, `golangci-lint run ./...` and `go test ./...` pass.

[ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md) covers what happens to a finding once it is raised.

## The executable check is the OIDF conformance suite

Citation checking covers each claim. The OpenID Foundation conformance suite verifies the running binary against the same specifications, in both directions. The wallet plans test this wallet ([runbook](../conformance-run.md)). The issuer and verifier plans test the demo issuer and verifier ([runbook](../conformance-run-demorp.md)). The results are recorded in [conformance results](../conformance-results.md). It is the only mature executable suite for the protocols the EUDI stack builds on (OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0), so a conformance statement about this project points at those runs.

EUDI stays the primary target, and [ADR-0013](0013-only-the-eudi-stack-is-supported.md) bounds the specification set to what the ARF references. The ARF rules the OIDF suite does not cover (registration certificates, over-asking) are checked by this toolkit's own validations.

## Watched sources

No other executable conformance suite exists for EUDI or the ARF as of 2026-08. Re-check these before extending conformance coverage, in rough order of expected relevance:

- The [Functional Conformance Assessment Framework](https://conformance.eudi.dev) (FCAF), the official EUDI conformance framework aimed at certification. Textual test books per system under test (relying party, attestation provider, PID provider), still skeletal at v0.0.10. When the attestation provider and relying party test books land, map the demo issuer and verifier onto them.
- [ISO/IEC TS 18013-6:2025](https://www.iso.org/standard/91153.html), mDL test methods against ISO/IEC 18013-5. The source for closing the mdoc certificate profile findings the OIDF suite reports as warnings.
- The EC Interoperability Test Bed with the EWC conformance testbed ([RFC100](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc100-interoperability-profile-towards-itb.md), [backend](https://github.com/EWC-consortium/ewc-wallet-conformance-backend)). Executable, but it certifies conformance to the EWC RFC profiles of the Large Scale Pilots rather than to the ARF or HAIP.
- [eudi-doc-testing-application](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application), the QA suite for the EC reference wallet apps. Its Gherkin scenarios catalogue EUDI behaviours worth mirroring in tests here.
- CIR (EU) 2024/2981 and the ETSI TS 119 4xx set, the certification layer. Documents without tooling.

## Consequences

A check without a citation is removed. Such a check refuses conformant input, which is the failure this tool exists to find in others.

Behaviour kept for interoperability with implementations built against an older rule may stay, as long as the code says so and does not call it a requirement. The wallet names the issuer in the subject alternative names of the leaves it signs with for that reason.

Documentation is held to the same standard as code. `docs/spec-compliance.md`, `docs/wallet.md` and `docs/validate.md` state what is checked and why, so a rule that changes is corrected in all of them at once.
