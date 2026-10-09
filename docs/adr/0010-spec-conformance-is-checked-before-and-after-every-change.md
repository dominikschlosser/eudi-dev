# Spec conformance is checked before and after every change

Developers use this tool to check whether issuers, verifiers and wallets follow the specifications. A wrong check or wrong documentation can lead them to change code that was already conformant.

Conformance takes priority over features and convenience. Before each change, confirm what the specification requires. After the change, verify the result against it.

## What checking means

Read the published document. A summary or a claim in the surrounding code does not count.

A citation gives the document, its version or date, and the section. Anything in quotation marks is verbatim from that section.

Specifications change. A profile can defer a rule to another document, and a later version of that document can drop the rule while the profile still references it. Follow the citation to the document that defines the rule, and cite that one.

## Before

Locate the exact section in the current document and confirm its requirement level. A check may only be fatal where the specification says MUST. Where a profile defers, read what it defers to, at the version the profile references. Record the version in the change.

## After

Confirm every citation the change touches is verbatim and correctly attributed, and that the tests state the requirement they encode. `gofmt`, `golangci-lint run ./...` and `go test ./...` must pass.

[ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md) covers what happens to a finding once it is raised.

## Executable checks follow the applicable specification

The versioned specifications and their applicable regulatory adaptations define the requirements. An executable test covers only the requirements and scenarios it runs. Each claim needs a specification reference and a matching check.

The OpenID Foundation conformance suite tests selected OpenID4VP 1.0, OpenID4VCI 1.0 and HAIP 1.0 plans and variants. The wallet plans test this wallet ([runbook](../conformance-run.md)). The issuer and verifier plans test the demo issuer and verifier ([runbook](../conformance-run-demorp.md)). [Conformance results](../conformance-results.md) record those runs and their limits. Passing these plans does not establish conformance to the full EUDI specification set.

[ADR-0013](0013-only-the-eudi-stack-is-supported.md) limits the specification set to what the ARF references. ETSI certificate profiles, trusted lists, registration information, PID rulebooks and ISO mdoc requirements need checks against their own versioned sources. The toolkit's validations and tests cover implemented rules, including registration certificates and over-asking. [Spec compliance](../spec-compliance.md) lists the remaining gaps.

## Watched sources

The repository uses the OIDF suite for executable conformance tests. Check these sources before extending EUDI coverage:

- The [Functional Conformance Assessment Framework](https://conformance.eudi.dev/latest/) (FCAF) publishes test books for the Wallet Solution, including relying party and attestation provider interactions. Content is under active development and has maturity stages. Check each test's version and maturity before using it as a conformance requirement.
- [ISO/IEC TS 18013-6:2025](https://www.iso.org/standard/91153.html), mDL test methods against ISO/IEC 18013-5. It is the reference for fixing the mdoc certificate profile findings that the OIDF suite reports as warnings.
- The EC Interoperability Test Bed with the EWC conformance testbed ([RFC100](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc100-interoperability-profile-towards-itb.md), [backend](https://github.com/EWC-consortium/ewc-wallet-conformance-backend)). Its executable tests certify conformance to the EWC RFC profiles of the Large Scale Pilots. ARF and HAIP conformance need separate checks.
- [eudi-doc-testing-application](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application), the QA suite for the EC reference wallet apps. Its Gherkin scenarios describe EUDI behaviours that tests here can mirror.
- CIR (EU) 2024/2981 and the ETSI TS 119 4xx set define regulatory and technical requirements for certification.

## Consequences

Remove checks that have no specification reference. They can reject conformant input.

Behaviour kept for interoperability with implementations of an older rule may stay. The code must say so and must not call it a requirement. For example, the wallet includes the issuer in the subject alternative names of its signing leaf certificates.

Documentation is held to the same standard as code. `docs/spec-compliance.md`, `docs/wallet.md` and `docs/validate.md` state what is checked and why. When a rule changes, update all of them together.
