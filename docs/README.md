# eudi-dev documentation

A testing toolkit for the EUDI wallet ecosystem (wallet, issuer, verifier, and CA in one binary). Start with the overview a page names, then follow into its detail.

## Getting started

- [Examples](examples.md) — end-to-end recipes that issue, present, and validate credentials

## The wallet

- [Wallet](wallet.md) — overview, subcommands, quick start, storage, and credential type inheritance
- [Serving the wallet](wallet/serve.md) — `wallet serve`, endpoints, trust lists, certificate export, and every serve flag
- [Presenting from the wallet](wallet/presenting.md) — `wallet accept`, `wallet scan`, invoking by URL, HAIP enforcement
- [Issuing into the wallet](wallet/issuing.md) — sign-in, deferred issuance, renewing, VCI feature level, wallet attestation, interactive authorization
- [Wallet HTTP API](wallet/http-api.md) — the full REST API and remote control

## Issuing credentials

- [Issue](issue.md) — the `issue` command, flags, and round-trip examples
- [Credential templates](templates.md) — named claim sets, card appearance (display), and the `templates` commands

## Presenting and validating

- [Validate](validate.md) — verify a presentation or a credential from the CLI
- [Decode](decode.md) — inspect a credential or request without validating it

## Deploying

- [Docker](docker.md) — run the wallet, issuer, and verifier in containers
- [Public demo hosting](public-demo.md) — the hardened `--demo` profile for an internet-facing instance
- [Debug proxy](proxy.md) — record and decode OID4VP/OID4VCI traffic

## Conformance

- [Conformance](conformance.md) — running against the OpenID Foundation test suites
- [Conformance run](conformance-run.md) — the harness that drives a conformance run
- [Conformance results](conformance-results.md) — the recorded suite results
- [Spec compliance](spec-compliance.md) — the per-feature compliance matrix

## Reference

- [Diagrams](diagrams/README.md) — interaction diagrams for the implemented OID4VP and OID4VCI flows
- [Architecture decision records](adr/) — the decisions behind the design
- [Agent notes](agents/) — domain, issue-tracker, and review conventions
