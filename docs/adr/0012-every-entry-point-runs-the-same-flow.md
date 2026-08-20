# Every entry point runs the same flow

An issuance or a presentation reaches this wallet through several doors: a URL-scheme dispatch from the handler, `eudi wallet accept` with a link, `eudi wallet scan` off a QR code or an image, a paste into the wallet UI, `POST /api/offers` or `POST /api/presentations` from a script, `GET /credential-offer` and `GET /authorize` addressed by an issuer or a verifier, and `POST /api/dc-api` for the Digital Credentials API. All of them run the same flow. A door decides only how a request arrives. What happens to it afterwards is one code path, and any door may be swapped for another without the protocol behaving differently.

## What a door may do

Recognise what arrived and hand it over. A scan additionally turns a picture into a URI, and a prompt may collect something the user has to type.

## What a door may not do

Read anything the flow will read. A `credential_offer_uri` and a `request_uri` are fetched by whoever runs the flow, and a door does not fetch them to look inside first. Issuers and verifiers do serve these once: eudiplo consumes a credential offer on the first read unless `ISSUER_MULTI_CONSUMPTION` is set, and RFC 9126 §4 says "the client MUST only use a `request_uri` value once". A door that peeks spends the read the flow needed and leaves it with a 404 for something the user is holding in front of them, which is what `eudi wallet scan` did against the eudiplo playground.

Where a door genuinely holds a copy of what the flow will read, it passes it on so the flow survives an issuer that will not serve a second read. `OfferOptions.ResolvedOffer` is that channel.

Nor may a door decide what the flow decides from the protocol: which credentials match, whether consent is required, what the user is asked. Settings the user chose (`--haip`, the validation mode, `--auto-accept`) are a different thing, and they travel as options rather than being inferred from what arrived.

## Where the transaction code comes from

A transaction code is delivered out of band, so somebody has to ask for it. The wallet's consent dialog asks whenever a wallet with a UI is asked interactively, which covers the handler, a remote wallet, and a scan or a link routed to a running instance. An issuance that is not interactive (`--auto-accept`, or an API caller) is not asked, and §4.1.1 puts `tx_code` in the grant because the Authorization Server expects one, so an issuance holding an offer that names it and no code refuses before the pre-authorized code is spent, naming what to supply.

The one flow with no UI is the local headless one, `eudi wallet accept` with no wallet server running, where the CLI prompt is the only channel. It is the single exception to the rule above and it pays for it: the issuance reads the URI again to notice an offer that changed under it, so against a one-shot issuer that read fails and the issuance continues on the copy the prompt handed over, with `credential_offer_reread_failed` in the activity log.

## Consequences

The CLI has one junction, `acceptOID4URI`: it decides local or remote, and nothing above it touches what arrived. The server has one per protocol, `POST /api/offers` and `POST /api/presentations`, which the handler, the UI and script callers all reach. A new entry point calls one of them rather than growing its own variant.

A bug found at one door is a bug at all of them, and a test written for one covers the rest. `TestRemoteAcceptLeavesTheOfferForTheWallet` pins the rule that costs the most when it is broken: a door that reads what the flow will read.

Behaviour that differs between doors is a defect unless it is the door's own job (a camera, a terminal prompt). Where you find one, make the doors agree rather than documenting the difference.
