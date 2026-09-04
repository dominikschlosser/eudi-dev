# Every entry point runs the same flow

An issuance or a presentation reaches this wallet through several entry points: a URL-scheme dispatch from the handler, `eudi wallet accept` with a link, `eudi wallet scan` off a QR code or an image, a paste into the wallet UI, `POST /api/offers` or `POST /api/presentations` from a script, `GET /credential-offer` and `GET /authorize` addressed by an issuer or a verifier, and `POST /api/dc-api` for the Digital Credentials API. All of them run the same flow. An entry point only decides how a request arrives. Everything after that is one code path.

## What an entry point may do

Recognise the input and pass it to the flow. A scan additionally turns a picture into a URI, and a prompt may collect something the user has to type.

## What an entry point may not do

Read anything the flow will read. A `credential_offer_uri` and a `request_uri` are fetched by whoever runs the flow. Some issuers consume a credential offer on the first read, and RFC 9126 §4 says "the client MUST only use a `request_uri` value once". An entry point that fetches it first uses up that read, and the flow gets a 404.

An entry point that already holds a copy of the offer passes it on in `OfferOptions.ResolvedOffer`, so the flow works with an issuer that serves the offer once.

An entry point does not decide what the protocol decides: which credentials match, whether consent is required, what the user is asked. Settings the user chose (`--haip`, the validation mode, `--auto-accept`) are passed as options.

## Where the transaction code comes from

A transaction code is delivered out of band, so the wallet has to ask the user for it. The consent dialog asks whenever an interactive wallet with a UI handles the offer. That covers the handler, a remote wallet, and a scan or a link routed to a running instance. A non-interactive issuance (`--auto-accept`, or an API caller) is never asked. §4.1.1 puts `tx_code` in the grant because the Authorization Server expects one. An issuance with such an offer and no code is refused before the pre-authorized code is used, and the refusal says what to supply.

The local headless flow (`eudi wallet accept` with no wallet server running) has no UI, so the CLI prompt asks. It is the single exception to the rule above. The issuance reads the URI again to notice an offer that changed in the meantime. With an issuer that serves the offer once, that read fails and the issuance continues with the copy from the prompt, with `credential_offer_reread_failed` in the activity log.

## Consequences

The CLI has one entry, `acceptOID4URI`. It decides between local and remote, and nothing before it reads the URI. The server has one per protocol, `POST /api/offers` and `POST /api/presentations`, which the handler, the UI and script callers all reach. A new entry point calls one of them.

A bug found at one entry point is a bug at all of them, and a test written for one covers the rest. `TestRemoteAcceptLeavesTheOfferForTheWallet` covers the most damaging violation, an entry point that reads what the flow will read.

Behaviour that differs between entry points is a defect unless it is the entry point's own job (a camera, a terminal prompt). Fix the difference instead of documenting it.
