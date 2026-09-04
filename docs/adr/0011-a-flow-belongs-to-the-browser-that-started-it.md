# A flow belongs to the browser that started it

One wallet serves several people at once on the public demo, and one person locally. A consent request, an error report and an issuer sign-in prompt each belong to the flow that raised them. Each records the browser that started the flow and reaches only that browser.

The browser is recognised by an opaque `eudi_session` cookie the wallet sets when it first serves it. A client that submits a flow on a page's behalf names that page instead. It puts the same value in the URL of the page it opens and in the `X-Eudi-Owner` header on the call it makes. The CLI does this, and the URL handler does it when it routes to a wallet somewhere else. A local wallet opens its own UI, so the handler names nothing there and the wallet names the request in the URL instead. `EventSource` sets no headers, so the event stream carries the value as a query parameter.

## Not a security boundary

Anyone can send any cookie or any header. [ADR-0002](0002-the-wallet-http-api-is-unauthenticated.md) keeps this API open, and this decision does not close it. It only stops two people using one wallet from seeing and answering each other's flows. The activity log stays shared (`docs/public-demo.md`), so a visitor can still read another's request there.

## Unowned flows stay answerable

A flow whose client named no browser is visible and answerable to every caller. That keeps the CLI, curl, CI, Testcontainers, the conformance harness and every URL handler working. `TestBackwardsCompatibility_ClientsThatNameNoBrowser` and `TestUnownedRequestStaysAnswerable` cover it.

The sign-in prompt navigates a browser, so it reaches only its owner. A client that named no browser already has the URL, in the answer to the call it made. An error report only informs, so it follows the same rule as a consent request. A consent request with no owner waits in the banner. A local wallet names the request in the URL of the tab it opens, so that tab answers it directly.

## The redirect carries the request id

A browser the wallet redirects is given the request id in the URL. A call that carries that id reaches and answers that request. This is how a browser that keeps no cookie (inside a cross-site frame, or with cookies turned off) still gets its flow. The id is unguessable and the wallet gave it to that browser, so it serves as a capability.

## Consequences

The owner is set when a signal is created and never changes. Nothing has to be published and then corrected, and the event streams read it without the registry lock.

The owner is never sent to a client. `ConsentRequest` is marshalled field by field, so a new field added there must not include it.

The rule runs on every wallet, local or shared. Do not add a demo-only branch. The only difference between the two is how many event streams are open.
