# A flow belongs to the browser that started it

One wallet serves several people at once on the public demo, and it serves one person locally. A consent request, an error report and an issuer sign-in prompt each belong to the flow that raised them, so each carries the browser that started that flow and reaches only that browser.

The browser is recognised by an opaque `eudi_session` cookie the wallet sets when it first serves it. A client that submits a flow on a page's behalf, rather than from the page, names that page instead: it puts the same value in the URL of the page it opens and in the `X-Eudi-Owner` header on the call it makes. The CLI does this, and the URL handler does it when it routes to a wallet somewhere else. A local wallet opens its own UI, so the handler names nothing there and the wallet names the request in the URL instead. `EventSource` sets no headers, so the event stream carries the value as a query parameter.

## Not a security boundary

Anyone can send any cookie or any header. [ADR-0002](0002-the-wallet-http-api-is-unauthenticated.md) keeps this API open, and this decision does not close it. What it buys is that two people using one wallet stop being shown, and stop being asked to answer, each other's flows. Do not build on it as though it were authentication, and do not describe it as one: `docs/public-demo.md` says plainly that the activity log stays shared, which is where a visitor can still read another's request.

## Unowned is load-bearing

A flow whose client named no browser is visible and answerable to every caller. That is what keeps the CLI, curl, CI, Testcontainers, the conformance harness and every URL handler working. `TestBackwardsCompatibility_ClientsThatNameNoBrowser` and `TestUnownedRequestStaysAnswerable` pin it.

The sign-in prompt is the one signal that acts on a browser rather than informing it, so it only ever reaches its owner. A client that named no browser already has the URL, in the answer to the call it made. An error report informs, so it follows the rule the consent request follows. A consent request nobody named waits in the banner, which is what a local wallet sees too: it is a shared wallet with one visitor, and the wallet names the request in the URL of the tab it opens so that tab answers it directly.

## The redirect hands over an id

A browser the wallet redirects is given the request id in the URL. Naming that id reaches and answers that request, which is what a browser that keeps no cookie has to show for itself: one inside a cross-site frame, or one with cookies turned off. The id is unguessable and the wallet gave it to that browser, so it serves as a capability.

## Consequences

Ownership is settled when a signal is created and never changed afterwards, so nothing has to be published and then corrected, and the event streams can read it without the registry lock.

The owner never leaves the server. `ConsentRequest` is marshalled field by field, so a new field added there must not echo it.

The rule runs on every wallet, local or shared. Resist adding a demo-only branch: the differences that look like they need one are answered by how many streams are watching.
