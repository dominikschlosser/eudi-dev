# The server reloads its store on every request

A wallet directory has more than one writer. `wallet serve` holds it open while `wallet import`, `wallet issue` and `wallet remove` run against the same directory from another terminal, and the UI must not show a credential list that a CLI invocation changed a minute ago. Rather than lock the directory or make the CLI talk to the running server, the server treats the file as the source of truth and re-reads it at the request boundary. `withFreshStore` wraps 41 of the 50 routes (`internal/wallet/server.go`).

## Consequences

This is a real cost and a real hazard, not a free consistency win.

Every wrapped request pays a JSON parse of the whole store, which grows with the credential count. More importantly, a reload landing in the middle of a long-lived flow discards in-memory state that was not saved yet. An OID4VCI authorization code flow stays open across the user's sign-in at the issuer while the UI keeps polling, and each poll reloads. A credential imported but not yet persisted would vanish, and issuance would report success with nothing to show for it. `saveIssuedCredential` exists for exactly this: it puts the credential back if a concurrent reload dropped it, and does the check and the save under the same lock the reload takes.

Anything holding wallet state across an await needs to assume a reload happened underneath it. That is the invariant to keep in mind when adding a flow that spans more than one request.
