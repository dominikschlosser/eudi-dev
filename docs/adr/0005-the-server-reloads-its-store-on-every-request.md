# The server reloads its store on every request

A wallet directory has more than one writer. `wallet serve` holds it open while `wallet import`, `issue --wallet` and `wallet remove` run against the same directory from another terminal, and the UI must not show a credential list that a CLI invocation changed a minute ago. So the server treats the file as the source of truth and re-reads it at the request boundary. `withFreshStore` wraps most routes (`internal/wallet/server.go`).

## Consequences

Every wrapped request pays a JSON parse of the whole store, which grows with the credential count. A reload landing in the middle of a long-lived flow discards in-memory state that was not saved yet. An OID4VCI authorization code flow stays open across the user's sign-in at the issuer while the UI keeps polling, and each poll reloads. A credential imported but not yet persisted would vanish, and issuance would report success with nothing to show for it. `saveIssuedCredential` handles this: it puts the credential back if a concurrent reload dropped it, and does the check and the save under the same lock the reload takes.

Anything holding wallet state across an await must assume a reload happened underneath it. Keep that invariant when adding a flow that spans more than one request.
