# The server reloads its store on every request

A running wallet must pick up changes made by CLI commands or another server. `withFreshStore` in `internal/wallet/server.go` checks storage before most request handlers run.

## Consequences

The file backend reloads `wallet.json` when its content hash changes. Modification times are too coarse on some filesystems to tell two writes apart. Memory and Postgres use section revisions and row versions to refresh changed state. Log views load the activity log on demand. See [ADR-0016](0016-state-goes-through-one-storage-layer.md) for the storage layout.

A reload during a flow can replace unsaved state. For example, the UI can poll while the user signs in at an issuer. `saveIssuedCredential` restores a credential dropped by a concurrent reload and saves it under the reload lock.

A flow that keeps wallet state across network calls or user interaction must account for a reload before saving.
