# Keys and credentials are stored unencrypted

Credentials, private keys and issuer refresh tokens are stored unencrypted. On the file backend they live in `~/.eudi-dev/wallet/`, with the shared CA key one level above it. The readable store makes test state easy to inspect and edit. Keeping the CA stable lets verifiers reuse their configured trust anchor across runs.

Key files use mode `0600` and directories use `0700`. Saving `wallet.json` writes a temporary file and atomically renames it.

## Consequences

Anyone who can read the CA key can issue credentials accepted by verifiers that trust this CA. Use it only for testing. Encryption would change the store format and the `--wallet-dir` contract. CI setups and the Docker image depend on that contract.
