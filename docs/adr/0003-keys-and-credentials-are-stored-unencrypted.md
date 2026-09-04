# Keys and credentials are stored unencrypted

The wallet store (`~/.eudi-dev/wallet/`) holds credentials, holder and issuer private keys and issuer refresh tokens in the clear. The CA key one level above it is shared by every wallet under the same base directory. A test wallet whose store you can read with `cat` and edit with an editor is easier to debug. A CA regenerated per run would invalidate every trust list and status list URL a verifier had already been pointed at.

File modes still apply (`0600` for keys, `0700` for directories, atomic write-then-rename for `wallet.json`).

## Consequences

The CA key is an unprotected trust anchor. Anyone who can read it can issue credentials the verifiers you configured will accept. That is acceptable for a test CA on a developer machine and nowhere else. Encryption would change the store format and the `--wallet-dir` contract that CI setups and the Docker image depend on.
