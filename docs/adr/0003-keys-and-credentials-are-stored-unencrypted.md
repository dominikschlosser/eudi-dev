# Keys and credentials are stored unencrypted

The wallet store (`~/.eudi-dev/wallet/`) holds credentials, holder and issuer private keys and issuer refresh tokens in the clear, and the CA key one level above it is shared by every wallet under the same base directory. Both are deliberate. A test wallet whose store you cannot read with `cat` and edit with an editor is harder to debug than the thing it is meant to help you debug, and a CA regenerated per run would invalidate every trust list and status list URL a verifier had already been pointed at.

File modes still apply (`0600` for keys, `0700` for directories, atomic write-then-rename for `wallet.json`), so this is about not encrypting at rest, not about being careless with what is written.

## Consequences

The CA key is an unprotected trust anchor. Anyone who can read it can issue credentials the verifiers you configured will accept. That is fine for a test CA on a developer machine and is not fine anywhere else, which is one more reason the tool states plainly that it is not for real credentials or real identity data. Adding encryption later would change the store format and the `--wallet-dir` contract that CI setups and the Docker image depend on, so it is not a drop-in change.
