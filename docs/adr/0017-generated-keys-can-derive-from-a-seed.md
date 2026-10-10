# Generated keys can derive from a seed

The wallet can derive generated holder, issuer, CA, TLS and role-specific signing keys from `--seed` or `EUDI_DEV_SEED` using HKDF-SHA256 with a separate label per key. A wallet using memory storage then keeps the same keys across restarts without a volume or database. Verifiers can keep using the same CA trust anchor.

Existing keys take precedence. The seed is used only when generating a missing key.

With memory storage, the wallet creates new certificates on each start, using random serial numbers. Their bytes change, while keys and subjects stay the same for a given seed. A verifier matches the CA by subject and key, so the chain still verifies. Certificates remain stable while their store exists. Persistent storage retains certificates across restarts. A certificate gets a new serial number when its subject or issuer URL changes, or when it is renewed.

## The image default

The image sets `EUDI_DEV_SEED=eudi-dev` with the memory backend, so every container uses the same keys and CA public key without persistent state. Certificate serial numbers differ across starts. The seed is public, so anyone can derive these keys. For persistent storage, set an empty seed to generate random keys, as the public demo does. `wallet serve` warns when the public seed is used with `--demo` or persistent storage. `auto` applies the same seed on the memory backend only.

## Consequences

Anyone who knows or guesses a seed can derive every key generated from it (see SECURITY.md). Test environments can choose a private seed or leave it empty.

The seed is passed through the environment. The detached server inherits `EUDI_DEV_SEED`, so the seed never appears on its command line. The URL handler script contains no seed, so a wallet started by the handler generates random keys unless the handler's environment sets `EUDI_DEV_SEED`.

The default container combines memory storage and a fixed public seed, and can run on a read-only filesystem.
