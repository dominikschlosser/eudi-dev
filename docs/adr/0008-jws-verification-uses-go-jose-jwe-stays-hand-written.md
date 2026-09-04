# JWS verification uses go-jose, JWE stays hand-written

Every JWS in the toolkit (`sdjwt`, `statuslist`, `wallet`, `demorp`) is verified through `jws.Verify`, which is go-jose underneath. The algorithm allow-list is passed in at every parse, never taken from the token. One verifier means one signature encoding, one algorithm-to-hash mapping and one algorithm set.

## Why go-jose cannot do the JWE

go-jose derives the ECDH-ES key with empty `apu` and `apv` on the encrypt path (`DeriveECDHES(algID, []byte{}, []byte{}, ...)` in its key generator) and exposes no way to set them. ISO 18013-7 Annex B requires the mdoc generated nonce in `apu` and the request nonce in `apv`, and this wallet sends both for mdoc presentations. Encrypting through go-jose would derive a key from empty values while the header advertised the nonces, and every such presentation would fail to decrypt at the verifier.

go-jose reads `apu` and `apv` correctly when decrypting. Splitting the two directions across two implementations would put the Concat KDF in two places with only the round-trip tests checking that they agree. So both directions stay on the same hand-written code.

The proxy also needs something no JOSE library offers: decrypting a captured JWE from a content encryption key read out of a key log, without the private key.

## Consequences

Before moving JWE onto any library, check that it can set `apu` and `apv` when encrypting. The mdoc presentation tests catch a regression here, the JWE tests do not.

The hand-written JWE code keeps its comments explaining the derivation. That includes the AES-CBC-HS256 path with its own PKCS#7 padding, the part most worth replacing once a suitable library exists.
