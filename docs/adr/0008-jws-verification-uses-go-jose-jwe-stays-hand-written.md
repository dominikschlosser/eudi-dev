# JWS verification uses go-jose, JWE stays hand-written

Four packages carried their own JWS verifier (`sdjwt`, `statuslist`, `wallet`, `demorp`): split the compact form, hash the signing input per algorithm, slice the raw `r||s` signature at the curve size, call `ecdsa.Verify`. Each had to get the fixed-width encoding and the algorithm-to-hash mapping right on its own, and they had drifted to different algorithm sets. All four now call `jws.Verify`, which is go-jose underneath, and the algorithm allow-list is passed in at every parse rather than taken from the token.

JWE stays hand-written, and that is the surprising half.

## Why go-jose cannot do the JWE

go-jose derives the ECDH-ES key with empty `apu` and `apv` on the encrypt path (`DeriveECDHES(algID, []byte{}, []byte{}, ...)` in its key generator) and exposes no way to set them. ISO 18013-7 Annex B requires the mdoc generated nonce in `apu` and the request nonce in `apv`, which is what this wallet sends for mdoc presentations. Encrypting through go-jose would derive a key from empty values while the header advertised the nonces, and every such presentation would fail to decrypt at the verifier.

The decrypt direction is not affected (go-jose reads `apu`/`apv` correctly), but splitting the two directions across two implementations is worse than keeping one. The Concat KDF would then exist twice, once in each library, with only the round-trip tests holding them together. So both directions stay on the same hand-written code.

The proxy needs one thing no JOSE library offers regardless: decrypting a captured JWE from a content encryption key read out of a key log, with no private key in hand.

## Consequences

Do not "finish the job" by moving JWE onto go-jose without first checking that whatever library is proposed can set `apu` and `apv` when encrypting. The mdoc presentation tests are what catch it, not the JWE tests.

The hand-written JWE code is therefore load-bearing and should keep its comments explaining the derivation. That includes the AES-CBC-HS256 path with its own PKCS#7 padding, which is the part most worth replacing if a library ever fits.
