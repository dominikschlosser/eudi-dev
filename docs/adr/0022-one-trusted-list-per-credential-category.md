# One trusted list per credential category

The ARF has the wallet check a received credential against the trusted list of its kind. A PID must chain to a PID Provider list (ISSU_07), a QEAA to a trusted list of QEAA Providers (ISSU_08) and a PuB-EAA to a list of PuB-EAA Providers (ISSU_09). Another EAA is checked whenever the wallet has the issuer's trust anchors (ISSU_10). A test wallet that issues all of these needs a trust anchor for each kind.

## Decision

Each credential type issued by the wallet has a credential category: `pid`, `qeaa`, `pub-eaa` or `eaa`. The predefined templates set it. A user template takes it from its catalogue entry. You set it in the registrar UI or with `wallet catalog add --category`. `--trust-profile` sets it for a single credential.

Each category has its own signing key, its own provider CA under the wallet CA and its own trusted list:

- `pid` uses the PID provider list type of ETSI TS 119 602 V1.1.1 Annex D
- `pub-eaa` uses the PuB-EAA provider list type of Annex H
- `qeaa` and `eaa` use the list type `http://uri.etsi.org/19602/LoTEType/local`. TS 119 602 has no list type for them, so this URI is the wallet's own. Real QEAA providers are on TS 119 612 trusted lists.

A list publishes its signers and their provider CA, so it anchors the credentials of its category and no others. A catalogue entry links the list of its category unless it names another one.

A credential without a category is on no list. That is an ad hoc credential without a template, or one from a user template without a catalogue entry. Its signer has its own key and provider CA, and no list names them.

The demo issuer and the demo verifier are ordinary registrations at the wallet's registrar. The demo issuer is registered for every credential type with a category and has the entitlement of each category. The demo verifier has its own access certificate, so it is a separate relying party.

## Consequences

The list IDs are `pid`, `qeaa`, `pub-eaa` and `eaa`. `--trust-profile local` selects `eaa`.

Credentials from a user template are on no list until the template gets a catalogue entry. The registration of the demo issuer does not list such a type either, so a wallet with `--arf` reports it when the demo issuer offers one.
