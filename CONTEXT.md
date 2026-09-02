# eudi-dev

A developer toolkit for the EUDI and OpenID4VC ecosystem. It borrows most of its vocabulary from the specifications it implements, so this glossary covers only the terms this project overloads, renames, or uses more narrowly than the specs do.

## Language

### Credentials

**Credential**:
A signed set of claims about a person, held by the wallet and shown to a verifier. Always the concrete artifact, never the type or the configuration that produced it.
_Avoid_: Attestation (see below), document, VC

**Credential type**:
What a credential is, named by its `vct` (SD-JWT VC) or `doctype` (mdoc). A wallet holds many credentials of one type.
_Avoid_: Credential configuration, schema

**Extending type**:
A credential type that carries everything another one defines and adds to it, the way the German PID (`urn:eudi:pid:de:1`) extends the country-independent EUDI PID (`urn:eudi:pid:1`). A credential of an extending type answers a request for the type it extends, never the other way round. Say **extending** and **extended type** rather than sub- or supertype, and never call it a trust relationship: it says what a credential is, not who may issue it.
_Avoid_: Subtype, derived type, inherited credential

**Attestation**:
Ambiguous on its own and never to be used unqualified. Three unrelated things wear this name: a **client attestation** (the wallet proving itself to an issuer), a **verifier attestation** (a verifier proving itself to the wallet), and an **issued attestation** (this wallet's record that it issues a given credential type, which is what registers that type on a trust list). In EUDI prose "attestation" is also a synonym for credential. Always say which.

**Template**:
A reusable, named claim set and issuance settings that a credential can be issued from. A template is not a credential and is not a credential type.
_Avoid_: Preset, profile

**PID**:
Person Identification Data, the EUDI-defined identity credential. It comes as the country-independent **EUDI PID** of the ARF rulebook and as domestic types that extend it, such as the **German PID**. Say which one is meant when it matters. "PID" unqualified means the credential, not a type. Never abbreviate process id this way in code that also touches credentials.
_Avoid_: PID as process id (write `processID`)

### Roles

**Wallet**:
The holder. Depending on context this is the stored state, the running server, or the CLI acting on either, so qualify it as **wallet state**, **wallet server**, or **wallet CLI** when the difference matters.

**Issuer**:
Whoever signs and hands over a credential. This toolkit is one, so say **external issuer** for somebody else's and **demo issuer** for the one this toolkit runs itself.

**Verifier**:
Whoever requests and checks a presentation. Say **demo verifier** for the one this toolkit runs itself. Not to be confused with validation, which is this tool checking a credential offline on the user's behalf.
_Avoid_: Relying party, RP

**Instance**:
A running wallet server registered on this machine so the CLI can find it and drive it remotely. An instance is a process, not a wallet: several instances can serve the same wallet state.

### Requests and flows

**Authorization request**:
A verifier's request for a presentation. Its parameters may arrive in a URI or inside a request object.

**Request object**:
The signed JWT (a JAR) carrying an authorization request's parameters. Distinct from the request itself, which may have no request object at all.
_Avoid_: JAR (in prose), signed request

**Consent request**:
A pending decision put to the user before a presentation is sent. Internal to this wallet and unrelated to the verifier's authorization request, though one causes the other.

**Owner**:
The browser a flow belongs to, recognised by the `eudi_session` cookie or named by a client in `X-Eudi-Owner`. A consent request, an error report and an issuer sign-in prompt each carry one. Not the wallet that owns a deferred issuance, not the credential holder, and not OAuth's resource owner. A flow whose client named no browser is **unowned**, and stays visible and answerable to every caller.
_Avoid_: session, page, acting owner

**Presentation**:
What the wallet sends a verifier in answer to an authorization request. The act and the artifact share the name, which is fine, but the artifact is a **VP token** when precision is needed.

**Offer**:
An issuer's invitation to collect a credential. Accepting one starts an issuance.
_Avoid_: Invitation, issuance request

**Deferred issuance**:
An issuance the issuer accepted but could not complete immediately, which the wallet collects later. The on-disk field is named `pending`.
_Avoid_: Pending issuance

**Renewal**:
Replacing a credential with a fresh copy from its issuer before it expires, keeping the same credential id. Distinct from a **refresh token**, which is the OAuth grant a renewal may use, and from **certificate refresh**, which re-issues the wallet's own signing leaf. The CLI verb is `refresh`.
_Avoid_: Refresh (for the credential operation)

### Trust and status

**Trust list**:
A signed list of the certificates a verifier should accept, published by this wallet so verifiers can be pointed at it.

**Trust profile**:
Which trust list a credential type is registered under (`pid`, `local`, or `auto`). Unrelated to the **demo profile**, which is a hosting configuration, and to **HAIP**, which is a specification profile. Never write "profile" unqualified.

**Status list**:
The published bitstring a verifier resolves to learn whether a credential is still valid. The wallet governs entries on its own list and can only read anybody else's.

**Revocation**:
Marking a credential invalid on a status list. The wallet does not refuse to present a revoked credential, so revocation is a statement to verifiers rather than a restriction on the holder.

### Modes

**Validation mode**:
Whether normative findings are warnings that let a flow continue (`debug`) or refusals (`strict`). The findings themselves are collected in both modes. Applies to what the wallet accepts from others, not to what it produces. Not to be confused with **HAIP enforcement** (`--haip`), which decides whether the counterparty is held to that profile at all and whose violations are errors in either mode.

**Demo profile**:
The hardened configuration for hosting a wallet publicly. A deployment shape, not a validation setting and not a trust profile.
_Avoid_: Demo mode, public mode

### Diagnostics

**Activity log**:
The persisted, user-facing record of what the wallet did, shown in the UI and printed by the CLI.

**Protocol log entry**:
An activity log entry that additionally carries the request or response as it went over the wire. The subset worth decoding, not a separate log.
