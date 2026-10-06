# eudi-dev

A developer toolkit for the EUDI and OpenID4VC ecosystem. This glossary covers the terms this project uses differently or more narrowly than the specifications it implements.

## Language

### Credentials

**Credential**:
A signed set of claims about a person. The wallet holds it and presents it to a verifier. The word always means the concrete artifact. For its kind, say credential type.
_Avoid_: Attestation (see below), document, VC

**Credential type**:
The kind of a credential, identified by its `vct` (SD-JWT VC) or `doctype` (mdoc). A wallet holds many credentials of one type.
_Avoid_: Credential configuration, schema

**Extending type**:
A credential type that contains everything another type defines and adds more. For example, the German PID (`urn:eudi:pid:de:1`) extends the country-independent EUDI PID (`urn:eudi:pid:1`). A credential of an extending type answers a request for the extended type. The reverse does not hold. Say **extending** and **extended type**. The relation describes content only. It does not say who may issue the credential.
_Avoid_: Subtype, derived type, inherited credential, trust relationship

**Attestation**:
Always qualify this word. It has three unrelated meanings: a **client attestation** (the wallet proving itself to an issuer), a **verifier attestation** (a verifier proving itself to the wallet), and an **issued attestation** (this wallet's record that it issues a given credential type, used to register that type on a trust list). EUDI documents also use "attestation" as a synonym for credential.

**Template**:
A named, reusable set of claims and issuance settings. The wallet issues credentials from it. A template is not a credential and not a credential type.
_Avoid_: Preset, profile

**PID**:
Person Identification Data, the EUDI-defined identity credential. There is the country-independent **EUDI PID** of the ARF rulebook and there are national types that extend it, such as the **German PID**. Say which one you mean when it matters. "PID" alone means the credential. Do not use it for a process id in code that also handles credentials.
_Avoid_: PID as process id (write `processID`)

### Roles

**Wallet**:
The holder. Depending on context this is the stored state, the running server, or the CLI that operates on either. Qualify it as **wallet state**, **wallet server**, or **wallet CLI** when the difference matters.

**Issuer**:
The party that signs and issues a credential. This toolkit is also an issuer. Say **external issuer** for any other issuer and **demo issuer** for the one this toolkit runs.

**Verifier**:
The party that requests and checks a presentation. Say **demo verifier** for the one this toolkit runs. It is different from validation, where this tool checks a credential offline for the user.
_Avoid_: RP

**Relying party**:
A verifier or issuer registered with a registrar (TS05). In a presentation flow, say verifier.
_Avoid_: RP, WRP (in prose)

**Registrar**:
Keeps the register of relying parties for a member state (ARF Topic 27) and issues their access and registration certificates. The wallet includes one.

**Intended use**:
A purpose a relying party registers, together with the credentials and claims it may request. Each registration certificate covers one intended use.

**Access certificate**:
Identifies a relying party (ETSI TS 119 411-8). The verifier signs its request objects with the matching key.

**Registration certificate**:
The signed JWT that lists one intended use (ETSI TS 119 475). A verifier sends it in `verifier_info`.

**Relying party access CA**:
Signs the access certificates that the wallet's registrar issues to relying parties. It is separate from the wallet CA.

**Instance**:
A running wallet server registered on this machine. The CLI uses the registration to find and control it. Several instances can serve the same wallet state.

### Requests and flows

**Authorization request**:
A verifier's request for a presentation. Its parameters may arrive in a URI or inside a request object.

**Request object**:
The signed JWT (a JAR) that carries the parameters of an authorization request. A request may also come without a request object.
_Avoid_: JAR (in prose), signed request

**Consent request**:
A pending decision the user makes before the wallet sends a presentation. A verifier's authorization request creates it. It exists only inside this wallet.

**Owner**:
The browser a flow belongs to. The wallet identifies it by the `eudi_session` cookie, or a client sets it in the `X-Eudi-Owner` header. A consent request, an error report and an issuer sign-in prompt each have an owner. The term is unrelated to the credential holder and to the OAuth resource owner. A flow started without an owner is **unowned**. Every caller can see and answer it.
_Avoid_: session, page, acting owner

**Presentation**:
What the wallet sends a verifier in answer to an authorization request. The word means both the act and the artifact. Say **VP token** for the artifact when the difference matters.

**Offer**:
An issuer's invitation to collect a credential. Accepting one starts an issuance.
_Avoid_: Invitation, issuance request

**Deferred issuance**:
An issuance the issuer accepted but did not complete immediately. The wallet collects the credential later. The stored field is `pending`.
_Avoid_: Pending issuance

**Renewal**:
Replacing a credential with a fresh copy from its issuer before it expires, keeping the same credential id. It differs from a **refresh token** (the OAuth grant a renewal may use) and from **certificate refresh** (re-issuing the wallet's own signing leaf certificate). The CLI verb is `refresh`.
_Avoid_: Refresh (for the credential operation)

### Trust and status

**Trust list**:
A signed list of the certificates a verifier should accept, published by this wallet.

**Trust profile**:
The trust list a credential type is registered on (`pid`, `local`, or `auto`). It is unrelated to the **demo profile** (a hosting configuration) and to **HAIP** (a specification profile). Always qualify "profile".

**Status list**:
The published bitstring a verifier fetches to check whether a credential is still valid. The wallet manages the entries on its own list and reads the lists of other issuers.

**Revocation**:
Marking a credential invalid on a status list. Revocation informs verifiers. The wallet can still present a revoked credential.

### Modes

**Validation mode**:
Controls whether normative findings in incoming messages are warnings and the flow continues (`debug`), or errors that stop the flow (`strict`). Both modes collect the same findings. **HAIP enforcement** (`--haip`) adds profile checks. Most findings follow the validation mode. Advisory findings are always warnings.

**Demo profile**:
The hardened configuration for hosting a wallet publicly. A deployment setting, unrelated to validation mode and trust profile.
_Avoid_: Demo mode, public mode

### State

**Storage backend**:
Where the wallet state is stored: `file` (the default, in the wallet directory), `memory` (in the process) or `postgres` (in a shared database). Set it with `--storage` or `EUDI_DEV_STORAGE`. Every backend stores the keys, certificates, assets and templates under the same names.
_Avoid_: Database (for the layer as a whole), persistence provider

**Seed**:
A string the wallet derives its generated keys from. With a seed, a wallet that stores nothing has the same keys on every start. It is unrelated to the baseline credentials of the demo profile.
_Avoid_: Seed (for the demo profile's starting credentials, say baseline)

**Wallet directory**:
The path that identifies a wallet. On the file backend the files are stored there. On every backend the CLI uses it to find the server for that wallet.

### Diagnostics

**Activity log**:
The persisted, user-facing record of what the wallet did, shown in the UI and printed by the CLI.

**Protocol log entry**:
An activity log entry that also contains the request or response exactly as sent or received.
