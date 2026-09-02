# Docker Verifier Testing Guide

The Docker image is mainly for **automated integration testing of OID4VP verifiers**. The container is an EUDI wallet your verifier can send presentation requests to.

## Quick start

```bash
docker pull ghcr.io/dominikschlosser/eudi-dev:latest
docker run -p 8085:8085 -p 8086:8086 ghcr.io/dominikschlosser/eudi-dev
```

The default CMD starts the wallet server headless with pre-loaded PID credentials, ready for verifier testing.

You can override the command to use any CLI feature:

```bash
echo "eyJhbGci..." | docker run -i ghcr.io/dominikschlosser/eudi-dev decode
docker run -i ghcr.io/dominikschlosser/eudi-dev validate --trust-list https://example.com/trustlist.jwt < credential.txt
```

## Demo profile

The container also runs the demo profile of the public instance at [eudi-test.dev](https://eudi-test.dev):

```bash
docker run -d --name eudi-demo -p 8085:8085 -p 8086:8086 \
  ghcr.io/dominikschlosser/eudi-dev:latest \
  wallet serve --demo --port 8085 --base-url http://localhost:8085
```

`--demo` seeds the four-PID baseline, runs HAIP in debug mode at OpenID4VCI feature level 1.1, disables the process and filesystem endpoints, and resets the wallet hourly (`--demo-reset` changes the schedule). The wallet UI is at `http://localhost:8085`, the demo issuer at `/issuer/`, the demo verifier at `/verifier/` and the decoder at `/decoder/`. The HTTPS issuer endpoints answer on port 8086 with a self-signed certificate.

Without a volume the state is ephemeral: removing the container discards the keys, the CA and every credential. The full deployment (TLS termination, rate limiting, usage statistics, persistence) is the compose example in [examples/public-demo](../examples/public-demo/), described in [public demo hosting](public-demo.md).

## How it works

1. The container starts with `--pid` (two pre-loaded EUDI PID credentials: one SD-JWT, one mDoc) and `--auto-accept` (automatically presents matching credentials without user consent)
2. Your verifier sends an OID4VP authorization request to the wallet's `/authorize` endpoint
3. The wallet evaluates the DCQL query, finds matching credentials, creates a VP token, and POSTs it back to your verifier's `response_uri`

## Wallet endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/authorize` | GET/POST | OID4VP authorization endpoint, accepting the standard OID4VP query parameters (`client_id`, `response_type`, `dcql_query`, `nonce`, `state`, `response_uri`, `response_mode`, `request_uri`) |
| `/api/trustlist` | GET | Legacy trust-list endpoint. Returns the PID trust list when one is registered, otherwise the first available trust-list profile |
| `/api/trustlists` | GET | JSON index of all coherent trust-list profiles registered in the wallet. Each entry includes a relative `path` plus optional `advertised_url` / legacy `url` |
| `/api/trustlists/<id>` | GET | ETSI trust list JWT for one specific trust-list profile |
| `https://<wallet>:8086/.well-known/openid-credential-issuer` | GET | OpenID Credential Issuer metadata with `issuer_info` / `registrar_dataset` authorization data. JSON by default, the signed JWT form (`application/jwt`) when the Accept header asks for only that |
| `https://<wallet>:8086/.well-known/jwt-vc-issuer` | GET | JWT VC issuer metadata for wallet-issued SD-JWTs. Exposes the signing key by `kid` and leaf `x5c` chain |
| `/api/registrar/wrp` | GET | Registrar-style signed dataset for provider entitlements and `providesAttestations`. Supports query filters such as `identifier`, `entitlement`, and `providesattestation` |
| `/api/credentials` | GET/POST | List all credentials / import a credential |
| `/api/credentials/<id>/status` | GET/POST | Resolve or set the revocation status for a credential |
| `/api/statuslist` | GET | Status List Token on both HTTP and HTTPS. JWT by default, CWT for a client sending `Accept: application/statuslist+cwt` (`--status-list` only controls whether generated credentials reference the list) |
| `/api/templates`, `/api/templates/<name>` | GET/PUT/DELETE | List and manage [credential templates](templates.md) |
| `/api/next-error` | POST/DELETE | Set or clear a one-shot error override |
| `/api/config/preferred-format` | PUT | Set credential format preference (`dc+sd-jwt` / `mso_mdoc` / `jwt_vc_json` / empty) |
| `/api/config` | GET | Instance introspection (PID baseline, directories, URLs, behavior) |
| `/api/shutdown` | POST | Stop the wallet server process |

## Typical verifier integration test flow

1. Start the wallet container
2. Your verifier constructs an OID4VP authorization request with a DCQL query requesting PID attributes
3. Redirect/send the request to `http://<wallet>/authorize?client_id=...&response_type=vp_token&response_mode=direct_post&response_uri=http://<your-verifier>/callback&nonce=...&dcql_query=...`
4. The wallet auto-selects matching credentials and POSTs `vp_token` + `state` to your `response_uri`
5. Your verifier receives the VP token and can validate its signing chain using the wallet's trust list from `/api/trustlist`
6. For EUDI issuer authorization checks, resolve provider entitlements and exact attestation types from the signed `/.well-known/openid-credential-issuer` metadata and `/api/registrar/wrp` responses

Behind Docker port mappings or Testcontainers, use the relative `path` from `/api/trustlists` and resolve it against the URL you actually used to reach the wallet. `advertised_url` is the wallet's configured issuer URL and can differ from the externally reachable test URL.

## Docker Compose example

```yaml
services:
  wallet:
    image: ghcr.io/dominikschlosser/eudi-dev:latest
    ports:
      - "8085:8085"
      - "8086:8086"
  verifier:
    build: .
    environment:
      WALLET_URL: http://wallet:8085
      # Use the wallet's trust list to validate received VP tokens
      TRUST_LIST_URL: http://wallet:8085/api/trustlist
      # Use signed issuer metadata + registrar data for EUDI issuer authorization checks
      OPENID_CREDENTIAL_ISSUER_URL: https://wallet:8086/.well-known/openid-credential-issuer
      REGISTRAR_URL: https://wallet:8086/api/registrar/wrp
      # Optional: use the wallet's issuer metadata for SD-JWT key discovery
      ISSUER_METADATA_URL: https://wallet:8086/.well-known/jwt-vc-issuer
```

## Testcontainers (Java)

```java
GenericContainer<?> wallet = new GenericContainer<>("ghcr.io/dominikschlosser/eudi-dev:latest")
    .withExposedPorts(8085)
    .waitingFor(Wait.forHttp("/api/trustlist").forStatusCode(200));
wallet.start();

String walletUrl = "http://" + wallet.getHost() + ":" + wallet.getMappedPort(8085);

// Send an OID4VP request to the wallet
String authorizeUrl = walletUrl + "/authorize"
    + "?client_id=" + URLEncoder.encode(verifierClientId, UTF_8)
    + "&response_type=vp_token"
    + "&response_mode=direct_post"
    + "&response_uri=" + URLEncoder.encode(callbackUrl, UTF_8)
    + "&nonce=" + nonce
    + "&dcql_query=" + URLEncoder.encode(dcqlQuery, UTF_8);

// The wallet will auto-accept and POST the VP token to your callbackUrl
httpClient.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
    HttpResponse.BodyHandlers.ofString());

// Validate received credentials using the wallet's trust list
String trustListUrl = walletUrl + "/api/trustlist";
```

## Testcontainers (Go)

```go
ctx := context.Background()
wallet, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
    ContainerRequest: testcontainers.ContainerRequest{
        Image:        "ghcr.io/dominikschlosser/eudi-dev:latest",
        ExposedPorts: []string{"8085/tcp"},
        WaitingFor:   wait.ForHTTP("/api/trustlist").WithPort("8085"),
    },
    Started: true,
})

walletURL, _ := wallet.Endpoint(ctx, "http")
// Send OID4VP request to walletURL + "/authorize?..."
// Wallet POSTs VP token back to your response_uri
// Validate with trust list from walletURL + "/api/trustlist"
```

## Custom PID claims

The default CMD loads two EUDI PID credentials (SD-JWT + mDoc) with the EUDI PID Rulebook attributes (`given_name`, `family_name`, `birth_date`, `place_of_birth`, `nationality`, etc.). To customize them, mount a folder of [credential templates](templates.md) that overrides the pre-defined PID templates (or adds your own):

```bash
# my-templates/pid-sdjwt.json overrides the pre-defined PID template
docker run -p 8085:8085 -v ./my-templates:/templates ghcr.io/dominikschlosser/eudi-dev \
  wallet serve --auto-accept --pid --port 8085 --templates-dir /templates
```

Alternatively generate customized PIDs into a mounted data directory first. Mount the parent of `wallet/`, so the shared CA persists alongside the credentials:

```bash
docker run --rm -v wallet-data:/home/app/.eudi-dev ghcr.io/dominikschlosser/eudi-dev \
  issue sdjwt --wallet --template german-pid-sdjwt --claims '{"given_name":"MAX","family_name":"POWER"}'

docker run -p 8085:8085 -v wallet-data:/home/app/.eudi-dev ghcr.io/dominikschlosser/eudi-dev \
  wallet serve --auto-accept --port 8085
```

## Testing API

The wallet exposes additional API endpoints for controlling its behavior in automated tests.

### Error simulation

Pre-program a one-shot error response. The next OID4VP request returns the configured error, then normal behavior resumes.

```bash
# Set up error for next request
curl -X POST http://localhost:8085/api/next-error \
  -H 'Content-Type: application/json' \
  -d '{"error": "access_denied", "error_description": "Simulated denial"}'

# Clear without consuming
curl -X DELETE http://localhost:8085/api/next-error
```

### Format preference

When the DCQL query matches both SD-JWT and mDoc credentials, control which format is selected:

```bash
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": "dc+sd-jwt"}'   # or "mso_mdoc" or "" to clear
```

Or set at startup: `--preferred-format dc+sd-jwt`

### Credential import

Supports SD-JWT (`dc+sd-jwt`), plain JWT VC (`jwt_vc_json`), and mDoc (`mso_mdoc`). Plain JWT VCs are presented as-is without selective disclosure.

```bash
curl -X POST http://localhost:8085/api/credentials -d 'eyJhbGci...'
```

### Status list (revocation)

With `wallet serve --pid`, generated credentials include a status list reference pointing to `https://<host>:<port+1>/api/statuslist`. `--status-list` forces the same behavior explicitly.

The HTTPS issuer URL uses the same host selection. By default the issuer runs on `https://<host>:<port+1>` and serves `/.well-known/jwt-vc-issuer`, the signed `/.well-known/openid-credential-issuer` endpoint, and `/api/registrar/wrp`.

For verifier tests that need to trust that HTTPS endpoint, export the persisted certificate:

```bash
eudi wallet tls-cert --docker --out wallet-tls-cert.pem
```

To trust all spawned wallets from one root instead of pinning one leaf certificate, export the shared wallet CA:

```bash
eudi wallet ca-cert --out wallet-ca-cert.pem
```

**Important:** The status list URI and issuer host are baked into credentials at generation time. When the verifier runs inside Docker and the wallet on the host (or vice versa), use `--docker` (or `--base-url` for a custom URL) so the status list URL, signed issuer metadata, and registrar endpoints are reachable from both sides:

```bash
# Wallet on host, verifier in Docker
eudi wallet serve --pid --auto-accept --docker
```

```yaml
# Docker Compose: both in containers — use the service name
services:
  wallet:
    image: ghcr.io/dominikschlosser/eudi-dev:latest
    command: ["wallet", "serve", "--auto-accept", "--pid", "--port", "8085",
              "--base-url", "http://wallet:8085"]
    ports:
      - "8085:8085"
      - "8086:8086"
```

Toggle revocation at runtime:

```bash
# Revoke (status=1)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' -d '{"status": 1}'

# Un-revoke (status=0)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' -d '{"status": 0}'
```

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/next-error` | POST/DELETE | Set or clear one-shot error override |
| `/api/config/preferred-format` | PUT | Set credential format preference |
| `/api/credentials` | GET/POST/DELETE | List, import, or remove all credentials |
| `/api/credentials/<id>` | GET/DELETE | Show or remove a single credential |
| `/api/credentials/<id>/status` | GET/POST | Resolve or set revocation status |
| `/api/issue` | POST | Issue a credential into the wallet (supports templates and always disclosed claims) |
| `/api/generate-pid` | POST | Regenerate default PID credentials (deprecated, use `/api/issue` with a template) |
| `/api/templates`, `/api/templates/<name>` | GET/PUT/DELETE | List and manage credential templates |
| `/api/certificates/ca`, `/api/certificates/tls` | GET | Export wallet CA / TLS certificate |
| `/api/statuslist` | GET | Status List Token, JWT by default and CWT under `Accept: application/statuslist+cwt` |
| `/api/config` | GET | Instance introspection document |
| `/api/shutdown` | POST | Stop the wallet server process |

> See [wallet HTTP API](wallet/http-api.md) for full details and an end-to-end example. The API has no authentication (the wallet is a testing tool). Keep it inside isolated test networks, or use the hardened `--demo` profile for internet-facing deployments (see [public demo hosting](public-demo.md)).

## Supported response modes

`direct_post` (default) and `direct_post.jwt` (JARM, the response encrypted to the verifier's ephemeral key from the request object).
