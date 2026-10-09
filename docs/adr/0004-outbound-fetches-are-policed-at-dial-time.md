# Outbound addresses are checked when connecting

The wallet fetches request objects, issuer metadata, status lists and trusted lists from URLs supplied by other parties. In a public demo, those URLs could expose private services on the host network.

A URL check before the fetch cannot prevent this. DNS can return a different address when the connection opens, and redirects can change the destination.

The address check runs in a `net.Dialer.Control` hook (`internal/format/policy.go`). It runs per connection attempt against the resolved `ip:port`, including connections opened after a redirect. `BlockPrivateAddresses` refuses loopback, RFC 1918, link-local (cloud metadata included), CGNAT, unique-local, unspecified and multicast.

## Consequences

Every HTTP client in the toolkit must be built through `format.NewHTTPClient` or `format.HTTPClientForURL`, or it bypasses the policy. `internal/wallet/issuance.go` therefore keeps a sentinel default client and sends requests through `doIssuanceRequest`.

A demo wallet also has to reach its own endpoints, which resolve to loopback. `AllowOwnOrigins` exempts the operator-configured URLs by exact resolved address and port. A visitor-supplied URL that happens to point at loopback is still blocked.
