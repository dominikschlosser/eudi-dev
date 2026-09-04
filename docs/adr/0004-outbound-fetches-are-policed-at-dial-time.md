# Outbound fetches are policed at dial time

The wallet fetches URLs it received from another party (request objects, issuer metadata, status lists, trust lists). This matters most on the public demo, which reaches the internet and sits on a host with a private network behind it. Checking the URL before fetching is not enough. A name resolving to a public address at check time can resolve to a private one at connect time, and a redirect moves the target after the check has passed.

So the policy is a `net.Dialer.Control` hook (`internal/format/policy.go`). It runs per connection attempt against the already resolved `ip:port`, after DNS and after any redirect. `BlockPrivateAddresses` refuses loopback, RFC 1918, link-local (cloud metadata included), CGNAT, unique-local, unspecified and multicast.

## Consequences

Every HTTP client in the toolkit must be built through `format.HTTPClientForURL`, or it bypasses the policy. `internal/wallet/issuance.go` therefore keeps a sentinel default client and routes through `doIssuanceRequest`.

A demo wallet also has to reach its own endpoints, which resolve to loopback. `AllowOwnOrigins` exempts the operator-configured URLs by exact resolved address and port. A visitor-supplied URL that happens to point at loopback is still blocked.
