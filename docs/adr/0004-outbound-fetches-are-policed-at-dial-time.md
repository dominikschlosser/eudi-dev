# Outbound fetches are policed at dial time, not at the URL

The wallet fetches URLs it was handed by somebody else (request objects, issuer metadata, status lists, trust lists). Where that matters most is the public demo, which reaches the internet and sits on a host with a private network behind it. Checking the URL before fetching does not hold: a name resolving to a public address at check time can resolve to a private one at connect time, and a redirect moves the target after the check has passed.

So the policy is a `net.Dialer.Control` hook (`internal/format/policy.go`). It runs per connection attempt against the already-resolved `ip:port`, which is after DNS and after any redirect, so rebinding and redirect-to-internal have nothing left to exploit. `BlockPrivateAddresses` refuses loopback, RFC 1918, link-local (cloud metadata included), CGNAT, unique-local, unspecified and multicast.

## Consequences

Every HTTP client in the toolkit must be built through `format.HTTPClientForURL` or it silently bypasses the policy. That is a real footgun and the reason `internal/wallet/issuance.go` keeps a sentinel default client and routes through `doIssuanceRequest` instead of calling `http.DefaultClient`. A new package that reaches for `http.Get` gets no policy and no error telling it so.

A demo wallet also has to reach its own endpoints, all of which resolve to loopback and would be refused. `AllowOwnOrigins` exempts the operator-configured URLs by exact resolved address and port, so a visitor-supplied URL that merely happens to point at loopback is still blocked.
