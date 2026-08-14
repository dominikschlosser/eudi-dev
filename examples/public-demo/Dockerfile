# Caddy with the rate limiting plugin, which the standard image does not
# carry (https://github.com/mholt/caddy-ratelimit). The Caddyfile's rate_limit
# block needs it, and Caddy refuses to start on an unknown directive, so the
# demo runs this image rather than caddy:2.
FROM caddy:2-builder AS builder

RUN xcaddy build --with github.com/mholt/caddy-ratelimit

FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
