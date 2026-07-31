#!/usr/bin/env python3
"""Demo UI for URI-based issuance and verification.

A plain web app: issuance renders a credential-offer link that targets the
wallet's /credential-offer URL, and verification is an ordinary OIDC login
against Keycloak — whose login page links straight to the wallet's /authorize
URL (the identity provider's walletScheme is configured with the wallet URL).
Everything runs on localhost: all services share one network namespace, so
the browser and the containers see the same URLs.
"""
import http.cookies
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.environ.get("DEMO_SCRIPTS_DIR", "/scripts"))
import oid4vp_demo as demo  # noqa: E402

LISTEN_PORT = int(os.environ.get("APP_LISTEN_PORT", "9090"))
APP_BASE_URL = os.environ.get("APP_BASE_URL", f"http://localhost:{LISTEN_PORT}").rstrip("/")
REDIRECT_URI = f"{APP_BASE_URL}/callback"
SESSION_COOKIE = "demo_session"

# state -> PKCE verifier for logins in flight
pending_logins = {}
# session id -> {"claims": ..., "id_token": ...} for logged-in browsers
sessions = {}
state_lock = threading.Lock()

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oid4vc-dev · wallet-URL demo</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  h1 { font-size: 1.4rem; }
  .card { border: 1px solid color-mix(in srgb, currentColor 25%, transparent); border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
  button, a.button { font-size: 1rem; padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid currentColor; background: transparent; color: inherit; cursor: pointer; text-decoration: none; display: inline-block; }
  button:hover, a.button:hover { background: color-mix(in srgb, currentColor 10%, transparent); }
  a.wallet-link { word-break: break-all; }
  code, .uri, pre { word-break: break-all; white-space: pre-wrap; font-family: ui-monospace, monospace; font-size: 0.85em; }
  .muted { opacity: 0.7; font-size: 0.9em; }
  .status { margin-top: 0.6rem; }
  .ok { color: #1a7f37; }
  .err { color: #cf222e; }
  ul { margin: 0.3rem 0; }
  details { margin-top: 0.5rem; }
</style>
</head>
<body>
<h1>oid4vc-dev — invoking the wallet by URL</h1>
<p class="muted">Custom-scheme links (<code>openid-credential-offer://</code>, <code>openid4vp://</code>) need
OS-level handler registration. Here everything runs on plain localhost URLs instead: offer links target the
wallet's <code>/credential-offer</code> endpoint, and Keycloak's login page links to the wallet's
<code>/authorize</code> endpoint (configured via the identity provider's <code>walletScheme</code>).</p>
<p class="muted">The wallet runs interactively: clicking a wallet link takes you to the
<a href="__WALLET_URL__" target="_blank">wallet UI</a>, which shows the consent request — after approving,
the flow continues automatically (logins return to this app).</p>

__RESULT__

<div class="card">
  <h2>Issuance</h2>
  <p>Creates a pre-authorized credential offer in Keycloak and turns it into a wallet link.</p>
  <button id="issue-btn">Create credential offer</button>
  <div id="issue-result" class="status"></div>
  <div class="status"><button id="creds-btn">Show wallet credentials</button></div>
  <div id="creds-result" class="status"></div>
</div>

<div class="card">
  <h2>Verification</h2>
  <p>A normal OIDC login: you are sent to Keycloak, its login page links to the wallet's
     <code>/authorize</code> URL, the wallet presents the PID credential and redirects back,
     and the login completes here.</p>
  <a class="button" href="/login">Login with wallet</a>
</div>

<script>
const el = (id) => document.getElementById(id);

function linkBlock(walletUrl, schemeUri) {
  return `
    <p><a class="wallet-link" href="${walletUrl}" target="_blank" rel="opener">${walletUrl.length > 140 ? walletUrl.slice(0, 140) + "…" : walletUrl}</a></p>
    <details><summary class="muted">equivalent custom-scheme URI</summary>
      <p class="uri">${schemeUri.length > 300 ? schemeUri.slice(0, 300) + "…" : schemeUri}</p></details>`;
}

el("issue-btn").onclick = async () => {
  el("issue-result").innerHTML = "Creating offer…";
  const res = await fetch("/api/issue", { method: "POST" });
  const data = await res.json();
  if (!res.ok) { el("issue-result").innerHTML = `<span class="err">${data.error}</span>`; return; }
  el("issue-result").innerHTML =
    `<p class="ok">Offer created — click to deliver it to the wallet:</p>` +
    linkBlock(data.wallet_url, data.scheme_uri);
};

el("creds-btn").onclick = async () => {
  const res = await fetch("/api/wallet/credentials");
  const data = await res.json();
  if (!res.ok) { el("creds-result").innerHTML = `<span class="err">${data.error}</span>`; return; }
  el("creds-result").innerHTML = "<ul>" +
    data.map(c => `<li><code>[${c.format}] ${c.vct || c.doctype || c.id}</code></li>`).join("") + "</ul>";
};
</script>
</body>
</html>
"""


def render_page(result_html=""):
    return PAGE.replace("__RESULT__", result_html).replace("__WALLET_URL__", demo.WALLET_BASE_URL)


def logged_in_html(session):
    claims = session["claims"]
    who = claims.get("preferred_username") or claims.get("sub", "?")
    return (
        '<div class="card"><p class="ok">Logged in as <b>'
        + html_escape(who)
        + '</b> via wallet presentation.</p><details><summary class="muted">id_token claims</summary><pre>'
        + html_escape(json.dumps(claims, indent=2))
        + '</pre></details><p class="status"><a class="button" href="/logout">Logout</a></p></div>'
    )


def html_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[ui] " + fmt % args, file=sys.stderr)

    def send_html(self, body):
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, url, set_cookie=None):
        self.send_response(302)
        self.send_header("Location", url)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def current_session(self):
        """Returns (session_id, session) for the browser's cookie, or (None, None)."""
        cookies = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookies.get(SESSION_COOKIE)
        if not morsel:
            return None, None
        with state_lock:
            return morsel.value, sessions.get(morsel.value)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            _, session = self.current_session()
            self.send_html(render_page(logged_in_html(session) if session else ""))
            return
        if parsed.path == "/login":
            state = f"s-{demo.random_token(12)}"
            code_verifier = demo.random_pkce_verifier()
            with state_lock:
                pending_logins[state] = code_verifier
            query = urllib.parse.urlencode(
                {
                    "client_id": demo.OIDC_CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "response_type": "code",
                    "scope": "openid",
                    "state": state,
                    "code_challenge": demo.pkce_challenge(code_verifier),
                    "code_challenge_method": "S256",
                }
            )
            self.redirect(
                f"{demo.KEYCLOAK_BASE_URL}/realms/{demo.VERIFIER_REALM}/protocol/openid-connect/auth?{query}"
            )
            return
        if parsed.path == "/callback":
            params = urllib.parse.parse_qs(parsed.query)
            state = params.get("state", [""])[0]
            code = params.get("code", [""])[0]
            with state_lock:
                code_verifier = pending_logins.pop(state, None)
            if not code or not code_verifier:
                self.send_html(render_page('<div class="card"><p class="err">Login failed: unknown state or missing code.</p></div>'))
                return
            try:
                token_response = self.exchange(code, code_verifier)
            except demo.DemoError as err:
                self.send_html(render_page(f'<div class="card"><p class="err">{html_escape(err)}</p></div>'))
                return
            id_token = token_response.get("id_token", "")
            session_id = demo.random_token(32)
            with state_lock:
                sessions[session_id] = {
                    "claims": demo.decode_jwt_payload(id_token),
                    "id_token": id_token,
                }
            self.redirect(
                "/",
                set_cookie=f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax",
            )
            return
        if parsed.path == "/logout":
            session_id, session = self.current_session()
            with state_lock:
                sessions.pop(session_id, None)
            expired_cookie = f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            if not session:
                self.redirect("/", set_cookie=expired_cookie)
                return
            # OIDC RP-initiated logout: end the Keycloak session, then land
            # back on this page. post.logout.redirect.uris is configured on
            # the wallet-mock client in the realm import.
            logout_url = (
                f"{demo.KEYCLOAK_BASE_URL}/realms/{demo.VERIFIER_REALM}/protocol/openid-connect/logout?"
                + urllib.parse.urlencode(
                    {
                        "id_token_hint": session["id_token"],
                        "post_logout_redirect_uri": f"{APP_BASE_URL}/",
                        "client_id": demo.OIDC_CLIENT_ID,
                    }
                )
            )
            self.redirect(logout_url, set_cookie=expired_cookie)
            return
        if parsed.path == "/api/wallet/credentials":
            try:
                self.send_json(200, demo.wallet_credentials())
            except demo.DemoError as err:
                self.send_json(502, {"error": str(err)})
            return
        self.send_json(404, {"error": "not found"})

    def exchange(self, code, code_verifier):
        token_url = f"{demo.KEYCLOAK_BASE_URL}/realms/{demo.VERIFIER_REALM}/protocol/openid-connect/token"
        status, body = demo.http_json(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": demo.OIDC_CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "code_verifier": code_verifier,
            },
        )
        if status != 200:
            raise demo.DemoError(f"Authorization code exchange failed ({status}): {body}")
        return body

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/issue":
            try:
                credential_offer = demo.create_credential_offer()
                self.send_json(
                    200,
                    {
                        "wallet_url": demo.offer_wallet_url(credential_offer),
                        "scheme_uri": demo.offer_scheme_uri(credential_offer),
                    },
                )
            except demo.DemoError as err:
                self.send_json(502, {"error": str(err)})
            return
        self.send_json(404, {"error": "not found"})


def main():
    server = ThreadingHTTPServer(("", LISTEN_PORT), Handler)
    print(f"Demo UI listening on :{LISTEN_PORT} ({APP_BASE_URL})")
    server.serve_forever()


if __name__ == "__main__":
    main()
