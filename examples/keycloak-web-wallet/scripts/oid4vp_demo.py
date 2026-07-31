"""Shared helpers for the URI-based issuance/verification demos and the demo UI.

All flows drive Keycloak server-side (with per-flow curl cookie jars) and
invoke the wallet at its plain web URLs — the same query parameters the
custom-scheme links carry, no URL scheme registration involved.
"""
import base64
import hashlib
import html.parser
import json
import os
import random
import re
import string
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://localhost:9080")
WALLET_BASE_URL = os.environ.get("WALLET_BASE_URL", "http://localhost:9085")

ISSUER_REALM = os.environ.get("ISSUER_REALM", "oid4vc-demo")
ISSUER_CLIENT_ID = os.environ.get("OID4VCI_CLIENT_ID", "oid4vc-demo-client")
ISSUER_CREDENTIAL_SCOPE = os.environ.get("OID4VCI_CREDENTIAL_SCOPE", "membership-credential")
ISSUER_USER = os.environ.get("OID4VCI_USER", "alice")
ISSUER_USER_PASSWORD = os.environ.get("OID4VCI_USER_PASSWORD", "alice")

KEYCLOAK_ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")

VERIFIER_REALM = os.environ.get("VERIFIER_REALM", "wallet-demo")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "wallet-mock")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://127.0.0.1:18080/callback")
BROKER_USERNAME_PREFIX = os.environ.get("BROKER_USERNAME_PREFIX", "wallet-user")


class DemoError(Exception):
    """A step of the demo flow failed."""


class ElementByIDParser(html.parser.HTMLParser):
    """Collects the attributes of every element that has an id."""

    def __init__(self):
        super().__init__()
        self.elements = {}

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        element_id = attr_map.get("id")
        if element_id:
            self.elements[element_id] = attr_map


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "GET").upper(),
                "inputs": [],
            }
            return
        if tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attr_map.get("name", ""),
                    "type": attr_map.get("type", "text"),
                    "value": attr_map.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def random_token(length):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def random_pkce_verifier():
    raw = os.urandom(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def decode_jwt_payload(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    raw = base64.urlsafe_b64decode(payload + padding)
    return json.loads(raw.decode("utf-8"))


def fetch(cookie_jar, url, method="GET", data=None, headers=None):
    """One curl request with a persistent cookie jar; returns (status, headers, body)."""
    with tempfile.NamedTemporaryFile() as header_file, tempfile.NamedTemporaryFile() as body_file:
        cmd = [
            "curl",
            "-sS",
            "-D",
            header_file.name,
            "-o",
            body_file.name,
            "-b",
            cookie_jar,
            "-c",
            cookie_jar,
            "-X",
            method,
            url,
        ]

        for key, value in (headers or {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        if data is not None:
            cmd.extend(["--data", urllib.parse.urlencode(data)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise DemoError(f"HTTP request failed for {url}:\n{result.stderr}".rstrip())

        header_text = Path(header_file.name).read_text()
        body = Path(body_file.name).read_text()

    header_blocks = [block for block in re.split(r"\r?\n\r?\n", header_text.strip()) if block.strip()]
    last_block = header_blocks[-1] if header_blocks else ""
    header_lines = last_block.splitlines()
    status_line = header_lines[0] if header_lines else "HTTP/1.1 000"
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError):
        status = 0

    parsed_headers = {}
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed_headers[key.strip()] = value.strip()

    return status, parsed_headers, body


def http_json(url, data=None, json_data=None, headers=None, method=None):
    """Cookie-less JSON request; returns (status, parsed body)."""
    headers = dict(headers or {})
    if json_data is not None:
        body = json.dumps(json_data).encode()
        headers["Content-Type"] = "application/json"
    else:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as err:
        return err.code, {"error": err.read().decode()}


def parse_elements(html_text):
    parser = ElementByIDParser()
    parser.feed(html_text)
    return parser.elements


def parse_link(html_text, element_id, base_url):
    href = parse_elements(html_text).get(element_id, {}).get("href")
    if not href:
        return None
    return urllib.parse.urljoin(base_url, href)


def parse_first_broker_form(html_text, base_url):
    parser = FormParser()
    parser.feed(html_text)
    for form in parser.forms:
        names = {item["name"] for item in form["inputs"] if item["name"]}
        if {"username", "email", "firstName", "lastName"} & names:
            action = urllib.parse.urljoin(base_url, form["action"] or base_url)
            fields = {}
            for item in form["inputs"]:
                name = item["name"]
                if not name:
                    continue
                if item["type"] in {"hidden", "text", "email"}:
                    fields[name] = item["value"]
            return action, form["method"], fields
    return None, None, None


def to_wallet_web_url(wallet_link, wallet_base_url=None):
    """Converts a custom-scheme wallet link to the wallet's /authorize URL.

    In a custom-scheme URI everything before the `?` only addresses the wallet;
    the wallet URL form keeps the query string and replaces that prefix.
    """
    if "?" not in wallet_link:
        raise DemoError(f"Wallet link has no query parameters: {wallet_link}")
    query = wallet_link.split("?", 1)[1]
    base = (wallet_base_url or WALLET_BASE_URL).rstrip("/")
    return f"{base}/authorize?{query}"


def invoke_wallet_by_url(wallet_url):
    """GETs a wallet /authorize URL and returns the verifier's redirect_uri."""
    status, _, body = fetch(os.devnull, wallet_url)
    if status != 200:
        raise DemoError(f"Wallet invocation failed ({status}):\n{body[:500]}")
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        raise DemoError(f"Wallet returned a non-JSON response:\n{body[:500]}")
    if result.get("status") != "submitted":
        raise DemoError(f"Wallet did not submit the presentation: {json.dumps(result)[:500]}")
    redirect_uri = (result.get("response") or {}).get("redirect_uri")
    if not redirect_uri:
        raise DemoError(f"Verifier response contained no redirect_uri: {json.dumps(result)[:500]}")
    return redirect_uri


def wallet_pending_requests():
    status, requests = http_json(f"{WALLET_BASE_URL}/api/requests")
    if status != 200:
        raise DemoError(f"Listing wallet consent requests failed ({status}): {requests}")
    return requests


def invoke_wallet_interactively(invoke, timeout=90):
    """Runs a blocking wallet invocation and approves the consent it creates.

    The wallet runs without --auto-accept, so it holds the invocation open
    until the request is approved. This plays the user's role: the invocation
    runs in a thread while the new consent request is approved through the
    same API the wallet UI's "Approve" button calls.
    """
    known_ids = {request.get("id") for request in wallet_pending_requests()}
    outcome = {}

    def run():
        try:
            outcome["value"] = invoke()
        except BaseException as err:
            outcome["error"] = err

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    deadline = time.time() + timeout
    approved = False
    while not approved and time.time() < deadline and thread.is_alive():
        for request in wallet_pending_requests():
            if request.get("id") not in known_ids:
                status, result = http_json(
                    f"{WALLET_BASE_URL}/api/requests/{request['id']}/approve", method="POST"
                )
                if status != 200:
                    raise DemoError(f"Approving the wallet consent request failed ({status}): {result}")
                approved = True
                break
        if not approved:
            time.sleep(0.2)

    thread.join(max(1, deadline - time.time()))
    if thread.is_alive():
        raise DemoError("Wallet invocation did not complete after the consent was approved.")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


# --- Issuance -----------------------------------------------------------


def ensure_user_credential_assignment():
    """Grants the demo user the credential scope (required since Keycloak 26.7).

    Keycloak 26.7 only creates offers for credentials that have been assigned
    to the user via the admin API (POST /users/{id}/vc/credentials).
    """
    status, token_response = http_json(
        f"{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": KEYCLOAK_ADMIN_USER,
            "password": KEYCLOAK_ADMIN_PASSWORD,
        },
    )
    if status != 200:
        raise DemoError(f"Admin token request failed ({status}): {token_response}")
    auth = {"Authorization": f"Bearer {token_response['access_token']}"}

    status, users = http_json(
        f"{KEYCLOAK_BASE_URL}/admin/realms/{ISSUER_REALM}/users?"
        + urllib.parse.urlencode({"username": ISSUER_USER, "exact": "true"}),
        headers=auth,
    )
    if status != 200 or not users:
        raise DemoError(f"Looking up user {ISSUER_USER} failed ({status}): {users}")
    user_id = users[0]["id"]

    credentials_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{ISSUER_REALM}/users/{user_id}/vc/credentials"
    status, assigned = http_json(credentials_url, headers=auth)
    if status == 200 and any(c.get("credentialScopeName") == ISSUER_CREDENTIAL_SCOPE for c in assigned):
        return

    status, result = http_json(
        credentials_url,
        json_data={"credentialScopeName": ISSUER_CREDENTIAL_SCOPE},
        headers=auth,
    )
    if status not in (200, 201, 204, 409):
        raise DemoError(f"Assigning credential to {ISSUER_USER} failed ({status}): {result}")


def create_credential_offer():
    """Creates and resolves a pre-authorized offer in Keycloak; returns the offer JSON."""
    ensure_user_credential_assignment()
    status, token_response = http_json(
        f"{KEYCLOAK_BASE_URL}/realms/{ISSUER_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": ISSUER_CLIENT_ID,
            "username": ISSUER_USER,
            "password": ISSUER_USER_PASSWORD,
        },
    )
    if status != 200:
        raise DemoError(f"Token request failed ({status}): {token_response}")
    access_token = token_response["access_token"]

    offer_endpoint = (
        f"{KEYCLOAK_BASE_URL}/realms/{ISSUER_REALM}/protocol/oid4vc/create-credential-offer"
        f"?credential_configuration_id={ISSUER_CREDENTIAL_SCOPE}&pre_authorized=true&type=uri"
    )
    status, offer_ref = http_json(offer_endpoint, headers={"Authorization": f"Bearer {access_token}"})
    if status != 200:
        raise DemoError(f"Offer creation failed ({status}): {offer_ref}")

    # Keycloak's offer URI is one-shot, so resolve it once and hand the wallet
    # the offer by value (see the keycloak-issuer-wallet example for details).
    offer_uri = f"{offer_ref['issuer'].rstrip('/')}/{offer_ref['nonce'].lstrip('/')}"
    status, credential_offer = http_json(offer_uri)
    if status != 200:
        raise DemoError(f"Resolving the offer failed ({status}): {credential_offer}")
    return credential_offer


def offer_wallet_url(credential_offer, wallet_base_url=None):
    base = (wallet_base_url or WALLET_BASE_URL).rstrip("/")
    return f"{base}/credential-offer?credential_offer=" + urllib.parse.quote(
        json.dumps(credential_offer), safe=""
    )


def offer_scheme_uri(credential_offer):
    return "openid-credential-offer://?credential_offer=" + urllib.parse.quote(
        json.dumps(credential_offer), safe=""
    )


def wallet_credentials():
    status, credentials = http_json(f"{WALLET_BASE_URL}/api/credentials")
    if status != 200:
        raise DemoError(f"Listing credentials failed ({status}): {credentials}")
    return credentials


def delete_credentials_by_vct(vct):
    """Removes credentials of the given type, e.g. leftovers of earlier demo runs."""
    removed = 0
    for credential in wallet_credentials():
        if credential.get("vct") != vct:
            continue
        status, result = http_json(
            f"{WALLET_BASE_URL}/api/credentials/{credential['id']}", method="DELETE"
        )
        if status not in (200, 204):
            raise DemoError(f"Deleting credential {credential['id']} failed ({status}): {result}")
        removed += 1
    return removed


# --- Verification -------------------------------------------------------


def build_authorize_url(state, code_challenge):
    query = urllib.parse.urlencode(
        {
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{KEYCLOAK_BASE_URL}/realms/{VERIFIER_REALM}/protocol/openid-connect/auth?{query}"


def start_broker_login(cookie_jar, state, code_challenge):
    """Starts the OIDC login and returns the parsed elements of the wallet login page."""
    authorize_url = build_authorize_url(state, code_challenge)
    status, _, body = fetch(cookie_jar, authorize_url)
    if status != 200:
        raise DemoError(f"Authorization endpoint returned {status} instead of the login page.")

    broker_link = parse_link(body, "social-oid4vp", authorize_url)
    if not broker_link:
        raise DemoError("Could not find the oid4vp identity-provider button on the Keycloak login page.")

    status, _, body = fetch(cookie_jar, broker_link)
    if status != 200:
        raise DemoError(f"OID4VP broker page returned {status}.")
    return parse_elements(body)


def follow_complete_auth(cookie_jar, start_url):
    current_url = start_url
    callback_url = None

    for _ in range(10):
        status, headers, body = fetch(cookie_jar, current_url)
        location = headers.get("Location") or headers.get("location")
        if 300 <= status < 400 and location:
            next_url = urllib.parse.urljoin(current_url, location)
            if next_url.startswith(OIDC_REDIRECT_URI):
                callback_url = next_url
                break
            current_url = next_url
            continue

        form_action, form_method, fields = parse_first_broker_form(body, current_url)
        if form_action:
            suffix = f"{BROKER_USERNAME_PREFIX}-{int(time.time())}"
            fields.update(
                {
                    "username": fields.get("username") or suffix,
                    "email": fields.get("email") or f"{suffix}@example.com",
                    "firstName": fields.get("firstName") or "Wallet",
                    "lastName": fields.get("lastName") or "User",
                }
            )
            status, headers, body = fetch(
                cookie_jar,
                form_action,
                method=form_method,
                data=fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            location = headers.get("Location") or headers.get("location")
            if 300 <= status < 400 and location:
                next_url = urllib.parse.urljoin(form_action, location)
                if next_url.startswith(OIDC_REDIRECT_URI):
                    callback_url = next_url
                    break
                current_url = next_url
                continue
            raise DemoError("First broker login form submission did not redirect to the callback URL.")

        page_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
        raise DemoError(
            "Keycloak did not return a first-broker-login form or callback redirect.\n"
            f"Last URL: {current_url}\n"
            f"HTTP status: {status}\n"
            f"Page text: {page_text[:1200]}"
        )

    if not callback_url:
        raise DemoError("Did not reach the callback redirect after completing the OID4VP flow.")
    return callback_url


def exchange_code(code, code_verifier):
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{VERIFIER_REALM}/protocol/openid-connect/token"
    status, _, body = fetch(
        os.devnull,
        token_url,
        method="POST",
        data={
            "grant_type": "authorization_code",
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise DemoError(f"Authorization code exchange failed ({status}):\n{body}".rstrip())
    return json.loads(body)


def complete_login(cookie_jar, redirect_uri, state, code_verifier):
    """Follows the complete-auth redirect and exchanges the code; returns id_token claims."""
    callback_url = follow_complete_auth(cookie_jar, redirect_uri)
    callback_params = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
    code = callback_params.get("code", [None])[0]
    returned_state = callback_params.get("state", [None])[0]
    if not code:
        raise DemoError(f"Callback redirect did not contain an authorization code: {callback_url}")
    if returned_state != state:
        raise DemoError(f"State mismatch after login: expected {state}, got {returned_state}")

    token_response = exchange_code(code, code_verifier)
    return decode_jwt_payload(token_response.get("id_token", ""))
