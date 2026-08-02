#!/usr/bin/env python3
import html.parser
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path


APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8090")
APP_REDIRECT_URI = os.environ.get("APP_REDIRECT_URI", f"{APP_BASE_URL}/callback")
OID4VC_WALLET_PORT = int(os.environ.get("OID4VC_WALLET_PORT", "8085"))
DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "alice")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "alice")

SCRIPT_DIR = Path(__file__).resolve().parent
SCENARIO_DIR = SCRIPT_DIR.parent
KEYCLOAK_CA_CERT = Path(os.environ.get("KEYCLOAK_CA_CERT", str(SCENARIO_DIR / "keycloak-ca-cert.pem"))).resolve()


class LinkByIDParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        attr_map = dict(attrs)
        element_id = attr_map.get("id")
        href = attr_map.get("href")
        if element_id and href:
            self.links[element_id] = href


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
            return
        if tag == "button" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attr_map.get("name", ""),
                    "type": attr_map.get("type", "submit"),
                    "value": attr_map.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def resolve_oid4vc_dev_command():
    path_bin = shutil.which("oid4vc-dev")
    if path_bin:
        return [path_bin], None

    fail("Unable to resolve oid4vc-dev in PATH. Install it first or run ./start.sh.")


def reset_wallet():
    cmd, cwd = resolve_oid4vc_dev_command()
    full_cmd = cmd + ["wallet", "remove", "--all"]
    result = subprocess.run(
        full_cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        output = strip_ansi((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
        fail(f"eudi wallet remove --all failed:\n{output}".rstrip())


def fetch(cookie_jar, url, method="GET", data=None, headers=None):
    with tempfile.NamedTemporaryFile() as header_file, tempfile.NamedTemporaryFile() as body_file:
        cmd = ["curl", "-sS", "-D", header_file.name, "-o", body_file.name]

        if cookie_jar:
            cmd.extend(["-b", cookie_jar, "-c", cookie_jar])

        if KEYCLOAK_CA_CERT.is_file():
            cmd.extend(["--cacert", str(KEYCLOAK_CA_CERT)])

        cmd.extend(["-X", method, url])

        for key, value in (headers or {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        if data is not None:
            cmd.extend(["--data", urllib.parse.urlencode(data)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            fail(f"HTTP request failed for {url}:\n{result.stderr}".rstrip())

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


def get_json(cookie_jar, path):
    status, _, body = fetch(cookie_jar, f"{APP_BASE_URL}{path}")
    if status != 200:
        fail(f"{path} returned HTTP {status}:\n{body}".rstrip())
    return json.loads(body)


def parse_link(html_text, element_id, base_url):
    parser = LinkByIDParser()
    parser.feed(html_text)
    href = parser.links.get(element_id)
    if not href:
        return None
    return urllib.parse.urljoin(base_url, href)


def parse_form(html_text, predicate, base_url):
    parser = FormParser()
    parser.feed(html_text)
    for form in parser.forms:
        if not predicate(form):
            continue
        action = urllib.parse.urljoin(base_url, form["action"] or base_url)
        fields = {}
        for item in form["inputs"]:
            name = item["name"]
            if not name:
                continue
            if item["type"] in {"hidden", "text", "email", "password"}:
                fields[name] = item["value"]
        return action, form["method"], fields
    return None, None, None


def submit_form(cookie_jar, action, method, fields):
    return fetch(
        cookie_jar,
        action,
        method=method,
        data=fields,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def extract_redirect_uri(wallet_output):
    matches = re.findall(r"https?://[^\s\"']+/broker/oid4vp/endpoint/complete-auth\?[^\s\"']+", wallet_output)
    if not matches:
        return None
    return matches[-1]


def run_wallet_accept(url, auto_accept=False):
    cmd, cwd = resolve_oid4vc_dev_command()
    full_cmd = cmd + ["wallet", "accept"]
    if auto_accept:
        full_cmd.extend(["--auto-accept", "--port", str(OID4VC_WALLET_PORT)])
    full_cmd.append(url)
    result = subprocess.run(
        full_cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    output = strip_ansi((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
    if result.returncode != 0:
        fail(f"eudi wallet accept failed:\n{output}".rstrip())
    return output.strip()


def open_login_page(cookie_jar, login_url):
    current_url = login_url
    for _ in range(5):
        status, headers, body = fetch(cookie_jar, current_url)
        location = headers.get("Location") or headers.get("location")
        if 300 <= status < 400 and location:
            current_url = urllib.parse.urljoin(current_url, location)
            continue
        return current_url, status, body
    fail(f"Too many redirects while opening {login_url}")


def complete_password_login(cookie_jar):
    login_url = get_json(cookie_jar, "/api/login-url?mode=login")["login_url"]
    current_url, status, body = open_login_page(cookie_jar, login_url)
    if status != 200:
        fail(f"Login page returned HTTP {status}.")

    def is_password_form(form):
        names = {item["name"] for item in form["inputs"] if item["name"]}
        return "username" in names and "password" in names

    action, method, fields = parse_form(body, is_password_form, current_url)
    if not action:
        fail("Could not find the Keycloak username/password login form.")
    fields.update({"username": DEMO_USERNAME, "password": DEMO_PASSWORD})

    status, headers, body = fetch(
        cookie_jar,
        action,
        method=method,
        data=fields,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    location = headers.get("Location") or headers.get("location")
    if not (300 <= status < 400 and location):
        fail(f"Password login did not redirect back to the app:\n{body[:1000]}".rstrip())

    callback_url = urllib.parse.urljoin(action, location)
    if not callback_url.startswith(APP_REDIRECT_URI):
        fail(f"Unexpected password-login callback URL: {callback_url}")

    status, _, callback_body = fetch(cookie_jar, callback_url)
    if status not in {200, 302}:
        fail(f"App callback after password login returned HTTP {status}:\n{callback_body}".rstrip())

    status, _, app_home = fetch(cookie_jar, APP_BASE_URL + "/")
    if status != 200 or "&#34;login_type&#34;: &#34;basic&#34;" not in app_home:
        fail(f"App session was not established after password login:\n{app_home[:1000]}".rstrip())


def follow_complete_auth(cookie_jar, start_url):
    current_url = start_url
    callback_url = None

    for _ in range(10):
        status, headers, body = fetch(cookie_jar, current_url)
        location = headers.get("Location") or headers.get("location")
        if 300 <= status < 400 and location:
            next_url = urllib.parse.urljoin(current_url, location)
            if next_url.startswith(APP_REDIRECT_URI):
                callback_url = next_url
                break
            current_url = next_url
            continue

        parser = FormParser()
        parser.feed(body)
        form_summaries = [
            {
                "action": form["action"],
                "method": form["method"],
                "names": [item["name"] for item in form["inputs"] if item["name"]],
            }
            for form in parser.forms
        ]
        fail(
            "Wallet login reached an unexpected first-broker-login page.\n"
            f"Last URL: {current_url}\n"
            f"HTTP status: {status}\n"
            f"Forms: {form_summaries}\n"
            f"Page excerpt: {body[:1000]}"
        )

    if not callback_url:
        fail("Did not reach the callback redirect after completing the OID4VP flow.")
    return callback_url


def complete_wallet_login(cookie_jar):
    status, headers, _ = fetch(cookie_jar, APP_BASE_URL + "/logout")
    location = headers.get("Location") or headers.get("location")
    current_url = APP_BASE_URL + "/logout"
    while 300 <= status < 400 and location:
        current_url = urllib.parse.urljoin(current_url, location)
        status, headers, body = fetch(cookie_jar, current_url)
        location = headers.get("Location") or headers.get("location")

    login_url = get_json(cookie_jar, "/api/login-url?mode=login")["login_url"]
    current_url, status, body = open_login_page(cookie_jar, login_url)
    if status != 200:
        fail(f"Wallet login page returned HTTP {status}.")

    wallet_url = parse_link(body, "oid4vp-open-wallet", current_url)
    if not wallet_url:
        broker_link = parse_link(body, "social-oid4vp", current_url)
        if broker_link:
            status, _, body = fetch(cookie_jar, broker_link)
            wallet_url = parse_link(body, "oid4vp-open-wallet", broker_link)
    if not wallet_url:
        fail("Could not find the wallet handoff link in the login flow.")

    wallet_output = run_wallet_accept(wallet_url, auto_accept=True)
    redirect_uri = extract_redirect_uri(wallet_output)
    if not redirect_uri:
        fail(f"Could not extract Keycloak redirect URI from wallet output:\n{wallet_output}".rstrip())

    callback_url = follow_complete_auth(cookie_jar, redirect_uri)
    status, _, callback_body = fetch(cookie_jar, callback_url)
    if status not in {200, 302}:
        fail(f"App callback after wallet login returned HTTP {status}:\n{callback_body}".rstrip())

    status, _, app_home = fetch(cookie_jar, APP_BASE_URL + "/")
    if status != 200 or "&#34;login_type&#34;: &#34;wallet&#34;" not in app_home:
        fail(f"App session was not updated after wallet login:\n{app_home[:1000]}".rstrip())


def main():
    reset_wallet()

    print(f"Checking demo app at {APP_BASE_URL} ...")
    status, _, body = fetch(None, f"{APP_BASE_URL}/healthz")
    if status != 200 or body.strip() != "ok":
        fail(f"Demo app health check failed ({status}): {body}".rstrip())

    with tempfile.NamedTemporaryFile() as cookie_jar_file:
        cookie_jar = cookie_jar_file.name

        print("Logging into the sample app with username/password ...")
        complete_password_login(cookie_jar)

        print("Requesting a credential offer from the authenticated app session ...")
        offer_uri = get_json(cookie_jar, "/api/credential-offer")["offer_uri"]

        print("Redeeming the Keycloak-issued credential ...")
        run_wallet_accept(offer_uri, auto_accept=False)

        print("Starting wallet login with the stored credential ...")
        complete_wallet_login(cookie_jar)

    print("End-to-end flow completed.")


if __name__ == "__main__":
    main()
