#!/usr/bin/env python3

import argparse
import base64
import copy
import json
import os
import queue
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


MODULE_ID_RE = re.compile(r"Created test module, new id:\s*([A-Za-z0-9]+)")
RUNNING_MODULE_RE = re.compile(r"Running test module:\s*([^\[]+)(.*)$")
VARIANT_RE = re.compile(r"\[([^=\]]+)=([^\]]*)\]")
PLAN_URL_RE = re.compile(r"(https://[^\s]+plan-detail\.html\?plan=[A-Za-z0-9]+)")
RUNNING_PLAN_CONFIG_RE = re.compile(r"Running plan '.+?' with configuration file '(.+?)'")
IMPLICIT_SUBMIT_RE = re.compile(r"xhr\.open\('POST',\s*([\"'])(.+?)\1", re.DOTALL)
JSON_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9._-]+\.json)\}")
TERMINAL_STATES = {"FINISHED", "INTERRUPTED"}
WALLET_MODE = os.environ.get("OIDF_WALLET_MODE", "strict")
POLL_INTERVAL = 1.0
REQUEST_TIMEOUT = 20
DEFAULT_MODULE_IDLE_TIMEOUT = 180
SCREENSHOT_DATA_URL = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WnRk9sAAAAASUVORK5CYII="
)


@dataclass(frozen=True)
class PlanScenario:
    slug: str
    kind: str
    template_relpath: str
    plan_name: str
    variant: dict[str, str]
    credential_kind: str
    requires_haip: bool = False


@dataclass(frozen=True)
class WalletMaterials:
    holder_jwk: dict
    issuer_jwk: dict
    ca_pem: str


@dataclass(frozen=True)
class WalletSubmissionResult:
    completed: bool
    retryable: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the official OIDF Final and HAIP wallet plans against the local wallet")
    parser.add_argument("--suite-dir", required=True, help="Path to the extracted official OIDF conformance suite")
    parser.add_argument("--wallet-url", required=True, help="Base URL of the local wallet server")
    parser.add_argument("--wallet-issuer-url", required=True, help="HTTPS issuer URL served by the local wallet")
    parser.add_argument("--wallet-ca-cert", required=True, help="Path to the shared wallet CA PEM")
    parser.add_argument("--vci-client-id", required=True, help="OID4VCI authorization-code client_id to configure in the suite")
    parser.add_argument("--vci-redirect-uri", required=True, help="OID4VCI authorization-code redirect_uri to configure in the suite")
    parser.add_argument("--results-dir", required=True, help="Directory for exported official runner results")
    parser.add_argument("--runner-log", required=True, help="Path for mirrored official runner stdout")
    parser.add_argument(
        "--rerun",
        help="Pass through to the official OIDF runner, e.g. 2 or 2:6 or 1:6,2:6",
        default=None,
    )
    return parser.parse_args()


def api_request(
    base_url: str,
    token: str | None,
    method: str,
    path: str,
    body: bytes | None = None,
    content_type: str | None = None,
):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
        data = resp.read()
        response_content_type = resp.headers.get("Content-Type", "")
        if "application/json" in response_content_type:
            return json.loads(data.decode("utf-8"))
        return data.decode("utf-8")


def request_json(url: str, context: ssl.SSLContext | None = None):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=context) as resp:
        return json.loads(resp.read().decode("utf-8"))


def conformance_api_context() -> ssl.SSLContext | None:
    if os.environ.get("CONFORMANCE_DEV_MODE") or os.environ.get("DISABLE_SSL_VERIFY"):
        return ssl._create_unverified_context()
    return None


def parse_running_module_line(line: str) -> dict:
    match = RUNNING_MODULE_RE.search(line)
    if not match:
        return {}
    return {
        "test_name": match.group(1).strip(),
        "variant": {key: value for key, value in VARIANT_RE.findall(match.group(2))},
    }


def merge_variants(*variants: dict | None) -> dict:
    merged = {}
    for variant in variants:
        if isinstance(variant, dict):
            merged.update(variant)
    return merged


def wallet_request(wallet_url: str, method: str, path: str, payload: dict | None = None, extra_headers: dict[str, str] | None = None):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    url = wallet_url.rstrip("/") + "/" + path.lstrip("/")
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def should_retry_wallet_submission(status_code: int, body: str) -> bool:
    if status_code not in {502, 503, 504}:
        return False
    lowered = body.lower()
    return "temporarily unavailable" in lowered or "timeout" in lowered or "timed out" in lowered


def verify_suite_support(suite_dir: Path) -> None:
    required = [
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vp-wallet-test-config-dcql-sdjwt.json",
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vp-wallet-test-config-dcql-mdoc.json",
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vci-wallet-test-config-plain.json",
        suite_dir / "scripts" / "test-configs-rp-against-op" / "vci-wallet-test-config-haip.json",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vp1finalwallet" / "VP1FinalWalletTestPlan.java",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vci10wallet" / "VCIWalletTestPlan.java",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vp1finalwallet" / "VP1FinalWalletTestPlanHaip.java",
        suite_dir / "src" / "main" / "java" / "net" / "openid" / "conformance" / "vci10wallet" / "VCIWalletTestPlanHaip.java",
    ]
    missing = [path for path in required if not path.exists()]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise FileNotFoundError(f"the extracted OIDF suite is missing required Final plan files:\n{formatted}")


def final_scenarios() -> list[PlanScenario]:
    import os as _os
    _only = _os.environ.get("ONLY_SCENARIOS", "")
    scenarios = [
        PlanScenario(
            slug="vp-final-sdjwt-signed-direct-post",
            kind="vp",
            template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post",
            },
            credential_kind="sdjwt",
        ),
        PlanScenario(
            slug="vp-final-sdjwt-signed-direct-post-jwt",
            kind="vp",
            template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post.jwt",
            },
            credential_kind="sdjwt",
        ),
        PlanScenario(
            slug="vp-final-sdjwt-unsigned-direct-post",
            kind="vp",
            template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "redirect_uri",
                "request_method": "request_uri_unsigned",
                "response_mode": "direct_post",
            },
            credential_kind="sdjwt",
        ),
        PlanScenario(
            slug="vp-final-mdoc-signed-direct-post-jwt",
            kind="vp",
            template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "iso_mdl",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post.jwt",
            },
            credential_kind="mdoc",
        ),
        PlanScenario(
            slug="vci-final-sdjwt",
            kind="vci",
            template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json",
            plan_name="oid4vci-1_0-wallet-test-plan",
            variant={
                "client_auth_type": "client_attestation",
                "fapi_request_method": "unsigned",
                "sender_constrain": "dpop",
                "authorization_request_type": "simple",
                "fapi_profile": "vci",
                "vci_grant_type": "authorization_code",
                "vci_authorization_code_flow_variant": "issuer_initiated",
                "vci_credential_offer_variant": "by_value",
                "credential_format": "sd_jwt_vc",
                "vci_credential_issuance_mode": "immediate",
                "vci_credential_encryption": "plain",
            },
            credential_kind="sdjwt",
        ),
        PlanScenario(
            slug="vci-final-mdoc",
            kind="vci",
            template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json",
            plan_name="oid4vci-1_0-wallet-test-plan",
            variant={
                "client_auth_type": "client_attestation",
                "fapi_request_method": "unsigned",
                "sender_constrain": "dpop",
                "authorization_request_type": "simple",
                "fapi_profile": "vci",
                "vci_grant_type": "authorization_code",
                "vci_authorization_code_flow_variant": "issuer_initiated",
                "vci_credential_offer_variant": "by_value",
                "credential_format": "mdoc",
                "vci_credential_issuance_mode": "immediate",
                "vci_credential_encryption": "plain",
            },
            credential_kind="mdoc",
        ),
        # The pre-authorized code grant. It is the flow a wallet meets most
        # often in the wild (scan a QR, get a credential, no sign-in) and the
        # one the authorization-code scenarios above never exercise. HAIP is
        # deliberately absent: the suite refuses the combination outright
        # (AbstractVCIWalletTest rejects PRE_AUTHORIZATION_CODE under
        # VCI_HAIP), and pre-authorized offers are out of HAIP's scope anyway.
        PlanScenario(
            slug="vci-final-sdjwt-preauth",
            kind="vci",
            template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json",
            plan_name="oid4vci-1_0-wallet-test-plan",
            variant={
                "client_auth_type": "client_attestation",
                "fapi_request_method": "unsigned",
                "sender_constrain": "dpop",
                "authorization_request_type": "simple",
                "fapi_profile": "vci",
                "vci_grant_type": "pre_authorization_code",
                # Pre-authorized offers are always issuer-initiated: there is
                # no authorization endpoint for a wallet to start from.
                "vci_authorization_code_flow_variant": "issuer_initiated",
                "vci_credential_offer_variant": "by_value",
                "credential_format": "sd_jwt_vc",
                "vci_credential_issuance_mode": "immediate",
                "vci_credential_encryption": "plain",
            },
            credential_kind="sdjwt",
        ),
        PlanScenario(
            slug="vci-final-mdoc-preauth",
            kind="vci",
            template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json",
            plan_name="oid4vci-1_0-wallet-test-plan",
            variant={
                "client_auth_type": "client_attestation",
                "fapi_request_method": "unsigned",
                "sender_constrain": "dpop",
                "authorization_request_type": "simple",
                "fapi_profile": "vci",
                "vci_grant_type": "pre_authorization_code",
                "vci_authorization_code_flow_variant": "issuer_initiated",
                "vci_credential_offer_variant": "by_value",
                "credential_format": "mdoc",
                "vci_credential_issuance_mode": "immediate",
                "vci_credential_encryption": "plain",
            },
            credential_kind="mdoc",
        ),
    ]
    scenarios.extend(
        [
            PlanScenario(
                slug="vp-haip-sdjwt-direct-post-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "sd_jwt_vc",
                    "response_mode": "direct_post.jwt",
                },
                credential_kind="sdjwt",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vp-haip-mdoc-direct-post-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "iso_mdl",
                    "response_mode": "direct_post.jwt",
                },
                credential_kind="mdoc",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vp-haip-sdjwt-dc-api-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "sd_jwt_vc",
                    "response_mode": "dc_api.jwt",
                },
                credential_kind="sdjwt",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vp-haip-mdoc-dc-api-jwt",
                kind="vp",
                template_relpath="scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc.json",
                plan_name="oid4vp-1final-wallet-haip-test-plan",
                variant={
                    "credential_format": "iso_mdl",
                    "response_mode": "dc_api.jwt",
                },
                credential_kind="mdoc",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vci-haip-sdjwt",
                kind="vci",
                template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-haip.json",
                plan_name="oid4vci-1_0-wallet-haip-test-plan",
                variant={
                    "vci_authorization_code_flow_variant": "issuer_initiated",
                    "vci_credential_offer_variant": "by_value",
                    "credential_format": "sd_jwt_vc",
                },
                credential_kind="sdjwt",
                requires_haip=True,
            ),
            PlanScenario(
                slug="vci-haip-mdoc",
                kind="vci",
                template_relpath="scripts/test-configs-rp-against-op/vci-wallet-test-config-haip.json",
                plan_name="oid4vci-1_0-wallet-haip-test-plan",
                variant={
                    "vci_authorization_code_flow_variant": "issuer_initiated",
                    "vci_credential_offer_variant": "by_value",
                    "credential_format": "mdoc",
                },
                credential_kind="mdoc",
                requires_haip=True,
            ),
        ]
    )
    if _only:
        scenarios = [sc for sc in scenarios if any(w in sc.slug for w in _only.split(","))]
    return scenarios


def decode_jwt_payload(jwt: str) -> dict | None:
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None


def browser_request_origin(browser_request: dict) -> str | None:
    if not isinstance(browser_request, dict):
        return None
    digital = browser_request.get("digital")
    if not isinstance(digital, dict):
        return None
    requests = digital.get("requests")
    if not isinstance(requests, list) or not requests:
        return None
    first = requests[0]
    if not isinstance(first, dict):
        return None
    data = first.get("data")
    client_id = None
    expected_origins = None
    if isinstance(data, dict):
        if isinstance(data.get("client_id"), str):
            client_id = data["client_id"]
        expected_origins = data.get("expected_origins")
        if isinstance(data.get("request"), str):
            payload = decode_jwt_payload(data["request"])
            if isinstance(payload, dict) and isinstance(payload.get("client_id"), str):
                client_id = payload["client_id"]
    if isinstance(data, str):
        payload = decode_jwt_payload(data)
        if isinstance(payload, dict) and isinstance(payload.get("client_id"), str):
            client_id = payload["client_id"]
    if isinstance(client_id, str) and client_id.startswith("web-origin:"):
        return client_id[len("web-origin:") :]
    if isinstance(expected_origins, list) and expected_origins:
        first_origin = expected_origins[0]
        if isinstance(first_origin, str) and first_origin:
            return first_origin
    return None


def origin_from_submit_url(submit_url: str) -> str | None:
    parsed = urllib.parse.urlsplit(submit_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def build_vp_dcql_query(credential_kind: str) -> dict:
    if credential_kind == "mdoc":
        return {
            "credentials": [
                {
                    "id": "pid",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "eu.europa.ec.eudi.pid.1",
                    },
                    "claims": [
                        {"path": ["eu.europa.ec.eudi.pid.1", "given_name"]},
                        {"path": ["eu.europa.ec.eudi.pid.1", "family_name"]},
                    ],
                }
            ]
        }
    return {
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["urn:eudi:pid:1"],
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                ],
            }
        ]
    }


def conformance_server_host() -> str:
    base_url = os.environ.get("CONFORMANCE_SERVER_LOCAL") or os.environ.get("CONFORMANCE_SERVER") or "https://demo.certification.openid.net/"
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.hostname:
        return parsed.hostname
    return "demo.certification.openid.net"


def load_config_template(source: Path) -> dict:
    raw = source.read_text()

    def replace_placeholder(match: re.Match[str]) -> str:
        name = match.group(1)
        candidate = source.parents[1] / "certs-keys" / name
        if not candidate.exists():
            raise FileNotFoundError(f"template placeholder {name} does not exist at {candidate}")
        return candidate.read_text().strip()

    expanded = JSON_PLACEHOLDER_RE.sub(replace_placeholder, raw)
    return json.loads(expanded)


def ssl_context_for_ca(ca_path: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_path))
    context.check_hostname = False
    return context


def public_jwk(jwk: dict) -> dict:
    return {key: value for key, value in jwk.items() if key not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}}


def fetch_wallet_materials(wallet_url: str, wallet_issuer_url: str, wallet_ca_cert: Path) -> WalletMaterials:
    credentials = wallet_request(wallet_url, "GET", "/api/credentials")
    holder_jwk = None
    for credential in credentials:
        claims = credential.get("claims", {})
        cnf = claims.get("cnf", {})
        candidate = cnf.get("jwk")
        if isinstance(candidate, dict):
            holder_jwk = candidate
            break
    if holder_jwk is None:
        raise RuntimeError("wallet did not expose a holder cnf.jwk in /api/credentials")

    issuer_meta = request_json(
        wallet_issuer_url.rstrip("/") + "/.well-known/jwt-vc-issuer",
        context=ssl_context_for_ca(wallet_ca_cert),
    )
    keys = issuer_meta.get("jwks", {}).get("keys", [])
    if len(keys) != 1 or not isinstance(keys[0], dict):
        raise RuntimeError(f"wallet issuer metadata did not expose exactly one issuer JWK: {keys!r}")

    ca_pem = wallet_ca_cert.read_text()
    return WalletMaterials(
        holder_jwk=public_jwk(holder_jwk),
        issuer_jwk=public_jwk(keys[0]),
        ca_pem=ca_pem,
    )


def baseline_credential_ids(wallet_url: str) -> set[str]:
    """Credential ids the wallet was started with (the --pid baseline)."""
    credentials = wallet_request(wallet_url, "GET", "/api/credentials")
    return {c["id"] for c in credentials if c.get("id")}


def purge_issued_credentials(wallet_url: str, baseline_ids: set[str]) -> int:
    """Drop everything the suite has issued, keeping only the baseline.

    One wallet serves every plan, so the credentials an issuance plan
    deposits are still there when a presentation plan runs. They match the
    same DCQL query as the baseline PID (same vct), and they are signed by
    the suite's own issuer, which nothing chains to the wallet CA the plan
    configures as its trust anchor. A presentation plan that picks one of
    them fails certificate validation for a reason that has nothing to do
    with the wallet. Each module starts from the baseline instead.
    """
    try:
        credentials = wallet_request(wallet_url, "GET", "/api/credentials")
    except Exception as exc:  # noqa: BLE001
        print(f"[monitor] could not list credentials to purge: {exc}", flush=True)
        return 0
    removed = 0
    for credential in credentials:
        cred_id = credential.get("id")
        if not cred_id or cred_id in baseline_ids:
            continue
        # Not wallet_request: a successful delete answers 204 with no body,
        # which json.loads would reject.
        url = wallet_url.rstrip("/") + f"/api/credentials/{cred_id}"
        try:
            req = urllib.request.Request(url, method="DELETE")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT):
                removed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[monitor] could not delete credential {cred_id}: {exc}", flush=True)
    return removed


def create_vp_config(suite_dir: Path, scenario: PlanScenario, materials: WalletMaterials, output: Path) -> None:
    config = load_config_template(suite_dir / scenario.template_relpath)
    config["alias"] = f"oid4vc-dev-{scenario.slug}"
    config["description"] = f"oid4vc-dev wallet ({scenario.slug})"
    config.setdefault("client", {})
    config["client"]["dcql"] = build_vp_dcql_query(scenario.credential_kind)
    if scenario.requires_haip:
        # The HAIP VP plan includes x509_san_dns Browser API variants where no response_uri
        # exists, so the suite expects a static client_id in the config.
        config["client"]["client_id"] = conformance_server_host()
    response_mode = scenario.variant.get("response_mode", "")
    if response_mode.endswith(".jwt"):
        config["client"]["authorization_encrypted_response_alg"] = "ECDH-ES"
        config["client"]["authorization_encrypted_response_enc"] = "A128GCM"
    if scenario.variant.get("request_method") == "request_uri_multisigned" or scenario.requires_haip:
        secondary_jwks = copy.deepcopy(config["client"].get("jwks", {"keys": []}))
        keys = secondary_jwks.get("keys", [])
        if keys and isinstance(keys[0], dict) and isinstance(keys[0].get("kid"), str):
            keys[0]["kid"] = keys[0]["kid"] + "-second"
        config["client2"] = {
            "client_id": config["client"]["client_id"],
            "jwks": secondary_jwks,
        }
    if scenario.requires_haip:
        config.setdefault("credential", {})
        config["credential"]["trust_anchor_pem"] = materials.ca_pem
        config["credential"]["status_list_trust_anchor_pem"] = materials.ca_pem
    with output.open("w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def create_vci_config(args: argparse.Namespace, suite_dir: Path, scenario: PlanScenario, materials: WalletMaterials, output: Path) -> None:
    config = load_config_template(suite_dir / scenario.template_relpath)
    redirect_uri = args.vci_redirect_uri
    parsed_redirect = urllib.parse.urlsplit(redirect_uri)
    if not parsed_redirect.path.endswith("/callback"):
        raise ValueError(f"VCI redirect_uri must end with /callback: {redirect_uri}")
    alias_prefix = parsed_redirect.path[: -len("/callback")].rstrip("/")
    alias = alias_prefix.rsplit("/", 1)[-1]
    if not alias:
        raise ValueError(f"VCI redirect_uri must include an alias path segment before /callback: {redirect_uri}")

    config["alias"] = alias
    config["description"] = f"oid4vc-dev wallet ({scenario.slug})"
    config["waitTimeoutSeconds"] = 10
    config["maxWaitForAdditionalRequestSeconds"] = 20

    offer_path = parsed_redirect.path[: -len("/callback")] + "/credential_offer"
    credential_offer_endpoint = urllib.parse.urlunsplit(
        (parsed_redirect.scheme, parsed_redirect.netloc, offer_path, "", "")
    )

    config.setdefault("client", {})
    config["client"]["client_id"] = args.vci_client_id
    config["client"]["redirect_uri"] = redirect_uri
    config["client"]["jwks"] = {"keys": [materials.holder_jwk]}

    config.setdefault("server", {})
    config.setdefault("credential", {})
    config.setdefault("vci", {})
    config.setdefault("client_attestation", {})
    config["vci"]["credential_offer_endpoint"] = credential_offer_endpoint
    if scenario.credential_kind == "mdoc":
        config["vci"]["credential_configuration_id"] = "eu.europa.ec.eudi.pid.mdoc.1.jwt.keyattest"
    else:
        config["vci"]["credential_configuration_id"] = "eu.europa.ec.eudi.pid.1"
    config["client_attestation"]["issuer"] = args.wallet_issuer_url
    config["client_attestation"]["trust_anchor"] = materials.ca_pem
    config["client_attestation"]["attester_jwks"] = {"keys": [materials.issuer_jwk]}
    config["client_attestation"]["key_attestation_jwks"] = {"keys": [materials.issuer_jwk]}
    config["client_attestation"]["key_attestation_trust_anchor_pem"] = materials.ca_pem
    config["vci"]["client_attestation_issuer"] = args.wallet_issuer_url
    config["vci"]["client_attestation_trust_anchor"] = materials.ca_pem
    config["vci"]["client_attester_keys_jwks"] = {"keys": [materials.issuer_jwk]}
    config["vci"]["key_attestation_jwks"] = {"keys": [materials.issuer_jwk]}
    config["vci"]["key_attestation_trust_anchor_pem"] = materials.ca_pem
    config["browser"] = []

    with output.open("w") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def create_config(args: argparse.Namespace, suite_dir: Path, results_dir: Path, scenario: PlanScenario, materials: WalletMaterials) -> Path:
    output = results_dir / f"{scenario.slug}-config.json"
    if scenario.kind == "vp":
        create_vp_config(suite_dir, scenario, materials, output)
    elif scenario.kind == "vci":
        create_vci_config(args, suite_dir, scenario, materials, output)
    else:
        raise RuntimeError(f"unknown scenario kind {scenario.kind}")
    return output


VP_FINAL_MODULE_HAPPY_FLOW = "oid4vp-1final-wallet-happy-flow"
VP_FINAL_MODULE_ALTERNATE_HAPPY_FLOW = "oid4vp-1final-wallet-alternate-happy-flow"
VP_FINAL_MODULE_REQUEST_URI_METHOD_POST = "oid4vp-1final-wallet-request-uri-method-post"
VP_FINAL_MODULE_FEWER_CLAIMS = "oid4vp-1final-wallet-fewer-claims-than-available"
VP_FINAL_MODULE_OPTIONAL_CREDENTIAL_SET = "oid4vp-1final-wallet-optional-credential-set"
VP_FINAL_MODULE_NO_CLAIMS = "oid4vp-1final-wallet-no-claims-in-dcql-query"
VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID = "oid4vp-1final-wallet-negative-test-response-uri-not-client-id"
VP_FINAL_MODULE_INVALID_REQUEST_SIGNATURE = "oid4vp-1final-wallet-negative-test-invalid-request-object-signature"
VP_FINAL_MODULE_MULTISIGNED_ONE_INVALID = "oid4vp-1final-wallet-multisigned-one-invalid-signature"
VP_FINAL_MODULE_MISMATCHED_CLIENT_ID = "oid4vp-1final-wallet-negative-test-mismatched-client-id"
VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST = "oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post"
VP_FINAL_MODULE_MISSING_NONCE = "oid4vp-1final-wallet-negative-test-missing-nonce"
VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS = "oid4vp-1final-wallet-negative-test-wrong-expected-origins"
VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX = "oid4vp-1final-wallet-negative-test-invalid-client-id-prefix"
VP_FINAL_MODULE_UNKNOWN_TRANSACTION_DATA = "oid4vp-1final-wallet-negative-test-unknown-transaction-data-type"
VP_FINAL_MODULE_IGNORES_UNUSABLE_ENCRYPTION_KEY = "oid4vp-1final-wallet-ignores-unusable-encryption-key"

VP_FINAL_MODULES = (
    VP_FINAL_MODULE_HAPPY_FLOW,
    VP_FINAL_MODULE_ALTERNATE_HAPPY_FLOW,
    VP_FINAL_MODULE_IGNORES_UNUSABLE_ENCRYPTION_KEY,
    VP_FINAL_MODULE_REQUEST_URI_METHOD_POST,
    VP_FINAL_MODULE_FEWER_CLAIMS,
    VP_FINAL_MODULE_OPTIONAL_CREDENTIAL_SET,
    VP_FINAL_MODULE_NO_CLAIMS,
    VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID,
    VP_FINAL_MODULE_INVALID_REQUEST_SIGNATURE,
    VP_FINAL_MODULE_MULTISIGNED_ONE_INVALID,
    VP_FINAL_MODULE_MISMATCHED_CLIENT_ID,
    VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST,
    VP_FINAL_MODULE_MISSING_NONCE,
    VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS,
    VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX,
    VP_FINAL_MODULE_UNKNOWN_TRANSACTION_DATA,
)


def vp_modules_for_scenario(scenario: PlanScenario) -> tuple[str, ...] | None:
    if scenario.kind != "vp":
        return None

    modules = list(VP_FINAL_MODULES)
    variant = scenario.variant
    response_mode = variant.get("response_mode", "")
    request_method = variant.get("request_method", "")
    client_id_prefix = variant.get("client_id_prefix", "")

    # release-v5.2.1 suite regression: VP1FinalWalletInvalidClientIdPrefix
    # overrides performRedirect() to call createPlaceholder() after
    # super.performRedirect() has already set the module status to WAITING.
    # Conditions cannot run while WAITING, so the suite kills the module with
    # "This is a bug in the test module" before the wallet is ever invoked,
    # and the interrupted module's alias steal breaks the next module too.
    # Re-enable once fixed upstream (broken for all external-wallet runs).
    modules.remove(VP_FINAL_MODULE_INVALID_CLIENT_ID_PREFIX)

    if scenario.requires_haip:
        modules.remove(VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID)
        return tuple(modules)

    if response_mode in {"direct_post", "dc_api"}:
        # @VariantNotApplicable: the unencrypted modes never advertise an
        # encryption key, so there is no unusable-key scenario to test.
        modules.remove(VP_FINAL_MODULE_IGNORES_UNUSABLE_ENCRYPTION_KEY)
    if response_mode == "direct_post":
        # The release-v5.1.44 alternate direct_post module unconditionally
        # replaces encrypted-response setup that is absent for plain direct_post.
        # Still present in release-v5.2.1.
        modules.remove(VP_FINAL_MODULE_ALTERNATE_HAPPY_FLOW)
    if client_id_prefix != "redirect_uri":
        modules.remove(VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID)
    if request_method in {"request_uri_unsigned", "url_query"}:
        modules.remove(VP_FINAL_MODULE_INVALID_REQUEST_SIGNATURE)
    if request_method != "request_uri_multisigned":
        modules.remove(VP_FINAL_MODULE_MULTISIGNED_ONE_INVALID)
    if response_mode in {"dc_api", "dc_api.jwt"}:
        modules.remove(VP_FINAL_MODULE_REQUEST_URI_METHOD_POST)
        modules.remove(VP_FINAL_MODULE_RESPONSE_URI_NOT_CLIENT_ID)
        modules.remove(VP_FINAL_MODULE_MISMATCHED_CLIENT_ID)
        modules.remove(VP_FINAL_MODULE_REDIRECT_URI_WITH_DIRECT_POST)
    else:
        modules.remove(VP_FINAL_MODULE_WRONG_EXPECTED_ORIGINS)

    return tuple(modules)


def scenario_plan_arg(scenario: PlanScenario) -> str:
    variant_suffix = "".join(f"[{key}={value}]" for key, value in scenario.variant.items())
    module_names = vp_modules_for_scenario(scenario)
    module_suffix = ""
    if module_names:
        module_suffix = ":" + ",".join(module_names)
    return f"{scenario.plan_name}{variant_suffix}{module_suffix}"



def official_runner_args(
    runner_path: Path,
    results_dir: Path,
    config_jobs: list[tuple[PlanScenario, Path]],
    rerun: str | None = None,
) -> list[str]:
    args = [sys.executable, str(runner_path), "--export-dir", str(results_dir), "--no-parallel"]
    if rerun:
        args.extend(["--rerun", rerun])
    for scenario, config_path in config_jobs:
        args.extend([scenario_plan_arg(scenario), str(config_path)])
    return args


def reader_thread(stream, line_queue: queue.Queue[str]) -> None:
    try:
        for line in iter(stream.readline, ""):
            line_queue.put(line)
    finally:
        stream.close()


def upload_placeholder(base_url: str, token: str | None, module_id: str, placeholder: str) -> None:
    api_request(
        base_url,
        token,
        "POST",
        f"api/log/{module_id}/images/{placeholder}",
        body=SCREENSHOT_DATA_URL.encode("utf-8"),
        content_type="text/plain;charset=utf-8",
    )
    print(f"[monitor] uploaded screenshot placeholder for {module_id}: {placeholder}", flush=True)


def follow_redirect(redirect_uri: str) -> None:
    parsed = urllib.parse.urlsplit(redirect_uri)
    request_uri = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    req = urllib.request.Request(request_uri, method="GET")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    if not parsed.fragment:
        return

    match = IMPLICIT_SUBMIT_RE.search(body)
    if not match:
        raise RuntimeError("implicit callback page did not expose an implicitSubmitUrl")

    submit_url = match.group(2).replace("\\/", "/")
    submit_req = urllib.request.Request(
        submit_url,
        data=("#" + parsed.fragment).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(submit_req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()):
        pass


def wallet_api_path_for_request(request_url: str) -> str:
    parsed = urllib.parse.urlsplit(request_url)
    if parsed.scheme in {"openid-credential-offer", "haip-vci"}:
        return "/api/offers"
    if parsed.scheme in {"openid4vp", "eudi-openid4vp", "haip-vp"}:
        return "/api/presentations"
    query = urllib.parse.parse_qs(parsed.query)
    if "credential_offer" in query or "credential_offer_uri" in query or "credential_offer" in parsed.path:
        return "/api/offers"
    return "/api/presentations"


# The suite prints the code it expects into the offer's own description, the
# way an issuer would print it on a letter, e.g. "Input the one-time code:
# <123456> for testing purposes". A real wallet asks the user for it; an
# automated run reads it from there, because a pre-authorized code offer that
# declares tx_code is only redeemable with it (OpenID4VCI 1.0 section 6.1).
TX_CODE_IN_DESCRIPTION = re.compile(r"<(\d{4,12})>")


def tx_code_from_offer(request_url: str) -> str | None:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(request_url).query)
    raw = (query.get("credential_offer") or [None])[0]
    if not raw:
        return None
    try:
        offer = json.loads(raw)
    except (TypeError, ValueError):
        return None
    grants = offer.get("grants")
    if not isinstance(grants, dict):
        return None
    grant = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    if not isinstance(grant, dict):
        return None
    tx_code = grant.get("tx_code")
    if not isinstance(tx_code, dict):
        return None
    match = TX_CODE_IN_DESCRIPTION.search(str(tx_code.get("description", "")))
    if match:
        return match.group(1)
    # No code to read: send something of the declared length rather than
    # nothing, so the failure is the issuer rejecting a wrong code rather than
    # the wallet omitting the parameter.
    length = tx_code.get("length")
    return "0" * length if isinstance(length, int) and 0 < length <= 12 else None



# The suite's Verifier lists one content encryption algorithm in
# client_metadata.encrypted_response_enc_values_supported, where HAIP section 5
# says "Verifiers MUST list both A128GCM and A256GCM". The suite reads the rule
# the same way (its own ValidateVpClientMetadataEncryptionForHaip enforces it
# against Verifiers under test) but does not follow it in the Verifier it uses
# to drive wallet tests, so a wallet that checks the profile refuses every HAIP
# module in strict mode.
#
# The wallet separates the two switches: the profile decides how many checks
# run, the mode decides whether a finding stops the flow. Running the HAIP
# modules in debug keeps every profile check running and reported while the
# exchange completes, which is what those modules are there to exercise. The
# negative modules keep the configured mode, because refusing a bad request is
# exactly what they test and a debug run would accept it.
def wallet_mode_for(test_name: str | None, requires_haip: bool) -> str:
    if not requires_haip:
        return WALLET_MODE
    if test_name and "negative" in test_name:
        return WALLET_MODE
    return "debug"


def submit_wallet_request(wallet_url: str, request_url: str, requires_haip: bool = False, test_name: str | None = None) -> WalletSubmissionResult:
    api_path = wallet_api_path_for_request(request_url)
    # State the profile explicitly rather than inheriting the server's
    # setting: the non-HAIP modules have to run without HAIP even against a
    # wallet that enforces it globally, and the issuance endpoint now honors
    # the same override.
    payload = {"uri": request_url, "mode": wallet_mode_for(test_name, requires_haip), "haip": bool(requires_haip)}
    tx_code = tx_code_from_offer(request_url)
    if tx_code:
        payload["tx_code"] = tx_code
        print(f"[monitor] offer declares a transaction code, submitting {tx_code}", flush=True)
    for attempt in range(1, 6):
        try:
            result = wallet_request(wallet_url, "POST", api_path, payload)
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if should_retry_wallet_submission(exc.code, body):
                if attempt < 5:
                    print(
                        f"[monitor] wallet request not ready yet for {request_url}: "
                        f"HTTP {exc.code}, retrying ({attempt}/5)",
                        flush=True,
                    )
                    time.sleep(0.4 * attempt)
                    continue
                print(
                    f"[monitor] wallet request still not ready for {request_url}: "
                    f"HTTP {exc.code}, deferring to next poll",
                    flush=True,
                )
                return WalletSubmissionResult(completed=False, retryable=True)
            print(f"[monitor] wallet rejected request {request_url}: HTTP {exc.code} {body}", flush=True)
            return WalletSubmissionResult(completed=True, retryable=False)

    print(f"[monitor] submitted {api_path} request to wallet: {request_url}", flush=True)
    response = result.get("response", {})
    redirect_uri = response.get("redirect_uri")
    if redirect_uri:
        try:
            follow_redirect(redirect_uri)
            print(f"[monitor] followed verifier redirect_uri: {redirect_uri}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[monitor] failed to follow redirect_uri {redirect_uri}: {exc}", flush=True)
    return WalletSubmissionResult(completed=True, retryable=False)


def module_test_name(info: dict, state: dict) -> str | None:
    test_name = info.get("testName")
    if isinstance(test_name, str) and test_name:
        return test_name
    test_name = state.get("test_name")
    if isinstance(test_name, str) and test_name:
        return test_name
    return None


def module_variant(info: dict, state: dict) -> dict:
    return merge_variants(state.get("variant"), info.get("variant"))


def fapi_vci_credential_configuration_id(variant: dict) -> str | None:
    credential_format = variant.get("credential_format")
    if credential_format == "sd_jwt_vc":
        return "eu.europa.ec.eudi.pid.1"
    if credential_format == "mdoc":
        return "eu.europa.ec.eudi.pid.mdoc.1"
    return None


def module_credential_offer_endpoint(info: dict, state: dict) -> str | None:
    config = info.get("config")
    if isinstance(config, dict):
        vci = config.get("vci")
        if isinstance(vci, dict):
            endpoint = vci.get("credential_offer_endpoint")
            if isinstance(endpoint, str) and endpoint:
                return endpoint
    endpoint = state.get("credential_offer_endpoint")
    if isinstance(endpoint, str) and endpoint:
        return endpoint
    base_url = info.get("baseUrl")
    if not isinstance(base_url, str) or not base_url:
        base_url = state.get("base_url")
    if isinstance(base_url, str) and base_url:
        return base_url.rstrip("/") + "/credential_offer"
    return None


def synthetic_fapi_vci_offer_url(info: dict, state: dict) -> str | None:
    test_name = module_test_name(info, state)
    if not isinstance(test_name, str) or not test_name.startswith("fapi2-security-profile-final-client-test-"):
        return None
    variant = module_variant(info, state)
    if variant.get("fapi_profile") not in {"vci", "vci_haip"}:
        return None
    credential_offer_endpoint = module_credential_offer_endpoint(info, state)
    if not credential_offer_endpoint:
        return None
    credential_configuration_id = fapi_vci_credential_configuration_id(variant)
    if not credential_configuration_id:
        return None
    credential_issuer = credential_offer_endpoint.removesuffix("/credential_offer").rstrip("/") + "/"
    offer = {
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [credential_configuration_id],
        "grants": {
            "authorization_code": {},
        },
    }
    encoded_offer = urllib.parse.quote(json.dumps(offer, separators=(",", ":")), safe="")
    return f"{credential_offer_endpoint}?credential_offer={encoded_offer}"


def submit_synthetic_fapi_vci_offer(wallet_url: str, info: dict, state: dict) -> None:
    offer_url = synthetic_fapi_vci_offer_url(info, state)
    test_name = module_test_name(info, state)
    if (
        not offer_url
        and isinstance(test_name, str)
        and test_name.startswith("fapi2-security-profile-final-client-test-")
        and not state.get("logged_synthetic_fapi_skip")
    ):
        state["logged_synthetic_fapi_skip"] = True
        variant = module_variant(info, state)
        print(
            "[monitor] FAPI VCI module is waiting, but no synthetic offer could be built "
            f"(baseUrl={info.get('baseUrl') or state.get('base_url')!r}, variant={variant!r})",
            flush=True,
        )
    if not offer_url or state.get("submitted_synthetic_fapi_offer"):
        return
    result = submit_wallet_request(wallet_url, offer_url, requires_haip=False)
    if result.completed or not result.retryable:
        state["submitted_synthetic_fapi_offer"] = True


def submit_browser_api_request(wallet_url: str, browser_request: dict, submit_url: str, requires_haip: bool = False, test_name: str | None = None) -> WalletSubmissionResult:
    extra_headers = {"X-OID4VC-Dev-Mode": wallet_mode_for(test_name, requires_haip)}
    if requires_haip:
        extra_headers["X-OID4VC-Dev-HAIP"] = "true"
    origin = browser_request_origin(browser_request)
    if not origin:
        origin = origin_from_submit_url(submit_url)
    if origin:
        extra_headers["Origin"] = origin

    for attempt in range(1, 6):
        try:
            result = wallet_request(wallet_url, "POST", "/api/dc-api", browser_request, extra_headers=extra_headers)
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if should_retry_wallet_submission(exc.code, body):
                if attempt < 5:
                    print(
                        f"[monitor] browser request not ready yet for {submit_url}: "
                        f"HTTP {exc.code}, retrying ({attempt}/5)",
                        flush=True,
                    )
                    time.sleep(0.4 * attempt)
                    continue
                print(
                    f"[monitor] browser request still not ready for {submit_url}: "
                    f"HTTP {exc.code}, deferring to next poll",
                    flush=True,
                )
                return WalletSubmissionResult(completed=False, retryable=True)
            print(f"[monitor] wallet rejected browser request for {submit_url}: HTTP {exc.code} {body}", flush=True)
            error_message = body.strip() or f"wallet request failed with HTTP {exc.code}"
            exception_payload = {
                "exception": {
                    "name": "NotAllowedError",
                    "message": error_message,
                }
            }
            req = urllib.request.Request(
                submit_url,
                data=json.dumps(exception_payload).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
                resp.read()
            print(f"[monitor] submitted Browser API exception to suite: {submit_url}", flush=True)
            return WalletSubmissionResult(completed=True, retryable=False)

    req = urllib.request.Request(
        submit_url,
        data=json.dumps(result).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=conformance_api_context()) as resp:
        resp.read()
    print(f"[monitor] submitted Browser API result to suite: {submit_url}", flush=True)
    return WalletSubmissionResult(completed=True, retryable=False)


def handle_module(base_url: str, token: str | None, wallet_url: str, module_id: str, state: dict) -> None:
    info = api_request(base_url, token, "GET", f"api/info/{module_id}")
    logs = api_request(base_url, token, "GET", f"api/log/{module_id}")

    for entry in logs:
        entry_base_url = entry.get("baseUrl")
        if isinstance(entry_base_url, str) and entry_base_url:
            state["base_url"] = entry_base_url
            break

    submit_synthetic_fapi_vci_offer(wallet_url, info, state)

    browser_entries = []
    browser = info.get("browser")
    if isinstance(browser, dict):
        browser_entries.extend(browser.get("browserApiRequests", []))

    pending_submit_url = None
    for entry in logs:
        browser_api_submit = entry.get("browser_api_submit")
        if isinstance(browser_api_submit, dict):
            submit_url = browser_api_submit.get("fullUrl")
            if isinstance(submit_url, str) and submit_url:
                pending_submit_url = submit_url

        if entry.get("msg") == "Calling browser API":
            browser_request = entry.get("request")
            if pending_submit_url and isinstance(browser_request, dict):
                browser_entries.append(
                    {
                        "submitUrl": pending_submit_url,
                        "request": copy.deepcopy(browser_request),
                    }
                )
                pending_submit_url = None

    for entry in browser_entries:
        submit_url = entry.get("submitUrl")
        browser_request = entry.get("request")
        if submit_url and browser_request and submit_url not in state["submitted_browser_api_requests"]:
            result = submit_browser_api_request(wallet_url, browser_request, submit_url, state.get("requires_haip", False), state.get("test_name"))
            if result.completed or not result.retryable:
                state["submitted_browser_api_requests"].add(submit_url)

    for entry in logs:
        request_url = entry.get("redirect_to") or entry.get("credential_offer_redirect_url")
        if request_url and request_url not in state["submitted_urls"]:
            result = submit_wallet_request(wallet_url, request_url, state.get("requires_haip", False), state.get("test_name"))
            if result.completed or not result.retryable:
                state["submitted_urls"].add(request_url)

        placeholder = entry.get("upload")
        if placeholder and placeholder not in state["uploaded_placeholders"]:
            state["uploaded_placeholders"].add(placeholder)
            upload_placeholder(base_url, token, module_id, placeholder)

    status = info.get("status", "")
    if status in TERMINAL_STATES:
        state["terminal"] = True


def main() -> int:
    args = parse_args()
    suite_dir = Path(args.suite_dir)
    results_dir = Path(args.results_dir)
    runner_log = Path(args.runner_log)
    runner_path = suite_dir / "scripts" / "run-test-plan.py"

    base_url = os.environ["CONFORMANCE_SERVER"]
    token = os.environ.get("CONFORMANCE_TOKEN")

    verify_suite_support(suite_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    materials = fetch_wallet_materials(args.wallet_url, args.wallet_issuer_url, Path(args.wallet_ca_cert))
    baseline_ids = baseline_credential_ids(args.wallet_url)
    scenarios = final_scenarios()
    config_jobs = [(scenario, create_config(args, suite_dir, results_dir, scenario, materials)) for scenario in scenarios]
    config_variants = {config_path.name: scenario.variant for scenario, config_path in config_jobs}

    print("[runner] detected OIDF Final wallet plans in the extracted suite", flush=True)
    for scenario, config_path in config_jobs:
        print(f"[runner] scheduled {scenario_plan_arg(scenario)} using {config_path.name}", flush=True)

    cmd = official_runner_args(runner_path, results_dir, config_jobs, args.rerun)
    proc = subprocess.Popen(
        cmd,
        cwd=suite_dir / "scripts",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    line_queue: queue.Queue[str] = queue.Queue()
    thread = threading.Thread(target=reader_thread, args=(proc.stdout, line_queue), daemon=True)
    thread.start()

    module_state: dict[str, dict] = {}
    plan_urls: list[str] = []
    pending_module_requires_haip = False
    pending_module_context: dict = {}
    current_plan_variant: dict = {}
    idle_timeout = int(os.environ.get("OIDF_MODULE_IDLE_TIMEOUT", str(DEFAULT_MODULE_IDLE_TIMEOUT)))
    last_runner_output = time.monotonic()

    with runner_log.open("w") as log_file:
        while True:
            try:
                while True:
                    line = line_queue.get_nowait()
                    last_runner_output = time.monotonic()
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    log_file.write(line)
                    log_file.flush()
                    if line.startswith("20") and "Running test module:" in line:
                        pending_module_requires_haip = "haip" in line.lower()
                        pending_module_context = parse_running_module_line(line)
                        pending_module_context["variant"] = merge_variants(
                            current_plan_variant,
                            pending_module_context.get("variant"),
                        )
                    plan_config_match = RUNNING_PLAN_CONFIG_RE.search(line)
                    if plan_config_match:
                        config_name = Path(plan_config_match.group(1)).name
                        current_plan_variant = config_variants.get(config_name, {})
                    match = MODULE_ID_RE.search(line)
                    if match:
                        module_id = match.group(1)
                        if module_id not in module_state:
                            removed = purge_issued_credentials(args.wallet_url, baseline_ids)
                            if removed:
                                print(
                                    f"[monitor] cleared {removed} credential(s) issued by earlier "
                                    f"modules before {module_id}",
                                    flush=True,
                                )
                        module_state.setdefault(
                            module_id,
                            {
                                "submitted_urls": set(),
                                "submitted_browser_api_requests": set(),
                                "uploaded_placeholders": set(),
                                "terminal": False,
                                "requires_haip": pending_module_requires_haip,
                                "submitted_synthetic_fapi_offer": False,
                                "logged_synthetic_fapi_skip": False,
                                "test_name": pending_module_context.get("test_name"),
                                "variant": pending_module_context.get("variant", {}),
                            },
                        )
                        pending_module_requires_haip = False
                        pending_module_context = {}
                    plan_match = PLAN_URL_RE.search(line)
                    if plan_match:
                        plan_url = plan_match.group(1)
                        if plan_url not in plan_urls:
                            plan_urls.append(plan_url)
            except queue.Empty:
                pass

            for module_id, state in module_state.items():
                if state["terminal"]:
                    continue
                try:
                    handle_module(base_url, token, args.wallet_url, module_id, state)
                except Exception as exc:  # noqa: BLE001
                    print(f"[monitor] failed to monitor module {module_id}: {exc}", flush=True)

            if proc.poll() is not None and line_queue.empty() and not thread.is_alive():
                break

            if proc.poll() is None and idle_timeout > 0 and time.monotonic() - last_runner_output > idle_timeout:
                active_modules = [module_id for module_id, state in module_state.items() if not state["terminal"]]
                active = ", ".join(active_modules) if active_modules else "unknown"
                print(
                    f"[monitor] no run-test-plan output for {idle_timeout}s; "
                    f"terminating stuck conformance run. Active modules: {active}",
                    flush=True,
                )
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                return 124

            time.sleep(POLL_INTERVAL)

    if plan_urls:
        print("[runner] OIDF plan URLs:", flush=True)
        for plan_url in plan_urls:
            print(f"[runner]   {plan_url}", flush=True)

    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
