#!/usr/bin/env python3
"""Configures the verifier's oid4vp identity provider with the wallet's URLs.

Sets `walletScheme` to the wallet's /authorize endpoint (so Keycloak's login
page links straight to the wallet web URL instead of a custom scheme) and
points `trustListUrl` at the wallet — both derived from WALLET_BASE_URL, so
port overrides keep working with the statically imported realm.
"""
import sys
import urllib.parse

import oid4vp_demo as demo


def main():
    status, token_response = demo.http_json(
        f"{demo.KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": demo.KEYCLOAK_ADMIN_USER,
            "password": demo.KEYCLOAK_ADMIN_PASSWORD,
        },
    )
    if status != 200:
        raise demo.DemoError(f"Admin token request failed ({status}): {token_response}")
    auth = {"Authorization": f"Bearer {token_response['access_token']}"}

    idp_url = f"{demo.KEYCLOAK_BASE_URL}/admin/realms/{demo.VERIFIER_REALM}/identity-provider/instances/oid4vp"
    status, idp = demo.http_json(idp_url, headers=auth)
    if status != 200:
        raise demo.DemoError(f"Loading the oid4vp identity provider failed ({status}): {idp}")

    wallet_base = demo.WALLET_BASE_URL.rstrip("/")
    idp["config"]["walletScheme"] = f"{wallet_base}/authorize"
    idp["config"]["trustListUrl"] = f"{wallet_base}/api/trustlist"

    status, result = demo.http_json(idp_url, json_data=idp, headers=auth, method="PUT")
    if status not in (200, 204):
        raise demo.DemoError(f"Updating the oid4vp identity provider failed ({status}): {result}")
    print(f"walletScheme  = {idp['config']['walletScheme']}")
    print(f"trustListUrl  = {idp['config']['trustListUrl']}")


if __name__ == "__main__":
    try:
        main()
    except demo.DemoError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
