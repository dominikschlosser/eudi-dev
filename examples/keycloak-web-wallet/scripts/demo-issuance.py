#!/usr/bin/env python3
"""URI-based issuance demo.

Creates a pre-authorized credential offer in Keycloak and delivers it to the
wallet's credential offer endpoint as a plain web URL — the same query
parameters an openid-credential-offer:// link would carry, no custom URL
scheme involved.
"""
import sys

import oid4vp_demo as demo


MEMBERSHIP_VCT = "https://credentials.example.com/membership"


def main():
    # Repeated demo runs would otherwise pile up membership credentials.
    removed = demo.delete_credentials_by_vct(MEMBERSHIP_VCT)
    if removed:
        print(f"0. Removed {removed} membership credential(s) from earlier runs")

    print(f"1. Creating a pre-authorized credential offer in {demo.KEYCLOAK_BASE_URL}/realms/{demo.ISSUER_REALM}")
    credential_offer = demo.create_credential_offer()

    # This is the whole point of the example: instead of building
    #   openid-credential-offer://?credential_offer=<offer>
    # the same query parameters go straight to the wallet's own URL.
    wallet_url = demo.offer_wallet_url(credential_offer)
    print("2. Invoking the wallet by URL:")
    print(f"   GET {wallet_url[:120]}...")
    # The wallet runs interactively (no --auto-accept), so it waits for
    # consent; the helper approves it via the consent API, as the user
    # would in the wallet UI.
    status, result = demo.invoke_wallet_interactively(lambda: demo.http_json(wallet_url))
    if status != 200:
        raise demo.DemoError(f"Wallet invocation failed ({status}): {result}")
    print("   Consent approved via the wallet's consent API.")
    print(f"   Wallet imported: format={result.get('format')} issuer={result.get('issuer')}")

    print("3. Credentials stored in the wallet:")
    credentials = demo.wallet_credentials()
    for credential in credentials:
        label = credential.get("vct") or credential.get("doctype") or credential.get("id")
        print(f"   - [{credential.get('format')}] {label}")

    if not any(c.get("vct") == MEMBERSHIP_VCT for c in credentials):
        raise demo.DemoError("Expected the membership credential to be stored in the wallet.")
    print()
    print("Success: credential issued via wallet URL, no custom scheme involved.")


if __name__ == "__main__":
    try:
        main()
    except demo.DemoError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
