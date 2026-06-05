import unittest

from oidf_wallet_conformance import PlanScenario, scenario_plan_arg


class ScenarioPlanArgTests(unittest.TestCase):
    def test_final_signed_direct_post_omits_inapplicable_modules(self):
        scenario = PlanScenario(
            slug="vp-final-sdjwt-signed-direct-post",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post",
            },
            credential_kind="sdjwt",
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn(":oid4vp-1final-wallet-happy-flow", plan_arg)
        self.assertIn("oid4vp-1final-wallet-request-uri-method-post", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-alternate-happy-flow", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-negative-test-response-uri-not-client-id", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-multisigned-one-invalid-signature", plan_arg)

    def test_final_redirect_uri_direct_post_keeps_applicable_response_uri_negative_test(self):
        scenario = PlanScenario(
            slug="vp-final-sdjwt-unsigned-direct-post",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "redirect_uri",
                "request_method": "request_uri_unsigned",
                "response_mode": "direct_post",
            },
            credential_kind="sdjwt",
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn("oid4vp-1final-wallet-negative-test-response-uri-not-client-id", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-negative-test-invalid-request-object-signature", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-multisigned-one-invalid-signature", plan_arg)

    def test_haip_dc_api_omits_web_origin_invalid_prefix_suite_bug(self):
        scenario = PlanScenario(
            slug="vp-haip-sdjwt-dc-api-jwt",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-haip-test-plan",
            variant={
                "credential_format": "sd_jwt_vc",
                "response_mode": "dc_api.jwt",
            },
            credential_kind="sdjwt",
            requires_haip=True,
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn(":oid4vp-1final-wallet-happy-flow", plan_arg)
        self.assertIn("oid4vp-1final-wallet-multisigned-one-invalid-signature", plan_arg)
        self.assertNotIn("oid4vp-1final-wallet-negative-test-invalid-client-id-prefix", plan_arg)


if __name__ == "__main__":
    unittest.main()
