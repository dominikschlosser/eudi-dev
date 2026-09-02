import unittest
from unittest import mock

import oidf_wallet_conformance as oidf
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
        # unencrypted response mode: no encryption key to test against
        self.assertNotIn("oid4vp-1final-wallet-ignores-unusable-encryption-key", plan_arg)
        self.assertIn("oid4vp-1final-wallet-negative-test-invalid-client-id-prefix", plan_arg)

    def test_haip_plans_run_complete(self):
        # The certifiable HAIP plans carry no module filter: the suite's plan
        # definition decides what runs, and a certification run covers the
        # whole plan.
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
        self.assertEqual(
            plan_arg,
            "oid4vp-1final-wallet-haip-test-plan[credential_format=sd_jwt_vc][response_mode=dc_api.jwt]",
        )

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

    def test_final_direct_post_jwt_includes_unusable_encryption_key_module(self):
        scenario = PlanScenario(
            slug="vp-final-sdjwt-signed-direct-post-jwt",
            kind="vp",
            template_relpath="unused.json",
            plan_name="oid4vp-1final-wallet-test-plan",
            variant={
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "x509_hash",
                "request_method": "request_uri_signed",
                "response_mode": "direct_post.jwt",
            },
            credential_kind="sdjwt",
        )

        plan_arg = scenario_plan_arg(scenario)

        self.assertIn("oid4vp-1final-wallet-ignores-unusable-encryption-key", plan_arg)


if __name__ == "__main__":
    unittest.main()


class PurgeIssuedCredentialsTests(unittest.TestCase):
    """One wallet serves every plan, so credentials an issuance plan deposits
    are still present when a presentation plan runs. Only the baseline the
    wallet was started with chains to the CA the plans trust."""

    def _run(self, listed, baseline):
        deleted = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_list(wallet_url, method, path, *args, **kwargs):
            self.assertEqual((method, path), ("GET", "/api/credentials"))
            return listed

        def fake_urlopen(req, timeout=None):
            self.assertEqual(req.get_method(), "DELETE")
            deleted.append(req.full_url.rsplit("/", 1)[-1])
            return FakeResponse()

        with mock.patch.object(oidf, "wallet_request", fake_list), mock.patch.object(
            oidf.urllib.request, "urlopen", fake_urlopen
        ):
            removed = oidf.purge_issued_credentials("http://wallet.test", baseline)
        return removed, deleted

    def test_keeps_the_baseline_and_removes_what_the_suite_issued(self):
        listed = [{"id": "base-sdjwt"}, {"id": "base-mdoc"}, {"id": "suite-1"}, {"id": "suite-2"}]

        removed, deleted = self._run(listed, {"base-sdjwt", "base-mdoc"})

        self.assertEqual(removed, 2)
        self.assertEqual(sorted(deleted), ["suite-1", "suite-2"])

    def test_a_clean_wallet_is_left_alone(self):
        listed = [{"id": "base-sdjwt"}]

        removed, deleted = self._run(listed, {"base-sdjwt"})

        self.assertEqual(removed, 0)
        self.assertEqual(deleted, [])
