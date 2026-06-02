import unittest

import pandas as pd

from src.label import add_labels


class LabelRuleTests(unittest.TestCase):
    def test_s3_missing_any_core_control_is_misconfigured(self):
        df = pd.DataFrame([
            {
                "resource_type": "s3",
                "encryption_enabled": 0,
                "versioning_enabled": 1,
                "logging_enabled": 1,
                "public_access_enabled": 0,
            },
            {
                "resource_type": "s3",
                "encryption_enabled": 1,
                "versioning_enabled": 1,
                "logging_enabled": 1,
                "public_access_enabled": 0,
            },
        ])

        labeled = add_labels(df)

        self.assertEqual(labeled.loc[0, "label"], 1)
        self.assertEqual(labeled.loc[1, "label"], 0)

    def test_iam_unconditioned_wildcard_resource_is_misconfigured(self):
        df = pd.DataFrame([
            {
                "resource_type": "iam",
                "has_wildcard_permission": 0,
                "has_admin_privilege": 0,
                "has_priv_esc_potential": 0,
                "dangerous_service_wildcard": 0,
                "has_no_condition": 1,
                "allow_wildcard_resource": 1,
            }
        ])

        labeled = add_labels(df)

        self.assertEqual(labeled.loc[0, "label"], 1)

    def test_security_group_public_ingress_is_misconfigured(self):
        df = pd.DataFrame([
            {
                "resource_type": "security_group",
                "open_ports_to_world": 1,
                "inbound_rule_count": 1,
            },
            {
                "resource_type": "security_group",
                "open_ports_to_world": 0,
                "inbound_rule_count": 1,
            },
        ])

        labeled = add_labels(df)

        self.assertEqual(labeled.loc[0, "label"], 1)
        self.assertEqual(labeled.loc[1, "label"], 0)


if __name__ == "__main__":
    unittest.main()
