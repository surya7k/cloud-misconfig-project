import unittest

from src.aws_translator import translate


class AwsTranslatorTests(unittest.TestCase):
    def test_translates_get_policy_version_document(self):
        payload = {
            "PolicyVersion": {
                "VersionId": "v1",
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ],
                },
            }
        }

        config, detected = translate(payload)

        self.assertEqual(detected, "iam")
        self.assertEqual(config["resource_type"], "iam")
        self.assertEqual(config["resource_name"], "custom-v1")
        self.assertEqual(config["policy"]["Statement"][0]["Resource"], "*")

    def test_translates_security_group_with_world_and_internal_rules(self):
        payload = {
            "SecurityGroups": [
                {
                    "GroupName": "web-sg",
                    "IpPermissions": [
                        {
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                        {
                            "FromPort": 8080,
                            "ToPort": 8080,
                            "IpProtocol": "tcp",
                            "UserIdGroupPairs": [{"GroupId": "sg-internal"}],
                        },
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        }

        config, detected = translate(payload)

        self.assertEqual(detected, "sg")
        self.assertEqual(config["resource_type"], "security_group")
        self.assertEqual(len(config["inbound_rules"]), 2)
        self.assertEqual(config["inbound_rules"][0]["cidr"], "0.0.0.0/0")
        self.assertEqual(config["inbound_rules"][1]["cidr"], "sg-internal")

    def test_translates_s3_bucket_security_signals(self):
        payload = {
            "BucketName": "secure-bucket",
            "Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{}]}},
            "Versioning": {"Status": "Enabled", "MFADelete": "Enabled"},
            "Logging": {"LoggingEnabled": {"TargetBucket": "logs"}},
            "PublicAccessBlock": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Condition": {
                            "Bool": {"aws:SecureTransport": "false"}
                        },
                    }
                ]
            },
        }

        config, detected = translate(payload)

        self.assertEqual(detected, "s3")
        self.assertEqual(config["resource_type"], "s3")
        self.assertEqual(config["encryption_enabled"], 1)
        self.assertEqual(config["versioning_enabled"], 1)
        self.assertEqual(config["logging_enabled"], 1)
        self.assertEqual(config["mfa_delete_enabled"], 1)
        self.assertEqual(config["tls_enforced"], 1)
        self.assertEqual(config["public_access_enabled"], 0)


if __name__ == "__main__":
    unittest.main()
