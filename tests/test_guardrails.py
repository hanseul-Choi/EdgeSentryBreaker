"""Unit tests for safety guardrails."""

import unittest
from edgesentry_breaker.config import Config, GuardrailViolationError


class TestGuardrails(unittest.TestCase):
    def test_local_targets_allowed(self):
        valid_targets = [
            "http://127.0.0.1:8080/v1/detect",
            "http://localhost:8080/v1/detect",
            "http://0.0.0.0:8000/v1/detect",
            "http://192.168.1.10:8080/v1/detect",
            "http://10.0.0.5:8080/v1/detect",
        ]
        for target in valid_targets:
            config = Config(target_url=target)
            config.validate_target()  # should not raise

    def test_external_target_blocked(self):
        external_targets = [
            "https://production.example.com/v1/detect",
            "http://8.8.8.8/v1/detect",
            "https://auth.company.corp/v1/detect",
        ]
        for target in external_targets:
            config = Config(target_url=target)
            with self.assertRaises(GuardrailViolationError):
                config.validate_target()

    def test_force_unsafe_target_override(self):
        config = Config(
            target_url="https://production.example.com/v1/detect",
            force_unsafe_target=True,
        )
        config.validate_target()  # should not raise when forced

    def test_test_account_patterns(self):
        valid_accounts = [
            "test_user@example.com",
            "mock_user@example.org",
            "dummy_admin@sub.example.com",
            "test_123@test.local",
            "test_velocity_1@example.com",
        ]
        config = Config()
        for acct in valid_accounts:
            config.validate_account_id(acct)  # should not raise

    def test_non_test_account_blocked(self):
        invalid_accounts = [
            "real_ceo@google.com",
            "alice@bank.com",
            "admin@production.net",
        ]
        config = Config()
        for acct in invalid_accounts:
            with self.assertRaises(GuardrailViolationError):
                config.validate_account_id(acct)

    def test_allow_non_test_accounts_override(self):
        config = Config(allow_non_test_accounts=True)
        config.validate_account_id("real_ceo@google.com")  # should not raise


if __name__ == "__main__":
    unittest.main()
