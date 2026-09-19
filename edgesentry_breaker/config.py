"""Configuration and safety guardrails for EdgeSentryBreaker."""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


class GuardrailViolationError(Exception):
    """Raised when safety guardrails prevent execution."""
    pass


@dataclass
class Config:
    """Execution configuration."""
    target_url: str = "http://127.0.0.1:8080/v1/detect"
    timeout: float = 5.0
    delay_scale: float = 1.0  # multiplier for sleep intervals (e.g. 0.05 for fast testing)
    results_dir: str = "results"
    force_unsafe_target: bool = False
    allow_non_test_accounts: bool = False

    def __post_init__(self):
        if self.target_url == "mock":
            self.target_url = "mock://local/v1/detect"

    def is_mock(self) -> bool:
        return self.target_url.startswith("mock://")

    def validate_target(self) -> None:
        """Enforces Section 7 guardrail 1: local/staging targets only."""
        if self.is_mock() or self.force_unsafe_target:
            return

        parsed = urlparse(self.target_url)
        hostname = parsed.hostname

        if not hostname:
            raise GuardrailViolationError(f"Invalid target URL: '{self.target_url}' (no hostname found)")

        # Local hostnames
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "testserver"):
            return

        # Check if it's a private RFC1918 / loopback IP
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_loopback or ip_obj.is_private:
                return
        except ValueError:
            pass

        raise GuardrailViolationError(
            f"Safety Guardrail Blocked: Target host '{hostname}' is not a local or private address.\n"
            f"EdgeSentryBreaker is restricted to local/staging environments (127.0.0.1).\n"
            f"To bypass this guardrail explicitly for authorized targets, use --force-unsafe-target."
        )

    def validate_account_id(self, account_id: str) -> None:
        """Enforces Section 7 guardrail 2: test-only accounts."""
        if self.allow_non_test_accounts:
            return

        # Test account patterns: test_*, mock_*, *@*.example.com, *@example.org, *@test.local, etc.
        test_patterns = [
            r"^test_",
            r"^mock_",
            r"^dummy_",
            r".*@.*example\.(com|org|net)$",
            r".*@.*test\.(local|internal)$",
        ]

        if not any(re.search(pattern, account_id, re.IGNORECASE) for pattern in test_patterns):
            raise GuardrailViolationError(
                f"Safety Guardrail Blocked: Account ID '{account_id}' does not match test patterns.\n"
                f"Only test-designated accounts (e.g., test_user@example.com) are permitted.\n"
                f"To bypass, specify --allow-non-test-accounts."
            )
