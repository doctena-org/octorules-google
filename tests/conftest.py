"""Shared fixtures for octorules-google tests."""

from unittest.mock import MagicMock

import pytest
from google.cloud import compute_v1


@pytest.fixture
def mock_armor_client():
    """Create a mock SecurityPoliciesClient."""
    return MagicMock(spec=compute_v1.SecurityPoliciesClient)


@pytest.fixture
def security_policy():
    """A sample security policy dict with one rule of each phase type."""
    return {
        "name": "my-policy",
        "id": "123456789",
        "rules": [
            {
                "priority": 100,
                "action": "deny(403)",
                "match": {
                    "config": {"src_ip_ranges": ["1.2.3.0/24"]},
                    "versioned_expr": "SRC_IPS_V1",
                },
                "description": "Block bad IPs",
                "preview": False,
            },
            {
                "priority": 200,
                "action": "throttle",
                "match": {
                    "expr": {"expression": "true"},
                },
                "description": "Rate limit all traffic",
                "rate_limit_options": {
                    "conform_action": "allow",
                    "exceed_action": "deny-429",
                    "rate_limit_threshold": {"count": 1000, "interval_sec": 60},
                },
                "preview": False,
            },
            {
                "priority": 300,
                "action": "deny(403)",
                "match": {
                    "expr": {
                        "expression": "evaluatePreconfiguredWaf('xss-v33-stable')",
                    },
                },
                "description": "Block XSS",
                "preview": False,
            },
            {
                "priority": 400,
                "action": "redirect",
                "match": {
                    "expr": {"expression": "true"},
                },
                "description": "reCAPTCHA challenge",
                "redirect_options": {
                    "type": "GOOGLE_RECAPTCHA",
                },
                "preview": False,
            },
            {
                "priority": 2147483647,
                "action": "allow",
                "match": {"config": {"src_ip_ranges": ["*"]}, "versioned_expr": "SRC_IPS_V1"},
                "description": "Default rule",
            },
        ],
    }
