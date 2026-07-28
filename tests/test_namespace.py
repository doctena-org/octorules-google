"""Tests for octorules-google namespace registration and nested zone format.

Verifies that the google namespace is properly registered with octorules
and that zone files can be written in both nested and flat formats.
"""

from octorules.config import normalize_zone_format
from octorules.phases import PROVIDER_NAMESPACES

import octorules_google  # noqa: F401 - triggers namespace registration


class TestGoogleNamespace:
    """Tests for the google provider namespace."""

    def test_namespace_is_registered(self):
        """Verify the google namespace is registered in PROVIDER_NAMESPACES."""
        assert "google" in PROVIDER_NAMESPACES

    def test_namespace_contains_all_keys(self):
        """Verify the google namespace maps all Cloud Armor sections."""
        expected = {
            "custom_rules": "google.custom_rules",
            "rate_rules": "google.rate_rules",
            "preconfigured_rules": "google.preconfigured_rules",
            "redirect_rules": "google.redirect_rules",
            "policy_settings": "google.policy_settings",
        }
        assert PROVIDER_NAMESPACES["google"] == expected

    def test_nested_format_flattens_correctly(self):
        """Verify nested google: block flattens to canonical keys."""
        nested_data = {
            "google": {
                "custom_rules": [{"ref": "100", "action": "allow"}],
                "rate_rules": [{"ref": "1000", "action": "throttle"}],
                "preconfigured_rules": [{"ref": "2000", "action": "deny(403)"}],
                "redirect_rules": [{"ref": "3000", "action": "redirect"}],
                "policy_settings": {"ddosProtectionConfig": {"ddosProtection": "ADVANCED"}},
            },
            "plan_outputs": [{"type": "text"}],
        }
        result = normalize_zone_format(nested_data, source="zone.yaml")

        # Verify flattened structure
        assert result == {
            "google.custom_rules": [{"ref": "100", "action": "allow"}],
            "google.rate_rules": [{"ref": "1000", "action": "throttle"}],
            "google.preconfigured_rules": [{"ref": "2000", "action": "deny(403)"}],
            "google.redirect_rules": [{"ref": "3000", "action": "redirect"}],
            "google.policy_settings": {"ddosProtectionConfig": {"ddosProtection": "ADVANCED"}},
            "plan_outputs": [{"type": "text"}],
        }

    def test_namespace_with_lists_and_rulesets(self):
        """Verify lists and custom_rulesets work inside google: block."""
        nested_data = {
            "google": {
                "custom_rules": [{"ref": "100", "action": "allow"}],
                "lists": [{"name": "ip_list"}],
                "custom_rulesets": [{"name": "rs1"}],
            },
        }
        result = normalize_zone_format(nested_data, source="zone.yaml")

        assert "google.custom_rules" in result
        assert "lists" in result
        assert "custom_rulesets" in result
        assert result["lists"] == [{"name": "ip_list"}]
        assert result["custom_rulesets"] == [{"name": "rs1"}]
