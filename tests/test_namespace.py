"""Tests for octorules-google namespace registration and nested zone format.

Verifies that the google namespace is properly registered with octorules
and that zone files can be written in both nested and flat formats.
"""

import pytest

import octorules_google  # noqa: F401 - triggers namespace registration
from octorules.config import normalize_zone_format
from octorules.phases import PROVIDER_NAMESPACES


class TestGoogleNamespace:
    """Tests for the google provider namespace."""

    def test_namespace_is_registered(self):
        """Verify the google namespace is registered in PROVIDER_NAMESPACES."""
        assert "google" in PROVIDER_NAMESPACES

    def test_namespace_contains_all_keys(self):
        """Verify the google namespace maps all Cloud Armor sections."""
        expected = {
            "custom_rules": "gcloud_armor_custom_rules",
            "rate_rules": "gcloud_armor_rate_rules",
            "preconfigured_rules": "gcloud_armor_preconfigured_rules",
            "redirect_rules": "gcloud_armor_redirect_rules",
            "policy_settings": "gcloud_armor_policy_settings",
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
            "gcloud_armor_custom_rules": [{"ref": "100", "action": "allow"}],
            "gcloud_armor_rate_rules": [{"ref": "1000", "action": "throttle"}],
            "gcloud_armor_preconfigured_rules": [{"ref": "2000", "action": "deny(403)"}],
            "gcloud_armor_redirect_rules": [{"ref": "3000", "action": "redirect"}],
            "gcloud_armor_policy_settings": {
                "ddosProtectionConfig": {"ddosProtection": "ADVANCED"}
            },
            "plan_outputs": [{"type": "text"}],
        }

    def test_flat_format_warns_but_works(self, caplog):
        """Verify flat spelling still works but emits a deprecation warning."""
        flat_data = {
            "gcloud_armor_custom_rules": [{"ref": "100", "action": "allow"}],
        }
        with caplog.at_level("WARNING", logger="octorules.config"):
            result = normalize_zone_format(flat_data, source="zone.yaml")

        # Flat format passes through unchanged
        assert result is flat_data
        # But a deprecation warning was issued
        assert "deprecated flat spelling" in caplog.text
        assert "google:" in caplog.text

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

        assert "gcloud_armor_custom_rules" in result
        assert "lists" in result
        assert "custom_rulesets" in result
        assert result["lists"] == [{"name": "ip_list"}]
        assert result["custom_rulesets"] == [{"name": "rs1"}]
