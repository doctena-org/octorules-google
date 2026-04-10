"""Tests for the Google Cloud Armor provider."""

from unittest.mock import MagicMock, patch

import pytest
from google.api_core.exceptions import (
    Forbidden,
    GoogleAPIError,
    NotFound,
    ServiceUnavailable,
    Unauthorized,
)
from google.auth.exceptions import DefaultCredentialsError
from octorules.config import ConfigError
from octorules.provider.base import BaseProvider, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderConnectionError, ProviderError

from octorules_google import CloudArmorProvider


def _zs(zone_id: str = "my-policy", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


class TestBaseProviderProtocol:
    def test_satisfies_protocol(self, mock_armor_client):
        instance = CloudArmorProvider(client=mock_armor_client, project="test")
        assert isinstance(instance, BaseProvider)


class TestProperties:
    def test_max_workers(self, mock_armor_client):
        provider = CloudArmorProvider(max_workers=4, client=mock_armor_client, project="p")
        assert provider.max_workers == 4

    def test_account_id_is_none(self, mock_armor_client):
        """Cloud Armor has no account-level scopes."""
        provider = CloudArmorProvider(client=mock_armor_client, project="my-proj")
        assert provider.account_id is None

    def test_account_name_is_none(self, mock_armor_client):
        """Cloud Armor has no account-level scopes."""
        provider = CloudArmorProvider(client=mock_armor_client, project="my-proj")
        assert provider.account_name is None

    def test_zone_plans_empty_before_resolve(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.zone_plans == {}


class TestResolveZoneId:
    def test_found(self, mock_armor_client):
        mock_armor_client.get.return_value = {"name": "my-policy"}
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        result = provider.resolve_zone_id("my-policy")
        assert result == "my-policy"

    def test_not_found(self, mock_armor_client):
        mock_armor_client.get.side_effect = NotFound("not found")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(Exception, match="No security policy found"):
            provider.resolve_zone_id("missing-policy")


class TestDetectTier:
    """Unit tests for the _detect_tier heuristic."""

    def test_no_ddos_config_is_standard(self):
        from octorules_google.provider import _detect_tier

        assert _detect_tier({}) == "standard"

    def test_none_ddos_config_is_standard(self):
        from octorules_google.provider import _detect_tier

        assert _detect_tier({"ddos_protection_config": None}) == "standard"

    def test_empty_ddos_config_is_standard(self):
        from octorules_google.provider import _detect_tier

        assert _detect_tier({"ddos_protection_config": {}}) == "standard"

    def test_non_advanced_ddos_is_standard(self):
        from octorules_google.provider import _detect_tier

        policy = {"ddos_protection_config": {"ddos_protection": "STANDARD"}}
        assert _detect_tier(policy) == "standard"

    def test_advanced_without_premium_visibility_is_plus(self):
        from octorules_google.provider import _detect_tier

        policy = {"ddos_protection_config": {"ddos_protection": "ADVANCED"}}
        assert _detect_tier(policy) == "plus"

    def test_advanced_preview_is_plus(self):
        from octorules_google.provider import _detect_tier

        policy = {"ddos_protection_config": {"ddos_protection": "ADVANCED_PREVIEW"}}
        assert _detect_tier(policy) == "plus"

    def test_advanced_with_premium_visibility_is_enterprise(self):
        from octorules_google.provider import _detect_tier

        policy = {
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "adaptive_protection_config": {
                "layer7_ddos_defense_config": {"rule_visibility": "PREMIUM"},
            },
        }
        assert _detect_tier(policy) == "enterprise"

    def test_advanced_preview_with_premium_visibility_is_enterprise(self):
        from octorules_google.provider import _detect_tier

        policy = {
            "ddos_protection_config": {"ddos_protection": "ADVANCED_PREVIEW"},
            "adaptive_protection_config": {
                "layer7_ddos_defense_config": {"rule_visibility": "PREMIUM"},
            },
        }
        assert _detect_tier(policy) == "enterprise"

    def test_advanced_with_non_premium_visibility_is_plus(self):
        from octorules_google.provider import _detect_tier

        policy = {
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "adaptive_protection_config": {
                "layer7_ddos_defense_config": {"rule_visibility": "STANDARD"},
            },
        }
        assert _detect_tier(policy) == "plus"

    def test_advanced_with_missing_adaptive_config_is_plus(self):
        from octorules_google.provider import _detect_tier

        policy = {
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "adaptive_protection_config": None,
        }
        assert _detect_tier(policy) == "plus"

    def test_advanced_with_empty_layer7_config_is_plus(self):
        from octorules_google.provider import _detect_tier

        policy = {
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "adaptive_protection_config": {"layer7_ddos_defense_config": None},
        }
        assert _detect_tier(policy) == "plus"


class TestResolveZoneIdTierDetection:
    """Tests that resolve_zone_id populates zone_plans with detected tier."""

    def test_detects_standard_tier(self, mock_armor_client):
        mock_armor_client.get.return_value = {"name": "my-policy"}
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        assert provider.zone_plans == {"my-policy": "standard"}

    def test_detects_plus_tier(self, mock_armor_client):
        mock_armor_client.get.return_value = {
            "name": "my-policy",
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
        }
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        assert provider.zone_plans == {"my-policy": "plus"}

    def test_detects_enterprise_tier(self, mock_armor_client):
        mock_armor_client.get.return_value = {
            "name": "my-policy",
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "adaptive_protection_config": {
                "layer7_ddos_defense_config": {"rule_visibility": "PREMIUM"},
            },
        }
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        assert provider.zone_plans == {"my-policy": "enterprise"}

    def test_detects_tier_missing_fields(self, mock_armor_client):
        """Minimal response with no ddos config -> standard."""
        mock_armor_client.get.return_value = {"name": "minimal"}
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("minimal")
        assert provider.zone_plans == {"minimal": "standard"}

    def test_zone_plans_returns_copy(self, mock_armor_client):
        """zone_plans returns a copy, not the internal dict."""
        mock_armor_client.get.return_value = {"name": "my-policy"}
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        plans = provider.zone_plans
        plans["injected"] = "hacked"
        assert "injected" not in provider.zone_plans

    def test_multiple_zones_accumulated(self, mock_armor_client):
        """Multiple resolve_zone_id calls accumulate zone plans."""
        policies = {
            "standard-policy": {"name": "standard-policy"},
            "plus-policy": {
                "name": "plus-policy",
                "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            },
        }
        mock_armor_client.get.side_effect = lambda **kw: policies[kw["security_policy"]]
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("standard-policy")
        provider.resolve_zone_id("plus-policy")
        assert provider.zone_plans == {
            "standard-policy": "standard",
            "plus-policy": "plus",
        }


class TestGetPhaseRules:
    def _setup(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        return provider

    def test_custom_rules(self, mock_armor_client, security_policy):
        provider = self._setup(mock_armor_client, security_policy)
        rules = provider.get_phase_rules(_zs(), "gcloud_armor_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "100"
        assert rules[0]["action"] == "deny(403)"

    def test_rate_rules(self, mock_armor_client, security_policy):
        provider = self._setup(mock_armor_client, security_policy)
        rules = provider.get_phase_rules(_zs(), "gcloud_armor_rate")
        assert len(rules) == 1
        assert rules[0]["ref"] == "200"
        assert rules[0]["action"] == "throttle"

    def test_preconfigured_rules(self, mock_armor_client, security_policy):
        provider = self._setup(mock_armor_client, security_policy)
        rules = provider.get_phase_rules(_zs(), "gcloud_armor_preconfigured")
        assert len(rules) == 1
        assert rules[0]["ref"] == "300"

    def test_redirect_rules(self, mock_armor_client, security_policy):
        provider = self._setup(mock_armor_client, security_policy)
        rules = provider.get_phase_rules(_zs(), "gcloud_armor_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "400"
        assert rules[0]["action"] == "redirect"

    def test_default_rule_excluded(self, mock_armor_client, security_policy):
        provider = self._setup(mock_armor_client, security_policy)
        all_rules = (
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")
            + provider.get_phase_rules(_zs(), "gcloud_armor_rate")
            + provider.get_phase_rules(_zs(), "gcloud_armor_preconfigured")
            + provider.get_phase_rules(_zs(), "gcloud_armor_redirect")
        )
        refs = [r["ref"] for r in all_rules]
        assert "2147483647" not in refs

    def test_unknown_phase_returns_empty(self, mock_armor_client, security_policy):
        provider = self._setup(mock_armor_client, security_policy)
        assert provider.get_phase_rules(_zs(), "http_request_dynamic_redirect") == []

    def test_empty_policy(self, mock_armor_client):
        mock_armor_client.get.return_value = {"name": "empty", "rules": []}
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("empty")
        assert provider.get_phase_rules(_zs(zone_id="empty"), "gcloud_armor_custom") == []


class TestPutPhaseRules:
    def test_removes_old_adds_new(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")

        new_rules = [
            {
                "ref": "150",
                "action": "deny(403)",
                "match": {"expr": {"expression": "origin.region_code == 'XX'"}},
                "description": "New geo block",
            }
        ]
        count = provider.put_phase_rules(_zs(), "gcloud_armor_custom", new_rules)
        assert count == 1

        # Should have removed old custom rule (priority 100)
        mock_armor_client.remove_rule.assert_called_once()
        remove_kwargs = mock_armor_client.remove_rule.call_args[1]
        assert remove_kwargs["request"]["priority"] == 100

        # Should have added new rule
        mock_armor_client.add_rule.assert_called_once()
        add_kwargs = mock_armor_client.add_rule.call_args[1]
        assert add_kwargs["security_policy_rule_resource"]["priority"] == 150

    def test_preserves_other_phases(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")

        provider.put_phase_rules(_zs(), "gcloud_armor_custom", [])

        # Only custom rule (priority 100) removed; rate (200) and preconfigured (300) untouched
        assert mock_armor_client.remove_rule.call_count == 1
        assert mock_armor_client.add_rule.call_count == 0

    def test_returns_rule_count(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        count = provider.put_phase_rules(_zs(), "gcloud_armor_rate", [])
        assert count == 0

    def test_patches_in_place_when_priority_unchanged(self, mock_armor_client, security_policy):
        """Rules with the same priority are patched, not remove+add."""
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")

        # Same priority 100 as existing custom rule, but updated content
        updated = [
            {
                "ref": "100",
                "action": "deny(502)",
                "match": {"expr": {"expression": "origin.region_code == 'XX'"}},
                "description": "Updated",
            }
        ]
        count = provider.put_phase_rules(_zs(), "gcloud_armor_custom", updated)
        assert count == 1

        # Should patch (same priority), not remove+add
        mock_armor_client.patch_rule.assert_called_once()
        patch_kwargs = mock_armor_client.patch_rule.call_args[1]
        assert patch_kwargs["priority"] == 100
        mock_armor_client.add_rule.assert_not_called()
        mock_armor_client.remove_rule.assert_not_called()

    def test_add_before_remove_ordering(self, mock_armor_client, security_policy):
        """New priorities are added before old ones are removed."""
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")

        new_rules = [
            {"ref": "150", "action": "deny(403)", "match": {}, "description": "New"},
        ]
        provider.put_phase_rules(_zs(), "gcloud_armor_custom", new_rules)

        # add_rule called before remove_rule
        calls = mock_armor_client.method_calls
        add_idx = next(i for i, c in enumerate(calls) if c[0] == "add_rule")
        remove_idx = next(i for i, c in enumerate(calls) if c[0] == "remove_rule")
        assert add_idx < remove_idx


class TestGetAllPhaseRules:
    def test_all_phases(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        result = provider.get_all_phase_rules(_zs())
        assert "gcloud_armor_custom" in result
        assert "gcloud_armor_rate" in result
        assert "gcloud_armor_preconfigured" in result
        assert "gcloud_armor_redirect" in result
        assert result.failed_phases == []

    def test_filtered_phases(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        result = provider.get_all_phase_rules(_zs(), provider_ids=["gcloud_armor_rate"])
        assert "gcloud_armor_rate" in result
        assert "gcloud_armor_custom" not in result

    def test_ignores_non_gcloud_phases(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        result = provider.get_all_phase_rules(_zs(), provider_ids=["http_request_dynamic_redirect"])
        assert dict(result) == {}


class TestCustomRulesets:
    """Cloud Armor doesn't support custom rulesets."""

    def test_list_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.list_custom_rulesets(_zs()) == []

    def test_get_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.get_custom_ruleset(_zs(), "rs-1") == []

    def test_put_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.put_custom_ruleset(_zs(), "rs-1", [])

    def test_get_all_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.get_all_custom_rulesets(_zs()) == {}


class TestLists:
    """Cloud Armor doesn't support standalone lists."""

    def test_list_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.list_lists(_zs()) == []

    def test_create_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.create_list(_zs(), "blocklist", "ip")

    def test_delete_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.delete_list(_zs(), "ip-1")

    def test_update_description_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.update_list_description(_zs(), "ip-1", "new desc")

    def test_get_items_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.get_list_items(_zs(), "ip-1") == []

    def test_put_items_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.put_list_items(_zs(), "ip-1", [])

    def test_poll_returns_completed(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.poll_bulk_operation(_zs(), "op-123") == "completed"

    def test_get_all_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.get_all_lists(_zs()) == {}


class TestExceptionWrapping:
    def test_forbidden_becomes_provider_auth_error(self, mock_armor_client):
        mock_armor_client.get.side_effect = Forbidden("forbidden")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderAuthError):
            provider.resolve_zone_id("my-policy")

    def test_unauthorized_becomes_provider_auth_error(self, mock_armor_client):
        mock_armor_client.get.side_effect = Unauthorized("unauthorized")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderAuthError):
            provider.resolve_zone_id("my-policy")

    def test_default_credentials_becomes_auth_error(self, mock_armor_client):
        mock_armor_client.get.side_effect = DefaultCredentialsError("no creds")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderAuthError):
            provider.resolve_zone_id("my-policy")

    def test_google_api_error_becomes_provider_error(self, mock_armor_client):
        mock_armor_client.get.side_effect = GoogleAPIError("server error")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderError):
            provider.resolve_zone_id("my-policy")

    def test_connection_error_becomes_provider_connection_error(self, mock_armor_client):
        mock_armor_client.get.side_effect = ConnectionError("connection refused")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderConnectionError):
            provider.resolve_zone_id("my-policy")


class TestAuthErrors:
    """Auth-related errors during get_phase_rules are wrapped as ProviderAuthError."""

    def _setup_provider(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        return provider

    def test_get_phase_rules_unauthorized(self, mock_armor_client, security_policy):
        """Unauthorized during get_phase_rules → ProviderAuthError."""
        provider = self._setup_provider(mock_armor_client, security_policy)
        mock_armor_client.get.side_effect = Unauthorized("unauthorized")
        with pytest.raises(ProviderAuthError, match="unauthorized"):
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")

    def test_get_phase_rules_forbidden(self, mock_armor_client, security_policy):
        """Forbidden during get_phase_rules → ProviderAuthError."""
        provider = self._setup_provider(mock_armor_client, security_policy)
        mock_armor_client.get.side_effect = Forbidden("forbidden")
        with pytest.raises(ProviderAuthError, match="forbidden"):
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")

    def test_default_credentials_error(self, mock_armor_client, security_policy):
        """DefaultCredentialsError during get_phase_rules → ProviderAuthError."""
        provider = self._setup_provider(mock_armor_client, security_policy)
        mock_armor_client.get.side_effect = DefaultCredentialsError("no creds")
        with pytest.raises(ProviderAuthError, match="no creds"):
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")


class TestConnectionErrors:
    """Connection-related errors are wrapped as ProviderConnectionError."""

    def _setup_provider(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        return provider

    def test_connection_error(self, mock_armor_client, security_policy):
        """ConnectionError during get_phase_rules → ProviderConnectionError."""
        provider = self._setup_provider(mock_armor_client, security_policy)
        mock_armor_client.get.side_effect = ConnectionError("connection refused")
        with pytest.raises(ProviderConnectionError, match="connection refused"):
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")

    def test_os_error(self, mock_armor_client, security_policy):
        """OSError during get_phase_rules → ProviderConnectionError."""
        provider = self._setup_provider(mock_armor_client, security_policy)
        mock_armor_client.get.side_effect = OSError("network unreachable")
        with pytest.raises(ProviderConnectionError, match="network unreachable"):
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")


class TestGenericErrors:
    """Non-auth GoogleAPIError is wrapped as ProviderError (not ProviderAuthError)."""

    def _setup_provider(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        return provider

    def test_google_api_error(self, mock_armor_client, security_policy):
        """GoogleAPIError during get_phase_rules → ProviderError, not ProviderAuthError."""
        provider = self._setup_provider(mock_armor_client, security_policy)
        mock_armor_client.get.side_effect = GoogleAPIError("server error")
        with pytest.raises(ProviderError, match="server error") as exc_info:
            provider.get_phase_rules(_zs(), "gcloud_armor_custom")
        # Must NOT be a ProviderAuthError subclass
        assert type(exc_info.value) is ProviderError


class TestPartialFailure:
    """Partial failure during put_phase_rules: early changes persist."""

    @patch("octorules.retry.time.sleep")
    def test_put_phase_rules_partial_failure(self, _mock_sleep, mock_armor_client, security_policy):
        """First rule patches OK, second add fails → ProviderError, first change persists."""
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")

        # Keep priority 100 (patch) and add priority 500 (add).
        new_rules = [
            {
                "ref": "100",
                "action": "deny(502)",
                "match": {"expr": {"expression": "origin.region_code == 'XX'"}},
                "description": "Updated custom rule",
            },
            {
                "ref": "500",
                "action": "deny(403)",
                "match": {"expr": {"expression": "true"}},
                "description": "New rule that will fail",
            },
        ]

        # patch_rule succeeds for priority 100, add_rule fails for priority 500
        mock_armor_client.patch_rule.return_value = None
        mock_armor_client.add_rule.side_effect = GoogleAPIError("quota exceeded")

        with pytest.raises(ProviderError, match="quota exceeded"):
            provider.put_phase_rules(_zs(), "gcloud_armor_custom", new_rules)

        # The patch for priority 100 already went through before the add failed
        mock_armor_client.patch_rule.assert_called_once()
        assert mock_armor_client.patch_rule.call_args[1]["priority"] == 100

    @patch("octorules.retry.time.sleep")
    def test_put_phase_rules_logs_partial_failure(
        self, _mock_sleep, mock_armor_client, security_policy, caplog
    ):
        """Partial failure emits ERROR log with patched/added/removed details."""
        import logging

        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")

        new_rules = [
            {
                "ref": "100",
                "action": "deny(502)",
                "match": {"expr": {"expression": "true"}},
            },
            {
                "ref": "500",
                "action": "deny(403)",
                "match": {"expr": {"expression": "true"}},
            },
        ]
        mock_armor_client.patch_rule.return_value = None
        mock_armor_client.add_rule.side_effect = GoogleAPIError("quota exceeded")

        with caplog.at_level(logging.ERROR), pytest.raises(ProviderError):
            provider.put_phase_rules(_zs(), "gcloud_armor_custom", new_rules)

        assert "PARTIAL FAILURE" in caplog.text
        assert "gcloud_armor_custom" in caplog.text


class TestRuleClassification:
    def test_deny_is_custom(self):
        from octorules_google.provider import _classify_phase

        assert _classify_phase({"action": "deny(403)", "match": {}}) == "gcloud_armor_custom"

    def test_allow_is_custom(self):
        from octorules_google.provider import _classify_phase

        assert _classify_phase({"action": "allow", "match": {}}) == "gcloud_armor_custom"

    def test_throttle_is_rate(self):
        from octorules_google.provider import _classify_phase

        assert _classify_phase({"action": "throttle", "match": {}}) == "gcloud_armor_rate"

    def test_rate_based_ban_is_rate(self):
        from octorules_google.provider import _classify_phase

        assert _classify_phase({"action": "rate_based_ban", "match": {}}) == "gcloud_armor_rate"

    def test_redirect_is_redirect(self):
        from octorules_google.provider import _classify_phase

        assert _classify_phase({"action": "redirect", "match": {}}) == "gcloud_armor_redirect"

    def test_preconfigured_waf_detected(self):
        from octorules_google.provider import _classify_phase

        rule = {
            "action": "deny(403)",
            "match": {"expr": {"expression": "evaluatePreconfiguredWaf('xss-v33-stable')"}},
        }
        assert _classify_phase(rule) == "gcloud_armor_preconfigured"

    def test_preconfigured_expr_detected(self):
        from octorules_google.provider import _classify_phase

        rule = {
            "action": "deny(403)",
            "match": {"expr": {"expression": "evaluatePreconfiguredExpr('xss-stable')"}},
        }
        assert _classify_phase(rule) == "gcloud_armor_preconfigured"

    def test_unknown_action_warns(self, caplog):
        from octorules_google.provider import _classify_phase

        result = _classify_phase({"action": "new_future_action", "priority": 42, "match": {}})
        assert result == "gcloud_armor_custom"
        assert "Unrecognized action" in caplog.text
        assert "new_future_action" in caplog.text

    def test_deny_with_status_no_warning(self, caplog):
        from octorules_google.provider import _classify_phase

        result = _classify_phase({"action": "deny(502)", "priority": 10, "match": {}})
        assert result == "gcloud_armor_custom"
        assert "Unrecognized action" not in caplog.text

    def test_plain_deny_warns(self, caplog):
        """Plain 'deny' (no status code) is unrecognized — should warn."""
        from octorules_google.provider import _classify_phase

        result = _classify_phase({"action": "deny", "priority": 10, "match": {}})
        assert result == "gcloud_armor_custom"
        assert "Unrecognized action" in caplog.text

    def test_allow_no_warning(self, caplog):
        from octorules_google.provider import _classify_phase

        result = _classify_phase({"action": "allow", "priority": 10, "match": {}})
        assert result == "gcloud_armor_custom"
        assert "Unrecognized action" not in caplog.text


class TestRuleNormalization:
    def test_normalize_maps_priority_to_ref(self):
        from octorules_google.provider import _normalize_rule

        rule = {"priority": 100, "action": "deny(403)"}
        normalized = _normalize_rule(rule)
        assert normalized["ref"] == "100"
        assert "priority" not in normalized

    def test_denormalize_maps_ref_to_priority(self):
        from octorules_google.provider import _denormalize_rule

        rule = {"ref": "100", "action": "deny(403)"}
        denormalized = _denormalize_rule(rule)
        assert denormalized["priority"] == 100
        assert "ref" not in denormalized


class TestSupports:
    def test_supports_zone_discovery_only(self):
        assert CloudArmorProvider.SUPPORTS == frozenset({"zone_discovery"})

    def test_does_not_support_optional_crud_features(self):
        assert "custom_rulesets" not in CloudArmorProvider.SUPPORTS
        assert "lists" not in CloudArmorProvider.SUPPORTS

    def test_supports_zone_discovery(self):
        assert "zone_discovery" in CloudArmorProvider.SUPPORTS

    def test_provider_supports_helper(self):
        from octorules.provider.base import (
            SUPPORTS_CUSTOM_RULESETS,
            SUPPORTS_LISTS,
            SUPPORTS_ZONE_DISCOVERY,
            provider_supports,
        )

        prov = CloudArmorProvider.__new__(CloudArmorProvider)
        assert not provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert not provider_supports(prov, SUPPORTS_LISTS)
        assert provider_supports(prov, SUPPORTS_ZONE_DISCOVERY)


class TestTimeoutPassthrough:
    def test_default_timeout(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider._timeout == 30.0

    def test_custom_timeout_stored(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=60.0)
        assert provider._timeout == 60.0

    def test_get_passes_timeout(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=42.0)
        provider.resolve_zone_id("my-policy")
        provider.get_phase_rules(_zs(), "gcloud_armor_custom")
        # All get calls should have timeout=42.0
        for call in mock_armor_client.get.call_args_list:
            assert call.kwargs.get("timeout") == 42.0

    def test_remove_rule_passes_timeout(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=15.0)
        provider.resolve_zone_id("my-policy")
        provider.put_phase_rules(_zs(), "gcloud_armor_custom", [])
        assert mock_armor_client.remove_rule.call_count == 1
        assert mock_armor_client.remove_rule.call_args.kwargs["timeout"] == 15.0

    def test_add_rule_passes_timeout(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=15.0)
        provider.resolve_zone_id("my-policy")
        new_rule = {"ref": "500", "action": "deny(403)", "match": {}}
        provider.put_phase_rules(_zs(), "gcloud_armor_custom", [new_rule])
        assert mock_armor_client.add_rule.call_count == 1
        assert mock_armor_client.add_rule.call_args.kwargs["timeout"] == 15.0


class TestPhaseRegistration:
    def test_phases_registered(self):
        from octorules.phases import PHASE_BY_NAME, get_phase

        assert "gcloud_armor_custom_rules" in PHASE_BY_NAME
        assert "gcloud_armor_rate_rules" in PHASE_BY_NAME
        assert "gcloud_armor_preconfigured_rules" in PHASE_BY_NAME
        assert "gcloud_armor_redirect_rules" in PHASE_BY_NAME

        phase = get_phase("gcloud_armor_custom_rules")
        assert phase.provider_id == "gcloud_armor_custom"
        assert phase.zone_level is True
        assert phase.account_level is False

        redirect_phase = get_phase("gcloud_armor_redirect_rules")
        assert redirect_phase.provider_id == "gcloud_armor_redirect"


class TestMalformedResponses:
    """Provider handles malformed or incomplete API responses gracefully."""

    def _setup(self, mock_armor_client, policy):
        mock_armor_client.get.return_value = policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        provider.resolve_zone_id("my-policy")
        return provider

    def test_get_phase_rules_empty_rules(self, mock_armor_client):
        """Provider handles policy with no rules."""
        policy = {"name": "empty", "rules": []}
        provider = self._setup(mock_armor_client, policy)
        assert provider.get_phase_rules(_zs(zone_id="empty"), "gcloud_armor_custom") == []
        assert provider.get_phase_rules(_zs(zone_id="empty"), "gcloud_armor_rate") == []
        assert provider.get_phase_rules(_zs(zone_id="empty"), "gcloud_armor_preconfigured") == []
        assert provider.get_phase_rules(_zs(zone_id="empty"), "gcloud_armor_redirect") == []

    def test_get_phase_rules_missing_rules_key(self, mock_armor_client):
        """Provider handles policy with no rules key at all."""
        policy = {"name": "no-rules"}
        provider = self._setup(mock_armor_client, policy)
        assert provider.get_phase_rules(_zs(zone_id="no-rules"), "gcloud_armor_custom") == []

    def test_get_phase_rules_rule_missing_priority(self, mock_armor_client):
        """Rules without priority don't crash."""
        policy = {
            "name": "bad-rules",
            "rules": [
                {
                    # No "priority" key
                    "action": "deny(403)",
                    "match": {"config": {"src_ip_ranges": ["10.0.0.0/8"]}},
                    "description": "Rule with no priority",
                },
            ],
        }
        provider = self._setup(mock_armor_client, policy)
        # Missing priority means _get_rules filter (r.get("priority") != DEFAULT)
        # passes, and _normalize_rule uses .pop("priority", "") -> ref = ""
        rules = provider.get_phase_rules(_zs(zone_id="bad-rules"), "gcloud_armor_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == ""

    def test_get_phase_rules_rule_missing_action(self, mock_armor_client):
        """Rules without action classify as custom and don't crash."""
        policy = {
            "name": "no-action",
            "rules": [
                {
                    "priority": 100,
                    # No "action" key
                    "match": {"config": {"src_ip_ranges": ["10.0.0.0/8"]}},
                    "description": "Rule with no action",
                },
            ],
        }
        provider = self._setup(mock_armor_client, policy)
        # Missing action -> _classify_phase returns "gcloud_armor_custom"
        rules = provider.get_phase_rules(_zs(zone_id="no-action"), "gcloud_armor_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "100"

    def test_get_phase_rules_rule_missing_match(self, mock_armor_client):
        """Rules without match field don't crash classification."""
        policy = {
            "name": "no-match",
            "rules": [
                {
                    "priority": 100,
                    "action": "deny(403)",
                    # No "match" key
                    "description": "Rule with no match",
                },
            ],
        }
        provider = self._setup(mock_armor_client, policy)
        rules = provider.get_phase_rules(_zs(zone_id="no-match"), "gcloud_armor_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "100"

    def test_get_all_phase_rules_empty_policy(self, mock_armor_client):
        """get_all_phase_rules returns empty result for policy with no rules."""
        policy = {"name": "empty", "rules": []}
        provider = self._setup(mock_armor_client, policy)
        result = provider.get_all_phase_rules(_zs(zone_id="empty"))
        assert dict(result) == {}
        assert result.failed_phases == []

    def test_get_all_phase_rules_missing_rules_key(self, mock_armor_client):
        """get_all_phase_rules handles policy with no rules key."""
        policy = {"name": "no-rules"}
        provider = self._setup(mock_armor_client, policy)
        result = provider.get_all_phase_rules(_zs(zone_id="no-rules"))
        assert dict(result) == {}
        assert result.failed_phases == []

    def test_only_default_rule_returns_empty(self, mock_armor_client):
        """Policy with only the default rule (priority 2147483647) returns empty."""
        policy = {
            "name": "default-only",
            "rules": [
                {
                    "priority": 2147483647,
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                    "description": "Default rule",
                },
            ],
        }
        provider = self._setup(mock_armor_client, policy)
        assert provider.get_phase_rules(_zs(zone_id="default-only"), "gcloud_armor_custom") == []
        result = provider.get_all_phase_rules(_zs(zone_id="default-only"))
        assert dict(result) == {}


class TestConcurrentWorkers:
    """Tests for concurrent/parallel usage with max_workers > 1."""

    def _make_policy(self, name):
        """Create a security policy with one custom rule."""
        return {
            "name": name,
            "id": f"id-{name}",
            "rules": [
                {
                    "priority": 100,
                    "action": "deny(403)",
                    "match": {
                        "config": {"src_ip_ranges": ["1.2.3.0/24"]},
                        "versioned_expr": "SRC_IPS_V1",
                    },
                    "description": f"Block for {name}",
                    "preview": False,
                },
                {
                    "priority": 2147483647,
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                    "description": "Default rule",
                },
            ],
        }

    def test_concurrent_get_phase_rules_success(self, mock_armor_client):
        """Multiple concurrent get_phase_rules calls all return correct results."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        policy_names = ["policy-a", "policy-b", "policy-c"]
        policies = {name: self._make_policy(name) for name in policy_names}

        def mock_get(**kwargs):
            name = kwargs.get("security_policy", "")
            return policies[name]

        mock_armor_client.get.side_effect = mock_get
        provider = CloudArmorProvider(client=mock_armor_client, project="p", max_workers=3)
        # Resolve all zones first
        for name in policy_names:
            provider.resolve_zone_id(name)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    _zs(zone_id=name),
                    "gcloud_armor_custom",
                ): name
                for name in policy_names
            }
            results = {}
            for future in as_completed(futures):
                name = futures[future]
                results[name] = future.result()

        # All three policies got results
        assert len(results) == 3
        for name in policy_names:
            assert len(results[name]) == 1
            assert results[name][0]["ref"] == "100"

    def test_concurrent_partial_failure(self, mock_armor_client):
        """Some zones succeed while others raise ProviderError."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        policy_names = ["policy-a", "policy-b", "policy-c"]
        policies = {name: self._make_policy(name) for name in policy_names}

        def mock_get(**kwargs):
            name = kwargs.get("security_policy", "")
            if name == "policy-b":
                raise GoogleAPIError("quota exceeded")
            return policies[name]

        mock_armor_client.get.side_effect = mock_get
        provider = CloudArmorProvider(client=mock_armor_client, project="p", max_workers=3)
        # Resolve all first (before the error side_effect kicks in)
        mock_armor_client.get.side_effect = lambda **kw: policies[kw["security_policy"]]
        for name in policy_names:
            provider.resolve_zone_id(name)
        # Now set the failing side_effect
        mock_armor_client.get.side_effect = mock_get

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    _zs(zone_id=name),
                    "gcloud_armor_custom",
                ): name
                for name in policy_names
            }
            results = {}
            errors = {}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except ProviderError as e:
                    errors[name] = e

        # policy-a and policy-c succeed, policy-b fails
        assert "policy-a" in results
        assert "policy-c" in results
        assert "policy-b" in errors
        assert len(results) == 2
        assert len(errors) == 1

    def test_concurrent_auth_error_propagates(self, mock_armor_client):
        """ProviderAuthError propagates from concurrent execution."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        policy_names = ["policy-a", "policy-b", "policy-c"]
        policies = {name: self._make_policy(name) for name in policy_names}

        # Resolve all first
        mock_armor_client.get.side_effect = lambda **kw: policies[kw["security_policy"]]
        provider = CloudArmorProvider(client=mock_armor_client, project="p", max_workers=3)
        for name in policy_names:
            provider.resolve_zone_id(name)

        # Now set auth error for policy-a
        def mock_get(**kwargs):
            name = kwargs.get("security_policy", "")
            if name == "policy-a":
                raise Forbidden("forbidden")
            return policies[name]

        mock_armor_client.get.side_effect = mock_get

        auth_errors = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    _zs(zone_id=name),
                    "gcloud_armor_custom",
                ): name
                for name in policy_names
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except ProviderAuthError as e:
                    auth_errors.append(e)

        # At least one ProviderAuthError surfaced
        assert len(auth_errors) >= 1

    def test_concurrent_resolve_zone_id(self, mock_armor_client):
        """Concurrent resolve_zone_id calls all succeed."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        policy_names = [f"policy-{i}" for i in range(10)]
        policies = {name: self._make_policy(name) for name in policy_names}

        mock_armor_client.get.side_effect = lambda **kw: policies[kw["security_policy"]]
        provider = CloudArmorProvider(client=mock_armor_client, project="p", max_workers=4)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(provider.resolve_zone_id, name): name for name in policy_names
            }
            results = {}
            for future in as_completed(futures):
                name = futures[future]
                results[name] = future.result()

        # All 10 policies resolved (Cloud Armor uses name as ID)
        assert len(results) == 10
        for name in policy_names:
            assert results[name] == name


class TestRetryTransient:
    """Tests for _retry_transient() delegating to retry_with_backoff."""

    def test_succeeds_first_try(self):
        """Function that succeeds immediately returns its result."""
        from octorules_google.provider import _retry_transient

        result = _retry_transient(lambda: 42, label="test")
        assert result == 42

    def test_succeeds_on_retry(self):
        """Function that fails then succeeds returns its result."""
        from octorules_google.provider import _retry_transient

        calls = [0]

        def flaky():
            calls[0] += 1
            if calls[0] == 1:
                raise ServiceUnavailable("transient")
            return "ok"

        with patch("octorules.retry.time.sleep"):
            result = _retry_transient(flaky, label="test", retries=2)
        assert result == "ok"
        assert calls[0] == 2

    def test_exhausts_retries(self):
        """Raises the last exception after all retries are exhausted."""
        from octorules_google.provider import _retry_transient

        err = ServiceUnavailable("persistent")
        with patch("octorules.retry.time.sleep"):
            with pytest.raises(ServiceUnavailable):
                _retry_transient(lambda: (_ for _ in ()).throw(err), label="test", retries=2)

    def test_auth_error_propagates_immediately(self):
        """Non-retryable errors (auth) propagate without retry."""
        from octorules_google.provider import _retry_transient

        calls = [0]

        def fail():
            calls[0] += 1
            raise DefaultCredentialsError()

        with pytest.raises(DefaultCredentialsError):
            _retry_transient(fail, label="test", retries=2)
        assert calls[0] == 1  # No retries

    def test_backoff_timing(self):
        """Retries use exponential backoff delays (via retry_with_backoff)."""
        from octorules_google.provider import _retry_transient

        err = ServiceUnavailable("fail")
        sleep_mock = MagicMock()
        with patch("octorules.retry.time.sleep", sleep_mock):
            with pytest.raises(ServiceUnavailable):
                _retry_transient(lambda: (_ for _ in ()).throw(err), label="test", retries=2)
        # Should have slept twice (before retry 1 and retry 2)
        assert sleep_mock.call_count == 2

    def test_backoff_uses_correct_base_delays(self):
        """Retries use backoff delays from _RETRY_BACKOFF (plus jitter)."""
        from octorules_google.provider import _retry_transient

        err = ServiceUnavailable("fail")
        sleep_mock = MagicMock()
        with patch("octorules.retry.time.sleep", sleep_mock):
            with patch("octorules.retry.random.uniform", return_value=0.0):
                with pytest.raises(ServiceUnavailable):
                    _retry_transient(lambda: (_ for _ in ()).throw(err), label="test", retries=2)
        # _RETRY_BACKOFF = (1.0, 2.0, 4.0) — with jitter=0, exact values
        sleep_mock.assert_any_call(1.0)
        sleep_mock.assert_any_call(2.0)


class TestTimeoutZero:
    """timeout=0 should be preserved, not silently replaced with 30s."""

    def test_timeout_zero_preserved(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=0)
        assert provider._timeout == 0

    def test_timeout_zero_passed_to_api(self, mock_armor_client, security_policy):
        mock_armor_client.get.return_value = security_policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=0)
        provider.resolve_zone_id("my-policy")
        assert mock_armor_client.get.call_args.kwargs["timeout"] == 0

    def test_timeout_none_defaults_to_30(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider._timeout == 30.0


class TestListZones:
    """Tests for list_zones() zone discovery."""

    def test_list_zones_success(self, mock_armor_client):
        """Returns list of policy names."""
        policy_a = MagicMock()
        policy_a.name = "policy-a"
        policy_b = MagicMock()
        policy_b.name = "policy-b"
        mock_armor_client.list.return_value = [policy_a, policy_b]
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        result = provider.list_zones()
        assert result == ["policy-a", "policy-b"]
        mock_armor_client.list.assert_called_once_with(
            project="p",
            timeout=30.0,
        )

    def test_list_zones_empty(self, mock_armor_client):
        """Empty project returns empty list."""
        mock_armor_client.list.return_value = []
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.list_zones() == []

    def test_list_zones_api_error(self, mock_armor_client):
        """GoogleAPIError is wrapped as ProviderError."""
        mock_armor_client.list.side_effect = GoogleAPIError("server error")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderError, match="server error"):
            provider.list_zones()

    def test_list_zones_timeout_passthrough(self, mock_armor_client):
        """Custom timeout is passed to the list API call."""
        mock_armor_client.list.return_value = []
        provider = CloudArmorProvider(client=mock_armor_client, project="p", timeout=99.0)
        provider.list_zones()
        assert mock_armor_client.list.call_args.kwargs["timeout"] == 99.0

    def test_list_zones_auth_error(self, mock_armor_client):
        """Auth errors are wrapped as ProviderAuthError."""
        mock_armor_client.list.side_effect = Forbidden("forbidden")
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderAuthError):
            provider.list_zones()


class TestCreateDeleteCustomRuleset:
    """create_custom_ruleset and delete_custom_ruleset are not supported."""

    def test_create_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.create_custom_ruleset(
                _zs(), name="test", phase="gcloud_armor_custom", capacity=10
            )

    def test_create_with_description_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.create_custom_ruleset(
                _zs(), name="test", phase="gcloud_armor_custom", capacity=10, description="desc"
            )

    def test_delete_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ConfigError, match="not supported"):
            provider.delete_custom_ruleset(_zs(), "rs-1")


class TestConfigErrorOnMissingProject:
    """ConfigError raised when project is empty or not specified."""

    def test_empty_string_project(self, mock_armor_client):
        with pytest.raises(ConfigError, match="GCP project not specified"):
            CloudArmorProvider(client=mock_armor_client, project="")

    def test_none_project_no_env(self, mock_armor_client):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError, match="GCP project not specified"):
                CloudArmorProvider(client=mock_armor_client, project=None)

    def test_env_var_fallback(self, mock_armor_client):
        with patch.dict("os.environ", {"GCLOUD_PROJECT": "env-proj"}):
            provider = CloudArmorProvider(client=mock_armor_client, project=None)
            assert provider._project == "env-proj"


class TestPhaseIdsDerivedFromPhases:
    """_GCLOUD_PHASE_IDS is derived from _GCLOUD_PHASES, not hand-maintained."""

    def test_phase_ids_match_phases(self):
        from octorules_google.provider import _GCLOUD_PHASE_IDS, _GCLOUD_PHASES

        expected = frozenset(p.provider_id for p in _GCLOUD_PHASES)
        assert _GCLOUD_PHASE_IDS == expected

    def test_phase_ids_contains_all_four(self):
        from octorules_google.provider import _GCLOUD_PHASE_IDS

        assert _GCLOUD_PHASE_IDS == frozenset(
            {
                "gcloud_armor_custom",
                "gcloud_armor_rate",
                "gcloud_armor_preconfigured",
                "gcloud_armor_redirect",
            }
        )


# ---------------------------------------------------------------------------
# _denormalize_rule edge cases
# ---------------------------------------------------------------------------
class TestDenormalizeEdgeCases:
    def test_non_numeric_ref_raises_config_error(self):
        """Non-numeric ref in _denormalize_rule raises ConfigError with context."""
        from octorules.config import ConfigError

        from octorules_google.provider import _denormalize_rule

        with pytest.raises(ConfigError, match="must be numeric"):
            _denormalize_rule({"ref": "abc", "action": "allow"})

    def test_non_numeric_ref_includes_value_in_message(self):
        """Error message includes the invalid ref value."""
        from octorules.config import ConfigError

        from octorules_google.provider import _denormalize_rule

        with pytest.raises(ConfigError, match="'abc'"):
            _denormalize_rule({"ref": "abc", "action": "allow"})

    def test_missing_ref_defaults_to_zero(self):
        """Missing ref defaults to priority 0."""
        from octorules_google.provider import _denormalize_rule

        result = _denormalize_rule({"action": "allow"})
        assert result["priority"] == 0
        assert "ref" not in result


# ---------------------------------------------------------------------------
# Default rule filtering
# ---------------------------------------------------------------------------
class TestDefaultRuleFiltering:
    def test_default_rule_filtered(self, mock_armor_client):
        """The GCP default rule (priority 2147483647) is excluded from results."""
        policy = {
            "rules": [
                {
                    "priority": 100,
                    "action": "deny(403)",
                    "match": {"expr": {"expression": "true"}},
                },
                {
                    "priority": 2147483647,
                    "action": "deny(403)",
                    "match": {
                        "versioned_expr": "SRC_IPS_V1",
                        "config": {"src_ip_ranges": ["*"]},
                    },
                },
            ],
        }
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        mock_armor_client.get.return_value = policy
        rules = provider.get_phase_rules(_zs(zone_id="policy-1"), "gcloud_armor_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "100"

    def test_default_only_returns_empty(self, mock_armor_client):
        """Policy with only the default rule returns empty list."""
        policy = {
            "rules": [
                {
                    "priority": 2147483647,
                    "action": "deny(403)",
                    "match": {
                        "versioned_expr": "SRC_IPS_V1",
                        "config": {"src_ip_ranges": ["*"]},
                    },
                },
            ],
        }
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        mock_armor_client.get.return_value = policy
        rules = provider.get_phase_rules(_zs(zone_id="policy-1"), "gcloud_armor_custom")
        assert rules == []


class TestNormalizationRoundTrip:
    """Verify normalize -> denormalize preserves rule structure."""

    def test_custom_rule_round_trip(self):
        from octorules_google.provider import _denormalize_rule, _normalize_rule

        api_rule = {
            "priority": 100,
            "action": "deny(403)",
            "match": {"expr": {"expression": "origin.region_code == 'CN'"}},
            "description": "Block CN",
        }
        normalized = _normalize_rule(api_rule)
        assert normalized["ref"] == "100"
        assert "priority" not in normalized

        denormalized = _denormalize_rule(normalized)
        assert denormalized["priority"] == 100
        assert "ref" not in denormalized
        assert denormalized["action"] == "deny(403)"
        assert denormalized["description"] == "Block CN"

    def test_rate_limit_rule_round_trip(self):
        from octorules_google.provider import _denormalize_rule, _normalize_rule

        api_rule = {
            "priority": 200,
            "action": "throttle",
            "match": {"expr": {"expression": "true"}},
            "rate_limit_options": {
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "conform_action": "allow",
                "exceed_action": "deny(429)",
            },
        }
        normalized = _normalize_rule(api_rule)
        assert normalized["ref"] == "200"

        denormalized = _denormalize_rule(normalized)
        assert denormalized["priority"] == 200
        assert denormalized["action"] == "throttle"
        rlo = denormalized.get("rate_limit_options", {})
        assert rlo["rate_limit_threshold"]["count"] == 100


class TestGetPolicySettings:
    """Tests for CloudArmorProvider.get_policy_settings()."""

    def test_returns_normalized_settings(self, mock_armor_client):
        """get_policy_settings returns normalized policy settings from the API."""
        policy = {
            "name": "my-policy",
            "adaptive_protection_config": {"layer7_ddos_defense_config": {"enable": True}},
            "advanced_options_config": {"json_parsing": "STANDARD"},
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "recaptcha_options_config": {"redirect_site_key": "key-123"},
            "rules": [
                {
                    "priority": 100,
                    "action": "deny(403)",
                    "match": {"config": {"src_ip_ranges": ["1.2.3.0/24"]}},
                },
                {
                    "priority": 2147483647,
                    "action": "deny(502)",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                    "description": "Default rule",
                },
            ],
        }
        mock_armor_client.get.return_value = policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        result = provider.get_policy_settings(_zs())
        assert result["adaptive_protection_config"] == {
            "layer7_ddos_defense_config": {"enable": True}
        }
        assert result["advanced_options_config"] == {"json_parsing": "STANDARD"}
        assert result["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}
        assert result["recaptcha_options_config"] == {"redirect_site_key": "key-123"}
        assert result["default_rule_action"] == "deny(502)"

    def test_minimal_policy(self, mock_armor_client):
        """Policy with no config fields and default allow rule."""
        policy = {
            "name": "bare",
            "rules": [
                {
                    "priority": 2147483647,
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                },
            ],
        }
        mock_armor_client.get.return_value = policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        result = provider.get_policy_settings(_zs())
        assert result == {"default_rule_action": "allow"}

    def test_no_rules_returns_empty(self, mock_armor_client):
        """Policy with no rules returns empty settings."""
        policy = {"name": "empty"}
        mock_armor_client.get.return_value = policy
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        result = provider.get_policy_settings(_zs())
        assert result == {}


class TestUpdatePolicySettings:
    """Tests for CloudArmorProvider.update_policy_settings()."""

    def _make_provider(self, mock_armor_client, policy=None):
        if policy is not None:
            mock_armor_client.get.return_value = policy
        return CloudArmorProvider(client=mock_armor_client, project="p")

    def test_policy_level_fields_only(self, mock_armor_client):
        """Patching only policy-level fields (no default_rule_action)."""
        provider = self._make_provider(mock_armor_client)
        settings = {
            "advanced_options_config": {"json_parsing": "STANDARD"},
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
        }
        provider.update_policy_settings(_zs(), settings)
        mock_armor_client.patch.assert_called_once()
        patch_kwargs = mock_armor_client.patch.call_args[1]
        resource = patch_kwargs["security_policy_resource"]
        assert resource["advanced_options_config"] == {"json_parsing": "STANDARD"}
        assert resource["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}
        assert "rules" not in resource

    @patch("octorules.retry.time.sleep")
    def test_default_rule_action_change(self, _mock_sleep, mock_armor_client):
        """Changing default_rule_action fetches the policy and patches the default rule."""
        policy = {
            "name": "my-policy",
            "rules": [
                {
                    "priority": 100,
                    "action": "deny(403)",
                    "match": {"config": {"src_ip_ranges": ["1.2.3.0/24"]}},
                },
                {
                    "priority": 2147483647,
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                    "description": "Default rule",
                },
            ],
        }
        mock_armor_client.get.return_value = policy
        provider = self._make_provider(mock_armor_client, policy)
        settings = {"default_rule_action": "deny(403)"}
        provider.update_policy_settings(_zs(), settings)
        mock_armor_client.patch.assert_called_once()
        patch_kwargs = mock_armor_client.patch.call_args[1]
        resource = patch_kwargs["security_policy_resource"]
        # rules should contain both rules, with the default rule action updated
        rules = resource["rules"]
        assert len(rules) == 2
        default_rules = [r for r in rules if r.get("priority") == 2147483647]
        assert len(default_rules) == 1
        assert default_rules[0]["action"] == "deny(403)"
        # Non-default rule unchanged
        non_default = [r for r in rules if r.get("priority") != 2147483647]
        assert len(non_default) == 1
        assert non_default[0]["action"] == "deny(403)"
        assert non_default[0]["priority"] == 100

    @patch("octorules.retry.time.sleep")
    def test_both_policy_fields_and_default_action(self, _mock_sleep, mock_armor_client):
        """Combined policy-level fields and default_rule_action in one call."""
        policy = {
            "name": "my-policy",
            "rules": [
                {
                    "priority": 2147483647,
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                },
            ],
        }
        mock_armor_client.get.return_value = policy
        provider = self._make_provider(mock_armor_client, policy)
        settings = {
            "adaptive_protection_config": {"layer7_ddos_defense_config": {"enable": True}},
            "default_rule_action": "deny(502)",
        }
        provider.update_policy_settings(_zs(), settings)
        mock_armor_client.patch.assert_called_once()
        patch_kwargs = mock_armor_client.patch.call_args[1]
        resource = patch_kwargs["security_policy_resource"]
        # Policy-level field present
        assert resource["adaptive_protection_config"] == {
            "layer7_ddos_defense_config": {"enable": True}
        }
        # Default rule action updated
        default_rule = resource["rules"][0]
        assert default_rule["priority"] == 2147483647
        assert default_rule["action"] == "deny(502)"

    def test_empty_settings_is_noop(self, mock_armor_client):
        """Empty settings dict results in no API call."""
        provider = self._make_provider(mock_armor_client)
        provider.update_policy_settings(_zs(), {})
        mock_armor_client.patch.assert_not_called()
        mock_armor_client.get.assert_not_called()
