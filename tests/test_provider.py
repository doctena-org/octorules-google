"""Tests for the Google Cloud Armor provider."""

from __future__ import annotations

import pytest
from google.api_core.exceptions import Forbidden, GoogleAPIError, NotFound, Unauthorized
from google.auth.exceptions import DefaultCredentialsError
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

    def test_zone_plans_is_empty(self, mock_armor_client):
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
        with pytest.raises(ProviderError, match="not supported"):
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
        with pytest.raises(ProviderError, match="not supported"):
            provider.create_list(_zs(), "blocklist", "ip")

    def test_delete_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderError, match="not supported"):
            provider.delete_list(_zs(), "ip-1")

    def test_get_items_returns_empty(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        assert provider.get_list_items(_zs(), "ip-1") == []

    def test_put_items_raises(self, mock_armor_client):
        provider = CloudArmorProvider(client=mock_armor_client, project="p")
        with pytest.raises(ProviderError, match="not supported"):
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
