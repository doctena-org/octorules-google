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

    def test_put_phase_rules_partial_failure(self, mock_armor_client, security_policy):
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
