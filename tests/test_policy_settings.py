"""Tests for Google Cloud Armor policy settings normalization and extension hooks."""

from unittest.mock import MagicMock, patch

import pytest
from google.api_core.exceptions import ServiceUnavailable
from google.cloud.compute_v1 import SecurityPoliciesClient
from octorules.provider.base import Scope

from octorules_google import CloudArmorProvider
from octorules_google._policy_settings import (
    PolicySettingsChange,
    PolicySettingsFormatter,
    PolicySettingsPlan,
    _apply_policy_settings,
    _dump_policy_settings,
    _finalize_policy_settings,
    _prefetch_policy_settings,
    _validate_policy_settings,
    denormalize_policy_settings,
    diff_policy_settings,
    normalize_policy_settings,
)


def _scope(zone_id: str = "my-policy") -> Scope:
    return Scope(zone_id=zone_id, label="my-policy")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalize:
    def test_all_fields(self):
        policy = {
            "adaptive_protection_config": {
                "layer7_ddos_defense_config": {
                    "enable": True,
                    "rule_visibility": "STANDARD",
                }
            },
            "advanced_options_config": {
                "json_parsing": "STANDARD",
                "log_level": "NORMAL",
            },
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "rules": [
                {"priority": 100, "action": "deny(403)"},
                {
                    "priority": 2147483647,
                    "action": "deny(502)",
                    "description": "Default rule",
                },
            ],
        }
        result = normalize_policy_settings(policy)
        assert result["adaptive_protection_config"] == {
            "layer7_ddos_defense_config": {
                "enable": True,
                "rule_visibility": "STANDARD",
            }
        }
        assert result["advanced_options_config"] == {
            "json_parsing": "STANDARD",
            "log_level": "NORMAL",
        }
        assert result["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}
        assert result["default_rule_action"] == "deny(502)"

    def test_default_rule_action_allow(self):
        policy = {
            "rules": [
                {
                    "priority": 2147483647,
                    "action": "allow",
                }
            ],
        }
        result = normalize_policy_settings(policy)
        assert result["default_rule_action"] == "allow"

    def test_no_default_rule(self):
        """If no default rule exists, default_rule_action is absent."""
        policy = {
            "rules": [{"priority": 100, "action": "deny(403)"}],
        }
        result = normalize_policy_settings(policy)
        assert "default_rule_action" not in result

    def test_no_rules_key(self):
        policy = {"advanced_options_config": {"json_parsing": "DISABLED"}}
        result = normalize_policy_settings(policy)
        assert result["advanced_options_config"] == {"json_parsing": "DISABLED"}
        assert "default_rule_action" not in result

    def test_empty_policy(self):
        assert normalize_policy_settings({}) == {}

    def test_missing_action_on_default_rule(self):
        """Default rule without action field defaults to 'allow'."""
        policy = {"rules": [{"priority": 2147483647}]}
        result = normalize_policy_settings(policy)
        assert result["default_rule_action"] == "allow"

    def test_only_relevant_fields_extracted(self):
        """Fields like 'name', 'id', 'rules' (non-settings) are ignored."""
        policy = {
            "name": "my-policy",
            "id": "123456",
            "fingerprint": "abc",
            "rules": [{"priority": 2147483647, "action": "allow"}],
        }
        result = normalize_policy_settings(policy)
        assert "name" not in result
        assert "id" not in result
        assert "fingerprint" not in result
        assert result["default_rule_action"] == "allow"

    def test_nested_structures_passed_through(self):
        """Nested config dicts are preserved as-is."""
        policy = {
            "advanced_options_config": {
                "json_parsing": "STANDARD",
                "json_custom_config": {"content_types": ["application/json"]},
            }
        }
        result = normalize_policy_settings(policy)
        assert result["advanced_options_config"]["json_custom_config"] == {
            "content_types": ["application/json"]
        }


class TestNormalizeDenormalizeRoundTrip:
    def test_round_trip_full_policy(self):
        """normalize -> denormalize preserves all settings fields."""
        policy = {
            "name": "my-policy",
            "id": "123456",
            "fingerprint": "abc",
            "adaptive_protection_config": {
                "layer7_ddos_defense_config": {
                    "enable": True,
                    "rule_visibility": "STANDARD",
                }
            },
            "advanced_options_config": {
                "json_parsing": "STANDARD",
                "log_level": "NORMAL",
                "json_custom_config": {"content_types": ["application/json"]},
            },
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "rules": [
                {"priority": 100, "action": "deny(403)"},
                {
                    "priority": 2147483647,
                    "action": "deny(502)",
                    "description": "Default rule",
                },
            ],
        }
        normalized = normalize_policy_settings(policy)
        denormalized = denormalize_policy_settings(normalized)

        # policy_fields should match the original policy-level settings
        assert (
            denormalized["policy_fields"]["adaptive_protection_config"]
            == (policy["adaptive_protection_config"])
        )
        assert (
            denormalized["policy_fields"]["advanced_options_config"]
            == (policy["advanced_options_config"])
        )
        assert (
            denormalized["policy_fields"]["ddos_protection_config"]
            == (policy["ddos_protection_config"])
        )
        # default_rule_action should match the default rule's action
        assert denormalized["default_rule_action"] == "deny(502)"


# ---------------------------------------------------------------------------
# Denormalization
# ---------------------------------------------------------------------------
class TestDenormalize:
    def test_policy_fields(self):
        settings = {
            "adaptive_protection_config": {"layer7_ddos_defense_config": {"enable": True}},
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
        }
        result = denormalize_policy_settings(settings)
        assert "policy_fields" in result
        assert result["policy_fields"]["adaptive_protection_config"] == {
            "layer7_ddos_defense_config": {"enable": True}
        }
        assert result["policy_fields"]["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}
        assert "default_rule_action" not in result

    def test_default_rule_action_only(self):
        settings = {"default_rule_action": "deny(403)"}
        result = denormalize_policy_settings(settings)
        assert "policy_fields" not in result
        assert result["default_rule_action"] == "deny(403)"

    def test_mixed(self):
        settings = {
            "advanced_options_config": {"json_parsing": "STANDARD"},
            "default_rule_action": "deny(502)",
        }
        result = denormalize_policy_settings(settings)
        assert result["policy_fields"] == {"advanced_options_config": {"json_parsing": "STANDARD"}}
        assert result["default_rule_action"] == "deny(502)"

    def test_empty(self):
        assert denormalize_policy_settings({}) == {}

    def test_partial_update(self):
        """Only specified fields are included in the output."""
        settings = {"ddos_protection_config": {"ddos_protection": "STANDARD"}}
        result = denormalize_policy_settings(settings)
        pf = result["policy_fields"]
        assert "ddos_protection_config" in pf
        assert "adaptive_protection_config" not in pf
        assert "advanced_options_config" not in pf


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffPolicySettings:
    def test_no_changes(self):
        settings = {
            "default_rule_action": "allow",
            "ddos_protection_config": {"ddos_protection": "STANDARD"},
        }
        plan = diff_policy_settings(settings, settings)
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_with_changes(self):
        current = {"default_rule_action": "allow"}
        desired = {"default_rule_action": "deny(403)"}
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1
        assert plan.changes[0].field == "default_rule_action"
        assert plan.changes[0].current == "allow"
        assert plan.changes[0].desired == "deny(403)"

    def test_partial_desired(self):
        """Only keys present in desired produce changes."""
        current = {
            "default_rule_action": "allow",
            "ddos_protection_config": {"ddos_protection": "STANDARD"},
            "advanced_options_config": {"json_parsing": "DISABLED"},
        }
        desired = {"default_rule_action": "deny(403)"}
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "default_rule_action"

    def test_new_field(self):
        """Desired has a field not in current."""
        current = {"default_rule_action": "allow"}
        desired = {
            "default_rule_action": "allow",
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
        }
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "ddos_protection_config"
        assert plan.changes[0].current is None
        assert plan.changes[0].desired == {"ddos_protection": "ADVANCED"}

    def test_multiple_changes(self):
        current = {
            "default_rule_action": "allow",
            "ddos_protection_config": {"ddos_protection": "STANDARD"},
        }
        desired = {
            "default_rule_action": "deny(403)",
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
        }
        plan = diff_policy_settings(current, desired)
        assert plan.total_changes == 2

    def test_nested_dict_change(self):
        """Changes deep within a nested dict are detected."""
        current = {"advanced_options_config": {"json_parsing": "DISABLED", "log_level": "NORMAL"}}
        desired = {"advanced_options_config": {"json_parsing": "STANDARD", "log_level": "NORMAL"}}
        plan = diff_policy_settings(current, desired)
        assert plan.has_changes
        assert plan.total_changes == 1


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class TestDataModel:
    def test_change_has_changes(self):
        c = PolicySettingsChange(field="default_rule_action", current="allow", desired="deny(403)")
        assert c.has_changes is True

    def test_change_no_changes(self):
        c = PolicySettingsChange(field="default_rule_action", current="allow", desired="allow")
        assert c.has_changes is False

    def test_plan_has_changes(self):
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "deny(403)")]
        )
        assert plan.has_changes is True
        assert plan.total_changes == 1

    def test_plan_empty(self):
        plan = PolicySettingsPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_policy_settings({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_settings(self):
        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.return_value = {
            "default_rule_action": "allow",
            "ddos_protection_config": {"ddos_protection": "STANDARD"},
        }
        all_desired = {"gcloud_armor_policy_settings": {"default_rule_action": "deny(403)"}}
        result = _prefetch_policy_settings(all_desired, _scope(), provider)
        assert result is not None
        current, desired = result
        assert current["default_rule_action"] == "allow"
        assert desired["default_rule_action"] == "deny(403)"

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.side_effect = ProviderError("API down")
        all_desired = {"gcloud_armor_policy_settings": {"default_rule_action": "deny(403)"}}
        result = _prefetch_policy_settings(all_desired, _scope(), provider)
        current, _desired = result
        assert current == {}

    def test_auth_error_propagates(self):
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.side_effect = ProviderAuthError("forbidden")
        all_desired = {"gcloud_armor_policy_settings": {"default_rule_action": "deny(403)"}}
        with pytest.raises(ProviderAuthError):
            _prefetch_policy_settings(all_desired, _scope(), provider)


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"default_rule_action": "allow"}
        desired = {"default_rule_action": "deny(403)"}
        ctx = (current, desired)

        _finalize_policy_settings(zp, {}, _scope(), MagicMock(), ctx)
        assert "gcloud_armor_policy_settings" in zp.extension_plans
        plan = zp.extension_plans["gcloud_armor_policy_settings"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"default_rule_action": "allow"}
        desired = {"default_rule_action": "allow"}
        ctx = (current, desired)

        _finalize_policy_settings(zp, {}, _scope(), MagicMock(), ctx)
        assert "gcloud_armor_policy_settings" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_policy_settings(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock(spec=CloudArmorProvider)
        zp = MagicMock()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("default_rule_action", "allow", "deny(403)"),
                PolicySettingsChange(
                    "ddos_protection_config",
                    {"ddos_protection": "STANDARD"},
                    {"ddos_protection": "ADVANCED"},
                ),
            ]
        )
        synced, error = _apply_policy_settings(zp, [plan], _scope(), provider)
        assert error is None
        assert "gcloud_armor_policy_settings" in synced
        provider.update_policy_settings.assert_called_once()
        call_args = provider.update_policy_settings.call_args
        payload = call_args[0][1]
        assert payload["default_rule_action"] == "deny(403)"
        assert payload["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}

    def test_no_changes_skipped(self):
        provider = MagicMock(spec=CloudArmorProvider)
        zp = MagicMock()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "allow")]
        )
        synced, error = _apply_policy_settings(zp, [plan], _scope(), provider)
        assert synced == []
        assert error is None
        provider.update_policy_settings.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_policy_settings(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert error is None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_settings(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "default_rule_action": "deny(403)",
                "ddos_protection_config": {"ddos_protection": "ADVANCED"},
                "advanced_options_config": {"json_parsing": "STANDARD"},
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_default_action(self):
        desired = {"gcloud_armor_policy_settings": {"default_rule_action": "block"}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "default_rule_action" in errors[0]
        assert "block" in errors[0]

    def test_invalid_ddos_protection(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "ddos_protection_config": {"ddos_protection": "ULTIMATE"}
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "ddos_protection" in errors[0]
        assert "ULTIMATE" in errors[0]

    def test_invalid_json_parsing(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "advanced_options_config": {"json_parsing": "AGGRESSIVE"}
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "json_parsing" in errors[0]
        assert "AGGRESSIVE" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_policy_settings({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        errors: list[str] = []
        _validate_policy_settings(
            {"gcloud_armor_policy_settings": "not-a-dict"}, "zone", errors, []
        )
        assert errors == []

    def test_multiple_errors(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "default_rule_action": "block",
                "ddos_protection_config": {"ddos_protection": "ULTIMATE"},
                "advanced_options_config": {"json_parsing": "AGGRESSIVE"},
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 3

    def test_valid_all_default_actions(self):
        """All valid default actions pass validation."""
        for action in ("allow", "deny(403)", "deny(404)", "deny(429)", "deny(502)"):
            desired = {"gcloud_armor_policy_settings": {"default_rule_action": action}}
            errors: list[str] = []
            _validate_policy_settings(desired, "zone", errors, [])
            assert errors == [], f"Action {action!r} should be valid"

    def test_valid_ddos_values(self):
        for val in ("STANDARD", "ADVANCED", "ADVANCED_PREVIEW"):
            desired = {
                "gcloud_armor_policy_settings": {"ddos_protection_config": {"ddos_protection": val}}
            }
            errors: list[str] = []
            _validate_policy_settings(desired, "zone", errors, [])
            assert errors == [], f"DDoS value {val!r} should be valid"

    def test_valid_json_parsing_values(self):
        for val in ("DISABLED", "STANDARD", "STANDARD_WITH_GRAPHQL"):
            desired = {
                "gcloud_armor_policy_settings": {"advanced_options_config": {"json_parsing": val}}
            }
            errors: list[str] = []
            _validate_policy_settings(desired, "zone", errors, [])
            assert errors == [], f"JSON parsing {val!r} should be valid"

    def test_nested_non_dict_config_skipped(self):
        """Non-dict nested configs don't crash validation."""
        desired = {
            "gcloud_armor_policy_settings": {
                "ddos_protection_config": "not-a-dict",
                "advanced_options_config": 42,
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_none_nested_values_skipped(self):
        """None values inside nested dicts don't trigger validation errors."""
        desired = {
            "gcloud_armor_policy_settings": {
                "ddos_protection_config": {"ddos_protection": None},
                "advanced_options_config": {"json_parsing": None},
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_recaptcha_options_config_non_dict(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "recaptcha_options_config": "not_a_dict",
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "zone/gcloud_armor_policy_settings:" in errors[0]
        assert "recaptcha_options_config" in errors[0]
        assert "mapping" in errors[0]

    def test_recaptcha_options_config_valid_dict(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "recaptcha_options_config": {"redirect_site_key": "key123"},
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_settings(self):
        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.return_value = {
            "default_rule_action": "allow",
            "ddos_protection_config": {"ddos_protection": "STANDARD"},
        }
        result = _dump_policy_settings(_scope(), provider, None)
        assert "gcloud_armor_policy_settings" in result
        assert result["gcloud_armor_policy_settings"]["default_rule_action"] == "allow"

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.side_effect = ProviderError("down")
        result = _dump_policy_settings(_scope(), provider, None)
        assert result is None

    def test_dump_empty_settings(self):
        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.return_value = {}
        result = _dump_policy_settings(_scope(), provider, None)
        assert result is None

    def test_dump_auth_error_propagates(self):
        from octorules.provider.exceptions import ProviderAuthError

        provider = MagicMock(spec=CloudArmorProvider)
        provider.get_policy_settings.side_effect = ProviderAuthError("forbidden")
        with pytest.raises(ProviderAuthError):
            _dump_policy_settings(_scope(), provider, None)


# ---------------------------------------------------------------------------
# Format extension — format_text
# ---------------------------------------------------------------------------
class TestFormatText:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("default_rule_action", "allow", "deny(403)"),
                PolicySettingsChange(
                    "ddos_protection_config",
                    {"ddos_protection": "STANDARD"},
                    {"ddos_protection": "ADVANCED"},
                ),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        assert "policy_settings.default_rule_action" in lines[0]
        assert "'allow'" in lines[0]
        assert "'deny(403)'" in lines[0]
        assert lines[0].startswith("  ~ ")
        assert "policy_settings.ddos_protection_config" in lines[1]

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "allow")]
        )
        assert fmt.format_text([plan], use_color=False) == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_with_color(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "deny(403)")]
        )
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]
        assert "policy_settings.default_rule_action" in lines[0]


# ---------------------------------------------------------------------------
# Format extension — format_json
# ---------------------------------------------------------------------------
class TestFormatJson:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("default_rule_action", "allow", "deny(403)"),
                PolicySettingsChange(
                    "ddos_protection_config",
                    {"ddos_protection": "STANDARD"},
                    {"ddos_protection": "ADVANCED"},
                ),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        changes = result[0]["changes"]
        assert len(changes) == 2
        assert changes[0]["field"] == "default_rule_action"
        assert changes[0]["current"] == "allow"
        assert changes[0]["desired"] == "deny(403)"
        assert changes[1]["field"] == "ddos_protection_config"

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "allow")]
        )
        assert fmt.format_json([plan]) == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_json([]) == []


# ---------------------------------------------------------------------------
# Format extension — format_markdown
# ---------------------------------------------------------------------------
class TestFormatMarkdown:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("default_rule_action", "allow", "deny(403)"),
            ]
        )
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert lines[0].startswith("| ~ |")
        assert "policy_settings.default_rule_action" in lines[0]
        assert "'allow'" in lines[0]
        assert "'deny(403)'" in lines[0]

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "allow")]
        )
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []


# ---------------------------------------------------------------------------
# Format extension — format_html
# ---------------------------------------------------------------------------
class TestFormatHtml:
    def test_with_changes(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[
                PolicySettingsChange("default_rule_action", "allow", "deny(403)"),
                PolicySettingsChange(
                    "ddos_protection_config",
                    {"ddos_protection": "STANDARD"},
                    {"ddos_protection": "ADVANCED"},
                ),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 2, 0)
        html = "\n".join(lines)
        assert "<table>" in html
        assert "</table>" in html
        assert "Modify" in html
        assert "policy_settings.default_rule_action" in html
        assert "policy_settings.ddos_protection_config" in html
        assert "&rarr;" in html
        assert "Updates=2" in html

    def test_skips_no_change(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "allow", "allow")]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_empty_plans(self):
        fmt = PolicySettingsFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_escapes_special_chars(self):
        fmt = PolicySettingsFormatter()
        plan = PolicySettingsPlan(
            changes=[PolicySettingsChange("default_rule_action", "<script>", "allow")]
        )
        lines: list[str] = []
        fmt.format_html([plan], lines)
        html = "\n".join(lines)
        assert "&lt;script&gt;" in html
        assert "<script>" not in html.replace("&lt;script&gt;", "")


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderGetPolicySettings:
    def test_get_policy_settings(self):
        from octorules_google import CloudArmorProvider

        policy_dict = {
            "name": "my-policy",
            "adaptive_protection_config": {"layer7_ddos_defense_config": {"enable": True}},
            "ddos_protection_config": {"ddos_protection": "ADVANCED"},
            "rules": [
                {"priority": 100, "action": "deny(403)"},
                {"priority": 2147483647, "action": "allow"},
            ],
        }
        client = MagicMock(spec=SecurityPoliciesClient)
        client.get.return_value = policy_dict
        provider = CloudArmorProvider(client=client, project="test-project")
        scope = _scope()
        result = provider.get_policy_settings(scope)
        assert result["adaptive_protection_config"] == {
            "layer7_ddos_defense_config": {"enable": True}
        }
        assert result["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}
        assert result["default_rule_action"] == "allow"
        assert "name" not in result

    def test_get_policy_settings_empty(self):
        from octorules_google import CloudArmorProvider

        client = MagicMock(spec=SecurityPoliciesClient)
        client.get.return_value = {"name": "empty-policy", "rules": []}
        provider = CloudArmorProvider(client=client, project="test-project")
        result = provider.get_policy_settings(_scope())
        assert result == {}


class TestProviderUpdatePolicySettings:
    def test_update_policy_fields_only(self):
        from octorules_google import CloudArmorProvider

        client = MagicMock(spec=SecurityPoliciesClient)
        # _get_policy is not called when there's no default_rule_action
        provider = CloudArmorProvider(client=client, project="test-project")
        provider.update_policy_settings(
            _scope(),
            {"ddos_protection_config": {"ddos_protection": "ADVANCED"}},
        )
        client.patch.assert_called_once()
        call_kwargs = client.patch.call_args[1]
        assert call_kwargs["project"] == "test-project"
        assert call_kwargs["security_policy"] == "my-policy"
        resource = call_kwargs["security_policy_resource"]
        assert resource["ddos_protection_config"] == {"ddos_protection": "ADVANCED"}
        assert "rules" not in resource

    def test_update_default_rule_action(self):
        from octorules_google import CloudArmorProvider

        policy_dict = {
            "name": "my-policy",
            "rules": [
                {"priority": 100, "action": "deny(403)"},
                {"priority": 2147483647, "action": "allow"},
            ],
        }
        client = MagicMock(spec=SecurityPoliciesClient)
        client.get.return_value = policy_dict
        provider = CloudArmorProvider(client=client, project="test-project")
        provider.update_policy_settings(
            _scope(),
            {"default_rule_action": "deny(502)"},
        )
        client.patch.assert_called_once()
        call_kwargs = client.patch.call_args[1]
        resource = call_kwargs["security_policy_resource"]
        # Should have the rules with the default rule's action updated
        assert "rules" in resource
        default_rule = next(r for r in resource["rules"] if r["priority"] == 2147483647)
        assert default_rule["action"] == "deny(502)"
        # Non-default rules should be unchanged
        other_rule = next(r for r in resource["rules"] if r["priority"] == 100)
        assert other_rule["action"] == "deny(403)"

    def test_update_mixed(self):
        from octorules_google import CloudArmorProvider

        policy_dict = {
            "name": "my-policy",
            "rules": [
                {"priority": 2147483647, "action": "allow"},
            ],
        }
        client = MagicMock(spec=SecurityPoliciesClient)
        client.get.return_value = policy_dict
        provider = CloudArmorProvider(client=client, project="test-project")
        provider.update_policy_settings(
            _scope(),
            {
                "advanced_options_config": {"json_parsing": "STANDARD"},
                "default_rule_action": "deny(403)",
            },
        )
        client.patch.assert_called_once()
        call_kwargs = client.patch.call_args[1]
        resource = call_kwargs["security_policy_resource"]
        assert resource["advanced_options_config"] == {"json_parsing": "STANDARD"}
        assert "rules" in resource
        default_rule = resource["rules"][0]
        assert default_rule["action"] == "deny(403)"

    def test_update_empty_settings_is_noop(self):
        from octorules_google import CloudArmorProvider

        client = MagicMock(spec=SecurityPoliciesClient)
        provider = CloudArmorProvider(client=client, project="test-project")
        provider.update_policy_settings(_scope(), {})
        client.patch.assert_not_called()

    def test_update_default_rule_action_retries_get_policy(self):
        """Regression: _get_policy inside update_policy_settings is retried on transient error."""
        from octorules_google import CloudArmorProvider

        policy_dict = {
            "name": "my-policy",
            "rules": [
                {"priority": 2147483647, "action": "allow"},
            ],
        }
        client = MagicMock(spec=SecurityPoliciesClient)
        client.get.side_effect = [
            ServiceUnavailable("503"),
            policy_dict,
        ]
        client.patch.return_value = None
        provider = CloudArmorProvider(client=client, project="test-project")

        with patch("octorules.retry.time.sleep"):
            provider.update_policy_settings(
                _scope(),
                {"default_rule_action": "deny(502)"},
            )

        # client.get was called twice: first failed, second succeeded
        assert client.get.call_count == 2
        # The patch should still have been applied with updated default rule
        client.patch.assert_called_once()
        resource = client.patch.call_args[1]["security_policy_resource"]
        default_rule = next(r for r in resource["rules"] if r["priority"] == 2147483647)
        assert default_rule["action"] == "deny(502)"


# ---------------------------------------------------------------------------
# Validate extension — log_level
# ---------------------------------------------------------------------------
class TestValidateLogLevel:
    def test_valid_log_levels(self):
        for val in ("NORMAL", "VERBOSE"):
            desired = {
                "gcloud_armor_policy_settings": {"advanced_options_config": {"log_level": val}}
            }
            errors: list[str] = []
            _validate_policy_settings(desired, "zone", errors, [])
            assert errors == [], f"log_level {val!r} should be valid"

    def test_invalid_log_level(self):
        desired = {
            "gcloud_armor_policy_settings": {"advanced_options_config": {"log_level": "DEBUG"}}
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "log_level" in errors[0]
        assert "DEBUG" in errors[0]

    def test_none_log_level_ok(self):
        desired = {"gcloud_armor_policy_settings": {"advanced_options_config": {"log_level": None}}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Validate extension — adaptive_protection_config sub-structure
# ---------------------------------------------------------------------------
class TestValidateAdaptiveProtection:
    def test_valid_config(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "adaptive_protection_config": {
                    "layer7_ddos_defense_config": {
                        "enable": True,
                        "rule_visibility": "STANDARD",
                    }
                }
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_enable_not_bool(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "adaptive_protection_config": {"layer7_ddos_defense_config": {"enable": "yes"}}
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "enable" in errors[0]
        assert "bool" in errors[0]

    def test_enable_int_not_bool(self):
        """Integer 1 should be rejected — must be actual bool."""
        desired = {
            "gcloud_armor_policy_settings": {
                "adaptive_protection_config": {"layer7_ddos_defense_config": {"enable": 1}}
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1

    def test_invalid_rule_visibility(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "adaptive_protection_config": {
                    "layer7_ddos_defense_config": {"rule_visibility": "BASIC"}
                }
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "rule_visibility" in errors[0]
        assert "BASIC" in errors[0]

    def test_valid_rule_visibility_values(self):
        for val in ("PREMIUM", "STANDARD"):
            desired = {
                "gcloud_armor_policy_settings": {
                    "adaptive_protection_config": {
                        "layer7_ddos_defense_config": {"rule_visibility": val}
                    }
                }
            }
            errors: list[str] = []
            _validate_policy_settings(desired, "zone", errors, [])
            assert errors == [], f"rule_visibility {val!r} should be valid"

    def test_none_values_ok(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "adaptive_protection_config": {
                    "layer7_ddos_defense_config": {
                        "enable": None,
                        "rule_visibility": None,
                    }
                }
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_non_dict_layer7_config_skipped(self):
        desired = {
            "gcloud_armor_policy_settings": {
                "adaptive_protection_config": {"layer7_ddos_defense_config": "not-a-dict"}
            }
        }
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []

    def test_non_dict_adaptive_config_skipped(self):
        desired = {"gcloud_armor_policy_settings": {"adaptive_protection_config": "not-a-dict"}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Normalize/denormalize — recaptcha_options_config
# ---------------------------------------------------------------------------
class TestRecaptchaOptionsConfig:
    def test_normalize_includes_recaptcha(self):
        policy = {
            "recaptcha_options_config": {"redirect_site_key": "key123"},
            "rules": [{"priority": 2147483647, "action": "allow"}],
        }
        result = normalize_policy_settings(policy)
        assert result["recaptcha_options_config"] == {"redirect_site_key": "key123"}

    def test_normalize_without_recaptcha(self):
        policy = {"rules": [{"priority": 2147483647, "action": "allow"}]}
        result = normalize_policy_settings(policy)
        assert "recaptcha_options_config" not in result

    def test_denormalize_includes_recaptcha(self):
        settings = {"recaptcha_options_config": {"redirect_site_key": "key123"}}
        result = denormalize_policy_settings(settings)
        assert "policy_fields" in result
        assert result["policy_fields"]["recaptcha_options_config"] == {
            "redirect_site_key": "key123"
        }

    def test_denormalize_recaptcha_with_other_fields(self):
        settings = {
            "recaptcha_options_config": {"redirect_site_key": "key123"},
            "default_rule_action": "deny(403)",
        }
        result = denormalize_policy_settings(settings)
        assert result["policy_fields"]["recaptcha_options_config"] == {
            "redirect_site_key": "key123"
        }
        assert result["default_rule_action"] == "deny(403)"

    def test_round_trip(self):
        policy = {
            "recaptcha_options_config": {"redirect_site_key": "key123"},
            "rules": [{"priority": 2147483647, "action": "allow"}],
        }
        normalized = normalize_policy_settings(policy)
        denormalized = denormalize_policy_settings(normalized)
        assert denormalized["policy_fields"]["recaptcha_options_config"] == {
            "redirect_site_key": "key123"
        }


# ---------------------------------------------------------------------------
# Validate extension — deny(429) default action
# ---------------------------------------------------------------------------
class TestValidateDeny429:
    def test_deny_429_is_valid(self):
        desired = {"gcloud_armor_policy_settings": {"default_rule_action": "deny(429)"}}
        errors: list[str] = []
        _validate_policy_settings(desired, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Registration idempotency
# ---------------------------------------------------------------------------
class TestRegistration:
    def test_register_is_idempotent(self):
        """Calling register_policy_settings() twice does not raise."""
        from octorules_google._policy_settings import register_policy_settings

        register_policy_settings()
        register_policy_settings()
