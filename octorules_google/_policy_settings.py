"""Policy settings management for Google Cloud Armor security policies.

These are non-phase YAML sections handled via extension hooks:
- ``gcloud_armor_policy_settings`` — adaptive protection, advanced options,
  DDoS config, and the default rule action

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension — same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.
"""

import logging

from octorules.extensions import ProviderExtension, SettingsChange, SettingsFormatter, SettingsPlan
from octorules.registration import idempotent_registration

log = logging.getLogger(__name__)

_EXT_KEY = "google.policy_settings"

# The default rule is the rule at the maximum priority (managed by GCP).
_DEFAULT_RULE_PRIORITY = 2147483647


# ---------------------------------------------------------------------------
# Data model for policy settings diffs (subclass core framework classes)
# ---------------------------------------------------------------------------
class PolicySettingsChange(SettingsChange):
    """A single field change in policy settings."""

    pass


class PolicySettingsPlan(SettingsPlan):
    """Plan for all policy settings changes in a zone."""

    pass


# ---------------------------------------------------------------------------
# Valid enum values
# ---------------------------------------------------------------------------
_VALID_DEFAULT_ACTIONS = frozenset({"allow", "deny(403)", "deny(404)", "deny(429)", "deny(502)"})
_VALID_DDOS_PROTECTION = frozenset({"STANDARD", "ADVANCED", "ADVANCED_PREVIEW"})
_VALID_JSON_PARSING = frozenset({"DISABLED", "STANDARD", "STANDARD_WITH_GRAPHQL"})
_VALID_LOG_LEVELS = frozenset({"NORMAL", "VERBOSE"})
_VALID_RULE_VISIBILITY = frozenset({"PREMIUM", "STANDARD"})


# ---------------------------------------------------------------------------
# Normalization: policy dict -> YAML-friendly canonical form
# ---------------------------------------------------------------------------
def normalize_policy_settings(policy: dict) -> dict:
    """Convert a full security policy dict to YAML-friendly settings.

    Extracts ``adaptive_protection_config``, ``advanced_options_config``,
    ``ddos_protection_config``, ``recaptcha_options_config`` (pass through
    as nested dicts), and ``default_rule_action`` (extracted from the rule
    at priority 2147483647).
    """
    result: dict = {}

    if "adaptive_protection_config" in policy:
        result["adaptive_protection_config"] = policy["adaptive_protection_config"]
    if "advanced_options_config" in policy:
        result["advanced_options_config"] = policy["advanced_options_config"]
    if "ddos_protection_config" in policy:
        result["ddos_protection_config"] = policy["ddos_protection_config"]
    if "recaptcha_options_config" in policy:
        result["recaptcha_options_config"] = policy["recaptcha_options_config"]

    # Extract default rule action
    for rule in policy.get("rules", []):
        if rule.get("priority") == _DEFAULT_RULE_PRIORITY:
            result["default_rule_action"] = rule.get("action", "allow")
            break

    return result


# ---------------------------------------------------------------------------
# Denormalization: YAML canonical form -> API patch payloads
# ---------------------------------------------------------------------------
def denormalize_policy_settings(settings: dict) -> dict:
    """Convert YAML canonical form back to API-ready format.

    Only includes keys that are present in *settings* so that partial
    updates don't reset unspecified fields to defaults.

    ``default_rule_action`` is separated from the policy-level fields
    because it requires patching the default rule, not the policy
    resource itself.

    Returns a dict with two possible keys:
    - ``policy_fields``: fields to patch on the policy resource
    - ``default_rule_action``: the action to set on the default rule
    """
    if not settings:
        return {}

    result: dict = {}
    policy_fields: dict = {}

    for key in (
        "adaptive_protection_config",
        "advanced_options_config",
        "ddos_protection_config",
        "recaptcha_options_config",
    ):
        if key in settings:
            policy_fields[key] = settings[key]

    if policy_fields:
        result["policy_fields"] = policy_fields

    if "default_rule_action" in settings:
        result["default_rule_action"] = settings["default_rule_action"]

    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_policy_settings(current: dict, desired: dict) -> PolicySettingsPlan:
    """Diff current vs desired policy settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    changes: list[PolicySettingsChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(PolicySettingsChange(field=key, current=cur, desired=des))
    return PolicySettingsPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_policy_settings(all_desired, scope, provider):
    """Prefetch: fetch current policy settings."""
    desired = all_desired.get(_EXT_KEY)
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_policy_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch policy settings for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_policy_settings(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_policy_settings(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault(_EXT_KEY, []).append(plan)


def _apply_policy_settings(zp, plans, scope, provider):
    """Apply policy settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, PolicySettingsPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_policy_settings(scope, desired_values)
            synced.append(_EXT_KEY)

    return synced, None


def _validate_policy_settings(desired, zone_name, errors, lines):
    """Validate gcloud_armor_policy_settings offline."""
    settings = desired.get(_EXT_KEY)
    if not isinstance(settings, dict):
        return

    # default_rule_action
    action = settings.get("default_rule_action")
    if action is not None and action not in _VALID_DEFAULT_ACTIONS:
        errors.append(
            f"  {zone_name}/{_EXT_KEY}: invalid"
            f" default_rule_action {action!r}"
            f" (must be one of {sorted(_VALID_DEFAULT_ACTIONS)})"
        )

    # ddos_protection_config.ddos_protection
    ddos_cfg = settings.get("ddos_protection_config")
    if isinstance(ddos_cfg, dict):
        ddos_val = ddos_cfg.get("ddos_protection")
        if ddos_val is not None and ddos_val not in _VALID_DDOS_PROTECTION:
            errors.append(
                f"  {zone_name}/{_EXT_KEY}: invalid"
                f" ddos_protection_config.ddos_protection {ddos_val!r}"
                f" (must be one of {sorted(_VALID_DDOS_PROTECTION)})"
            )

    # advanced_options_config.json_parsing and log_level
    adv_cfg = settings.get("advanced_options_config")
    if isinstance(adv_cfg, dict):
        jp_val = adv_cfg.get("json_parsing")
        if jp_val is not None and jp_val not in _VALID_JSON_PARSING:
            errors.append(
                f"  {zone_name}/{_EXT_KEY}: invalid"
                f" advanced_options_config.json_parsing {jp_val!r}"
                f" (must be one of {sorted(_VALID_JSON_PARSING)})"
            )
        ll_val = adv_cfg.get("log_level")
        if ll_val is not None and ll_val not in _VALID_LOG_LEVELS:
            errors.append(
                f"  {zone_name}/{_EXT_KEY}: invalid"
                f" advanced_options_config.log_level {ll_val!r}"
                f" (must be one of {sorted(_VALID_LOG_LEVELS)})"
            )

    # adaptive_protection_config sub-structure
    ap_cfg = settings.get("adaptive_protection_config")
    if isinstance(ap_cfg, dict):
        l7_cfg = ap_cfg.get("layer7_ddos_defense_config")
        if isinstance(l7_cfg, dict):
            enable_val = l7_cfg.get("enable")
            if enable_val is not None and not isinstance(enable_val, bool):
                errors.append(
                    f"  {zone_name}/{_EXT_KEY}: invalid"
                    f" adaptive_protection_config.layer7_ddos_defense_config.enable"
                    f" {enable_val!r} (must be a bool)"
                )
            rv_val = l7_cfg.get("rule_visibility")
            if rv_val is not None and rv_val not in _VALID_RULE_VISIBILITY:
                errors.append(
                    f"  {zone_name}/{_EXT_KEY}: invalid"
                    f" adaptive_protection_config.layer7_ddos_defense_config.rule_visibility"
                    f" {rv_val!r} (must be one of {sorted(_VALID_RULE_VISIBILITY)})"
                )

    rc_cfg = settings.get("recaptcha_options_config")
    if rc_cfg is not None and not isinstance(rc_cfg, dict):
        errors.append(
            f"  {zone_name}/{_EXT_KEY}: recaptcha_options_config must be a mapping,"
            f" got {type(rc_cfg).__name__}"
        )


def _dump_policy_settings(scope, provider):
    """Export current policy settings to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_policy_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if settings:
        return {_EXT_KEY: settings}
    return None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class PolicySettingsFormatter(SettingsFormatter):
    """Formats policy settings diffs for plan output.

    Subclasses the core SettingsFormatter with parameters fixed for
    Google Cloud Armor policy settings:
    - prefix: "policy_settings" (for labels like "policy_settings.field")
    - phase: "policy_settings"
    - provider_id: "google.policy_settings"
    """

    def __init__(self) -> None:
        """Initialize with Google Cloud Armor policy settings parameters."""
        super().__init__(
            plan_type=PolicySettingsPlan,
            prefix="policy_settings",
        )


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class PolicySettingsExtension(ProviderExtension):
    """Cloud Armor policy-level settings."""

    section = "google.policy_settings"
    formatter = PolicySettingsFormatter()

    def prefetch(self, desired, scope, provider):
        return _prefetch_policy_settings(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_policy_settings(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_policy_settings(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_policy_settings(scope, provider)

    def validate(self, desired, zone_name, errors, lines):
        return _validate_policy_settings(desired, zone_name, errors, lines)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_policy_settings() -> None:
    """Register all policy settings hooks with the core extension system."""
    from octorules.extensions import (
        register_apply_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_policy_settings, _finalize_policy_settings)
    register_apply_extension(_EXT_KEY, _apply_policy_settings)
    register_format_extension(_EXT_KEY, PolicySettingsFormatter())
    register_validate_extension(_validate_policy_settings)
