"""Google Cloud Armor provider for octorules.

Maps octorules concepts to Cloud Armor security policies:
  - Zones → Security policies (resolve_zone_id looks up by name)
  - Phases → Rule types within a policy (custom / rate / preconfigured)
  - Custom rulesets / Lists → Not supported
"""

from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING

from google.api_core.exceptions import Forbidden, GoogleAPIError, NotFound, Unauthorized
from google.auth.exceptions import DefaultCredentialsError
from octorules.config import ConfigError

if TYPE_CHECKING:
    from google.cloud import compute_v1
from octorules.phases import Phase
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.utils import (
    denormalize_fields,
    make_error_wrapper,
    normalize_fields,
    to_plain_dict,
)
from octorules.retry import retry_with_backoff

log = logging.getLogger(__name__)

# Phase definitions for Google Cloud Armor — single source of truth.
# __init__.py imports _GCLOUD_PHASES for registration; _GCLOUD_PHASE_IDS is
# derived here so the two can never drift out of sync.

_GCLOUD_PHASES = [
    Phase(
        "google.custom_rules",
        "gcloud_armor_custom",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "google.rate_rules",
        "gcloud_armor_rate",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "google.preconfigured_rules",
        "gcloud_armor_preconfigured",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "google.redirect_rules",
        "gcloud_armor_redirect",
        None,
        zone_level=True,
        account_level=False,
    ),
]

_GCLOUD_PHASE_IDS = frozenset(p.provider_id for p in _GCLOUD_PHASES)

# The default rule (priority 2147483647) is managed by GCP, not octorules.
_DEFAULT_RULE_PRIORITY = 2147483647
_wrap_provider_errors = make_error_wrapper(
    auth_errors=(Unauthorized, Forbidden, DefaultCredentialsError),
    connection_errors=(ConnectionError, OSError),
    generic_errors=(GoogleAPIError,),
)

# Auth errors should NOT be retried.
_NO_RETRY_ERRORS = (Unauthorized, Forbidden, DefaultCredentialsError, NotFound)
_RETRY_BACKOFF = (1.0, 2.0, 4.0)


def _retry_transient(fn, *, label: str, retries: int = 2):
    """Call *fn* with retry on transient GoogleAPIError.

    Auth/NotFound errors propagate immediately.  Delegates to
    :func:`octorules.retry.retry_with_backoff` for the actual retry loop.
    """

    def _guarded():
        try:
            return fn()
        except _NO_RETRY_ERRORS:
            raise

    return retry_with_backoff(
        _guarded,
        retryable=(GoogleAPIError, ConnectionError, OSError),
        max_attempts=retries + 1,
        backoff=_RETRY_BACKOFF,
        label=label,
    )


# ---------------------------------------------------------------------------
# Tier detection
# ---------------------------------------------------------------------------


def _detect_tier(policy: dict) -> str:
    """Detect the Cloud Armor tier from a SecurityPolicy dict.

    Heuristic:
    - No ``ddos_protection_config`` or ddos_protection is not ADVANCED/ADVANCED_PREVIEW
      → ``"standard"``
    - ADVANCED or ADVANCED_PREVIEW with layer7 rule_visibility ``"PREMIUM"``
      → ``"enterprise"``
    - ADVANCED or ADVANCED_PREVIEW otherwise → ``"plus"``
    """
    ddos_cfg = policy.get("ddos_protection_config") or {}
    ddos_protection = ddos_cfg.get("ddos_protection", "")
    if ddos_protection not in ("ADVANCED", "ADVANCED_PREVIEW"):
        return "standard"
    adaptive = policy.get("adaptive_protection_config") or {}
    layer7 = adaptive.get("layer7_ddos_defense_config") or {}
    if layer7.get("rule_visibility") == "PREMIUM":
        return "enterprise"
    return "plus"


# ---------------------------------------------------------------------------
# Rule classification
# ---------------------------------------------------------------------------
def _is_rate_rule(rule: dict) -> bool:
    """True if the rule uses rate limiting (rateLimitOptions with enforce action)."""
    return rule.get("action") in ("rate_based_ban", "throttle")


def _is_preconfigured_rule(rule: dict) -> bool:
    """True if the rule references preconfigured WAF expressions.

    Preconfigured rules use ``match.expr.expression`` containing
    ``evaluatePreconfiguredWaf(...)`` or ``evaluatePreconfiguredExpr(...)``.
    """
    match = rule.get("match", {})
    expr = match.get("expr", {})
    expression = expr.get("expression", "")
    return "evaluatePreconfiguredWaf(" in expression or "evaluatePreconfiguredExpr(" in expression


def _is_redirect_rule(rule: dict) -> bool:
    """True if the rule uses a redirect action (reCAPTCHA challenge or external 302)."""
    return rule.get("action") == "redirect"


_KNOWN_CUSTOM_ACTIONS = frozenset({"allow"})


def _classify_phase(rule: dict) -> str:
    """Return the Cloud Armor phase id for a rule."""
    if _is_rate_rule(rule):
        return "gcloud_armor_rate"
    if _is_redirect_rule(rule):
        return "gcloud_armor_redirect"
    if _is_preconfigured_rule(rule):
        return "gcloud_armor_preconfigured"
    action = rule.get("action")
    if action and action not in _KNOWN_CUSTOM_ACTIONS and not str(action).startswith("deny("):
        log.warning(
            "Unrecognized action %r for rule priority %s, classifying as custom_rules",
            action,
            rule.get("priority", rule.get("ref", "?")),
        )
    return "gcloud_armor_custom"


# ---------------------------------------------------------------------------
# Rule normalization
# ---------------------------------------------------------------------------

_GCLOUD_FIELD_MAP = {"priority": "ref"}


def _normalize_rule(rule) -> dict:
    """Convert a Cloud Armor SecurityPolicyRule to an octorules dict.

    Maps ``priority`` to ``ref`` (string) since Cloud Armor rules are
    identified by their integer priority.  Accepts both proto-plus objects
    and plain dicts.
    """
    d = to_plain_dict(rule)
    d = normalize_fields(d, _GCLOUD_FIELD_MAP)
    # Cloud Armor priorities are ints; octorules refs are strings.
    d["ref"] = str(d.get("ref", ""))
    return d


def _denormalize_rule(rule: dict) -> dict:
    """Convert an octorules dict back to Cloud Armor format (ref -> priority)."""
    d = dict(rule)
    # octorules refs are strings; Cloud Armor priorities are ints.
    ref_str = d.get("ref", "0")
    try:
        d["ref"] = int(ref_str)
    except (ValueError, TypeError) as e:
        raise ConfigError(
            f"Invalid rule ref {ref_str!r}: Cloud Armor rule priorities"
            f" must be numeric strings (e.g., '100')"
        ) from e
    d = denormalize_fields(d, _GCLOUD_FIELD_MAP)
    return d


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------
class CloudArmorProvider:
    """Google Cloud Armor provider for octorules.

    Maps octorules concepts to Cloud Armor:
      - Zones → Security policies (resolve_zone_id looks up by name)
      - Phases → Rule types (custom / rate-limit / preconfigured WAF)
      - Custom rulesets, Lists → Not supported

    Authentication uses Google Application Default Credentials (ADC).
    The ``token`` parameter is accepted for BaseProvider compatibility
    but not used for auth.
    """

    NAMESPACE: str = "google"
    SUPPORTS: frozenset[str] = frozenset({"zone_discovery"})

    # Built lazily by the `extensions` property.
    _extensions: list | None = None

    def __init__(
        self,
        *,
        timeout: float | None = None,
        max_workers: int = 1,
        client: compute_v1.SecurityPoliciesClient | None = None,
        project: str | None = None,
        **_extra: object,
    ) -> None:
        if client is None:
            # Deferred: google.cloud.compute_v1 takes ~0.6-1.0 s to import
            # (protobuf schema modules). Lint-only runs import this package
            # to register rules and never construct a provider, so the SDK
            # must not load at module import time.
            from google.cloud import compute_v1

            client = compute_v1.SecurityPoliciesClient()
        self._client = client
        self._project = project or os.environ.get("GCLOUD_PROJECT", "")
        if not self._project:
            raise ConfigError(
                "GCP project not specified"
                " (set 'project' in provider config or GCLOUD_PROJECT env var)"
            )
        self._max_workers = max_workers
        self._timeout = timeout if timeout is not None else 30.0
        self._zone_plans: dict[str, str] = {}
        self._lock = threading.Lock()

    # -- Properties --

    @property
    def max_workers(self) -> int:
        """Maximum number of concurrent workers for this provider."""
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        """Return None; Cloud Armor has no account-level scope."""
        return None

    @property
    def account_name(self) -> str | None:
        """Return None; Cloud Armor has no account-level scope."""
        return None

    @property
    def zone_plans(self) -> dict[str, str]:
        """Zone tiers detected from policy properties."""
        return dict(self._zone_plans)

    # -- Helpers --

    def _get_policy(self, scope: Scope) -> dict:
        """Fetch a security policy as a dict."""
        policy_name = scope.zone_id
        response = self._client.get(
            project=self._project,
            security_policy=policy_name,
            timeout=self._timeout,
        )
        return to_plain_dict(response)

    def _get_rules(self, scope: Scope) -> list[dict]:
        """Fetch all non-default rules from a security policy."""
        policy = self._get_policy(scope)
        rules = policy.get("rules", [])
        return [r for r in rules if r.get("priority") != _DEFAULT_RULE_PRIORITY]

    # -- Policy settings --

    @_wrap_provider_errors
    def get_policy_settings(self, scope: Scope) -> dict:
        """Fetch and normalize policy-level settings."""
        from octorules_google._policy_settings import normalize_policy_settings

        policy = self._get_policy(scope)
        log.debug("GET policy_settings %s", scope.zone_id)
        return normalize_policy_settings(policy)

    @_wrap_provider_errors
    def update_policy_settings(self, scope: Scope, settings: dict) -> None:
        """Update policy settings via patch.

        Handles two types of changes:
        - Policy-level fields (adaptive_protection_config, etc.) are
          patched on the policy resource directly.
        - ``default_rule_action`` requires fetching the policy, updating
          the default rule's action, and patching the policy with the
          modified rule.
        """
        from octorules_google._policy_settings import denormalize_policy_settings

        payload = denormalize_policy_settings(settings)
        if not payload:
            return

        policy_name = scope.zone_id

        # Build the SecurityPolicy resource to patch.
        patch_resource: dict = {}

        # Policy-level config fields
        policy_fields = payload.get("policy_fields")
        if policy_fields:
            patch_resource.update(policy_fields)

        # Default rule action: fetch current policy and update the
        # default rule's action field.
        default_action = payload.get("default_rule_action")
        if default_action is not None:
            policy = _retry_transient(
                lambda: self._get_policy(scope),
                label=f"get_policy({policy_name})",
            )
            rules = policy.get("rules", [])
            updated_rules = []
            for rule in rules:
                if rule.get("priority") == _DEFAULT_RULE_PRIORITY:
                    rule = dict(rule)
                    rule["action"] = default_action
                updated_rules.append(rule)
            patch_resource["rules"] = updated_rules

        if patch_resource:
            _retry_transient(
                lambda: self._client.patch(
                    project=self._project,
                    security_policy=policy_name,
                    security_policy_resource=patch_resource,
                    timeout=self._timeout,
                ),
                label=f"update_policy_settings {policy_name}",
            )
            log.debug("Updated policy settings for %s", policy_name)

    # -- Zone resolution --

    @_wrap_provider_errors
    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a security policy name to itself (Cloud Armor uses names).

        Verifies the policy exists and detects the Cloud Armor tier.
        Raises ConfigError if not found.
        """
        try:
            response = self._client.get(
                project=self._project,
                security_policy=zone_name,
                timeout=self._timeout,
            )
        except NotFound:
            raise ConfigError(f"No security policy found for {zone_name!r}") from None
        policy = to_plain_dict(response)
        tier = _detect_tier(policy)
        with self._lock:
            self._zone_plans[zone_name] = tier
        log.debug("Resolved %s -> %s (tier=%s)", zone_name, zone_name, tier)
        return zone_name

    @_wrap_provider_errors
    def list_zones(self) -> list[str]:
        """List all security policy names in the project."""
        response = self._client.list(
            project=self._project,
            timeout=self._timeout,
        )
        result = [policy.name for policy in response]
        log.debug("list_zones: %d policies in project %s", len(result), self._project)
        return result

    # -- Phase rules --

    @_wrap_provider_errors
    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]:
        """Get rules from a security policy filtered by phase type."""
        if provider_id not in _GCLOUD_PHASE_IDS:
            return []
        rules = self._get_rules(scope)
        result = [_normalize_rule(r) for r in rules if _classify_phase(r) == provider_id]
        log.debug("get_phase_rules %s/%s: %d rules", scope.zone_id, provider_id, len(result))
        return result

    @_wrap_provider_errors
    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int:
        """Replace rules of a specific phase type in a security policy.

        Cloud Armor doesn't support atomic bulk replacement. To minimise the
        window of inconsistency this method:

        1. Patches rules whose priority exists in both old and new sets.

        **Design limitation (G1):** If a step fails partway through, the
        policy is left in a mixed state (some rules patched, new rules
        partially added, stale rules not yet removed). This is inherent to
        per-rule CRUD without transactional support. The next successful
        sync will reconcile the state. Partial progress is logged at ERROR
        level so operators know exactly what succeeded before the failure.
        2. Adds rules with new priorities (policy briefly has *extra* rules).
        3. Removes old priorities that are no longer needed.

        This guarantees the policy never has *fewer* rules than intended.
        If a step fails partway through, the policy may have stale rules
        until the next successful sync.
        """
        current_rules = self._get_rules(scope)
        policy_name = scope.zone_id

        old_by_pri: dict[int, dict] = {}
        for r in current_rules:
            if _classify_phase(r) == provider_id:
                old_by_pri[r["priority"]] = r

        new_by_pri: dict[int, dict] = {}
        for rule in rules:
            gcloud_rule = _denormalize_rule(rule)
            new_by_pri[gcloud_rule["priority"]] = gcloud_rule

        patched: list[int] = []
        added: list[int] = []
        removed: list[int] = []

        try:
            # 1. Patch in-place (priority exists in both old and new)
            for pri, gcloud_rule in new_by_pri.items():
                if pri in old_by_pri:
                    _retry_transient(
                        lambda _p=pri, _r=gcloud_rule: self._client.patch_rule(
                            project=self._project,
                            security_policy=policy_name,
                            priority=_p,
                            security_policy_rule_resource=_r,
                            timeout=self._timeout,
                        ),
                        label=f"patch rule priority={pri} in {policy_name}",
                    )
                    patched.append(pri)

            # 2. Add new priorities (not in old set)
            for pri, gcloud_rule in new_by_pri.items():
                if pri not in old_by_pri:
                    _retry_transient(
                        lambda _p=pri, _r=gcloud_rule: self._client.add_rule(
                            project=self._project,
                            security_policy=policy_name,
                            security_policy_rule_resource=_r,
                            timeout=self._timeout,
                        ),
                        label=f"add rule priority={pri} to {policy_name}",
                    )
                    added.append(pri)

            # 3. Remove old priorities (not in new set)
            for pri in old_by_pri:
                if pri not in new_by_pri:
                    _retry_transient(
                        lambda _p=pri: self._client.remove_rule(
                            request={
                                "project": self._project,
                                "security_policy": policy_name,
                                "priority": _p,
                            },
                            timeout=self._timeout,
                        ),
                        label=f"remove rule priority={pri} from {policy_name}",
                    )
                    removed.append(pri)
        except (GoogleAPIError, DefaultCredentialsError, ConnectionError, OSError):
            # Log what succeeded before the failure so the user knows
            # the policy state.  The error itself propagates.
            log.error(
                "put_phase_rules %s/%s PARTIAL FAILURE: "
                "patched=%s added=%s removed=%s (of %d total rules)",
                policy_name,
                provider_id,
                patched,
                added,
                removed,
                len(rules),
            )
            raise

        if patched or added or removed:
            log.debug(
                "put_phase_rules %s/%s: patched=%s added=%s removed=%s",
                policy_name,
                provider_id,
                patched,
                added,
                removed,
            )

        return len(rules)

    @_wrap_provider_errors
    def get_all_phase_rules(
        self, scope: Scope, *, provider_ids: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for all Cloud Armor phases from a security policy."""
        phases_to_fetch = provider_ids if provider_ids is not None else list(_GCLOUD_PHASE_IDS)
        phases_to_fetch = [p for p in phases_to_fetch if p in _GCLOUD_PHASE_IDS]

        if not phases_to_fetch:
            return PhaseRulesResult({}, failed_phases=[])

        log.debug("Fetching %d phase(s) for %s", len(phases_to_fetch), scope.zone_id)
        all_rules = self._get_rules(scope)

        result: dict[str, list[dict]] = {}
        for phase_id in phases_to_fetch:
            phase_rules = [_normalize_rule(r) for r in all_rules if _classify_phase(r) == phase_id]
            if phase_rules:
                result[phase_id] = phase_rules

        return PhaseRulesResult(result, failed_phases=[])

    # -- Custom rulesets (not supported by Cloud Armor) --

    @_wrap_provider_errors
    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        """Return empty list; Cloud Armor does not support custom rulesets."""
        return []

    @_wrap_provider_errors
    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]:
        """Return empty list; Cloud Armor does not support custom rulesets."""
        return []

    @_wrap_provider_errors
    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        """Raise ConfigError; Cloud Armor does not support custom rulesets."""
        raise ConfigError("Custom rulesets are not supported by Cloud Armor")

    @_wrap_provider_errors
    def create_custom_ruleset(
        self, scope: Scope, name: str, phase: str, capacity: int, description: str = ""
    ) -> dict:
        """Raise ConfigError; Cloud Armor does not support custom rulesets."""
        raise ConfigError("Custom rulesets are not supported by Cloud Armor")

    @_wrap_provider_errors
    def delete_custom_ruleset(self, scope: Scope, ruleset_id: str) -> None:
        """Raise ConfigError; Cloud Armor does not support custom rulesets."""
        raise ConfigError("Custom rulesets are not supported by Cloud Armor")

    @_wrap_provider_errors
    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        """Return empty dict; Cloud Armor does not support custom rulesets."""
        return {}

    # -- Lists (not supported — Cloud Armor uses inline IP ranges) --

    @_wrap_provider_errors
    def list_lists(self, scope: Scope) -> list[dict]:
        """Return empty list; Cloud Armor uses inline IP ranges, not lists."""
        return []

    @_wrap_provider_errors
    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        """Raise ConfigError; Cloud Armor uses inline IP ranges, not lists."""
        raise ConfigError("Lists are not supported by Cloud Armor (use inline IP ranges)")

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Raise ConfigError; Cloud Armor does not support lists."""
        raise ConfigError("Lists are not supported by Cloud Armor (use inline IP ranges)")

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Raise ConfigError; Cloud Armor does not support lists."""
        raise ConfigError("Lists are not supported by Cloud Armor (use inline IP ranges)")

    @_wrap_provider_errors
    def get_list_items(self, scope: Scope, list_id: str) -> list[dict]:
        """Return empty list; Cloud Armor does not support lists."""
        return []

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Raise ConfigError; Cloud Armor does not support lists."""
        raise ConfigError("Lists are not supported by Cloud Armor (use inline IP ranges)")

    @_wrap_provider_errors
    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        """Return 'completed'; Cloud Armor has no async bulk operations."""
        return "completed"

    @_wrap_provider_errors
    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        """Return empty dict; Cloud Armor does not support lists."""
        return {}

    # --- Extensions ---

    @property
    def extensions(self) -> list:
        """Cloud Armor's own provider extensions.

        Core walks this instead of a global registry, so an extension is
        only ever handed the provider that owns it.
        """
        from octorules_google._policy_settings import PolicySettingsExtension

        if self._extensions is None:
            self._extensions = [
                PolicySettingsExtension(),
            ]
        return self._extensions

    # --- Dump ---

    def dump_extra_sections(self, scope: Scope) -> dict:
        """Cloud Armor-owned sections for the dumped zone file."""
        result: dict = {}
        for ext in self.extensions:
            data = ext.dump(scope, self)
            if data:
                result.update(data)
        return result
