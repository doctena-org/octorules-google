"""Google Cloud Armor provider for octorules.

Maps octorules concepts to Cloud Armor security policies:
  - Zones → Security policies (resolve_zone_id looks up by name)
  - Phases → Rule types within a policy (custom / rate / preconfigured)
  - Custom rulesets / Lists → Not supported
"""

from __future__ import annotations

import logging
import os

from google.api_core.exceptions import Forbidden, GoogleAPIError, NotFound, Unauthorized
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import compute_v1
from octorules.config import ConfigError
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderError
from octorules.provider.utils import make_error_wrapper

log = logging.getLogger(__name__)

# Phase identifiers registered by this provider.
_GCLOUD_PHASE_IDS = frozenset(
    {
        "gcloud_armor_custom",
        "gcloud_armor_rate",
        "gcloud_armor_preconfigured",
        "gcloud_armor_redirect",
    }
)

# The default rule (priority 2147483647) is managed by GCP, not octorules.
_DEFAULT_RULE_PRIORITY = 2147483647


_wrap_provider_errors = make_error_wrapper(
    auth_errors=(Unauthorized, Forbidden, DefaultCredentialsError),
    connection_errors=(ConnectionError, OSError),
    generic_errors=(GoogleAPIError,),
)


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


def _classify_phase(rule: dict) -> str:
    """Return the Cloud Armor phase id for a rule."""
    if _is_rate_rule(rule):
        return "gcloud_armor_rate"
    if _is_redirect_rule(rule):
        return "gcloud_armor_redirect"
    if _is_preconfigured_rule(rule):
        return "gcloud_armor_preconfigured"
    return "gcloud_armor_custom"


# ---------------------------------------------------------------------------
# Rule normalization
# ---------------------------------------------------------------------------


def _normalize_rule(rule) -> dict:
    """Convert a Cloud Armor SecurityPolicyRule to an octorules dict.

    Maps ``priority`` to ``ref`` (string) since Cloud Armor rules are
    identified by their integer priority.  Accepts both proto-plus objects
    and plain dicts.
    """
    if hasattr(rule, "to_dict") and not isinstance(rule, dict):
        # Proto-plus object — convert via to_dict()
        d = type(rule).to_dict(rule)
    else:
        d = dict(rule)
    d["ref"] = str(d.pop("priority", ""))
    return d


def _denormalize_rule(rule: dict) -> dict:
    """Convert an octorules dict back to Cloud Armor format (ref -> priority)."""
    d = dict(rule)
    d["priority"] = int(d.pop("ref", "0"))
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

    SUPPORTS: frozenset[str] = frozenset({"zone_discovery"})

    def __init__(
        self,
        *,
        timeout: float | None = None,
        max_workers: int = 1,
        client: compute_v1.SecurityPoliciesClient | None = None,
        project: str | None = None,
        **_extra: object,
    ):
        self._client = client or compute_v1.SecurityPoliciesClient()
        self._project = project or os.environ.get("GCLOUD_PROJECT", "")
        if not self._project:
            raise ConfigError(
                "GCP project not specified"
                " (set 'project' in provider config or GCLOUD_PROJECT env var)"
            )
        self._max_workers = max_workers
        self._timeout = timeout or 30.0

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
        """Return empty dict; Cloud Armor has no zone plan tiers."""
        return {}

    # -- Helpers --

    def _get_policy(self, scope: Scope) -> dict:
        """Fetch a security policy as a dict."""
        policy_name = scope.zone_id
        response = self._client.get(
            project=self._project,
            security_policy=policy_name,
            timeout=self._timeout,
        )
        if isinstance(response, dict):
            return response
        # Proto-plus objects have to_dict on the class (metaclass method).
        return type(response).to_dict(response)

    def _get_rules(self, scope: Scope) -> list[dict]:
        """Fetch all non-default rules from a security policy."""
        policy = self._get_policy(scope)
        rules = policy.get("rules", [])
        return [r for r in rules if r.get("priority") != _DEFAULT_RULE_PRIORITY]

    # -- Zone resolution --

    @_wrap_provider_errors
    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a security policy name to itself (Cloud Armor uses names).

        Verifies the policy exists. Raises ConfigError if not found.
        """
        try:
            self._client.get(
                project=self._project,
                security_policy=zone_name,
                timeout=self._timeout,
            )
        except NotFound:
            raise ConfigError(f"No security policy found for {zone_name!r}") from None
        return zone_name

    @_wrap_provider_errors
    def list_zones(self) -> list[str]:
        """List all security policy names in the project."""
        response = self._client.list(
            project=self._project,
            timeout=self._timeout,
        )
        return [policy.name for policy in response]

    # -- Phase rules --

    @_wrap_provider_errors
    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]:
        """Get rules from a security policy filtered by phase type."""
        if provider_id not in _GCLOUD_PHASE_IDS:
            return []
        rules = self._get_rules(scope)
        return [_normalize_rule(r) for r in rules if _classify_phase(r) == provider_id]

    @_wrap_provider_errors
    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int:
        """Replace rules of a specific phase type in a security policy.

        Cloud Armor doesn't support atomic bulk replacement. To minimise the
        window of inconsistency this method:

        1. Patches rules whose priority exists in both old and new sets.
        2. Adds rules with new priorities (policy briefly has *extra* rules).
        3. Removes old priorities that are no longer needed.

        This guarantees the policy never has *fewer* rules than intended.
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

        # 1. Patch in-place (priority exists in both old and new)
        for pri, gcloud_rule in new_by_pri.items():
            if pri in old_by_pri:
                self._client.patch_rule(
                    project=self._project,
                    security_policy=policy_name,
                    priority=pri,
                    security_policy_rule_resource=gcloud_rule,
                    timeout=self._timeout,
                )

        # 2. Add new priorities (not in old set)
        for pri, gcloud_rule in new_by_pri.items():
            if pri not in old_by_pri:
                self._client.add_rule(
                    project=self._project,
                    security_policy=policy_name,
                    security_policy_rule_resource=gcloud_rule,
                    timeout=self._timeout,
                )

        # 3. Remove old priorities (not in new set)
        for pri in old_by_pri:
            if pri not in new_by_pri:
                self._client.remove_rule(
                    request={
                        "project": self._project,
                        "security_policy": policy_name,
                        "priority": pri,
                    },
                    timeout=self._timeout,
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
        """Raise ProviderError; Cloud Armor does not support custom rulesets."""
        raise ProviderError("Custom rulesets are not supported by Cloud Armor")

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
        """Raise ProviderError; Cloud Armor uses inline IP ranges, not lists."""
        raise ProviderError("Lists are not supported by Cloud Armor (use inline IP ranges)")

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Raise ProviderError; Cloud Armor does not support lists."""
        raise ProviderError("Lists are not supported by Cloud Armor")

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Raise ProviderError; Cloud Armor does not support lists."""
        raise ProviderError("Lists are not supported by Cloud Armor")

    @_wrap_provider_errors
    def get_list_items(self, scope: Scope, list_id: str) -> list[dict]:
        """Return empty list; Cloud Armor does not support lists."""
        return []

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Raise ProviderError; Cloud Armor does not support lists."""
        raise ProviderError("Lists are not supported by Cloud Armor")

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
