"""Google Cloud Armor lint plugin — orchestrates all GCloud-specific linter checks."""

from __future__ import annotations

from typing import Any

from octorules.linter.engine import LintContext
from octorules.phases import PHASE_BY_NAME

from octorules_google.linter._rules import GA_RULE_METAS
from octorules_google.validate import validate_rules

# Phase names owned by this provider.
_GCLOUD_PHASE_NAMES = frozenset(
    {
        "gcloud_armor_custom_rules",
        "gcloud_armor_rate_rules",
        "gcloud_armor_preconfigured_rules",
        "gcloud_armor_redirect_rules",
    }
)

GA_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in GA_RULE_METAS)


def google_lint(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Google Cloud Armor lint checks on a zone rules file."""
    for phase_name, rules in rules_data.items():
        if phase_name not in _GCLOUD_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        results = validate_rules(rules, phase=phase_name)
        for result in results:
            ctx.add(result)
