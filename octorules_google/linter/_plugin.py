"""Google Cloud Armor lint plugin — orchestrates all GCloud-specific linter checks."""

from typing import Any

from octorules.linter.engine import LintContext
from octorules.phases import PHASE_BY_NAME

from octorules_google import GCLOUD_PHASE_NAMES
from octorules_google.linter._rules import GA_RULE_METAS
from octorules_google.validate import (
    validate_regex_rule_count,
    validate_rule_count,
    validate_rules,
)

# Re-export for backward compatibility
_GCLOUD_PHASE_NAMES = GCLOUD_PHASE_NAMES

GA_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in GA_RULE_METAS)


def google_lint(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Google Cloud Armor lint checks on a zone rules file."""
    all_rules: list[dict] = []
    for phase_name, rules in rules_data.items():
        if phase_name not in _GCLOUD_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        all_rules.extend(rules)

        results = validate_rules(rules, phase=phase_name)
        for result in results:
            ctx.add(result)

        tier_results = validate_rule_count(rules, phase=phase_name, plan_tier=ctx.plan_tier)
        for result in tier_results:
            ctx.add(result)

    # Cross-phase checks (aggregated across all phases in the policy).
    for result in validate_regex_rule_count(all_rules):
        ctx.add(result)
