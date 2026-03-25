"""Google Cloud Armor audit extension — extracts IP ranges from rules."""

from __future__ import annotations

import re

from octorules.audit import RuleIPInfo
from octorules.extensions import register_audit_extension
from octorules.phases import PHASE_BY_NAME

from octorules_google import GCLOUD_PHASE_NAMES

# Regex to extract CIDRs from inIpRange() CEL calls
_IN_IP_RANGE_RE = re.compile(r"""inIpRange\s*\(\s*[^,]+,\s*["']([^"']+)["']\s*\)""")


def _extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Extract IP ranges from Google Cloud Armor rules in *phase_name*."""
    if phase_name not in GCLOUD_PHASE_NAMES:
        return []
    if phase_name not in PHASE_BY_NAME:
        return []

    rules = rules_data.get(phase_name)
    if not isinstance(rules, list):
        return []

    results: list[RuleIPInfo] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = str(rule.get("ref", ""))
        action = str(rule.get("action", ""))

        match = rule.get("match")
        if not isinstance(match, dict):
            continue

        all_cidrs: list[str] = []

        # Extract from match.config.src_ip_ranges
        config = match.get("config")
        if isinstance(config, dict):
            ranges = config.get("src_ip_ranges", [])
            if isinstance(ranges, list):
                for cidr in ranges:
                    if isinstance(cidr, str) and cidr != "*":
                        all_cidrs.append(cidr)

        # Extract from inIpRange() in CEL expressions
        expr_obj = match.get("expr")
        if isinstance(expr_obj, dict):
            expression = expr_obj.get("expression", "")
            if isinstance(expression, str):
                for m in _IN_IP_RANGE_RE.finditer(expression):
                    all_cidrs.append(m.group(1))

        if all_cidrs:
            results.append(
                RuleIPInfo(
                    zone_name="",  # Stamped by caller
                    phase_name=phase_name,
                    ref=ref,
                    action=action,
                    ip_ranges=all_cidrs,
                )
            )

    return results


def register_google_audit() -> None:
    """Register the Google Cloud Armor audit IP extractor."""
    register_audit_extension("gcloud_armor", _extract_ips)
