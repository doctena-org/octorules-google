"""Google Cloud Armor lint rule definitions — all GCloud-specific RuleMeta instances."""

from __future__ import annotations

from octorules.linter.engine import Severity
from octorules.linter.rules.registry import RuleMeta

# Category GA0xx — Structural checks
GA001 = RuleMeta("GA001", "structure", "Rule missing 'ref'", Severity.ERROR)
GA002 = RuleMeta("GA002", "structure", "Rule missing 'action'", Severity.ERROR)
GA003 = RuleMeta("GA003", "structure", "Rule missing 'match'", Severity.ERROR)

# Category GA1xx — Priority & cross-rule checks
GA100 = RuleMeta(
    "GA100", "priority", "Invalid priority (must be non-negative integer)", Severity.ERROR
)
GA101 = RuleMeta("GA101", "priority", "Priority out of range (0-2147483646)", Severity.ERROR)
GA102 = RuleMeta("GA102", "priority", "Duplicate priority", Severity.ERROR)
GA103 = RuleMeta("GA103", "cross_rule", "Unreachable rule after match-all", Severity.WARNING)
GA104 = RuleMeta("GA104", "cross_rule", "Duplicate CEL expression across rules", Severity.WARNING)

# Category GA2xx — Action validation
GA200 = RuleMeta("GA200", "action", "Invalid action", Severity.ERROR)
GA201 = RuleMeta("GA201", "action", "Invalid deny status code", Severity.ERROR)

# Category GA3xx — Match / CEL / CIDR checks
GA300 = RuleMeta(
    "GA300",
    "match",
    "Match must have 'expr' or 'config'+'versioned_expr', not both/neither",
    Severity.ERROR,
)
GA301 = RuleMeta("GA301", "match", "Invalid CIDR notation", Severity.WARNING)
GA302 = RuleMeta("GA302", "match", "CEL syntax error", Severity.WARNING)
GA303 = RuleMeta("GA303", "match", "Unknown preconfigured WAF rule set", Severity.WARNING)
GA304 = RuleMeta("GA304", "match", "CEL expression exceeds 2048 character limit", Severity.WARNING)
GA305 = RuleMeta("GA305", "match", "Overlapping or duplicate CIDRs", Severity.WARNING)
GA306 = RuleMeta("GA306", "match", "/0 CIDR matches all traffic", Severity.WARNING)

# Category GA4xx — Rate-limit and redirect option checks
GA400 = RuleMeta(
    "GA400", "rate_limit", "Rate-limit action requires 'rate_limit_options'", Severity.ERROR
)
GA401 = RuleMeta("GA401", "redirect", "Redirect action requires 'redirect_options'", Severity.ERROR)
GA402 = RuleMeta("GA402", "redirect", "Invalid redirect type", Severity.ERROR)
GA403 = RuleMeta(
    "GA403", "rate_limit", "Missing required field in rate_limit_options", Severity.ERROR
)
GA404 = RuleMeta("GA404", "redirect", "EXTERNAL_302 redirect requires 'target' URL", Severity.ERROR)
GA405 = RuleMeta("GA405", "rate_limit", "conform_action must be 'allow'", Severity.ERROR)
GA406 = RuleMeta("GA406", "rate_limit", "Invalid exceed_action", Severity.ERROR)
GA407 = RuleMeta("GA407", "rate_limit", "Invalid interval_sec value", Severity.ERROR)
GA408 = RuleMeta("GA408", "rate_limit", "rate_limit_threshold count out of range", Severity.ERROR)

# GA1xx continued — cross-rule analysis
GA105 = RuleMeta(
    "GA105",
    "cross_rule",
    "Inconsistent enforce_on_key across rate-limit rules",
    Severity.WARNING,
)
GA108 = RuleMeta(
    "GA108",
    "cross_rule",
    "Duplicate preconfigured WAF rule set across rules",
    Severity.WARNING,
)

# GA3xx continued — Expression / match deep validation
GA310 = RuleMeta("GA310", "match", "Unknown field reference in CEL expression", Severity.WARNING)
GA311 = RuleMeta("GA311", "match", "Unknown function in CEL expression", Severity.WARNING)
GA312 = RuleMeta("GA312", "match", "Invalid versioned_expr value", Severity.ERROR)
GA313 = RuleMeta(
    "GA313",
    "match",
    "Missing config when versioned_expr is present",
    Severity.ERROR,
)
GA314 = RuleMeta("GA314", "match", "Empty match conditions", Severity.WARNING)

# GA4xx continued — Rate-limit deep parameter validation
GA420 = RuleMeta(
    "GA420",
    "rate_limit",
    "rate_limit_threshold missing required subfields",
    Severity.ERROR,
)
GA421 = RuleMeta("GA421", "rate_limit", "Invalid type for rate limit field", Severity.ERROR)
GA422 = RuleMeta(
    "GA422",
    "rate_limit",
    "enforce_on_key required for rate_based_ban with redirect exceed_action",
    Severity.WARNING,
)
GA423 = RuleMeta("GA423", "rate_limit", "Invalid enforce_on_key value", Severity.ERROR)
GA424 = RuleMeta(
    "GA424",
    "rate_limit",
    "enforce_on_key_name required for HTTP_HEADER/HTTP_COOKIE",
    Severity.ERROR,
)
GA425 = RuleMeta(
    "GA425",
    "rate_limit",
    "ban_duration_sec required for rate_based_ban",
    Severity.ERROR,
)
GA426 = RuleMeta(
    "GA426", "rate_limit", "Invalid ban_duration_sec (must be positive integer)", Severity.ERROR
)

# GA4xx continued — Action parameter validation
GA429 = RuleMeta(
    "GA429",
    "rate_limit",
    "ban_duration_sec is only valid for rate_based_ban",
    Severity.WARNING,
)
GA431 = RuleMeta(
    "GA431",
    "rate_limit",
    "redirect exceed_action requires exceed_redirect_options",
    Severity.ERROR,
)

# Category GA5xx — Description & IP range checks
GA500 = RuleMeta(
    "GA500", "description", "Description exceeds 1024 character limit", Severity.WARNING
)
GA503 = RuleMeta("GA503", "match", "Private/reserved IP range in src_ip_ranges", Severity.WARNING)

# Collect all rule metas for registration
GA_RULE_METAS: list[RuleMeta] = [obj for obj in globals().values() if isinstance(obj, RuleMeta)]
