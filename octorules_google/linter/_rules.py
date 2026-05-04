"""Google Cloud Armor lint rule definitions — all GCloud-specific RuleMeta instances."""

from octorules.linter.engine import Severity
from octorules.linter.rules.registry import RuleMeta

# Category GA0xx — Structural checks
GA001 = RuleMeta("GA001", "structure", "Rule missing 'ref'", Severity.ERROR)
GA002 = RuleMeta("GA002", "structure", "Rule missing 'action'", Severity.ERROR)
GA003 = RuleMeta("GA003", "structure", "Rule missing 'match'", Severity.ERROR)
GA004 = RuleMeta("GA004", "structure", "Rule entry is not a dict", Severity.ERROR)
GA005 = RuleMeta("GA005", "structure", "Duplicate ref within phase", Severity.ERROR)
GA006 = RuleMeta("GA006", "structure", "Phase value is not a list", Severity.ERROR)
GA020 = RuleMeta("GA020", "structure", "Unknown top-level rule field", Severity.ERROR)
GA027 = RuleMeta(
    "GA027", "structure", "Leading/trailing whitespace in match.expr.expression", Severity.INFO
)

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
GA307 = RuleMeta("GA307", "match", "CIDR has host bits set (will be normalized)", Severity.WARNING)

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
# GA408 was reused briefly during 2026-04-27 patch development for an overlap rule
# that turned out to duplicate GA305. Reverted before release; GA305 now uses
# sweep-line O(n log n) directly. Don't re-use GA408 — leave the gap.

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
GA427 = RuleMeta(
    "GA427", "rate_limit", "ban_duration_sec exceeds maximum (3600 seconds)", Severity.ERROR
)
GA430 = RuleMeta(
    "GA430", "rate_limit", "ban_duration_sec very short (< 60 seconds)", Severity.WARNING
)
GA428 = RuleMeta(
    "GA428",
    "rate_limit",
    "Invalid enforce_on_key_name value",
    Severity.WARNING,
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
GA432 = RuleMeta(
    "GA432",
    "rate_limit",
    "Conflicting rate-limit options",
    Severity.ERROR,
)
GA433 = RuleMeta(
    "GA433",
    "redirect",
    "Redirect URL exceeds 1024 characters",
    Severity.WARNING,
)

# GA4xx continued — Redirect target, ban_threshold, exceed_redirect, enforce_on_key_configs
GA409 = RuleMeta(
    "GA409",
    "redirect",
    "redirect_options.target must be a valid URL for EXTERNAL_302",
    Severity.ERROR,
)
GA410 = RuleMeta(
    "GA410",
    "rate_limit",
    "Invalid ban_threshold structure",
    Severity.ERROR,
)
GA411 = RuleMeta(
    "GA411",
    "rate_limit",
    "Invalid exceed_redirect_options.type",
    Severity.ERROR,
)
GA412 = RuleMeta(
    "GA412",
    "rate_limit",
    "exceed_redirect_options.target must be a valid URL for EXTERNAL_302",
    Severity.ERROR,
)
GA413 = RuleMeta(
    "GA413",
    "match",
    "Invalid regex pattern in matches()",
    Severity.WARNING,
)
GA414 = RuleMeta(
    "GA414",
    "rate_limit",
    "Invalid enforce_on_key_configs structure",
    Severity.ERROR,
)
GA415 = RuleMeta(
    "GA415",
    "rate_limit",
    "Duplicate enforce_on_key_type in enforce_on_key_configs",
    Severity.WARNING,
)
GA416 = RuleMeta(
    "GA416",
    "match",
    "Preconfigured WAF sensitivity level must be 0-4",
    Severity.WARNING,
)
GA418 = RuleMeta(
    "GA418",
    "match",
    "Invalid HTTP header name in CEL expression",
    Severity.WARNING,
)
GA419 = RuleMeta(
    "GA419",
    "redirect",
    "Redirect target must not be empty",
    Severity.ERROR,
)

# GA3xx continued — CEL deep analysis
GA315 = RuleMeta(
    "GA315",
    "match",
    "Unknown country code in origin.region_code comparison",
    Severity.WARNING,
)
GA316 = RuleMeta(
    "GA316",
    "match",
    "Unknown HTTP method in request.method comparison",
    Severity.WARNING,
)
GA317 = RuleMeta("GA317", "match", "Invalid CIDR in inIpRange()", Severity.ERROR)
GA320 = RuleMeta("GA320", "match", "Private/reserved IP range in inIpRange()", Severity.WARNING)
GA318 = RuleMeta("GA318", "match", "CEL type mismatch", Severity.WARNING)
GA319 = RuleMeta(
    "GA319",
    "match",
    "Case-sensitive string comparison may need case-insensitive matching",
    Severity.INFO,
)

GA325 = RuleMeta("GA325", "match", "Invalid header_action structure", Severity.ERROR)
GA326 = RuleMeta("GA326", "match", "Invalid network_match structure", Severity.ERROR)
GA327 = RuleMeta("GA327", "match", "Invalid preconfigured_waf_config structure", Severity.ERROR)
GA328 = RuleMeta("GA328", "match", "Overly-permissive regex in matches()", Severity.WARNING)
GA329 = RuleMeta(
    "GA329", "match", "Anchored-literal regex should use equality operator", Severity.INFO
)
GA526 = RuleMeta(
    "GA526", "match", "HTTP header name should be lowercase in bracket access", Severity.INFO
)

# Category GA5xx — Description & IP range checks & deprecated fields
GA500 = RuleMeta(
    "GA500", "description", "Description exceeds 1024 character limit", Severity.WARNING
)
GA529 = RuleMeta(
    "GA529",
    "match",
    "Deprecated field or versioned_expr value detected",
    Severity.WARNING,
)
GA501 = RuleMeta(
    "GA501", "cross_rule", "Regex rule count exceeds standard tier limit (10)", Severity.WARNING
)
GA502 = RuleMeta("GA502", "cross_rule", "Rule count exceeds tier limit", Severity.WARNING)
GA503 = RuleMeta("GA503", "match", "Private/reserved IP range in src_ip_ranges", Severity.WARNING)

# Category GA6xx — Best-practice / operational checks
GA600 = RuleMeta("GA600", "best_practice", "Rule is in preview mode (preview: true)", Severity.INFO)
GA601 = RuleMeta(
    "GA601",
    "best_practice",
    "Expression is always true — this is a catch-all rule",
    Severity.WARNING,
)
GA602 = RuleMeta(
    "GA602",
    "best_practice",
    "Expression is always false — rule never matches",
    Severity.WARNING,
)
GA603 = RuleMeta("GA603", "best_practice", "Rule is disabled (enabled: false)", Severity.INFO)

# Category GA1xx — CEL expression style checks (continued)
GA110 = RuleMeta(
    "GA110",
    "match",
    "Negated comparison can be simplified (!(a == b) → a != b)",
    Severity.INFO,
)
GA111 = RuleMeta(
    "GA111",
    "match",
    "OR chain of same-field equality can use 'in' operator",
    Severity.INFO,
)
GA112 = RuleMeta(
    "GA112",
    "match",
    "Contradictory AND condition (always false)",
    Severity.WARNING,
)
GA113 = RuleMeta(
    "GA113",
    "match",
    "Mixed && and || without explicit parentheses (precedence clarity)",
    Severity.INFO,
)

# Collect all rule metas for registration
GA_RULE_METAS: list[RuleMeta] = [obj for obj in globals().values() if isinstance(obj, RuleMeta)]
