"""Offline validation for Google Cloud Armor rules."""

from __future__ import annotations

import ipaddress
import re

import celpy
from octorules.linter.engine import LintResult, Severity

_BASE_ACTIONS = frozenset({"allow", "throttle", "rate_based_ban", "redirect"})
_DENY_STATUSES = frozenset({403, 404, 502})
_DENY_RE = re.compile(r"^deny\((\d+)\)$")
_VALID_REDIRECT_TYPES = frozenset({"GOOGLE_RECAPTCHA", "EXTERNAL_302"})
_MAX_PRIORITY = 2_147_483_646
_MAX_DESCRIPTION = 1024
_MAX_EXPRESSION = 2048

_KNOWN_WAF_RULE_SETS = frozenset(
    {
        "cve",
        "java",
        "lfi",
        "methodenforcement",
        "nodejs",
        "php",
        "protocolattack",
        "rce",
        "rfi",
        "scannerdetection",
        "sessionfixation",
        "sqli",
        "xss",
    }
)
_PRECONFIGURED_RE = re.compile(r"evaluatePreconfigured(?:Waf|Expr)\(\s*['\"]([^'\"]+)['\"]")

# --- GA310/GA311: Known CEL fields & functions for Cloud Armor ---

_KNOWN_FIELDS = frozenset(
    {
        "request.headers",
        "request.method",
        "request.path",
        "request.scheme",
        "request.query",
        "request.url",
        "origin.ip",
        "origin.user_ip",
        "origin.region_code",
        "origin.asn",
        "origin.tls_ja3_fingerprint",
        "origin.tls_ja4_fingerprint",
        "token.recaptcha_action",
        "token.recaptcha_session",
        "token.recaptcha_exemption",
    }
)

# Match dotted identifiers: word.word (with optional further .word segments).
# Captures the first two segments (e.g. "origin.ip" from "origin.ip").
_FIELD_RE = re.compile(r"\b([a-zA-Z_]\w*\.[a-zA-Z_]\w*)")

# Match single- or double-quoted string literals (including escaped quotes).
_STRING_LITERAL_RE = re.compile(r"""'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*\"""")


def _strip_string_literals(expr: str) -> str:
    """Remove quoted string literals from a CEL expression.

    Prevents false positives from field-like text inside strings, e.g.
    ``request.headers["origin.ip"]`` should not flag ``origin.ip`` as a field.
    """
    return _STRING_LITERAL_RE.sub("", expr)


_KNOWN_FUNCTIONS = frozenset(
    {
        "contains",
        "startsWith",
        "endsWith",
        "matches",
        "lower",
        "upper",
        "base64Decode",
        "inIpRange",
        "size",
        "int",
        "evaluatePreconfiguredWaf",
        "evaluatePreconfiguredExpr",
        "has",
    }
)

# Match function calls: word immediately followed by '('.
_FUNCTION_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")

# --- GA423: Valid enforce_on_key values ---

_VALID_ENFORCE_ON_KEYS = frozenset(
    {
        "IP",
        "ALL",
        "HTTP_HEADER",
        "XFF_IP",
        "HTTP_COOKIE",
        "HTTP_PATH",
        "SNI",
        "REGION_CODE",
    }
)

_VALID_EXCEED_ACTIONS = frozenset(
    {
        "deny-403",
        "deny-404",
        "deny-429",
        "deny-502",
        "redirect",
    }
)
_VALID_INTERVALS = frozenset(
    {
        10,
        30,
        60,
        120,
        180,
        240,
        300,
        600,
        900,
        1200,
        1800,
        2700,
        3600,
    }
)

# RFC 1918 / RFC 4193 / loopback / link-local — flagged as likely mistakes in
# Cloud Armor src_ip_ranges.
_PRIVATE_SUPERNETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_rules(rules: list[dict], *, phase: str = "") -> list[LintResult]:
    """Validate normalized Google Cloud Armor rules. Returns list of issues."""
    results: list[LintResult] = []
    seen_priorities: dict[int, list[str]] = {}
    seen_expressions: dict[str, list[str]] = {}
    seen_waf_rulesets: dict[str, list[str]] = {}
    seen_enforce_on_keys: dict[str, str] = {}  # ref -> key value

    for rule in rules:
        ref = rule.get("ref", "")
        if not ref:
            results.append(
                LintResult(
                    rule_id="GA001",
                    severity=Severity.ERROR,
                    message="Rule missing 'ref'",
                    phase=phase,
                )
            )
        ref_str = str(ref)

        _check_priority(ref_str, results, phase, seen_priorities)
        _check_action(rule, results, phase, ref_str)
        _check_match(rule, results, phase, ref_str, seen_expressions, seen_waf_rulesets)
        _check_match_deep(rule, results, phase, ref_str)
        _check_description(rule, results, phase, ref_str)
        _check_rate_limit_deep(rule, results, phase, ref_str, seen_enforce_on_keys)
        _check_action_params(rule, results, phase, ref_str)

    _check_duplicate_priorities(seen_priorities, results, phase)
    _check_duplicate_expressions(seen_expressions, results, phase)
    _check_dead_rules(rules, results, phase)
    _check_inconsistent_enforce_on_key(seen_enforce_on_keys, results, phase)
    _check_duplicate_waf_rulesets(seen_waf_rulesets, results, phase)

    return results


# --- Per-rule checks --------------------------------------------------------


def _check_priority(
    ref: str,
    results: list[LintResult],
    phase: str,
    seen: dict[int, list[str]],
) -> None:
    if not ref:
        return
    try:
        pri = int(ref)
    except (ValueError, TypeError):
        results.append(
            LintResult(
                rule_id="GA100",
                severity=Severity.ERROR,
                message=f"ref must be a non-negative integer string, got {ref!r}",
                phase=phase,
                ref=ref,
                field="ref",
            )
        )
        return
    if pri < 0:
        results.append(
            LintResult(
                rule_id="GA100",
                severity=Severity.ERROR,
                message=f"ref must be a non-negative integer string, got {ref!r}",
                phase=phase,
                ref=ref,
                field="ref",
            )
        )
        return
    if pri > _MAX_PRIORITY:
        results.append(
            LintResult(
                rule_id="GA101",
                severity=Severity.ERROR,
                message=f"Priority {pri} out of range (0\u2013{_MAX_PRIORITY})",
                phase=phase,
                ref=ref,
                field="ref",
            )
        )
        return
    seen.setdefault(pri, []).append(ref)


def _check_action(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    action = rule.get("action", "")
    if not action:
        results.append(
            LintResult(
                rule_id="GA002",
                severity=Severity.ERROR,
                message="Rule missing 'action'",
                phase=phase,
                ref=ref,
            )
        )
        return

    # GA200 / GA201: validate action string
    m = _DENY_RE.match(action)
    if m:
        status = int(m.group(1))
        if status not in _DENY_STATUSES:
            results.append(
                LintResult(
                    rule_id="GA201",
                    severity=Severity.ERROR,
                    message=f"Invalid deny status: {status}",
                    phase=phase,
                    ref=ref,
                    field="action",
                    suggestion="Valid deny statuses: 403, 404, 502",
                )
            )
    elif action not in _BASE_ACTIONS:
        results.append(
            LintResult(
                rule_id="GA200",
                severity=Severity.ERROR,
                message=f"Invalid action: {action!r}",
                phase=phase,
                ref=ref,
                field="action",
                suggestion=(
                    "Valid actions: allow, deny(403), deny(404), deny(502),"
                    " rate_based_ban, redirect, throttle"
                ),
            )
        )

    # GA400–GA408: rate_limit_options
    if action in ("throttle", "rate_based_ban"):
        if "rate_limit_options" not in rule:
            results.append(
                LintResult(
                    rule_id="GA400",
                    severity=Severity.ERROR,
                    message=f"Action '{action}' requires 'rate_limit_options'",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options",
                )
            )
        else:
            _check_rate_limit_options(rule["rate_limit_options"], action, results, phase, ref)

    # GA401 / GA402 / GA404: redirect options
    if action == "redirect":
        if "redirect_options" not in rule:
            results.append(
                LintResult(
                    rule_id="GA401",
                    severity=Severity.ERROR,
                    message="Action 'redirect' requires 'redirect_options'",
                    phase=phase,
                    ref=ref,
                    field="redirect_options",
                )
            )
        else:
            _check_redirect_options(rule["redirect_options"], results, phase, ref)


def _check_rate_limit_options(
    rlo: object,
    action: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA403/GA405/GA406/GA407/GA408 — rate_limit_options structure."""
    if not isinstance(rlo, dict):
        return

    # GA403: required fields
    for field in ("conform_action", "exceed_action", "rate_limit_threshold"):
        if field not in rlo:
            results.append(
                LintResult(
                    rule_id="GA403",
                    severity=Severity.ERROR,
                    message=f"rate_limit_options missing required field '{field}'",
                    phase=phase,
                    ref=ref,
                    field=f"rate_limit_options.{field}",
                )
            )

    # GA405: conform_action must be "allow"
    ca = rlo.get("conform_action")
    if ca is not None and ca != "allow":
        results.append(
            LintResult(
                rule_id="GA405",
                severity=Severity.ERROR,
                message=f"conform_action must be 'allow', got {ca!r}",
                phase=phase,
                ref=ref,
                field="rate_limit_options.conform_action",
            )
        )

    # GA406: exceed_action validation
    ea = rlo.get("exceed_action")
    if ea is not None and ea not in _VALID_EXCEED_ACTIONS:
        results.append(
            LintResult(
                rule_id="GA406",
                severity=Severity.ERROR,
                message=f"Invalid exceed_action: {ea!r}",
                phase=phase,
                ref=ref,
                field="rate_limit_options.exceed_action",
                suggestion=f"Valid values: {sorted(_VALID_EXCEED_ACTIONS)}",
            )
        )

    # GA407 / GA408: rate_limit_threshold
    rlt = rlo.get("rate_limit_threshold")
    if isinstance(rlt, dict):
        interval = rlt.get("interval_sec")
        if interval is not None and interval not in _VALID_INTERVALS:
            results.append(
                LintResult(
                    rule_id="GA407",
                    severity=Severity.ERROR,
                    message=f"Invalid interval_sec: {interval!r}",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.rate_limit_threshold.interval_sec",
                    suggestion=f"Valid values: {sorted(_VALID_INTERVALS)}",
                )
            )

        count = rlt.get("count")
        if count is not None:
            max_count = 10_000 if action == "rate_based_ban" else 1_000_000
            bad = not isinstance(count, int) or isinstance(count, bool)
            if bad or count < 1 or count > max_count:
                results.append(
                    LintResult(
                        rule_id="GA408",
                        severity=Severity.ERROR,
                        message=(
                            f"rate_limit_threshold.count must be 1\u2013{max_count:,}"
                            f" for {action}, got {count!r}"
                        ),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.rate_limit_threshold.count",
                    )
                )


def _check_redirect_options(
    redir: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA402/GA404 — redirect_options validation."""
    if not isinstance(redir, dict):
        return
    rtype = redir.get("type", "")
    if rtype and rtype not in _VALID_REDIRECT_TYPES:
        results.append(
            LintResult(
                rule_id="GA402",
                severity=Severity.ERROR,
                message=f"Invalid redirect type: {rtype!r}",
                phase=phase,
                ref=ref,
                field="redirect_options.type",
                suggestion=f"Valid types: {sorted(_VALID_REDIRECT_TYPES)}",
            )
        )
    if rtype == "EXTERNAL_302" and "target" not in redir:
        results.append(
            LintResult(
                rule_id="GA404",
                severity=Severity.ERROR,
                message="EXTERNAL_302 redirect requires 'target' URL",
                phase=phase,
                ref=ref,
                field="redirect_options.target",
            )
        )


def _check_match(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    seen_expressions: dict[str, list[str]],
    seen_waf_rulesets: dict[str, list[str]],
) -> None:
    match = rule.get("match")
    if match is None:
        results.append(
            LintResult(
                rule_id="GA003",
                severity=Severity.ERROR,
                message="Rule missing 'match'",
                phase=phase,
                ref=ref,
            )
        )
        return
    if not isinstance(match, dict):
        return

    has_expr = "expr" in match
    has_config = "config" in match or "versioned_expr" in match

    # GA300: must have expr OR config+versioned_expr, not both / neither
    if has_expr and has_config:
        results.append(
            LintResult(
                rule_id="GA300",
                severity=Severity.ERROR,
                message="Match must have 'expr' or 'config'+'versioned_expr', not both",
                phase=phase,
                ref=ref,
                field="match",
            )
        )
    elif not has_expr and not has_config:
        results.append(
            LintResult(
                rule_id="GA300",
                severity=Severity.ERROR,
                message="Match must have 'expr' or 'config'+'versioned_expr'",
                phase=phase,
                ref=ref,
                field="match",
            )
        )

    # GA301 / GA305 / GA306 / GA503: CIDR checks
    config = match.get("config", {})
    if isinstance(config, dict):
        ranges = config.get("src_ip_ranges", [])
        if isinstance(ranges, list):
            _check_cidrs(ranges, results, phase, ref)

    # GA302 / GA303 / GA304: CEL expression checks
    if has_expr:
        expr_obj = match.get("expr", {})
        if isinstance(expr_obj, dict):
            expression = expr_obj.get("expression", "")
            if isinstance(expression, str) and expression:
                _check_cel_length(expression, results, phase, ref)
                _check_cel(expression, results, phase, ref)
                _check_preconfigured(expression, results, phase, ref)
                # Track for GA104 duplicate detection
                norm = " ".join(expression.split())
                seen_expressions.setdefault(norm, []).append(ref)
                # Track WAF rulesets for GA108
                for m in _PRECONFIGURED_RE.finditer(expression):
                    seen_waf_rulesets.setdefault(m.group(1), []).append(ref)


def _check_cidrs(
    ranges: list,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA301/GA305/GA306/GA503 — CIDR validation."""
    networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []

    for cidr in ranges:
        if not isinstance(cidr, str):
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            results.append(
                LintResult(
                    rule_id="GA301",
                    severity=Severity.WARNING,
                    message=f"Invalid CIDR: {cidr!r}",
                    phase=phase,
                    ref=ref,
                    field="match.config.src_ip_ranges",
                )
            )
            continue
        networks.append((cidr, net))

    for cidr, net in networks:
        # GA306: /0 matches all traffic
        if net.prefixlen == 0:
            results.append(
                LintResult(
                    rule_id="GA306",
                    severity=Severity.WARNING,
                    message=f"/{0} CIDR matches all traffic: {cidr}",
                    phase=phase,
                    ref=ref,
                    field="match.config.src_ip_ranges",
                )
            )

        # GA503: private/reserved range
        for private in _PRIVATE_SUPERNETS:
            if net.version == private.version and net.subnet_of(private):
                results.append(
                    LintResult(
                        rule_id="GA503",
                        severity=Severity.WARNING,
                        message=f"Private/reserved IP range: {cidr}",
                        phase=phase,
                        ref=ref,
                        field="match.config.src_ip_ranges",
                    )
                )
                break

    # GA305: overlapping CIDRs
    for i, (cidr_a, net_a) in enumerate(networks):
        for cidr_b, net_b in networks[i + 1 :]:
            if net_a.version != net_b.version:
                continue
            if net_a.overlaps(net_b):
                if net_a == net_b:
                    msg = f"Duplicate CIDR: {cidr_a}"
                elif net_b.subnet_of(net_a):
                    msg = f"Redundant: {cidr_b} contained in {cidr_a}"
                else:
                    msg = f"Redundant: {cidr_a} contained in {cidr_b}"
                results.append(
                    LintResult(
                        rule_id="GA305",
                        severity=Severity.WARNING,
                        message=msg,
                        phase=phase,
                        ref=ref,
                        field="match.config.src_ip_ranges",
                    )
                )


def _check_cel_length(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA304: CEL expression length check."""
    if len(expr) > _MAX_EXPRESSION:
        results.append(
            LintResult(
                rule_id="GA304",
                severity=Severity.WARNING,
                message=f"CEL expression exceeds {_MAX_EXPRESSION} characters ({len(expr)})",
                phase=phase,
                ref=ref,
                field="match.expr.expression",
            )
        )


def _check_cel(expr: str, results: list[LintResult], phase: str, ref: str) -> None:
    """GA302: CEL syntax check."""
    try:
        env = celpy.Environment()
        env.compile(expr)
    except celpy.CELParseError as exc:
        results.append(
            LintResult(
                rule_id="GA302",
                severity=Severity.WARNING,
                message=f"CEL syntax error: {exc}",
                phase=phase,
                ref=ref,
                field="match.expr.expression",
            )
        )


def _check_preconfigured(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA303: unknown preconfigured WAF rule set."""
    for m in _PRECONFIGURED_RE.finditer(expr):
        ruleset = m.group(1)
        prefix = ruleset.split("-")[0].lower()
        if prefix not in _KNOWN_WAF_RULE_SETS:
            results.append(
                LintResult(
                    rule_id="GA303",
                    severity=Severity.WARNING,
                    message=f"Unknown preconfigured WAF rule set: {ruleset!r}",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )


def _check_description(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    desc = rule.get("description", "")
    if isinstance(desc, str) and len(desc) > _MAX_DESCRIPTION:
        results.append(
            LintResult(
                rule_id="GA500",
                severity=Severity.WARNING,
                message=f"Description exceeds {_MAX_DESCRIPTION} characters ({len(desc)})",
                phase=phase,
                ref=ref,
                field="description",
            )
        )


# --- Deep per-rule checks (new GA310–GA431) ---------------------------------


def _check_match_deep(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA310/GA311/GA312/GA313/GA314 — deep match/expression validation."""
    match = rule.get("match")
    if not isinstance(match, dict):
        return

    # --- GA312/GA313: versioned_expr checks ---
    ve = match.get("versioned_expr")
    if ve is not None:
        if ve != "SRC_IPS_V1":
            results.append(
                LintResult(
                    rule_id="GA312",
                    severity=Severity.ERROR,
                    message=f"Invalid versioned_expr: {ve!r} (only 'SRC_IPS_V1' is valid)",
                    phase=phase,
                    ref=ref,
                    field="match.versioned_expr",
                )
            )
        config = match.get("config")
        if config is None or not isinstance(config, dict):
            results.append(
                LintResult(
                    rule_id="GA313",
                    severity=Severity.ERROR,
                    message="versioned_expr requires 'config' with 'src_ip_ranges'",
                    phase=phase,
                    ref=ref,
                    field="match.config",
                )
            )
        elif "src_ip_ranges" not in config:
            results.append(
                LintResult(
                    rule_id="GA313",
                    severity=Severity.ERROR,
                    message="versioned_expr requires 'config' with 'src_ip_ranges'",
                    phase=phase,
                    ref=ref,
                    field="match.config.src_ip_ranges",
                )
            )

    # --- GA314: empty match conditions ---
    config = match.get("config")
    if isinstance(config, dict):
        ranges = config.get("src_ip_ranges")
        if isinstance(ranges, list) and len(ranges) == 0:
            results.append(
                LintResult(
                    rule_id="GA314",
                    severity=Severity.WARNING,
                    message="Empty src_ip_ranges matches nothing",
                    phase=phase,
                    ref=ref,
                    field="match.config.src_ip_ranges",
                )
            )

    expr_obj = match.get("expr")
    if isinstance(expr_obj, dict):
        expression = expr_obj.get("expression")
        if isinstance(expression, str) and expression.strip() == "":
            results.append(
                LintResult(
                    rule_id="GA314",
                    severity=Severity.WARNING,
                    message="Empty or whitespace-only CEL expression matches nothing",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )
            return  # No point in field/function extraction on empty expr

        # --- GA310/GA311: field and function extraction (only on non-empty exprs) ---
        if isinstance(expression, str) and expression.strip():
            _check_cel_fields(expression, results, phase, ref)
            _check_cel_functions(expression, results, phase, ref)


def _check_cel_fields(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA310: unknown field references in CEL expression."""
    stripped = _strip_string_literals(expr)
    seen: set[str] = set()
    for m in _FIELD_RE.finditer(stripped):
        field = m.group(1)
        if field in seen:
            continue
        seen.add(field)
        # Check if the base field (first two segments) is known.
        # "token.recaptcha_action.score" -> base is "token.recaptcha_action" (known).
        # Also handle exact matches like "origin.ip".
        base = field
        if base in _KNOWN_FIELDS:
            continue
        # Check if it's a sub-field of a known token field
        # e.g. "token.recaptcha_action" is a prefix of known fields
        if any(base.startswith(k + ".") or k.startswith(base + ".") for k in _KNOWN_FIELDS):
            continue
        # Skip CEL/string literals that look like field refs but aren't
        # (e.g. part of a string value). We only flag top-level field-like patterns.
        results.append(
            LintResult(
                rule_id="GA310",
                severity=Severity.WARNING,
                message=f"Unknown field reference: {field!r}",
                phase=phase,
                ref=ref,
                field="match.expr.expression",
                suggestion="Known fields: origin.*, request.*, token.*",
            )
        )


def _check_cel_functions(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA311: unknown function calls in CEL expression."""
    stripped = _strip_string_literals(expr)
    seen: set[str] = set()
    for m in _FUNCTION_RE.finditer(stripped):
        func = m.group(1)
        if func in seen:
            continue
        seen.add(func)
        if func not in _KNOWN_FUNCTIONS:
            results.append(
                LintResult(
                    rule_id="GA311",
                    severity=Severity.WARNING,
                    message=f"Unknown function: {func!r}",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                    suggestion=f"Known functions: {sorted(_KNOWN_FUNCTIONS)}",
                )
            )


def _check_rate_limit_deep(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    seen_enforce_on_keys: dict[str, str],
) -> None:
    """GA420-GA426 — deep rate-limit parameter validation."""
    action = rule.get("action", "")
    rlo = rule.get("rate_limit_options")
    if not isinstance(rlo, dict):
        return

    # --- GA420/GA421: rate_limit_threshold subfield validation ---
    rlt = rlo.get("rate_limit_threshold")
    if rlt is not None:
        if not isinstance(rlt, dict):
            results.append(
                LintResult(
                    rule_id="GA420",
                    severity=Severity.ERROR,
                    message="rate_limit_threshold must be a dict with 'count' and 'interval_sec'",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.rate_limit_threshold",
                )
            )
        else:
            if "count" not in rlt:
                results.append(
                    LintResult(
                        rule_id="GA420",
                        severity=Severity.ERROR,
                        message="rate_limit_threshold missing required field 'count'",
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.rate_limit_threshold.count",
                    )
                )
            if "interval_sec" not in rlt:
                results.append(
                    LintResult(
                        rule_id="GA420",
                        severity=Severity.ERROR,
                        message="rate_limit_threshold missing required field 'interval_sec'",
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.rate_limit_threshold.interval_sec",
                    )
                )

            # GA421: type validation
            count = rlt.get("count")
            if count is not None and (not isinstance(count, int) or isinstance(count, bool)):
                results.append(
                    LintResult(
                        rule_id="GA421",
                        severity=Severity.ERROR,
                        message=(
                            f"rate_limit_threshold.count must be int, got {type(count).__name__}"
                        ),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.rate_limit_threshold.count",
                    )
                )
            interval = rlt.get("interval_sec")
            if interval is not None and (
                not isinstance(interval, int) or isinstance(interval, bool)
            ):
                results.append(
                    LintResult(
                        rule_id="GA421",
                        severity=Severity.ERROR,
                        message=(
                            f"rate_limit_threshold.interval_sec must be int,"
                            f" got {type(interval).__name__}"
                        ),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.rate_limit_threshold.interval_sec",
                    )
                )

    # --- GA423/GA424: enforce_on_key validation ---
    eok = rlo.get("enforce_on_key")
    if eok is not None:
        if eok not in _VALID_ENFORCE_ON_KEYS:
            results.append(
                LintResult(
                    rule_id="GA423",
                    severity=Severity.ERROR,
                    message=f"Invalid enforce_on_key: {eok!r}",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.enforce_on_key",
                    suggestion=f"Valid values: {sorted(_VALID_ENFORCE_ON_KEYS)}",
                )
            )
        elif eok in ("HTTP_HEADER", "HTTP_COOKIE"):
            # GA424: need enforce_on_key_name
            if "enforce_on_key_name" not in rlo:
                results.append(
                    LintResult(
                        rule_id="GA424",
                        severity=Severity.ERROR,
                        message=(f"enforce_on_key '{eok}' requires 'enforce_on_key_name'"),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.enforce_on_key_name",
                    )
                )

    # --- GA422: enforce_on_key for rate_based_ban with redirect ---
    if action == "rate_based_ban":
        ea = rlo.get("exceed_action")
        if ea == "redirect" and eok is None:
            results.append(
                LintResult(
                    rule_id="GA422",
                    severity=Severity.WARNING,
                    message="rate_based_ban with redirect exceed_action should set enforce_on_key",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.enforce_on_key",
                )
            )

    # --- GA425/GA426: ban_duration_sec for rate_based_ban ---
    if action == "rate_based_ban":
        bds = rlo.get("ban_duration_sec")
        if bds is None:
            results.append(
                LintResult(
                    rule_id="GA425",
                    severity=Severity.ERROR,
                    message="rate_based_ban requires 'ban_duration_sec' in rate_limit_options",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.ban_duration_sec",
                )
            )
        else:
            bad = not isinstance(bds, int) or isinstance(bds, bool) or bds <= 0
            if bad:
                results.append(
                    LintResult(
                        rule_id="GA426",
                        severity=Severity.ERROR,
                        message=f"ban_duration_sec must be a positive integer, got {bds!r}",
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.ban_duration_sec",
                    )
                )

    # Track enforce_on_key for cross-rule GA105 check
    if action in ("throttle", "rate_based_ban") and eok is not None:
        seen_enforce_on_keys[ref] = eok


def _check_action_params(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA429/GA431 — action parameter validation."""
    action = rule.get("action", "")
    rlo = rule.get("rate_limit_options")
    if not isinstance(rlo, dict):
        return

    # GA429: ban_duration_sec only valid for rate_based_ban
    if action == "throttle" and "ban_duration_sec" in rlo:
        results.append(
            LintResult(
                rule_id="GA429",
                severity=Severity.WARNING,
                message="ban_duration_sec is only valid for rate_based_ban, not throttle",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_duration_sec",
            )
        )

    # GA431: redirect exceed_action needs exceed_redirect_options
    ea = rlo.get("exceed_action")
    if ea == "redirect" and "exceed_redirect_options" not in rlo:
        results.append(
            LintResult(
                rule_id="GA431",
                severity=Severity.ERROR,
                message="exceed_action 'redirect' requires 'exceed_redirect_options'",
                phase=phase,
                ref=ref,
                field="rate_limit_options.exceed_redirect_options",
            )
        )


# --- Cross-rule checks ------------------------------------------------------


def _check_inconsistent_enforce_on_key(
    seen: dict[str, str],
    results: list[LintResult],
    phase: str,
) -> None:
    """GA105: inconsistent enforce_on_key across rate-limit rules."""
    if len(seen) < 2:
        return
    unique_keys = set(seen.values())
    if len(unique_keys) > 1:
        detail_parts = [f"{ref}={key}" for ref, key in sorted(seen.items())]
        results.append(
            LintResult(
                rule_id="GA105",
                severity=Severity.WARNING,
                message=(
                    f"Inconsistent enforce_on_key across rate-limit rules:"
                    f" {', '.join(detail_parts)}"
                ),
                phase=phase,
            )
        )


def _check_duplicate_waf_rulesets(
    seen: dict[str, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    """GA108: duplicate preconfigured WAF rule set across rules."""
    for ruleset, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                LintResult(
                    rule_id="GA108",
                    severity=Severity.WARNING,
                    message=(
                        f"Preconfigured WAF rule set {ruleset!r} used in multiple rules:"
                        f" {', '.join(refs)}"
                    ),
                    phase=phase,
                )
            )


def _check_duplicate_priorities(
    seen: dict[int, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    for pri, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                LintResult(
                    rule_id="GA102",
                    severity=Severity.ERROR,
                    message=f"Duplicate priority {pri} in rules: {', '.join(refs)}",
                    phase=phase,
                )
            )


def _check_duplicate_expressions(
    seen: dict[str, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    """GA104: duplicate CEL expression across rules."""
    for _expr, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                LintResult(
                    rule_id="GA104",
                    severity=Severity.WARNING,
                    message=f"Duplicate expression across rules: {', '.join(refs)}",
                    phase=phase,
                )
            )


def _check_dead_rules(
    rules: list[dict],
    results: list[LintResult],
    phase: str,
) -> None:
    """GA103: rules unreachable after a match-all rule."""
    # Find the lowest-priority match-all rule (expression == "true")
    match_all_pri: int | None = None
    for rule in rules:
        ref = rule.get("ref", "")
        try:
            pri = int(ref)
        except (ValueError, TypeError):
            continue
        match = rule.get("match")
        if not isinstance(match, dict):
            continue
        expr_obj = match.get("expr")
        if not isinstance(expr_obj, dict):
            continue
        expression = expr_obj.get("expression", "")
        if isinstance(expression, str) and expression.strip().lower() == "true":
            if match_all_pri is None or pri < match_all_pri:
                match_all_pri = pri

    if match_all_pri is None:
        return

    for rule in rules:
        ref = rule.get("ref", "")
        try:
            pri = int(ref)
        except (ValueError, TypeError):
            continue
        if pri > match_all_pri:
            results.append(
                LintResult(
                    rule_id="GA103",
                    severity=Severity.WARNING,
                    message=(
                        f"Rule unreachable: priority {match_all_pri} matches all traffic first"
                    ),
                    phase=phase,
                    ref=str(ref),
                )
            )
