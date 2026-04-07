"""Offline validation for Google Cloud Armor rules."""

import difflib
import ipaddress
import re
import urllib.parse

import celpy
from octorules.linter.engine import LintResult, Severity, is_always_false, is_always_true

# Reusable CEL environment — stateless, safe to share across calls.
_CEL_ENV = celpy.Environment()


def _parse_priority(ref: str) -> int | None:
    """Parse a rule ref as an integer priority, returning None on failure."""
    try:
        return int(ref)
    except (ValueError, TypeError):
        return None


def _result(
    rule_id: str,
    severity: Severity,
    message: str,
    phase: str,
    ref: str = "",
    *,
    field: str = "",
    suggestion: str = "",
) -> LintResult:
    """Create a LintResult with common defaults."""
    return LintResult(
        rule_id=rule_id,
        severity=severity,
        message=message,
        phase=phase,
        ref=ref,
        field=field,
        suggestion=suggestion,
    )


def _is_strict_int(val: object) -> bool:
    """True if *val* is an int but not a bool."""
    return isinstance(val, int) and not isinstance(val, bool)


# --- GA020: Valid top-level rule fields ------------------------------------
_VALID_RULE_FIELDS = frozenset(
    {
        "ref",
        "action",
        "match",
        "description",
        "preview",
        "header_action",
        "rate_limit_options",
        "redirect_options",
        "kind",
        "network_match",
        "preconfigured_waf_config",
    }
)

_BASE_ACTIONS = frozenset({"allow", "throttle", "rate_based_ban", "redirect"})
_DENY_STATUSES = frozenset({403, 404, 429, 502})
_DENY_RE = re.compile(r"^deny\((\d+)\)$")
_VALID_REDIRECT_TYPES = frozenset({"GOOGLE_RECAPTCHA", "EXTERNAL_302"})
_MAX_PRIORITY = 2_147_483_646
_MAX_DESCRIPTION = 1024
_MAX_EXPRESSION = 2048
_MAX_REGEX_PATTERN_LEN = 512

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
        "request.host",
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
        "evaluateThreatIntelligence",
        "evaluateThreatIntelligenceWithExcl",
        "evaluateJsonPath",
        "has",
        "evaluateAdaptiveProtection",
        "evaluateAdaptiveProtectionAutoDeploy",
        "urlDecode",
        "htmlDecode",
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
        "TLS_JA3_FINGERPRINT",
        "TLS_JA4_FINGERPRINT",
        "USER_IP",
    }
)

_MAX_BAN_DURATION = 3600

# RFC 7230 token characters for HTTP header names: tchar = "!" / "#" / "$" /
# "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" /
# DIGIT / ALPHA.  We allow these (case-insensitive) for enforce_on_key_name
# when enforce_on_key is HTTP_HEADER.
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")
_MAX_ENFORCE_ON_KEY_NAME = 128
_MAX_ENFORCE_ON_KEY_CONFIGS = 3

# GA413: regex patterns in CEL matches() calls — two alternations so that
# a single-quoted pattern can contain double quotes and vice versa.
_MATCHES_RE = re.compile(r"""matches\(\s*(?:"([^"]+)"|'([^']+)')\s*\)""")

# GA416: sensitivity level in evaluatePreconfiguredWaf/Expr calls.
# The sensitivity key may appear at any position within the options dict,
# so we allow arbitrary content before the "sensitivity" key.
_SENSITIVITY_RE = re.compile(
    r"""evaluatePreconfigured(?:Waf|Expr)\(\s*["'][^"']+["']\s*,"""
    r"""\s*\{[^}]*?["']sensitivity["']\s*:\s*(\d+)[^}]*\}\s*\)"""
)

# GA418: header names in request.headers["..."] bracket access
_HEADER_BRACKET_RE = re.compile(r"""request\.headers\[\s*["']([^"']+)["']\s*\]""")

# --- GA315: Country code validation in CEL expressions ---
_COUNTRY_CODE_EQ_RE = re.compile(r"""origin\.region_code\s*[!=]=\s*["']([A-Za-z]+)["']""")
_COUNTRY_CODE_IN_RE = re.compile(r"""origin\.region_code\s+in\s*\[([^\]]+)\]""")
_QUOTED_STRING_RE = re.compile(r"""["']([^"']+)["']""")

# --- GA316: HTTP method validation in CEL expressions ---
_VALID_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)
_HTTP_METHOD_EQ_RE = re.compile(r"""request\.method\s*[!=]=\s*["']([^"']+)["']""")
_HTTP_METHOD_IN_RE = re.compile(r"""request\.method\s+in\s*\[([^\]]+)\]""")

# --- GA317: CIDR validation in inIpRange() ---
_IN_IP_RANGE_RE = re.compile(r"""inIpRange\s*\(\s*[^,]+,\s*["']([^"']+)["']\s*\)""")

# --- GA318: CEL type mismatch detection ---
_CEL_FIELD_TYPES: dict[str, str] = {
    "origin.ip": "string",
    "origin.user_ip": "string",
    "origin.region_code": "string",
    "origin.asn": "int",
    "origin.tls_ja3_fingerprint": "string",
    "origin.tls_ja4_fingerprint": "string",
    "request.method": "string",
    "request.path": "string",
    "request.query": "string",
    "request.scheme": "string",
    "request.host": "string",
    "request.url": "string",
}
_TYPE_MISMATCH_RE = re.compile(
    r"""(\b[a-zA-Z_]\w*\.[a-zA-Z_]\w*)\s*(==|!=|>|<|>=|<=)\s*(["'].*?["']|\d+)"""
)

# --- GA319: Case sensitivity reminder ---
_CASE_SENSITIVE_FIELDS = frozenset({"request.path", "request.query", "request.host", "request.url"})
_CASE_SENSITIVE_CMP_RE = re.compile(
    r"""(request\.(?:path|query|host|url))\s*==\s*["']([^"']+)["']"""
)

# --- GA502: Tier-aware rule count limits ---
_TIER_RULE_LIMITS: dict[str, int] = {
    "standard": 256,
    "plus": 512,
    "enterprise": 1024,
}

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
                _result(
                    rule_id="GA001",
                    severity=Severity.ERROR,
                    message="Rule missing 'ref'",
                    phase=phase,
                )
            )
        ref_str = str(ref)

        _check_unknown_fields(rule, results, phase, ref_str)
        _check_priority(ref_str, results, phase, seen_priorities)
        _check_action(rule, results, phase, ref_str)
        _check_match(rule, results, phase, ref_str, seen_expressions, seen_waf_rulesets)
        _check_match_deep(rule, results, phase, ref_str)
        _check_description(rule, results, phase, ref_str)
        _check_rate_limit_deep(rule, results, phase, ref_str, seen_enforce_on_keys)
        _check_header_action(rule, results, phase, ref_str)
        _check_network_match(rule, results, phase, ref_str)
        _check_preconfigured_waf_config(rule, results, phase, ref_str)
        _check_preview(rule, results, phase, ref_str)
        _check_always_true_false(rule, results, phase, ref_str)

    _check_duplicate_priorities(seen_priorities, results, phase)
    _check_duplicate_expressions(seen_expressions, results, phase)
    _check_dead_rules(rules, results, phase)
    _check_inconsistent_enforce_on_key(seen_enforce_on_keys, results, phase)
    _check_duplicate_waf_rulesets(seen_waf_rulesets, results, phase)

    return results


# --- Per-rule checks --------------------------------------------------------
def _check_unknown_fields(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """GA020: flag unknown top-level rule fields."""
    unknown = set(rule) - _VALID_RULE_FIELDS
    for field in sorted(unknown):
        results.append(
            _result(
                rule_id="GA020",
                severity=Severity.ERROR,
                message=f"Unknown top-level rule field: '{field}'",
                phase=phase,
                ref=ref,
                field=field,
            )
        )


def _check_priority(
    ref: str,
    results: list[LintResult],
    phase: str,
    seen: dict[int, list[str]],
) -> None:
    if not ref:
        return
    pri = _parse_priority(ref)
    if pri is None:
        results.append(
            _result(
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
            _result(
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
            _result(
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
    """GA002/GA200/GA201/GA400/GA401 -- validate action and its required options."""
    action = rule.get("action", "")
    if not action:
        results.append(
            _result(
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
                _result(
                    rule_id="GA201",
                    severity=Severity.ERROR,
                    message=f"Invalid deny status: {status}",
                    phase=phase,
                    ref=ref,
                    field="action",
                    suggestion="Valid deny statuses: 403, 404, 429, 502",
                )
            )
    elif action not in _BASE_ACTIONS:
        if action == "deny":
            suggestion = "deny requires a status code, e.g. deny(403)"
        else:
            suggestion = (
                "Valid actions: allow, deny(403), deny(404), deny(429),"
                " deny(502), rate_based_ban, redirect, throttle"
            )
        results.append(
            _result(
                rule_id="GA200",
                severity=Severity.ERROR,
                message=f"Invalid action: {action!r}",
                phase=phase,
                ref=ref,
                field="action",
                suggestion=suggestion,
            )
        )

    # GA400-GA407: rate_limit_options
    if action in ("throttle", "rate_based_ban"):
        if "rate_limit_options" not in rule:
            results.append(
                _result(
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
                _result(
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
    """GA403/GA405/GA406/GA407 — rate_limit_options structure."""
    if not isinstance(rlo, dict):
        return

    # GA403: required fields
    for field in ("conform_action", "exceed_action", "rate_limit_threshold"):
        if field not in rlo:
            results.append(
                _result(
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
            _result(
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
            _result(
                rule_id="GA406",
                severity=Severity.ERROR,
                message=f"Invalid exceed_action: {ea!r}",
                phase=phase,
                ref=ref,
                field="rate_limit_options.exceed_action",
                suggestion=f"Valid values: {sorted(_VALID_EXCEED_ACTIONS)}",
            )
        )

    # GA407: rate_limit_threshold.interval_sec
    rlt = rlo.get("rate_limit_threshold")
    if isinstance(rlt, dict):
        interval = rlt.get("interval_sec")
        if interval is not None and interval not in _VALID_INTERVALS:
            results.append(
                _result(
                    rule_id="GA407",
                    severity=Severity.ERROR,
                    message=f"Invalid interval_sec: {interval!r}",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.rate_limit_threshold.interval_sec",
                    suggestion=f"Valid values: {sorted(_VALID_INTERVALS)}",
                )
            )
        # NOTE: count type/range validation is handled by GA421 in
        # _check_rate_limit_deep to avoid duplicate diagnostics.


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
            _result(
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
            _result(
                rule_id="GA404",
                severity=Severity.ERROR,
                message="EXTERNAL_302 redirect requires 'target' URL",
                phase=phase,
                ref=ref,
                field="redirect_options.target",
            )
        )

    # GA419: empty or whitespace-only redirect target
    target = redir.get("target")
    if target is not None and isinstance(target, str) and not target.strip():
        results.append(
            _result(
                rule_id="GA419",
                severity=Severity.ERROR,
                message="redirect target must not be empty",
                phase=phase,
                ref=ref,
                field="redirect_options.target",
            )
        )
        return  # No point checking URL format on empty target

    # GA409: EXTERNAL_302 target must be a valid URL
    if rtype == "EXTERNAL_302" and target is not None and isinstance(target, str):
        if not target.startswith(("http://", "https://")):
            results.append(
                _result(
                    rule_id="GA409",
                    severity=Severity.ERROR,
                    message=(
                        f"redirect_options.target must start with http:// or https://"
                        f" for EXTERNAL_302 (got {target!r})"
                    ),
                    phase=phase,
                    ref=ref,
                    field="redirect_options.target",
                )
            )
        else:
            parsed = urllib.parse.urlparse(target)
            if not parsed.netloc:
                results.append(
                    _result(
                        rule_id="GA409",
                        severity=Severity.ERROR,
                        message=(
                            f"redirect_options.target must include a host"
                            f" for EXTERNAL_302 (got {target!r})"
                        ),
                        phase=phase,
                        ref=ref,
                        field="redirect_options.target",
                    )
                )
            # GA433: redirect URL length
            if len(target) > 1024:
                results.append(
                    _result(
                        rule_id="GA433",
                        severity=Severity.WARNING,
                        message=(
                            f"redirect_options.target length ({len(target)}) exceeds"
                            " 1024 characters"
                        ),
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
    """GA003/GA300-GA304 -- validate match structure, CIDRs, and CEL expressions."""
    match = rule.get("match")
    if match is None:
        results.append(
            _result(
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
            _result(
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
            _result(
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
            net = ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            # Host bits set — try non-strict to see if it's a normalizable CIDR
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                results.append(
                    _result(
                        rule_id="GA301",
                        severity=Severity.WARNING,
                        message=f"Invalid CIDR: {cidr!r}",
                        phase=phase,
                        ref=ref,
                        field="match.config.src_ip_ranges",
                    )
                )
                continue
            # Parseable but host bits were set — warn about normalization
            results.append(
                _result(
                    rule_id="GA307",
                    severity=Severity.WARNING,
                    message=(
                        f"CIDR {cidr!r} has host bits set and will be normalized to {str(net)!r}"
                    ),
                    phase=phase,
                    ref=ref,
                    field="match.config.src_ip_ranges",
                    suggestion=f"Use {str(net)!r} instead",
                )
            )
        networks.append((cidr, net))

    for cidr, net in networks:
        # GA306: /0 matches all traffic
        if net.prefixlen == 0:
            results.append(
                _result(
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
                    _result(
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
                    _result(
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
            _result(
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
        _CEL_ENV.compile(expr)
    except celpy.CELParseError as exc:
        results.append(
            _result(
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
                _result(
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
            _result(
                rule_id="GA500",
                severity=Severity.WARNING,
                message=f"Description exceeds {_MAX_DESCRIPTION} characters ({len(desc)})",
                phase=phase,
                ref=ref,
                field="description",
            )
        )


# --- Deep per-rule checks (new GA310-GA431) ---------------------------------
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
                _result(
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
                _result(
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
                _result(
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
                _result(
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
                _result(
                    rule_id="GA314",
                    severity=Severity.WARNING,
                    message="Empty or whitespace-only CEL expression matches nothing",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )
            return  # No point in field/function extraction on empty expr

        # --- GA310/GA311/GA413/GA416/GA418: field, function, regex, sensitivity,
        #     and header name extraction (only on non-empty exprs) ---
        if isinstance(expression, str) and expression.strip():
            _check_cel_fields(expression, results, phase, ref)
            _check_cel_functions(expression, results, phase, ref)
            _check_cel_regex(expression, results, phase, ref)
            _check_cel_sensitivity(expression, results, phase, ref)
            _check_cel_header_names(expression, results, phase, ref)
            _check_cel_country_codes(expression, results, phase, ref)
            _check_cel_http_methods(expression, results, phase, ref)
            _check_cel_iniprange_cidr(expression, results, phase, ref)
            _check_cel_type_mismatch(expression, results, phase, ref)
            _check_cel_case_sensitivity(expression, results, phase, ref)


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
            _result(
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
                _result(
                    rule_id="GA311",
                    severity=Severity.WARNING,
                    message=f"Unknown function: {func!r}",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                    suggestion=f"Known functions: {sorted(_KNOWN_FUNCTIONS)}",
                )
            )


def _check_cel_regex(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA413: invalid/overlong regex pattern in CEL matches() calls."""
    for m in _MATCHES_RE.finditer(expr):
        pattern = m.group(1) or m.group(2)
        if len(pattern) > _MAX_REGEX_PATTERN_LEN:
            results.append(
                _result(
                    rule_id="GA413",
                    severity=Severity.WARNING,
                    message=(
                        f"Regex pattern too long ({len(pattern)} chars,"
                        f" max {_MAX_REGEX_PATTERN_LEN})"
                    ),
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            results.append(
                _result(
                    rule_id="GA413",
                    severity=Severity.WARNING,
                    message=f"Invalid regex pattern in matches(): {exc}",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )


def _check_cel_sensitivity(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA416: preconfigured WAF sensitivity level must be 0-4."""
    for m in _SENSITIVITY_RE.finditer(expr):
        level = int(m.group(1))
        if level < 0 or level > 4:
            results.append(
                _result(
                    rule_id="GA416",
                    severity=Severity.WARNING,
                    message=f"Preconfigured WAF sensitivity level must be 0-4 (got {level})",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )


def _check_cel_header_names(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA418: invalid HTTP header name in CEL bracket access."""
    seen: set[str] = set()
    for m in _HEADER_BRACKET_RE.finditer(expr):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        if not _HEADER_NAME_RE.match(name):
            results.append(
                _result(
                    rule_id="GA418",
                    severity=Severity.WARNING,
                    message=f"Invalid HTTP header name in CEL expression: {name!r}",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )


def _check_cel_country_codes(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA315: validate country codes in origin.region_code comparisons."""
    codes: list[str] = []

    # origin.region_code == "XX"
    for m in _COUNTRY_CODE_EQ_RE.finditer(expr):
        codes.append(m.group(1))

    # origin.region_code in ["US", "CA", ...]
    for m in _COUNTRY_CODE_IN_RE.finditer(expr):
        for qm in _QUOTED_STRING_RE.finditer(m.group(1)):
            codes.append(qm.group(1))

    seen: set[str] = set()
    for code in codes:
        if code in seen:
            continue
        seen.add(code)
        if len(code) != 2:
            results.append(
                _result(
                    rule_id="GA315",
                    severity=Severity.WARNING,
                    message=(
                        f"Country code {code!r} in origin.region_code comparison"
                        " must be exactly 2 letters"
                    ),
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )
        elif not code.isalpha():
            results.append(
                _result(
                    rule_id="GA315",
                    severity=Severity.WARNING,
                    message=(
                        f"Country code {code!r} in origin.region_code comparison must be alphabetic"
                    ),
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )
        elif code != code.upper():
            results.append(
                _result(
                    rule_id="GA315",
                    severity=Severity.WARNING,
                    message=(f"Country code {code!r} should be uppercase ({code.upper()!r})"),
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                    suggestion=f"Replace {code!r} with {code.upper()!r}",
                )
            )


def _check_cel_http_methods(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA316: validate HTTP method names in request.method comparisons."""
    methods: list[str] = []

    # request.method == "GET"
    for m in _HTTP_METHOD_EQ_RE.finditer(expr):
        methods.append(m.group(1))

    # request.method in ["GET", "POST"]
    for m in _HTTP_METHOD_IN_RE.finditer(expr):
        for qm in _QUOTED_STRING_RE.finditer(m.group(1)):
            methods.append(qm.group(1))

    seen: set[str] = set()
    for method in methods:
        if method in seen:
            continue
        seen.add(method)
        if method not in _VALID_HTTP_METHODS:
            close = difflib.get_close_matches(method.upper(), _VALID_HTTP_METHODS, n=1)
            suggestion = f" (did you mean {close[0]!r}?)" if close else ""
            results.append(
                _result(
                    rule_id="GA316",
                    severity=Severity.WARNING,
                    message=f"Unknown HTTP method {method!r}{suggestion}",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                    suggestion=(f"Valid methods: {sorted(_VALID_HTTP_METHODS)}"),
                )
            )


def _check_cel_iniprange_cidr(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA317/GA320: validate CIDR notation inside inIpRange() calls."""
    for m in _IN_IP_RANGE_RE.finditer(expr):
        cidr = m.group(1)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            results.append(
                _result(
                    rule_id="GA317",
                    severity=Severity.ERROR,
                    message=f"Invalid CIDR in inIpRange(): {cidr!r} ({exc})",
                    phase=phase,
                    ref=ref,
                    field="match.expr.expression",
                )
            )
            continue

        # GA320: check for private/reserved ranges
        for private in _PRIVATE_SUPERNETS:
            if net.version == private.version and net.subnet_of(private):
                results.append(
                    _result(
                        rule_id="GA320",
                        severity=Severity.WARNING,
                        message=(f"Private/reserved IP range in inIpRange(): {cidr!r}"),
                        phase=phase,
                        ref=ref,
                        field="match.expr.expression",
                    )
                )
                break


def _check_cel_type_mismatch(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA318: detect type mismatches in CEL field comparisons."""
    seen: set[str] = set()
    for m in _TYPE_MISMATCH_RE.finditer(expr):
        field_name = m.group(1)
        literal = m.group(3)

        expected_type = _CEL_FIELD_TYPES.get(field_name)
        if expected_type is None:
            continue

        # Determine literal type
        if literal.startswith(("'", '"')):
            literal_type = "string"
        else:
            literal_type = "int"

        if expected_type == literal_type:
            continue

        # Deduplicate
        key = f"{field_name}:{literal}"
        if key in seen:
            continue
        seen.add(key)

        results.append(
            _result(
                rule_id="GA318",
                severity=Severity.WARNING,
                message=(
                    f"Type mismatch: {field_name} is {expected_type}"
                    f" but compared with {literal_type} ({literal})"
                ),
                phase=phase,
                ref=ref,
                field="match.expr.expression",
            )
        )


def _check_cel_case_sensitivity(
    expr: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA319: warn when string comparisons on path/query/host use mixed case."""
    seen: set[str] = set()
    for m in _CASE_SENSITIVE_CMP_RE.finditer(expr):
        field_name = m.group(1)
        literal = m.group(2)

        # Only warn if the literal has mixed case (not all-lower, not all-upper)
        if literal == literal.lower() or literal == literal.upper():
            continue

        # Deduplicate
        key = f"{field_name}:{literal}"
        if key in seen:
            continue
        seen.add(key)

        results.append(
            _result(
                rule_id="GA319",
                severity=Severity.INFO,
                message=(
                    f"String comparison on {field_name} is case-sensitive;"
                    " use matches() with (?i) for case-insensitive matching"
                ),
                phase=phase,
                ref=ref,
                field="match.expr.expression",
            )
        )


def _check_rate_limit_threshold(
    rlo: dict,
    action: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA420/GA421 — rate_limit_threshold subfield validation."""
    rlt = rlo.get("rate_limit_threshold")
    if rlt is None:
        return

    if not isinstance(rlt, dict):
        results.append(
            _result(
                rule_id="GA420",
                severity=Severity.ERROR,
                message="rate_limit_threshold must be a dict with 'count' and 'interval_sec'",
                phase=phase,
                ref=ref,
                field="rate_limit_options.rate_limit_threshold",
            )
        )
        return

    if "count" not in rlt:
        results.append(
            _result(
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
            _result(
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
    if count is not None:
        if not _is_strict_int(count):
            results.append(
                _result(
                    rule_id="GA421",
                    severity=Severity.ERROR,
                    message=(f"rate_limit_threshold.count must be int, got {type(count).__name__}"),
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.rate_limit_threshold.count",
                )
            )
        else:
            max_count = 10_000 if action == "rate_based_ban" else 1_000_000
            if count < 1 or count > max_count:
                results.append(
                    _result(
                        rule_id="GA421",
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
    interval = rlt.get("interval_sec")
    if interval is not None and (not _is_strict_int(interval)):
        results.append(
            _result(
                rule_id="GA421",
                severity=Severity.ERROR,
                message=(
                    f"rate_limit_threshold.interval_sec must be int, got {type(interval).__name__}"
                ),
                phase=phase,
                ref=ref,
                field="rate_limit_options.rate_limit_threshold.interval_sec",
            )
        )


def _check_enforce_on_key(
    rlo: dict,
    action: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> str | None:
    """GA422/GA423/GA424 — enforce_on_key validation.

    Returns the enforce_on_key value (or None) so callers can pass it
    to downstream checks.
    """
    eok = rlo.get("enforce_on_key")
    if eok is not None:
        if eok not in _VALID_ENFORCE_ON_KEYS:
            results.append(
                _result(
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
                    _result(
                        rule_id="GA424",
                        severity=Severity.ERROR,
                        message=(f"enforce_on_key '{eok}' requires 'enforce_on_key_name'"),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.enforce_on_key_name",
                    )
                )

    # GA422: enforce_on_key for rate_based_ban with redirect
    if action == "rate_based_ban":
        ea = rlo.get("exceed_action")
        if ea == "redirect" and eok is None:
            results.append(
                _result(
                    rule_id="GA422",
                    severity=Severity.WARNING,
                    message="rate_based_ban with redirect exceed_action should set enforce_on_key",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.enforce_on_key",
                )
            )

    return eok


def _check_ban_duration_sec(
    rlo: dict,
    action: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA425/GA426/GA427/GA430 — ban_duration_sec validation for rate_based_ban."""
    if action != "rate_based_ban":
        return

    bds = rlo.get("ban_duration_sec")
    if bds is None:
        results.append(
            _result(
                rule_id="GA425",
                severity=Severity.ERROR,
                message="rate_based_ban requires 'ban_duration_sec' in rate_limit_options",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_duration_sec",
            )
        )
        return

    bad = not _is_strict_int(bds) or bds <= 0
    if bad:
        results.append(
            _result(
                rule_id="GA426",
                severity=Severity.ERROR,
                message=f"ban_duration_sec must be a positive integer, got {bds!r}",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_duration_sec",
            )
        )
    elif bds < 60:
        results.append(
            _result(
                rule_id="GA430",
                severity=Severity.WARNING,
                message=(f"ban_duration_sec {bds} is very short (< 60 seconds may be ineffective)"),
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_duration_sec",
                suggestion="Consider a duration of 60 seconds or more",
            )
        )
    elif bds > _MAX_BAN_DURATION:
        results.append(
            _result(
                rule_id="GA427",
                severity=Severity.ERROR,
                message=(f"ban_duration_sec {bds} exceeds maximum ({_MAX_BAN_DURATION} seconds)"),
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_duration_sec",
                suggestion=f"Must be between 1 and {_MAX_BAN_DURATION}",
            )
        )


def _check_enforce_on_key_name(
    rlo: dict,
    eok: str | None,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA428 — enforce_on_key_name content validation."""
    eokn = rlo.get("enforce_on_key_name")
    if eokn is None or not isinstance(eokn, str) or eok not in ("HTTP_HEADER", "HTTP_COOKIE"):
        return

    if not eokn:
        results.append(
            _result(
                rule_id="GA428",
                severity=Severity.WARNING,
                message="enforce_on_key_name must not be empty",
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_name",
            )
        )
    elif len(eokn) > _MAX_ENFORCE_ON_KEY_NAME:
        results.append(
            _result(
                rule_id="GA428",
                severity=Severity.WARNING,
                message=(
                    f"enforce_on_key_name exceeds {_MAX_ENFORCE_ON_KEY_NAME}"
                    f" characters ({len(eokn)})"
                ),
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_name",
            )
        )
    elif any(c <= "\x1f" or c == "\x7f" for c in eokn):
        results.append(
            _result(
                rule_id="GA428",
                severity=Severity.WARNING,
                message="enforce_on_key_name contains control characters",
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_name",
            )
        )
    elif " " in eokn:
        results.append(
            _result(
                rule_id="GA428",
                severity=Severity.WARNING,
                message="enforce_on_key_name contains spaces",
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_name",
            )
        )
    elif eok == "HTTP_HEADER" and not _HEADER_NAME_RE.match(eokn):
        results.append(
            _result(
                rule_id="GA428",
                severity=Severity.WARNING,
                message=(
                    f"enforce_on_key_name {eokn!r} contains invalid header name"
                    " characters (RFC 7230)"
                ),
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_name",
                suggestion="Header names may only contain tchar (RFC 7230)",
            )
        )


def _check_enforce_on_key_configs(
    rlo: dict,
    eok: str | None,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA414/GA415 — enforce_on_key_configs validation."""
    eokc = rlo.get("enforce_on_key_configs")
    if eokc is None:
        return

    # GA414: mutually exclusive with enforce_on_key
    if eok is not None:
        results.append(
            _result(
                rule_id="GA414",
                severity=Severity.ERROR,
                message=("enforce_on_key_configs is mutually exclusive with enforce_on_key"),
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_configs",
            )
        )

    if not isinstance(eokc, list):
        results.append(
            _result(
                rule_id="GA414",
                severity=Severity.ERROR,
                message="enforce_on_key_configs must be a list",
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_configs",
            )
        )
        return

    # GA414: max 3 entries
    if len(eokc) > _MAX_ENFORCE_ON_KEY_CONFIGS:
        results.append(
            _result(
                rule_id="GA414",
                severity=Severity.ERROR,
                message=(
                    f"enforce_on_key_configs allows at most"
                    f" {_MAX_ENFORCE_ON_KEY_CONFIGS} entries (got {len(eokc)})"
                ),
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_configs",
            )
        )
    # GA414: each entry must be a dict with enforce_on_key_type
    for i, entry in enumerate(eokc):
        if not isinstance(entry, dict):
            results.append(
                _result(
                    rule_id="GA414",
                    severity=Severity.ERROR,
                    message=(f"enforce_on_key_configs[{i}] must be a dict"),
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.enforce_on_key_configs",
                )
            )
        elif "enforce_on_key_type" not in entry:
            results.append(
                _result(
                    rule_id="GA414",
                    severity=Severity.ERROR,
                    message=(f"enforce_on_key_configs[{i}] missing 'enforce_on_key_type'"),
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.enforce_on_key_configs",
                )
            )
        else:
            # GA423: validate the enforce_on_key_type value
            kt = entry["enforce_on_key_type"]
            if kt not in _VALID_ENFORCE_ON_KEYS:
                results.append(
                    _result(
                        rule_id="GA423",
                        severity=Severity.ERROR,
                        message=(
                            f"Invalid enforce_on_key_type in enforce_on_key_configs[{i}]: {kt!r}"
                        ),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.enforce_on_key_configs",
                        suggestion=f"Valid values: {sorted(_VALID_ENFORCE_ON_KEYS)}",
                    )
                )

    # GA415: duplicate enforce_on_key_type values
    seen_types: list[str] = []
    for entry in eokc:
        if isinstance(entry, dict):
            kt = entry.get("enforce_on_key_type")
            if kt is not None:
                seen_types.append(kt)
    if len(seen_types) != len(set(seen_types)):
        results.append(
            _result(
                rule_id="GA415",
                severity=Severity.WARNING,
                message="Duplicate enforce_on_key_type in enforce_on_key_configs",
                phase=phase,
                ref=ref,
                field="rate_limit_options.enforce_on_key_configs",
            )
        )


def _check_exceed_redirect_options(
    rlo: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA411/GA412/GA419 — exceed_redirect_options validation."""
    ero = rlo.get("exceed_redirect_options")
    if not isinstance(ero, dict):
        return

    ero_type = ero.get("type", "")
    if ero_type and ero_type not in _VALID_REDIRECT_TYPES:
        results.append(
            _result(
                rule_id="GA411",
                severity=Severity.ERROR,
                message=(
                    f"exceed_redirect_options.type must be one of: {sorted(_VALID_REDIRECT_TYPES)}"
                ),
                phase=phase,
                ref=ref,
                field="rate_limit_options.exceed_redirect_options.type",
            )
        )

    ero_target = ero.get("target")
    if ero_target is not None and isinstance(ero_target, str):
        if not ero_target.strip():
            results.append(
                _result(
                    rule_id="GA419",
                    severity=Severity.ERROR,
                    message="redirect target must not be empty",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.exceed_redirect_options.target",
                )
            )
        elif ero_type == "EXTERNAL_302":
            if not ero_target.startswith(("http://", "https://")):
                results.append(
                    _result(
                        rule_id="GA412",
                        severity=Severity.ERROR,
                        message=(
                            "exceed_redirect_options.target must start with"
                            " http:// or https:// for EXTERNAL_302"
                        ),
                        phase=phase,
                        ref=ref,
                        field="rate_limit_options.exceed_redirect_options.target",
                    )
                )
            else:
                parsed = urllib.parse.urlparse(ero_target)
                if not parsed.netloc:
                    results.append(
                        _result(
                            rule_id="GA412",
                            severity=Severity.ERROR,
                            message=(
                                "exceed_redirect_options.target must include a host"
                                " for EXTERNAL_302"
                            ),
                            phase=phase,
                            ref=ref,
                            field="rate_limit_options.exceed_redirect_options.target",
                        )
                    )


def _check_ban_threshold(
    rlo: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA410 — ban_threshold structure validation."""
    bt = rlo.get("ban_threshold")
    if bt is None:
        return

    if not isinstance(bt, dict):
        results.append(
            _result(
                rule_id="GA410",
                severity=Severity.ERROR,
                message="ban_threshold must be a dict with 'count' and 'interval_sec'",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_threshold",
            )
        )
        return

    bt_count = bt.get("count")
    if bt_count is not None:
        bad_type = not _is_strict_int(bt_count)
        if bad_type or bt_count < 1:
            results.append(
                _result(
                    rule_id="GA410",
                    severity=Severity.ERROR,
                    message="ban_threshold.count must be a positive integer",
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.ban_threshold.count",
                )
            )
    else:
        results.append(
            _result(
                rule_id="GA410",
                severity=Severity.ERROR,
                message="ban_threshold missing required field 'count'",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_threshold.count",
            )
        )

    bt_interval = bt.get("interval_sec")
    if bt_interval is not None:
        if bt_interval not in _VALID_INTERVALS:
            results.append(
                _result(
                    rule_id="GA410",
                    severity=Severity.ERROR,
                    message=(f"ban_threshold.interval_sec invalid (got {bt_interval!r})"),
                    phase=phase,
                    ref=ref,
                    field="rate_limit_options.ban_threshold.interval_sec",
                    suggestion=f"Valid values: {sorted(_VALID_INTERVALS)}",
                )
            )
    else:
        results.append(
            _result(
                rule_id="GA410",
                severity=Severity.ERROR,
                message="ban_threshold missing required field 'interval_sec'",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_threshold.interval_sec",
            )
        )


def _check_rate_limit_deep(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    seen_enforce_on_keys: dict[str, str],
) -> None:
    """GA410-GA432 — deep rate-limit and action parameter validation.

    Delegates to focused helpers for each concern.
    """
    action = rule.get("action", "")
    rlo = rule.get("rate_limit_options")
    if not isinstance(rlo, dict):
        return

    _check_rate_limit_threshold(rlo, action, results, phase, ref)
    eok = _check_enforce_on_key(rlo, action, results, phase, ref)
    _check_ban_duration_sec(rlo, action, results, phase, ref)
    _check_enforce_on_key_name(rlo, eok, results, phase, ref)
    _check_enforce_on_key_configs(rlo, eok, results, phase, ref)
    _check_exceed_redirect_options(rlo, results, phase, ref)
    _check_ban_threshold(rlo, results, phase, ref)

    # Track enforce_on_key for cross-rule GA105 check
    if action in ("throttle", "rate_based_ban") and eok is not None:
        seen_enforce_on_keys[ref] = eok

    # GA429: ban_duration_sec only valid for rate_based_ban
    if action == "throttle" and "ban_duration_sec" in rlo:
        results.append(
            _result(
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
            _result(
                rule_id="GA431",
                severity=Severity.ERROR,
                message="exceed_action 'redirect' requires 'exceed_redirect_options'",
                phase=phase,
                ref=ref,
                field="rate_limit_options.exceed_redirect_options",
            )
        )

    # GA432: conflicting rate-limit option combinations
    if ea is not None and ea != "redirect" and "exceed_redirect_options" in rlo:
        results.append(
            _result(
                rule_id="GA432",
                severity=Severity.ERROR,
                message=(
                    f"exceed_redirect_options is only valid when exceed_action"
                    f" is 'redirect', got {ea!r}"
                ),
                phase=phase,
                ref=ref,
                field="rate_limit_options.exceed_redirect_options",
            )
        )

    # ban_threshold without rate_limit_threshold makes no sense
    if "ban_threshold" in rlo and "rate_limit_threshold" not in rlo:
        results.append(
            _result(
                rule_id="GA432",
                severity=Severity.ERROR,
                message="ban_threshold requires rate_limit_threshold to be set",
                phase=phase,
                ref=ref,
                field="rate_limit_options.ban_threshold",
            )
        )


# --- GA325/GA326/GA327: Sub-structure validation ---------------------------
def _check_header_action(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA325: validate header_action sub-structure."""
    ha = rule.get("header_action")
    if ha is None:
        return
    if not isinstance(ha, dict):
        results.append(
            _result(
                rule_id="GA325",
                severity=Severity.ERROR,
                message="header_action must be a dict",
                phase=phase,
                ref=ref,
                field="header_action",
            )
        )
        return

    rhta = ha.get("request_headers_to_adds")
    if rhta is None:
        return
    if not isinstance(rhta, list):
        results.append(
            _result(
                rule_id="GA325",
                severity=Severity.ERROR,
                message="header_action.request_headers_to_adds must be a list",
                phase=phase,
                ref=ref,
                field="header_action.request_headers_to_adds",
            )
        )
        return

    for i, entry in enumerate(rhta):
        if not isinstance(entry, dict):
            results.append(
                _result(
                    rule_id="GA325",
                    severity=Severity.ERROR,
                    message=f"header_action.request_headers_to_adds[{i}] must be a dict",
                    phase=phase,
                    ref=ref,
                    field="header_action.request_headers_to_adds",
                )
            )
            continue
        for required in ("header_name", "header_value"):
            if required not in entry:
                results.append(
                    _result(
                        rule_id="GA325",
                        severity=Severity.ERROR,
                        message=(
                            f"header_action.request_headers_to_adds[{i}] missing '{required}'"
                        ),
                        phase=phase,
                        ref=ref,
                        field=f"header_action.request_headers_to_adds.{required}",
                    )
                )


def _check_network_match(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA326: validate network_match sub-structure."""
    nm = rule.get("network_match")
    if nm is None:
        return
    if not isinstance(nm, dict):
        results.append(
            _result(
                rule_id="GA326",
                severity=Severity.ERROR,
                message="network_match must be a dict",
                phase=phase,
                ref=ref,
                field="network_match",
            )
        )


def _check_preconfigured_waf_config(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA327: validate preconfigured_waf_config sub-structure."""
    pwc = rule.get("preconfigured_waf_config")
    if pwc is None:
        return
    if not isinstance(pwc, dict):
        results.append(
            _result(
                rule_id="GA327",
                severity=Severity.ERROR,
                message="preconfigured_waf_config must be a dict",
                phase=phase,
                ref=ref,
                field="preconfigured_waf_config",
            )
        )
        return

    exclusions = pwc.get("exclusions")
    if exclusions is None:
        return
    if not isinstance(exclusions, list):
        results.append(
            _result(
                rule_id="GA327",
                severity=Severity.ERROR,
                message="preconfigured_waf_config.exclusions must be a list",
                phase=phase,
                ref=ref,
                field="preconfigured_waf_config.exclusions",
            )
        )
        return

    for i, exc in enumerate(exclusions):
        if not isinstance(exc, dict):
            results.append(
                _result(
                    rule_id="GA327",
                    severity=Severity.ERROR,
                    message=f"preconfigured_waf_config.exclusions[{i}] must be a dict",
                    phase=phase,
                    ref=ref,
                    field="preconfigured_waf_config.exclusions",
                )
            )
        elif "target_rule_set" not in exc:
            results.append(
                _result(
                    rule_id="GA327",
                    severity=Severity.ERROR,
                    message=(f"preconfigured_waf_config.exclusions[{i}] missing 'target_rule_set'"),
                    phase=phase,
                    ref=ref,
                    field="preconfigured_waf_config.exclusions",
                )
            )


# --- GA600/GA601/GA602: Preview, always-true, always-false ------------------
def _check_preview(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA600: rule is in preview mode (logs only, not enforced)."""
    if rule.get("preview") is True:
        results.append(
            _result(
                rule_id="GA600",
                severity=Severity.INFO,
                message="Rule is in preview mode (preview: true) — not enforced",
                phase=phase,
                ref=ref,
                field="preview",
            )
        )


def _check_always_true_false(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """GA601/GA602: expression is always true (catch-all) or always false (dead).

    Checks both CEL expressions and IP-based match-all patterns.
    """
    match = rule.get("match")
    if not isinstance(match, dict):
        return

    # --- CEL expression checks ---
    expr_obj = match.get("expr")
    if isinstance(expr_obj, dict):
        expression = expr_obj.get("expression")
        if isinstance(expression, str) and expression.strip():
            normalized = " ".join(expression.strip().lower().split())
            if is_always_true(normalized):
                results.append(
                    _result(
                        rule_id="GA601",
                        severity=Severity.WARNING,
                        message="Expression is always true — this is a catch-all rule",
                        phase=phase,
                        ref=ref,
                        field="match.expr.expression",
                    )
                )
                return
            if is_always_false(normalized):
                results.append(
                    _result(
                        rule_id="GA602",
                        severity=Severity.WARNING,
                        message="Expression is always false — rule never matches",
                        phase=phase,
                        ref=ref,
                        field="match.expr.expression",
                    )
                )
                return

    # --- IP-based match-all: SRC_IPS_V1 with srcIpRanges: ["*"] ---
    ve = match.get("versioned_expr")
    if ve == "SRC_IPS_V1":
        config = match.get("config")
        if isinstance(config, dict):
            ranges = config.get("src_ip_ranges")
            if isinstance(ranges, list) and ranges == ["*"]:
                results.append(
                    _result(
                        rule_id="GA601",
                        severity=Severity.WARNING,
                        message=("src_ip_ranges is ['*'] — this is a catch-all rule"),
                        phase=phase,
                        ref=ref,
                        field="match.config.src_ip_ranges",
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
            _result(
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
                _result(
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
                _result(
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
                _result(
                    rule_id="GA104",
                    severity=Severity.WARNING,
                    message=f"Duplicate expression across rules: {', '.join(refs)}",
                    phase=phase,
                )
            )


def _is_match_all(rule: dict) -> bool:
    """Return True if *rule* matches all traffic (catch-all).

    Checks both CEL expressions that are always true (including parenthesized
    forms like ``((true))``) and IP-wildcard ``SRC_IPS_V1`` with ``["*"]``.
    """
    match = rule.get("match")
    if not isinstance(match, dict):
        return False

    # CEL expression check (handles "true", "((true))", etc.)
    expr_obj = match.get("expr")
    if isinstance(expr_obj, dict):
        expression = expr_obj.get("expression", "")
        if isinstance(expression, str) and expression.strip():
            normalized = " ".join(expression.strip().lower().split())
            if is_always_true(normalized):
                return True

    # IP-wildcard match-all: SRC_IPS_V1 with src_ip_ranges: ["*"]
    ve = match.get("versioned_expr")
    if ve == "SRC_IPS_V1":
        config = match.get("config")
        if isinstance(config, dict):
            ranges = config.get("src_ip_ranges")
            if isinstance(ranges, list) and ranges == ["*"]:
                return True

    return False


def _check_dead_rules(
    rules: list[dict],
    results: list[LintResult],
    phase: str,
) -> None:
    """GA103: rules unreachable after a match-all rule."""
    # Find the lowest-priority match-all rule
    match_all_pri: int | None = None
    for rule in rules:
        ref = rule.get("ref", "")
        pri = _parse_priority(ref)
        if pri is None:
            continue
        if _is_match_all(rule):
            if match_all_pri is None or pri < match_all_pri:
                match_all_pri = pri

    if match_all_pri is None:
        return

    for rule in rules:
        ref = rule.get("ref", "")
        pri = _parse_priority(ref)
        if pri is None:
            continue
        if pri > match_all_pri:
            results.append(
                _result(
                    rule_id="GA103",
                    severity=Severity.WARNING,
                    message=(
                        f"Rule unreachable: priority {match_all_pri} matches all traffic first"
                    ),
                    phase=phase,
                    ref=str(ref),
                )
            )


def validate_rule_count(
    rules: list[dict],
    *,
    phase: str = "",
    plan_tier: str = "enterprise",
) -> list[LintResult]:
    """GA502: check rule count against tier-specific limits.

    Args:
        rules: List of Cloud Armor rule dicts.
        phase: Phase name (for reporting).
        plan_tier: One of "standard", "plus", "enterprise". Defaults to
            "enterprise" (most permissive).

    Returns:
        List of lint results (empty if within limits).
    """
    results: list[LintResult] = []
    tier = plan_tier.lower()
    limit = _TIER_RULE_LIMITS.get(tier)
    if limit is None:
        return results

    count = len(rules)
    if count > limit:
        results.append(
            _result(
                rule_id="GA502",
                severity=Severity.WARNING,
                message=(f"Rule count ({count}) exceeds {tier} tier limit ({limit})"),
                phase=phase,
            )
        )
    return results


# --- GA501: Regex rule count per policy (standard tier limit: 10) ----------
_MAX_REGEX_RULES_STANDARD = 10


def _rule_uses_regex(rule: dict) -> bool:
    """Return True if the rule's CEL expression contains a matches() call."""
    match = rule.get("match")
    if not isinstance(match, dict):
        return False
    expr_block = match.get("expr")
    if isinstance(expr_block, dict):
        expression = expr_block.get("expression", "")
    elif isinstance(expr_block, str):
        expression = expr_block
    else:
        return False
    return bool(_MATCHES_RE.search(expression))


def validate_regex_rule_count(
    all_rules: list[dict],
    *,
    phase: str = "",
) -> list[LintResult]:
    """GA501: warn when regex rule count exceeds standard tier limit (10).

    Google Cloud Armor standard tier limits each policy to 10 rules
    that use ``matches()`` in their CEL expression.  This check counts
    regex rules across all phases in a policy.

    Args:
        all_rules: List of Cloud Armor rule dicts (aggregated across phases).
        phase: Phase name for reporting (cosmetic; the check is cross-phase).

    Returns:
        List of lint results (empty if within limits).
    """
    results: list[LintResult] = []
    regex_count = sum(1 for r in all_rules if _rule_uses_regex(r))
    if regex_count > _MAX_REGEX_RULES_STANDARD:
        results.append(
            _result(
                rule_id="GA501",
                severity=Severity.WARNING,
                message=(
                    f"Regex rule count ({regex_count}) exceeds standard"
                    f" tier limit ({_MAX_REGEX_RULES_STANDARD})"
                ),
                phase=phase,
            )
        )
    return results
