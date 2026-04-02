# Lint Rule Reference

`octorules lint` performs offline static analysis of your Cloud Armor rules files. **69 rules** with the **GA** prefix cover structure, priorities, actions, CEL expressions, CIDR validation, rate limiting, redirects, and cross-rule analysis.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

**Per-rule suppression** -- suppresses the rule for a single ref:

```yaml
gcloud_armor_custom_rules:
  # octorules:disable=GA001
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "1.2.3.4/32"
```

**Multiple rules:**

```yaml
  # octorules:disable=GA301,GA503
  - ref: "2000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "192.168.1.0/24"
```

Suppressed findings are excluded from the report but counted in the summary line (e.g., `Total: 0 error(s), 0 warning(s), 0 info (2 suppressed)`).

### Severity levels

| Level | Meaning |
|-------|---------|
| **ERROR** | Invalid config that will fail at the Cloud Armor API |
| **WARNING** | Likely mistake or suboptimal pattern |
| **INFO** | Style suggestion |

---

## Rule ID Quick Reference

| ID | Description | Severity |
|----|-------------|----------|
| [GA001](#ga001--rule-missing-ref) | Rule missing 'ref' | ERROR |
| [GA002](#ga002--rule-missing-action) | Rule missing 'action' | ERROR |
| [GA003](#ga003--rule-missing-match) | Rule missing 'match' | ERROR |
| [GA100](#ga100--invalid-priority-must-be-non-negative-integer) | Invalid priority (must be non-negative integer) | ERROR |
| [GA101](#ga101--priority-out-of-range-0-2147483646) | Priority out of range (0-2147483646) | ERROR |
| [GA102](#ga102--duplicate-priority) | Duplicate priority | ERROR |
| [GA103](#ga103--unreachable-rule-after-match-all) | Unreachable rule after match-all (incl. `((true))`, `SRC_IPS_V1` with `["*"]`) | WARNING |
| [GA104](#ga104--duplicate-cel-expression-across-rules) | Duplicate CEL expression across rules | WARNING |
| [GA105](#ga105--inconsistent-enforce_on_key-across-rate-limit-rules) | Inconsistent enforce_on_key across rate-limit rules | WARNING |
| [GA108](#ga108--duplicate-preconfigured-waf-rule-set-across-rules) | Duplicate preconfigured WAF rule set across rules | WARNING |
| [GA200](#ga200--invalid-action) | Invalid action | ERROR |
| [GA201](#ga201--invalid-deny-status-code) | Invalid deny status code | ERROR |
| [GA300](#ga300--match-must-have-expr-or-configversioned_expr-not-bothneither) | Match must have 'expr' or 'config'+'versioned_expr', not both/neither | ERROR |
| [GA301](#ga301--invalid-cidr-notation) | Invalid CIDR notation | WARNING |
| [GA302](#ga302--cel-syntax-error) | CEL syntax error | WARNING |
| [GA303](#ga303--unknown-preconfigured-waf-rule-set) | Unknown preconfigured WAF rule set | WARNING |
| [GA304](#ga304--cel-expression-exceeds-2048-character-limit) | CEL expression exceeds 2048 character limit | WARNING |
| [GA305](#ga305--overlapping-or-duplicate-cidrs) | Overlapping or duplicate CIDRs | WARNING |
| [GA306](#ga306--0-cidr-matches-all-traffic) | /0 CIDR matches all traffic | WARNING |
| [GA310](#ga310--unknown-field-reference-in-cel-expression) | Unknown field reference in CEL expression | WARNING |
| [GA311](#ga311--unknown-function-in-cel-expression) | Unknown function in CEL expression | WARNING |
| [GA312](#ga312--invalid-versioned_expr-value) | Invalid versioned_expr value | ERROR |
| [GA313](#ga313--missing-config-when-versioned_expr-is-present) | Missing config when versioned_expr is present | ERROR |
| [GA314](#ga314--empty-match-conditions) | Empty match conditions | WARNING |
| [GA315](#ga315--unknown-country-code-in-originregion_code-comparison) | Unknown country code in origin.region_code comparison | WARNING |
| [GA316](#ga316--unknown-http-method-in-requestmethod-comparison) | Unknown HTTP method in request.method comparison | WARNING |
| [GA317](#ga317--invalid-cidr-in-iniprange) | Invalid CIDR in inIpRange() | ERROR |
| [GA317b](#ga317b--privatereserved-ip-range-in-iniprange) | Private/reserved IP range in inIpRange() | WARNING |
| [GA318](#ga318--cel-type-mismatch) | CEL type mismatch | WARNING |
| [GA319](#ga319--case-sensitive-string-comparison) | Case-sensitive string comparison may need case-insensitive matching | INFO |
| [GA400](#ga400--rate-limit-action-requires-rate_limit_options) | Rate-limit action requires 'rate_limit_options' | ERROR |
| [GA401](#ga401--redirect-action-requires-redirect_options) | Redirect action requires 'redirect_options' | ERROR |
| [GA402](#ga402--invalid-redirect-type) | Invalid redirect type | ERROR |
| [GA403](#ga403--missing-required-field-in-rate_limit_options) | Missing required field in rate_limit_options | ERROR |
| [GA404](#ga404--external_302-redirect-requires-target-url) | EXTERNAL_302 redirect requires 'target' URL | ERROR |
| [GA409](#ga409--redirect-target-must-be-valid-url-for-external_302) | redirect_options.target must be a valid URL for EXTERNAL_302 | ERROR |
| [GA433](#ga433--redirect-url-exceeds-1024-characters) | Redirect URL exceeds 1,024 characters | WARNING |
| [GA405](#ga405--conform_action-must-be-allow) | conform_action must be 'allow' | ERROR |
| [GA406](#ga406--invalid-exceed_action) | Invalid exceed_action | ERROR |
| [GA407](#ga407--invalid-interval_sec-value) | Invalid interval_sec value | ERROR |
| [GA408](#ga408--rate_limit_threshold-interval_sec-validation) | rate_limit_threshold interval_sec validation (count moved to GA421) | ERROR |
| [GA410](#ga410--invalid-ban_threshold-structure) | Invalid ban_threshold structure | ERROR |
| [GA411](#ga411--invalid-exceed_redirect_optionstype) | Invalid exceed_redirect_options.type | ERROR |
| [GA412](#ga412--exceed_redirect_optionstarget-must-be-valid-url-for-external_302) | exceed_redirect_options.target must be a valid URL for EXTERNAL_302 | ERROR |
| [GA413](#ga413--invalid-regex-pattern-in-matches) | Invalid regex pattern in matches() | WARNING |
| [GA414](#ga414--invalid-enforce_on_key_configs-structure) | Invalid enforce_on_key_configs structure | ERROR |
| [GA415](#ga415--duplicate-enforce_on_key_type-in-enforce_on_key_configs) | Duplicate enforce_on_key_type in enforce_on_key_configs | WARNING |
| [GA416](#ga416--preconfigured-waf-sensitivity-level-must-be-0-4) | Preconfigured WAF sensitivity level must be 0-4 | WARNING |
| [GA418](#ga418--invalid-http-header-name-in-cel-expression) | Invalid HTTP header name in CEL expression | WARNING |
| [GA419](#ga419--redirect-target-must-not-be-empty) | Redirect target must not be empty | ERROR |
| [GA420](#ga420--rate_limit_threshold-missing-required-subfields) | rate_limit_threshold missing required subfields | ERROR |
| [GA421](#ga421--invalid-type-for-rate-limit-field) | Invalid type for rate limit field + count-range validation | ERROR |
| [GA422](#ga422--enforce_on_key-required-for-rate_based_ban-with-redirect-exceed_action) | enforce_on_key required for rate_based_ban with redirect exceed_action | WARNING |
| [GA423](#ga423--invalid-enforce_on_key-value) | Invalid enforce_on_key value | ERROR |
| [GA424](#ga424--enforce_on_key_name-required-for-http_headerhttp_cookie) | enforce_on_key_name required for HTTP_HEADER/HTTP_COOKIE | ERROR |
| [GA425](#ga425--ban_duration_sec-required-for-rate_based_ban) | ban_duration_sec required for rate_based_ban | ERROR |
| [GA426](#ga426--invalid-ban_duration_sec-must-be-positive-integer) | Invalid ban_duration_sec (must be positive integer) | ERROR |
| [GA427](#ga427--ban_duration_sec-exceeds-maximum-3600-seconds) | ban_duration_sec exceeds maximum (3600 seconds) | ERROR |
| [GA430](#ga430--ban_duration_sec-very-short) | ban_duration_sec very short (< 60 seconds) | WARNING |
| [GA428](#ga428--invalid-enforce_on_key_name-value) | Invalid enforce_on_key_name value | WARNING |
| [GA429](#ga429--ban_duration_sec-is-only-valid-for-rate_based_ban) | ban_duration_sec is only valid for rate_based_ban | WARNING |
| [GA431](#ga431--redirect-exceed_action-requires-exceed_redirect_options) | redirect exceed_action requires exceed_redirect_options | ERROR |
| [GA432](#ga432--conflicting-rate-limit-options) | Conflicting rate-limit options | ERROR |
| [GA500](#ga500--description-exceeds-1024-character-limit) | Description exceeds 1024 character limit | WARNING |
| [GA502](#ga502--rule-count-exceeds-tier-limit) | Rule count exceeds tier limit | WARNING |
| [GA503](#ga503--privatereserved-ip-range-in-src_ip_ranges) | Private/reserved IP range in src_ip_ranges | WARNING |
| [GA600](#ga600--rule-is-in-preview-mode) | Rule is in preview mode (preview: true) | INFO |
| [GA601](#ga601--expression-is-always-true) | Expression is always true — catch-all rule | WARNING |
| [GA602](#ga602--expression-is-always-false) | Expression is always false — dead rule | WARNING |

---

## Structure (GA001--GA003)

### GA001 -- Rule missing 'ref'

**Severity:** ERROR

Every Cloud Armor rule must have a `ref` field that maps to its integer priority. Without it, the rule cannot be identified or ordered.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - action: deny(403)
    match:
      expr:
        expression: "origin.region_code == 'CN'"
```

**Fix:** Add a `ref` field with a unique integer priority string:

```yaml
  - ref: "1000"
    action: deny(403)
```

---

### GA002 -- Rule missing 'action'

**Severity:** ERROR

Every Cloud Armor rule must specify an `action` (e.g. `allow`, `deny(403)`, `throttle`, `rate_based_ban`, `redirect`). There is no default action.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    match:
      expr:
        expression: "origin.region_code == 'CN'"
```

**Fix:** Add an `action` field:

```yaml
  - ref: "1000"
    action: deny(403)
```

---

### GA003 -- Rule missing 'match'

**Severity:** ERROR

Every Cloud Armor rule must specify a `match` block defining which traffic the rule applies to -- either a CEL expression (`expr`) or IP-based matching (`config` + `versioned_expr`).

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
```

**Fix:** Add a `match` block:

```yaml
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.region_code == 'CN'"
```

---

## Priority and Cross-Rule (GA100--GA108)

### GA100 -- Invalid priority (must be non-negative integer)

**Severity:** ERROR

The `ref` field must be a non-negative integer string representing the rule's priority. Negative values, non-numeric strings, and floats are rejected.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "high-priority"
    action: deny(403)
    match:
      expr:
        expression: "true"
```

**Fix:** Use a non-negative integer string:

```yaml
  - ref: "1000"
```

---

### GA101 -- Priority out of range (0-2147483646)

**Severity:** ERROR

Cloud Armor priorities must be between 0 and 2,147,483,646 (inclusive). Priority 2,147,483,647 is reserved for the default rule.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "2147483647"
    action: allow
    match:
      expr:
        expression: "true"
```

**Fix:** Use a priority within the valid range:

```yaml
  - ref: "2147483646"
```

---

### GA102 -- Duplicate priority

**Severity:** ERROR

Two or more rules share the same priority value. Cloud Armor requires each rule to have a unique priority.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.region_code == 'CN'"
  - ref: "1000"
    action: allow
    match:
      expr:
        expression: "origin.region_code == 'US'"
```

**Fix:** Assign unique priorities to each rule. Space priorities by 10 or 100 (e.g. 1000, 1010, 1020) to leave room for future insertions.

---

### GA103 -- Unreachable rule after match-all

**Severity:** WARNING

A rule with a `"true"` CEL expression matches all traffic. Any rule with a higher priority number (lower precedence) is unreachable because the match-all rule fires first. This now also detects parenthesized forms like `((true))` and IP-wildcard `SRC_IPS_V1` with `["*"]`.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "true"
  - ref: "2000"
    action: allow
    match:
      expr:
        expression: "origin.region_code == 'US'"
```

**Fix:** Remove the unreachable rule, or give it a lower priority number (higher precedence) than the match-all rule. Remember: lower priority number = higher precedence in Cloud Armor.

---

### GA104 -- Duplicate CEL expression across rules

**Severity:** WARNING

Two or more rules use the same CEL expression (after whitespace normalization). This is usually a copy-paste mistake -- the rules will match identical traffic.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.region_code == 'CN'"
  - ref: "2000"
    action: allow
    match:
      expr:
        expression: "origin.region_code == 'CN'"
```

**Fix:** Remove the duplicate or update one expression to match different traffic. If the rules intentionally use the same expression with different actions, combine them into a single rule or suppress with `# octorules:disable=GA104`.

---

### GA105 -- Inconsistent enforce_on_key across rate-limit rules

**Severity:** WARNING

Multiple rate-limit rules (`throttle` / `rate_based_ban`) use different `enforce_on_key` values. While not technically invalid, this is often unintentional and can lead to confusing rate-limiting behavior.

**Triggers on:**

```yaml
gcloud_armor_rate_rules:
  - ref: "1000"
    action: throttle
    match:
      expr:
        expression: "request.path.startsWith('/api/')"
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      enforce_on_key: IP
      rate_limit_threshold:
        count: 100
        interval_sec: 60
  - ref: "2000"
    action: throttle
    match:
      expr:
        expression: "request.path.startsWith('/login')"
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      enforce_on_key: XFF_IP
      rate_limit_threshold:
        count: 10
        interval_sec: 60
```

**Fix:** Use a consistent `enforce_on_key` across rate-limit rules unless the difference is intentional.

---

### GA108 -- Duplicate preconfigured WAF rule set across rules

**Severity:** WARNING

The same preconfigured WAF rule set (e.g. `sqli-v33-stable`) appears in multiple rules. This causes redundant evaluation and may produce confusing behavior.

**Triggers on:**

```yaml
gcloud_armor_preconfigured_rules:
  - ref: "3000"
    action: deny(403)
    match:
      expr:
        expression: "evaluatePreconfiguredWaf('sqli-v33-stable')"
  - ref: "3001"
    action: deny(403)
    match:
      expr:
        expression: "evaluatePreconfiguredWaf('sqli-v33-stable')"
```

**Fix:** Remove the duplicate rule or use a different WAF rule set in each.

---

## Action (GA200--GA201)

### GA200 -- Invalid action

**Severity:** ERROR

The `action` value is not a recognized Cloud Armor action. Valid actions are: `allow`, `deny(403)`, `deny(404)`, `deny(502)`, `throttle`, `rate_based_ban`, and `redirect`.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: block
    match:
      expr:
        expression: "origin.region_code == 'CN'"
```

**Fix:** Use a valid action:

```yaml
    action: deny(403)
```

---

### GA201 -- Invalid deny status code

**Severity:** ERROR

The `deny()` action only supports status codes 403, 404, and 502. Other HTTP status codes are rejected by the Cloud Armor API.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(429)
    match:
      expr:
        expression: "origin.region_code == 'CN'"
```

**Fix:** Use one of the valid deny status codes:

```yaml
    action: deny(403)
```

---

## Match / Expression / CEL (GA300--GA319)

### GA300 -- Match must have 'expr' or 'config'+'versioned_expr', not both/neither

**Severity:** ERROR

A match block must use exactly one of two forms: a CEL expression (`expr`) or IP-range matching (`config` + `versioned_expr`). Providing both or neither is invalid.

**Triggers on:**

```yaml
# Both forms present:
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.region_code == 'CN'"
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "1.2.3.0/24"
```

**Fix:** Remove one of the two match forms. Use `expr` for CEL expressions or `config`+`versioned_expr` for IP-range matching.

---

### GA301 -- Invalid CIDR notation

**Severity:** WARNING

An entry in `src_ip_ranges` is not valid CIDR notation. The value must be a valid IPv4 or IPv6 network (e.g. `10.0.0.0/8`, `2001:db8::/32`).

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "not-a-cidr"
```

**Fix:** Use standard CIDR notation -- `10.0.0.0/24` not `10.0.0.0/33`. Common mistakes: prefix length exceeding 32 (IPv4) or 128 (IPv6), missing `/` prefix, or typos in the IP address.

```yaml
        src_ip_ranges:
          - "1.2.3.0/24"
```

---

### GA302 -- CEL syntax error

**Severity:** WARNING

The CEL expression has a syntax error detected by the cel-python parser. The rule will be rejected by the Cloud Armor API.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.region_code =="
```

**Fix:** Check CEL syntax -- ensure quotes, parentheses, and operators are balanced. Common mistakes: unmatched `(` or `"`, missing `==` operator, or using `=` instead of `==`. Refer to the [Cloud Armor rules language reference](https://cloud.google.com/armor/docs/rules-language-reference).

---

### GA303 -- Unknown preconfigured WAF rule set

**Severity:** WARNING

The preconfigured WAF rule set name passed to `evaluatePreconfiguredWaf()` or `evaluatePreconfiguredExpr()` is not in the list of known Cloud Armor WAF rule sets (e.g. `sqli`, `xss`, `lfi`, `rce`, `rfi`, `php`, `java`, `nodejs`, `cve`, `methodenforcement`, `protocolattack`, `scannerdetection`, `sessionfixation`).

**Triggers on:**

```yaml
gcloud_armor_preconfigured_rules:
  - ref: "3000"
    action: deny(403)
    match:
      expr:
        expression: "evaluatePreconfiguredWaf('nosuchruleset-v1-stable')"
```

**Fix:** Use a valid preconfigured WAF rule set name:

```yaml
        expression: "evaluatePreconfiguredWaf('sqli-v33-stable')"
```

---

### GA304 -- CEL expression exceeds 2048 character limit

**Severity:** WARNING

Cloud Armor CEL expressions have a 2,048-character limit. Expressions exceeding this length will be rejected by the API.

**Triggers on:** A CEL expression longer than 2,048 characters.

**Fix:** Shorten the expression -- split complex logic across multiple rules with different priorities, or use preconfigured WAF rules instead of long inline expressions. For large IP lists, use `versioned_expr: SRC_IPS_V1` with `src_ip_ranges` instead of chaining `inIpRange()` calls.

---

### GA305 -- Overlapping or duplicate CIDRs

**Severity:** WARNING

Two or more entries in `src_ip_ranges` overlap or are duplicates. One range contains or is identical to another, making the narrower entry redundant.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "10.0.0.0/8"
          - "10.1.0.0/16"
```

**Fix:** Remove the redundant (narrower) CIDR entry since it is already covered by the broader range. For example, if you have both `10.0.0.0/8` and `10.1.0.0/16`, remove the `/16` -- it is already contained within the `/8`.

---

### GA306 -- /0 CIDR matches all traffic

**Severity:** WARNING

A `/0` CIDR (e.g. `0.0.0.0/0` or `::/0`) matches all traffic. This is usually unintentional -- if you want a catch-all rule, use a CEL expression of `"true"` instead.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "0.0.0.0/0"
```

**Fix:** Use a CEL match-all expression or narrow the CIDR range. If you truly intend to match all traffic, use a CEL `"true"` expression instead of `/0` -- it is more explicit and avoids confusion:

```yaml
    match:
      expr:
        expression: "true"
```

---

### GA310 -- Unknown field reference in CEL expression

**Severity:** WARNING

The CEL expression references a dotted field name that is not in the set of known Cloud Armor fields. Known field prefixes are `origin.*`, `request.*`, and `token.*`.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "source.ip == '1.2.3.4'"
```

**Fix:** Use a known Cloud Armor field:

```yaml
        expression: "origin.ip == '1.2.3.4'"
```

---

### GA311 -- Unknown function in CEL expression

**Severity:** WARNING

The CEL expression calls a function not in the set of known Cloud Armor functions. Known functions include: `contains`, `startsWith`, `endsWith`, `matches`, `lower`, `upper`, `base64Decode`, `inIpRange`, `size`, `int`, `evaluatePreconfiguredWaf`, `evaluatePreconfiguredExpr`, and `has`.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "customFunc(origin.ip)"
```

**Fix:** Use a supported Cloud Armor CEL function.

---

### GA312 -- Invalid versioned_expr value

**Severity:** ERROR

The `versioned_expr` field only accepts the value `SRC_IPS_V1`. Any other value is rejected by the Cloud Armor API.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V2
      config:
        src_ip_ranges:
          - "1.2.3.0/24"
```

**Fix:** Use the only valid value:

```yaml
      versioned_expr: SRC_IPS_V1
```

---

### GA313 -- Missing config when versioned_expr is present

**Severity:** ERROR

When `versioned_expr` is set, a `config` dict with `src_ip_ranges` must also be provided. The `versioned_expr` tells Cloud Armor *how* to interpret the config, so both are required together.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
```

**Fix:** Add a `config` block with `src_ip_ranges`:

```yaml
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "1.2.3.0/24"
```

---

### GA314 -- Empty match conditions

**Severity:** WARNING

The match condition is empty -- either `src_ip_ranges` is an empty list or the CEL expression is blank/whitespace-only. An empty match will not match any traffic, making the rule a no-op.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges: []
```

**Fix:** Add at least one CIDR range or provide a non-empty CEL expression.

---

### GA315 -- Unknown country code in origin.region_code comparison

**Severity:** WARNING

Validates country codes used in `origin.region_code` comparisons. Country codes must be exactly 2 uppercase ASCII letters (ISO 3166-1 alpha-2 format).

Detected patterns:
- `origin.region_code == "xx"` — equality comparison
- `origin.region_code in ["xx", "yy"]` — list membership

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.region_code == 'USA'"
```

**Fix:** Use 2-letter uppercase ISO country codes: `"US"`, not `"USA"` or `"us"`.

---

### GA316 -- Unknown HTTP method in request.method comparison

**Severity:** WARNING

Validates HTTP method names used in `request.method` comparisons. Catches typos like `"GETT"` and suggests the closest valid method using fuzzy matching.

Valid methods: CONNECT, DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, TRACE.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "request.method == 'GETT'"
```

**Fix:** Use the correct HTTP method spelling: `"GET"`, not `"GETT"`.

---

### GA317 -- Invalid CIDR in inIpRange()

**Severity:** ERROR

Validates CIDR notation inside `inIpRange(origin.ip, "CIDR")` calls. Invalid CIDR strings will cause a runtime error at the Cloud Armor API.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "inIpRange(origin.ip, 'not-a-cidr')"
```

**Fix:** Use valid CIDR notation: `"1.2.3.0/24"` or `"2001:db8::/32"`.

---

### GA317b -- Private/reserved IP range in inIpRange()

**Severity:** WARNING

Flags private or reserved IP ranges (RFC 1918, loopback, link-local, ULA) inside `inIpRange()` calls. Cloud Armor operates on public internet traffic, so private ranges are likely mistakes.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "inIpRange(origin.ip, '192.168.1.0/24')"
```

**Fix:** Use public IP ranges, or suppress with `# octorules:disable=GA317b` if intentional.

---

### GA318 -- CEL type mismatch

**Severity:** WARNING

Detects type mismatches in CEL field comparisons. For example, `origin.ip` is a string but comparing it with an integer literal, or `origin.asn` is an integer but comparing it with a string literal.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "origin.ip == 42"
```

**Fix:** Use the correct literal type: `origin.ip == '1.2.3.4'` (string) or `origin.asn == 15169` (integer).

---

### GA319 -- Case-sensitive string comparison

**Severity:** INFO

Warns when string equality comparisons on `request.path`, `request.query`, or `request.host` use mixed-case string literals. These comparisons are case-sensitive in CEL, which may cause unexpected behavior.

Only triggers when the literal contains mixed case (not all-lowercase or all-uppercase). Does not trigger for `request.method` or `origin.region_code` which are conventionally uppercase.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      expr:
        expression: "request.path == '/Admin'"
```

**Fix:** Use `matches()` with the `(?i)` flag for case-insensitive matching: `request.path.matches('(?i)/admin')`.

---

## Rate Limit / Redirect / Action Params (GA400--GA431)

### GA400 -- Rate-limit action requires 'rate_limit_options'

**Severity:** ERROR

Rules with `action: throttle` or `action: rate_based_ban` must include a `rate_limit_options` block defining the rate-limit parameters.

**Triggers on:**

```yaml
gcloud_armor_rate_rules:
  - ref: "1000"
    action: throttle
    match:
      expr:
        expression: "request.path.startsWith('/api/')"
```

**Fix:** Add `rate_limit_options`:

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

---

### GA401 -- Redirect action requires 'redirect_options'

**Severity:** ERROR

Rules with `action: redirect` must include a `redirect_options` block specifying the redirect type and target.

**Triggers on:**

```yaml
gcloud_armor_redirect_rules:
  - ref: "1000"
    action: redirect
    match:
      expr:
        expression: "request.path.startsWith('/old/')"
```

**Fix:** Add `redirect_options`:

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "https://example.com/new/"
```

---

### GA402 -- Invalid redirect type

**Severity:** ERROR

The `redirect_options.type` value must be either `GOOGLE_RECAPTCHA` or `EXTERNAL_302`.

**Triggers on:**

```yaml
gcloud_armor_redirect_rules:
  - ref: "1000"
    action: redirect
    match:
      expr:
        expression: "true"
    redirect_options:
      type: PERMANENT_301
```

**Fix:** Use a valid redirect type:

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "https://example.com/"
```

---

### GA403 -- Missing required field in rate_limit_options

**Severity:** ERROR

The `rate_limit_options` block is missing one or more required fields: `conform_action`, `exceed_action`, or `rate_limit_threshold`.

**Triggers on:**

```yaml
gcloud_armor_rate_rules:
  - ref: "1000"
    action: throttle
    match:
      expr:
        expression: "true"
    rate_limit_options:
      conform_action: allow
```

**Fix:** Include all three required fields:

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

---

### GA404 -- EXTERNAL_302 redirect requires 'target' URL

**Severity:** ERROR

When `redirect_options.type` is `EXTERNAL_302`, a `target` URL must be provided for the redirect destination.

**Triggers on:**

```yaml
gcloud_armor_redirect_rules:
  - ref: "1000"
    action: redirect
    match:
      expr:
        expression: "true"
    redirect_options:
      type: EXTERNAL_302
```

**Fix:** Add a `target` URL:

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "https://example.com/blocked"
```

---

### GA409 -- redirect_options.target must be a valid URL for EXTERNAL_302

**Severity:** ERROR

When `redirect_options.type` is `EXTERNAL_302`, the `target` must be a full URL starting with `http://` or `https://` and must include a host (netloc). Relative paths, bare schemes (e.g. `https://`), and other schemes are not valid.

**Triggers on:**

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "/relative/path"
```

or:

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "https://"
```

**Fix:** Use a full URL including scheme and host. Ensure the target is not just `https://` without a hostname:

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "https://example.com/blocked"
```

---

### GA405 -- conform_action must be 'allow'

**Severity:** ERROR

The `conform_action` field in `rate_limit_options` must be `"allow"`. Cloud Armor only supports allowing requests that conform to the rate limit.

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: deny-403
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

**Fix:** Set `conform_action` to `"allow"`:

```yaml
      conform_action: allow
```

---

### GA406 -- Invalid exceed_action

**Severity:** ERROR

The `exceed_action` value is not recognized. Valid values are: `deny-403`, `deny-404`, `deny-429`, `deny-502`, and `redirect`.

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: block
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

**Fix:** Use a valid `exceed_action`:

```yaml
      exceed_action: deny-429
```

---

### GA407 -- Invalid interval_sec value

**Severity:** ERROR

The `interval_sec` in `rate_limit_threshold` must be one of the fixed values supported by Cloud Armor: 10, 30, 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, or 3600.

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
        interval_sec: 45
```

**Fix:** Use a valid interval:

```yaml
        interval_sec: 60
```

---

### GA408 -- rate_limit_threshold interval_sec validation

**Severity:** ERROR

Validates the `interval_sec` field in `rate_limit_threshold`. Count-range validation (minimum and maximum values) has been consolidated into GA421 to eliminate duplicate diagnostics.

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 0
        interval_sec: 60
```

**Fix:** Use a count within the valid range:

```yaml
        count: 100
```

---

### GA410 -- Invalid ban_threshold structure

**Severity:** ERROR

The `ban_threshold` object (used with `rate_based_ban`) must be a dict with two fields: `count` (positive integer) and `interval_sec` (one of the valid Cloud Armor interval values). Both fields are required.

**Triggers on:**

```yaml
    rate_limit_options:
      ban_threshold:
        count: -1
        interval_sec: 45
```

**Fix:** Use valid values:

```yaml
      ban_threshold:
        count: 5
        interval_sec: 60
```

---

### GA411 -- Invalid exceed_redirect_options.type

**Severity:** ERROR

The `exceed_redirect_options.type` value must be either `GOOGLE_RECAPTCHA` or `EXTERNAL_302`, the same valid types as `redirect_options.type`.

**Triggers on:**

```yaml
    rate_limit_options:
      exceed_action: redirect
      exceed_redirect_options:
        type: PERMANENT_301
        target: "https://example.com"
```

**Fix:** Use a valid redirect type:

```yaml
      exceed_redirect_options:
        type: EXTERNAL_302
        target: "https://example.com"
```

---

### GA412 -- exceed_redirect_options.target must be a valid URL for EXTERNAL_302

**Severity:** ERROR

When `exceed_redirect_options.type` is `EXTERNAL_302`, the `target` must be a full URL starting with `http://` or `https://` and must include a host. Bare schemes and relative paths are rejected.

**Triggers on:**

```yaml
      exceed_redirect_options:
        type: EXTERNAL_302
        target: "/relative/path"
```

**Fix:** Use a full URL including scheme and host:

```yaml
      exceed_redirect_options:
        type: EXTERNAL_302
        target: "https://example.com/rate-limited"
```

---

### GA413 -- Invalid regex pattern in matches()

**Severity:** WARNING

A CEL `matches()` call contains a regex pattern that fails to compile. Cloud Armor will reject the rule at the API level.

**Triggers on:**

```yaml
    match:
      expr:
        expression: "request.path.matches('[invalid')"
```

**Fix:** Use a valid regex pattern. Common mistakes: unmatched `[` or `(`, unescaped special characters like `.` or `*` at invalid positions, and PCRE-only features (Cloud Armor uses RE2 syntax, which does not support backreferences or lookahead):

```yaml
        expression: "request.path.matches('.*api.*')"
```

---

### GA414 -- Invalid enforce_on_key_configs structure

**Severity:** ERROR

The `enforce_on_key_configs` field must be a list of at most 3 dicts, each containing an `enforce_on_key_type` field. It is mutually exclusive with `enforce_on_key` -- you cannot use both.

**Triggers on:**

```yaml
    rate_limit_options:
      enforce_on_key: IP
      enforce_on_key_configs:
        - enforce_on_key_type: IP
```

**Fix:** Use either `enforce_on_key` or `enforce_on_key_configs`, not both:

```yaml
    rate_limit_options:
      enforce_on_key_configs:
        - enforce_on_key_type: IP
        - enforce_on_key_type: HTTP_HEADER
          enforce_on_key_name: "X-API-Key"
```

---

### GA415 -- Duplicate enforce_on_key_type in enforce_on_key_configs

**Severity:** WARNING

Two or more entries in `enforce_on_key_configs` use the same `enforce_on_key_type` value. This is redundant and likely a copy-paste mistake.

**Triggers on:**

```yaml
    rate_limit_options:
      enforce_on_key_configs:
        - enforce_on_key_type: IP
        - enforce_on_key_type: IP
```

**Fix:** Remove the duplicate entry or use different key types.

---

### GA416 -- Preconfigured WAF sensitivity level must be 0-4

**Severity:** WARNING

The `sensitivity` option passed to `evaluatePreconfiguredWaf()` or `evaluatePreconfiguredExpr()` must be an integer between 0 and 4 (inclusive). Values outside this range are rejected by Cloud Armor.

**Triggers on:**

```yaml
    match:
      expr:
        expression: "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 9})"
```

**Fix:** Use a valid sensitivity level:

```yaml
        expression: "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 4})"
```

---

### GA418 -- Invalid HTTP header name in CEL expression

**Severity:** WARNING

A `request.headers["..."]` bracket access uses a header name that violates RFC 7230 token character rules. Header names may only contain `A-Z a-z 0-9 ! # $ % & ' * + - . ^ _ `` | ~`. Spaces, parentheses, and other characters are not valid.

**Triggers on:**

```yaml
    match:
      expr:
        expression: 'request.headers["Bad Header"] == "value"'
```

**Fix:** Use a valid HTTP header name:

```yaml
        expression: 'request.headers["X-Custom-Header"] == "value"'
```

---

### GA419 -- Redirect target must not be empty

**Severity:** ERROR

The `target` field in `redirect_options` or `exceed_redirect_options` is empty or whitespace-only. A redirect must have a non-empty destination.

**Triggers on:**

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: ""
```

**Fix:** Provide a non-empty target URL:

```yaml
    redirect_options:
      type: EXTERNAL_302
      target: "https://example.com/blocked"
```

---

### GA420 -- rate_limit_threshold missing required subfields

**Severity:** ERROR

The `rate_limit_threshold` object must be a dict containing both `count` and `interval_sec` fields.

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
```

**Fix:** Include both required subfields:

```yaml
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

---

### GA421 -- Invalid type for rate limit field

**Severity:** ERROR

The `count` and `interval_sec` fields within `rate_limit_threshold` must be integers (not booleans, strings, or floats). This rule now also covers count-range validation (previously in GA408): for `throttle` actions, the maximum count is 1,000,000; for `rate_based_ban` actions, the maximum is 10,000.

**Triggers on:**

```yaml
      rate_limit_threshold:
        count: "100"
        interval_sec: 60
```

**Fix:** Use integer values:

```yaml
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

---

### GA422 -- enforce_on_key required for rate_based_ban with redirect exceed_action

**Severity:** WARNING

When using `rate_based_ban` with `exceed_action: redirect`, setting `enforce_on_key` is recommended. Without it, the ban behavior may not work as expected.

**Triggers on:**

```yaml
gcloud_armor_rate_rules:
  - ref: "1000"
    action: rate_based_ban
    match:
      expr:
        expression: "true"
    rate_limit_options:
      conform_action: allow
      exceed_action: redirect
      ban_duration_sec: 120
      rate_limit_threshold:
        count: 50
        interval_sec: 60
      exceed_redirect_options:
        type: EXTERNAL_302
        target: "https://example.com/banned"
```

**Fix:** Add `enforce_on_key`:

```yaml
      enforce_on_key: IP
```

---

### GA423 -- Invalid enforce_on_key value

**Severity:** ERROR

The `enforce_on_key` value must be one of: `IP`, `ALL`, `HTTP_HEADER`, `XFF_IP`, `HTTP_COOKIE`, `HTTP_PATH`, `SNI`, or `REGION_CODE`.

**Triggers on:**

```yaml
      enforce_on_key: SOURCE_IP
```

**Fix:** Use a valid value:

```yaml
      enforce_on_key: IP
```

---

### GA424 -- enforce_on_key_name required for HTTP_HEADER/HTTP_COOKIE

**Severity:** ERROR

When `enforce_on_key` is `HTTP_HEADER` or `HTTP_COOKIE`, the `enforce_on_key_name` field must be provided to specify which header or cookie to use as the rate-limit key.

**Triggers on:**

```yaml
      enforce_on_key: HTTP_HEADER
```

**Fix:** Add `enforce_on_key_name`:

```yaml
      enforce_on_key: HTTP_HEADER
      enforce_on_key_name: "X-API-Key"
```

---

### GA425 -- ban_duration_sec required for rate_based_ban

**Severity:** ERROR

Rules with `action: rate_based_ban` must specify `ban_duration_sec` in `rate_limit_options` to define how long offending clients are banned.

**Triggers on:**

```yaml
gcloud_armor_rate_rules:
  - ref: "1000"
    action: rate_based_ban
    match:
      expr:
        expression: "true"
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-403
      rate_limit_threshold:
        count: 50
        interval_sec: 60
```

**Fix:** Add `ban_duration_sec`:

```yaml
      ban_duration_sec: 120
```

---

### GA426 -- Invalid ban_duration_sec (must be positive integer)

**Severity:** ERROR

The `ban_duration_sec` value must be a positive integer representing the ban duration in seconds.

**Triggers on:**

```yaml
      ban_duration_sec: -60
```

**Fix:** Use a positive integer:

```yaml
      ban_duration_sec: 120
```

---

### GA427 -- ban_duration_sec exceeds maximum (3600 seconds)

**Severity:** ERROR

The `ban_duration_sec` value must not exceed 3600 seconds (1 hour). Cloud Armor rejects values above this limit.

**Triggers on:**

```yaml
      ban_duration_sec: 86400
```

**Fix:** Use a value between 1 and 3600:

```yaml
      ban_duration_sec: 3600
```

---

### GA428 -- Invalid enforce_on_key_name value

**Severity:** WARNING

When `enforce_on_key` is `HTTP_HEADER` or `HTTP_COOKIE`, the `enforce_on_key_name` value must be a valid name:

- Must not be empty
- Must not exceed 128 characters
- Must not contain spaces or control characters
- For `HTTP_HEADER`: must contain only valid RFC 7230 token characters (`A-Z a-z 0-9 ! # $ % & ' * + - . ^ _ `` | ~`)

**Triggers on:**

```yaml
      enforce_on_key: HTTP_HEADER
      enforce_on_key_name: "X-Bad Header"
```

**Fix:** Use a valid header or cookie name:

```yaml
      enforce_on_key: HTTP_HEADER
      enforce_on_key_name: "X-Custom-Header"
```

---

### GA429 -- ban_duration_sec is only valid for rate_based_ban

**Severity:** WARNING

The `ban_duration_sec` field was specified on a `throttle` rule, but it only applies to `rate_based_ban` rules. It will be ignored.

**Triggers on:**

```yaml
gcloud_armor_rate_rules:
  - ref: "1000"
    action: throttle
    match:
      expr:
        expression: "true"
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      ban_duration_sec: 120
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

**Fix:** Remove `ban_duration_sec` from throttle rules, or change the action to `rate_based_ban`.

---

### GA431 -- redirect exceed_action requires exceed_redirect_options

**Severity:** ERROR

When `exceed_action` is `"redirect"`, the `exceed_redirect_options` block must be present to specify the redirect type and target.

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: redirect
      rate_limit_threshold:
        count: 100
        interval_sec: 60
```

**Fix:** Add `exceed_redirect_options`:

```yaml
      exceed_action: redirect
      exceed_redirect_options:
        type: EXTERNAL_302
        target: "https://example.com/rate-limited"
```

---

### GA432 -- Conflicting rate-limit options

**Severity:** ERROR

Detects impossible or meaningless combinations of rate-limit options:

- `exceed_redirect_options` is present but `exceed_action` is not `redirect` -- the redirect options will be ignored
- `ban_threshold` is present but `rate_limit_threshold` is missing -- a ban threshold without a rate-limit threshold makes no sense

**Triggers on:**

```yaml
    rate_limit_options:
      conform_action: allow
      exceed_action: deny-429
      rate_limit_threshold:
        count: 100
        interval_sec: 60
      exceed_redirect_options:
        type: EXTERNAL_302
        target: "https://example.com"
```

**Fix:** Remove the conflicting option, or change `exceed_action` to `redirect`.

---

## Best Practice (GA500--GA503)

### GA500 -- Description exceeds 1024 character limit

**Severity:** WARNING

Cloud Armor rule descriptions have a 1,024-character limit. Descriptions exceeding this limit will be truncated or rejected by the API.

**Triggers on:** A rule with a `description` field longer than 1,024 characters.

**Fix:** Shorten the description to 1,024 characters or fewer. Focus on the rule's purpose and link to an external ticket or wiki for detailed context.

---

### GA503 -- Private/reserved IP range in src_ip_ranges

**Severity:** WARNING

A CIDR in `src_ip_ranges` falls within a private or reserved IP range (RFC 1918, RFC 4193, loopback, or link-local). Cloud Armor operates on public internet traffic, so private ranges like `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `fc00::/7`, `::1/128`, and `fe80::/10` will never match real client traffic.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "1000"
    action: deny(403)
    match:
      versioned_expr: SRC_IPS_V1
      config:
        src_ip_ranges:
          - "192.168.1.0/24"
```

**Fix:** Use public IP ranges that match actual client traffic, or remove the rule if it was added in error. If you are testing locally, suppress with `# octorules:disable=GA503`. Private ranges like `10.x`, `172.16.x`, and `192.168.x` will never match real internet traffic in Cloud Armor.

---

### GA502 -- Rule count exceeds tier limit

**Severity:** WARNING

Cloud Armor has per-policy rule count limits that vary by tier:

| Tier | Limit |
|------|-------|
| Standard | 256 |
| Plus | 512 |
| Enterprise | 1024 |

This check compares the number of rules in a phase against the configured tier's limit. The tier is determined by the `plan_tier` setting (defaults to "enterprise", the most permissive).

**Triggers on:** A phase with more rules than the tier allows.

**Fix:** Reduce the number of rules, upgrade to a higher tier, or split rules across multiple policies.

---

## Best Practice (GA600--GA602)

### GA600 -- Rule is in preview mode

**Severity:** INFO

The rule has `preview: true`, meaning it logs matches but does not enforce the action. This is Cloud Armor's equivalent of a disabled rule — useful during testing but should be removed or set to `false` before production use.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "5000"
    action: deny(403)
    preview: true
    match:
      expr: 'origin.region_code == "CN"'
```

**Fix:** Set `preview: false` or remove the `preview` field when the rule is ready for enforcement.

---

### GA601 -- Expression is always true

**Severity:** WARNING

The rule's match condition always evaluates to true, making it a catch-all that affects all traffic. This is often a mistake — the rule shadows all lower-priority rules.

Detected patterns:
- CEL expression `"true"` (including parenthesized forms like `(true)`)
- IP match with `src_ip_ranges: ["*"]`

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "6000"
    action: deny(403)
    match:
      expr: "true"
```

**Fix:** Add a specific match condition, or use `# octorules:disable=GA601` if the catch-all is intentional. A common pattern is a low-priority catch-all `deny(403)` as the default rule -- suppress the warning if this is the intended behavior.

---

### GA602 -- Expression is always false

**Severity:** WARNING

The rule's CEL expression always evaluates to false, so the rule never matches any traffic. This is likely dead code.

**Triggers on:**

```yaml
gcloud_armor_custom_rules:
  - ref: "7000"
    action: deny(403)
    match:
      expr: "false"
```

**Fix:** Fix the expression to match the intended traffic, or remove the rule. Common causes: leftover `"false"` from debugging, or a typo that makes the condition logically impossible (e.g. `origin.region_code == 'XX'` with a non-existent country code).

### GA430 -- ban_duration_sec very short

**Severity:** WARNING

`ban_duration_sec` is less than 60 seconds. Very short ban durations may be ineffective — by the time the ban takes effect the attacker has already completed their burst.

**Fix:** Consider a duration of 60 seconds or more for meaningful rate-based bans.

### GA433 -- Redirect URL exceeds 1,024 characters

**Severity:** WARNING

The `redirect_options.target` URL exceeds 1,024 characters. Long redirect URLs may be rejected by browsers or intermediate proxies.

**Fix:** Shorten the redirect URL.
