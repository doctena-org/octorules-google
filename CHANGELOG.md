# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.13.1] - 2026-08-16

### Changed
- Minimum `octorules` dependency: `>=0.35.0` (for `iter_audit_rules`).

### Fixed
- **GA328** and **GA329** skipped any `matches()` regex containing an escaped
  quote — the pattern was never extracted, so the rules reported nothing.
- **GA110**, **GA111**, **GA112** and **GA113** misread comparison operators,
  parentheses and `&&`/`||` appearing inside quoted values, producing wrong
  parses and, for GA110/GA111, broken suggestions.

## [0.13.0] - 2026-08-08

### Added
- **GA308** (ERROR): more than 10 `src_ip_ranges` in a rule — Cloud Armor's
  per-rule maximum.
- **GA309** and **GA321** (ERROR): a custom expression joining more than 5
  top-level subexpressions, or a subexpression over 1024 characters — both
  Cloud Armor limits.

### Changed
- Minimum `octorules` dependency: `>=0.33.0`.
- **GA427** validates `ban_duration_sec` against Cloud Armor's documented value
  set (60–3600 in fixed steps) instead of only an upper bound. This covers
  GA430's old below-60 warning, so GA430 is retired.
- **GA500**, **GA501**, **GA502** and **GA413**'s thresholds are labelled
  octorules guidance; Google publishes none of them.

### Removed
- **GA529**: it claimed `versioned_expr` is deprecated; Google's API definition
  does not.

### Fixed
- `deny(429)` was accepted as a rule action and forwarded to the API, which
  rejects it — 429 is valid only for a rate-limit `exceed_action`.
- `exceed_action` accepted only the gcloud spelling (`deny-403`) and sent it
  verbatim, so plans never converged; both spellings are accepted and the REST
  form (`deny(403)`) goes to the API.

## [0.12.0] - 2026-07-26

### Added
- Zone files can nest all Cloud Armor sections under a single `google:` block; the flat spelling is deprecated.

### Changed
- Minimum `octorules` dependency: `>=0.32.0`.
- Policy settings use the shared settings framework from octorules 0.32.0
  (no output changes).

## [0.11.0] - 2026-06-11

### Changed
- Importing `octorules_google` no longer loads the Google Cloud SDK;
  lint-only runs and CLI startup are ~3x faster.
- Minimum `octorules` dependency: `>=0.29.0`.

### Fixed
- **GA310** no longer recognizes `request.host` / `request.url`; they
  don't exist in Cloud Armor's rules language, and expressions using
  them now warn.
- **GA311** now recognizes `evaluateAddressGroup` and
  `evaluateOrganizationAddressGroup`, and no longer recognizes
  `htmlDecode`, `evaluateJsonPath`, or
  `evaluateThreatIntelligenceWithExcl`; calls to removed names warn.

## [0.10.0] - 2026-05-04

### Added
- **GA027** (INFO): Leading/trailing whitespace in `match.expr.expression`.
- **GA110** (INFO): Negated comparison simplification — `!(a == b)` → `a != b`.
- **GA111** (INFO): OR chain of equality on the same field — `a == "x" || a == "y" || a == "z"` → `a in ["x", "y", "z"]`.
- **GA112** (WARNING): Illogical condition — contradictory `&&` (always false) or tautological `||` (always true).
- **GA113** (INFO): Mixed `&&` and `||` at top paren depth — suggests explicit grouping.
- **GA328** (WARNING): Overly-permissive regex in CEL `.matches()` (e.g., `.`, `.*`, `^.+$`).
- **GA329** (INFO): Anchored-literal regex in CEL `.matches()` (`^foo$`) — suggests equality operator instead.
- **GA526** (INFO): HTTP header name should be lowercase in CEL `request.headers["..."]` bracket access.
- **GA529** (WARNING): Deprecated `versioned_expr` field — use CEL `match.expr` instead.
- New module `octorules_google.linter.cel_regex` — CEL expression scanning helpers backing GA328/329 and the GA110-113 family.

## [0.9.3] - 2026-04-27

### Added
- GA603: Flag Cloud Armor rules with `enabled: false` (mirrors CF018, WA600,
  AZ600, BN602). Severity: INFO. Helps identify disabled rules that may be
  stale or no longer needed.

### Changed
- GA305 (overlapping/duplicate CIDRs in `src_ip_ranges`) rewritten from O(n²)
  pairwise comparison to O(n log n) sweep-line, mirroring CF478 / WA164 /
  BN307. 1,000-entry lists now lint in well under a second. Catch-all
  entries (`0.0.0.0/0`, `::/0`) are now excluded from GA305 — they were
  previously flagged against every other CIDR in the list, producing noise.
  GA306 still flags catch-all on its own. Each contained or duplicate CIDR
  is reported once against its immediate parent in sorted order (was: once
  per pair, so a chain of three nested CIDRs produced three findings; now
  produces two).

## [0.9.2] - 2026-04-18

### Changed
- Minimum ``octorules`` dependency: ``>=0.26.0`` (was ``>=0.24.0``).

## [0.9.1] - 2026-04-13

### Fixed
- GA416: Sensitivity regex now handles nested option dicts (e.g.
  `opt_out_rule_ids` arrays) via brace-counting instead of `[^}]*?`.

### Changed
- GA303, GA411: Valid options moved to `suggestion` field.
- Reserved IP list expanded from 8 to 28 networks (adds CGNAT, documentation,
  benchmark, multicast, IPv6 ranges).
- Explicit `RULE_IDS` per validator module for dead-rule detection.

## [0.9.0] - 2026-04-10

### Added
- Automatic Cloud Armor tier detection — `resolve_zone_id` inspects
  `ddos_protection_config` and
  `adaptive_protection_config.layer7_ddos_defense_config.rule_visibility` to
  classify policies as `standard`, `plus`, or `enterprise`. Detected tiers are
  exposed via `zone_plans` and feed into the core zone plans cache for automatic
  plan-tier-aware linting (GA501, GA502).

### Fixed
- `recaptcha_options_config` validation error message now includes the
  `zone_name/extension_key` prefix consistent with all other validation
  messages.

### Changed
- Policy settings and linter registration are now thread-safe
  (`threading.Lock`).

### Removed
- Unused `format_plan` and `count_changes` methods from
  `PolicySettingsFormatter`.

## [0.8.5] - 2026-04-09

### Changed
- Extension registration guard now uses `threading.Lock` for correctness.
- Pre-commit hook now runs `yamllint` on workflow files.

## [0.8.4] - 2026-04-08

### Added
- GA004 lint rule: "Rule entry is not a dict" (ERROR)
- GA005 lint rule: "Duplicate ref within phase" (ERROR)
- GA006 lint rule: "Phase value is not a list" (ERROR)

### Changed
- Lists error messages now consistently include "(use inline IP ranges)"
  guidance
- docs/lint.md: added auto-registration note

## [0.8.3] - 2026-04-07

### Added
- Debug logging across provider operations — resolve, get/put phase rules,
  extension hooks, and list/ruleset operations are now visible with `--debug`.

## [0.8.2] - 2026-04-07

### Added
- **GA325** (ERROR): `header_action` sub-structure validation — checks that
  `header_action` is a dict, `request_headers_to_adds` is a list of dicts,
  and each entry has `header_name` and `header_value`.
- **GA326** (ERROR): `network_match` must be a dict.
- **GA327** (ERROR): `preconfigured_waf_config` exclusions validation — checks
  that `exclusions` is a list of dicts, each with a `target_rule_set` key.

### Changed
- **GA317b** renamed to **GA320** (private/reserved IP range in `inIpRange()`)
  to follow the standard `[PREFIX][DIGITS]` rule ID convention. Update any
  `# octorules:disable=GA317b` suppression comments to `GA320`.

### Fixed
- `update_policy_settings` now retries the initial GET (`_get_policy`) on
  transient errors, matching the retry behaviour of the subsequent PATCH.
- `recaptcha_options_config` type-checked: non-dict values now produce a
  validation error instead of passing through silently.

## [0.8.1] - 2026-04-06

### Added
- `deny(429)` added to valid deny status codes and default action choices.
- `evaluateAdaptiveProtection`, `evaluateAdaptiveProtectionAutoDeploy`,
  `urlDecode`, `htmlDecode` added to known CEL functions.
- `TLS_JA3_FINGERPRINT`, `TLS_JA4_FINGERPRINT`, `USER_IP` added to valid
  `enforce_on_key` / `enforce_on_key_type` values.
- GA423 now also validates `enforce_on_key_type` inside
  `enforce_on_key_configs` entries.
- `network_match` and `preconfigured_waf_config` added to valid top-level
  rule fields (no longer trigger GA020).
- `recaptcha_options_config` pass-through support in the
  `gcloud_armor_policy_settings` extension.
- `advanced_options_config.log_level` validation (`NORMAL` or `VERBOSE`).
- `adaptive_protection_config.layer7_ddos_defense_config.rule_visibility`
  validation (`PREMIUM` or `STANDARD`).
- `adaptive_protection_config.layer7_ddos_defense_config.enable` must be a
  bool.
- `ADVANCED_PREVIEW` added to valid `ddos_protection_config` values.

### Changed
- GA200 suggestion messages now include `deny(429)` in the valid actions
  list.

## [0.8.0] - 2026-04-05

### Added
- `gcloud_armor_policy_settings` extension — manage policy-level settings
  (`adaptive_protection_config`, `advanced_options_config`,
  `ddos_protection_config`, `default_rule_action`) as code.
- `evaluateThreatIntelligence`, `evaluateThreatIntelligenceWithExcl`,
  `evaluateJsonPath` added to known CEL functions — eliminates false GA311
  warnings.

### Fixed
- GA307 (`CIDR has host bits set`) was emitted by the validator but never
  registered as a `RuleMeta` — added to `_rules.py`.
- `_MATCHES_RE` regex failed on regex patterns containing the opposite quote
  type — now uses separate alternations for single-quoted and double-quoted
  patterns.
- `_SENSITIVITY_RE` only matched `sensitivity` as the first key in the options
  dict — now matches at any position via `[^}]*?` lookahead.
- Bare `deny` action (without status code) produced a generic GA200 error — now
  gives a targeted suggestion: "deny requires a status code, e.g. deny(403)".
  `_classify_phase` also warns on bare `deny` since it is not a valid Cloud
  Armor action.
- GA315 (country code) and GA316 (HTTP method) validation only checked `==`
  comparisons — now also validates `!=` operands.
- `request.url` missing from GA319 case-sensitivity check — added to
  `_CASE_SENSITIVE_FIELDS` and regex.
- `request.host` was missing from `_KNOWN_FIELDS`, causing spurious GA310
  "unknown field" warnings on a valid Cloud Armor field.

### Changed
- `celpy.Environment()` created once at module level instead of per-expression
  — avoids redundant initialization.
- Added test coverage for `update_list_description` raising `ConfigError`.

## [0.7.1] - 2026-04-03

### Changed
- Transient retry uses shared `retry_with_backoff()` from core with jitter.
- Rule normalization uses shared `to_plain_dict()`,
  `normalize_fields()`/`denormalize_fields()` from core.
- `_check_rate_limit_deep()` split into 7 focused helpers for
  maintainability.
- CIDR validation uses `strict=True` first, then warns on auto-correctable
  host bits.
- `put_phase_rules` logs exactly which operations succeeded (patched/added/
  removed) on partial failure before re-raising, so users know the policy state.

### Added
- GA307: CIDR host bits normalization warning — warns when CIDR has host bits
  set (e.g., `10.0.0.1/24` → `10.0.0.0/24`).

### Removed
- `from __future__ import annotations` from all source files.

## [0.7.0] - 2026-04-02

### Added
- GA430: ``ban_duration_sec`` very short (< 60 seconds) warning.
- GA433: Redirect URL exceeds 1,024 characters (WARNING).

### Changed
- Unsupported operations (`create_custom_ruleset`, `delete_custom_ruleset`,
  `create_list`, etc.) now raise `ConfigError` instead of `ProviderError`, since
  these are configuration mistakes, not transient API failures.
- `_classify_phase()` logs a warning for unrecognized rule actions instead of
  silently classifying them as `custom_rules`.
- Removed CI `concurrency` blocks from lint and test workflows.
- Removed redundant `pip install yamllint` from lint workflow (now in dev deps).

## [0.6.1] - 2026-03-31

### Changed
- GA103 (`unreachable rules`) now detects parenthesized match-all expressions like `((true))` and IP-wildcard `SRC_IPS_V1` with `["*"]`.
- GA408 count-range validation consolidated into GA421 to eliminate duplicate diagnostics. GA408 is retained for `interval_sec` validation only.
- Phase IDs are now derived from phase definitions instead of a hand-maintained frozenset.
- `timeout=0` is now preserved instead of silently falling back to 30 seconds.

### Fixed
- `_IN_IP_RANGE_RE` regex was duplicated between `validate.py` and `audit.py`; now defined once and imported.

### Added
- Tests for `list_zones()` (success, empty, API errors, timeout passthrough, auth errors).
- Tests for `create_custom_ruleset` and `delete_custom_ruleset`.
- Tests for `ConfigError` on missing project (empty string, env var fallback).

## [0.6.0] - 2026-03-30

### Added
- GA421 now validates `rate_limit_threshold.count` range (1--10,000 for
  `rate_based_ban`, 1--1,000,000 for `throttle`).
- GA409/GA412 now validates redirect URL structure (scheme + host) using
  `urllib.parse`.
- GA413 rejects regex patterns exceeding 512 characters before compilation
  (ReDoS protection).
- GA315 includes a `suggestion` field for lowercase country codes.
- Remediation guidance added to all 67 lint rules in `docs/lint.md`.

### Changed
- Boolean-as-int validation uses `_is_strict_int()` helper for consistency.

## [0.5.3] - 2026-03-30

### Changed
- Extract `_parse_priority()` helper in `validate.py` to deduplicate
  three identical `try: int(ref) / except` blocks.
- Extract `_result()` factory helper in `validate.py` to reduce
  `LintResult` boilerplate across 89 call sites.
- `_retry_transient()`: replace `# type: ignore[misc]` with explicit
  `assert last_exc is not None` before re-raising.

## [0.5.2] - 2026-03-30

### Changed
- `put_phase_rules()` now retries each API call (patch, add, remove) for
  transient errors with exponential backoff. Partial success is logged so
  the next sync can reconcile.

### Added
- Ruff `B` (bugbear) and `RUF` lint rule categories to `pyproject.toml`.
- `yamllint` step in lint CI workflow (parity with core/cloudflare).
- Pre-commit hook (`scripts/hooks/pre-commit`) for ruff lint + format.
- `Topic` classifiers and `Issues` URL in `pyproject.toml`.
- Comprehensive `.gitignore` (aligned with core).

## [0.5.1] - 2026-03-25

### Fixed
- Require `octorules>=0.19.0` (audit module dependency).

## [0.5.0] - 2026-03-25

### Added
- Audit IP extractor: extracts IPs from `src_ip_ranges` and `inIpRange()` CEL
  calls for use by `octorules audit`.
- Export `GCLOUD_PHASE_NAMES` frozenset from package root.

## [0.4.1] - 2026-03-24

### Added
- `TestConcurrentWorkers` tests: concurrent `get_phase_rules` success, partial
  failure, auth error propagation, and stateless concurrent zone resolution.

## [0.4.0] - 2026-03-23

### Added
- **GA315** (WARNING): Unknown country code in `origin.region_code` comparisons
  (must be exactly 2 uppercase letters).
- **GA316** (WARNING): Unknown HTTP method in `request.method` comparisons with
  fuzzy-match suggestions for typos.
- **GA317** (ERROR): Invalid CIDR notation inside `inIpRange()` calls.
- **GA320** (WARNING): Private/reserved IP range inside `inIpRange()` calls.
- **GA318** (WARNING): CEL type mismatch detection (e.g., `origin.ip == 42` where
  `origin.ip` is a string).
- **GA319** (INFO): Case-sensitive string comparison on `request.path`,
  `request.query`, or `request.host` with mixed-case literals.
- **GA502** (WARNING): Rule count exceeds Cloud Armor tier limit (standard: 256,
  plus: 512, enterprise: 1024).
- `create_custom_ruleset` and `delete_custom_ruleset` stub methods. Required by
  the updated `BaseProvider` protocol. Cloud Armor does not support custom
  rulesets, so both raise `ProviderError`.
- **GA409** (ERROR): `redirect_options.target` must be a valid URL for `EXTERNAL_302`.
- **GA410** (ERROR): `ban_threshold` structure validation (`count` must be positive
  integer, `interval_sec` must be valid interval).
- **GA411** (ERROR): `exceed_redirect_options.type` must be `GOOGLE_RECAPTCHA` or
  `EXTERNAL_302`.
- **GA412** (ERROR): `exceed_redirect_options.target` must be a valid URL for
  `EXTERNAL_302`.
- **GA413** (WARNING): Invalid regex pattern in CEL `matches()` calls.
- **GA414** (ERROR): `enforce_on_key_configs` structure validation (must be list,
  max 3 entries, each dict with `enforce_on_key_type`, mutually exclusive with
  `enforce_on_key`).
- **GA415** (WARNING): Duplicate `enforce_on_key_type` in `enforce_on_key_configs`.
- **GA416** (WARNING): Preconfigured WAF sensitivity level must be 0-4.
- **GA418** (WARNING): Invalid HTTP header name in CEL `request.headers["..."]`
  bracket access (RFC 7230 tchar compliance).
- **GA419** (ERROR): Redirect target must not be empty or whitespace-only (applies
  to both `redirect_options.target` and `exceed_redirect_options.target`).

### Changed
- Requires `octorules>=0.18.0`.

## [0.3.0] - 2026-03-20

### Added
- **GA600** (INFO): Rule is in preview mode (`preview: true`).
- **GA601** (WARNING): Expression is always true — catch-all rule.
- **GA602** (WARNING): Expression is always false — dead rule.
- Lint rule reference: `docs/lint.md`.

## [0.2.0] - 2026-03-19

### Changed
- Error wrapping uses `make_error_wrapper` from `octorules.provider.utils`
  instead of a hand-rolled decorator.
- Requires `octorules>=0.17.0`.

### Removed
- Page Shield stub methods removed from `CloudArmorProvider`. The `BaseProvider`
  protocol no longer requires them.

## [0.1.0] - 2026-03-17

### Added

- Initial release: CloudArmorProvider for octorules.
- Document `octorules:` rule-level metadata support (`ignored`, `included`,
  `excluded`) — inherited from octorules core.
- **CEL expression deep validation** (GA310-GA314): unknown field references,
  unknown function calls, invalid `versioned_expr`, missing `config` when
  `versioned_expr` present, empty match conditions.
- **Rate limit deep validation** (GA420-GA426): `rate_limit_threshold` subfield
  validation, `enforce_on_key` enum, `enforce_on_key_name` required for
  HTTP_HEADER/HTTP_COOKIE, `ban_duration_sec` required for `rate_based_ban`.
- **Action parameter validation** (GA429, GA431): `ban_duration_sec` on throttle
  (wrong action), redirect `exceed_action` without redirect options.
- **Cross-rule analysis** (GA105, GA108): inconsistent `enforce_on_key` across
  rate-limit rules, duplicate preconfigured WAF rule sets.
- Linter plugin: registers 44 Cloud Armor lint rules (GA*) with octorules
  core lint engine.
- Register `kind` as an API field to strip from rules.
- `gcloud_armor_redirect_rules` phase.

### Changed

- Logger uses `__name__` instead of hardcoded `"octorules"`.
- Removed unused `max_retries` parameter from `CloudArmorProvider.__init__`.

### Fixed

- `CloudArmorProvider` validates that `project` is non-empty at init.
- Proto-plus object detection uses `hasattr(obj, 'to_dict')` instead of
  `hasattr(obj, '__iter__')`, which incorrectly matched strings.
- `put_phase_rules` now patches rules in place, adds new rules, then removes
  stale rules — so the policy never has fewer rules than intended.
- README examples use correct snake_case field names.
- Entry point `octorules.providers: google` for auto-discovery by octorules core.
- Phase mapping: `gcloud_armor_custom_rules`, `gcloud_armor_rate_rules`,
  `gcloud_armor_preconfigured_rules`.
- Exception wrapping: Google Cloud errors mapped to ProviderError/ProviderAuthError.
