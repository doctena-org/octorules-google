# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **GA315** (WARNING): Unknown country code in `origin.region_code` comparisons
  (must be exactly 2 uppercase letters).
- **GA316** (WARNING): Unknown HTTP method in `request.method` comparisons with
  fuzzy-match suggestions for typos.
- **GA317** (ERROR): Invalid CIDR notation inside `inIpRange()` calls.
- **GA317b** (WARNING): Private/reserved IP range inside `inIpRange()` calls.
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
