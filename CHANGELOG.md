# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
