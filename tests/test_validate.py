"""Tests for Google Cloud Armor rule validation."""

from __future__ import annotations

import pytest
from octorules.linter.engine import LintResult

from octorules_google.validate import validate_rules


def _rule(**overrides):
    """Build a minimal valid Cloud Armor rule with overrides."""
    base = {
        "ref": "100",
        "action": "allow",
        "match": {"expr": {"expression": "true"}},
    }
    base.update(overrides)
    return base


def _ids(results: list[LintResult]) -> list[str]:
    return [r.rule_id for r in results]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestValidRules:
    def test_no_errors(self):
        r = _rule(match={"expr": {"expression": "origin.region_code == 'US'"}})
        assert validate_rules([r]) == []

    def test_empty_list(self):
        assert validate_rules([]) == []

    def test_phase_passed_through(self):
        r = _rule()
        del r["ref"]
        results = validate_rules([r], phase="gcloud_armor_custom_rules")
        assert results[0].phase == "gcloud_armor_custom_rules"

    def test_returns_lint_result_instances(self):
        r = _rule()
        del r["ref"]
        results = validate_rules([r])
        assert all(isinstance(r, LintResult) for r in results)


# ---------------------------------------------------------------------------
# GA001–GA003  Structural checks
# ---------------------------------------------------------------------------


class TestStructural:
    def test_ga001_missing_ref(self):
        r = _rule()
        del r["ref"]
        assert "GA001" in _ids(validate_rules([r]))

    def test_ga001_empty_ref(self):
        assert "GA001" in _ids(validate_rules([_rule(ref="")]))

    def test_ga002_missing_action(self):
        r = _rule()
        del r["action"]
        assert "GA002" in _ids(validate_rules([r]))

    def test_ga002_empty_action(self):
        assert "GA002" in _ids(validate_rules([_rule(action="")]))

    def test_ga003_missing_match(self):
        r = _rule()
        del r["match"]
        assert "GA003" in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# GA100–GA104  Priority & cross-rule checks
# ---------------------------------------------------------------------------


class TestPriority:
    def test_ga100_not_integer_string(self):
        assert "GA100" in _ids(validate_rules([_rule(ref="abc")]))

    def test_ga100_negative(self):
        assert "GA100" in _ids(validate_rules([_rule(ref="-1")]))

    def test_ga100_float_string(self):
        assert "GA100" in _ids(validate_rules([_rule(ref="1.5")]))

    def test_ga100_zero_accepted(self):
        assert "GA100" not in _ids(validate_rules([_rule(ref="0")]))

    def test_ga101_out_of_range(self):
        assert "GA101" in _ids(validate_rules([_rule(ref="2147483647")]))

    def test_ga101_max_valid(self):
        assert "GA101" not in _ids(validate_rules([_rule(ref="2147483646")]))

    def test_ga102_duplicate(self):
        a = _rule(ref="100")
        b = _rule(ref="100")
        assert "GA102" in _ids(validate_rules([a, b]))

    def test_ga102_no_false_positive(self):
        a = _rule(ref="100")
        b = _rule(ref="200")
        assert "GA102" not in _ids(validate_rules([a, b]))


class TestDeadRules:
    def test_ga103_unreachable_after_allow_all(self):
        rules = [
            _rule(ref="100", action="allow", match={"expr": {"expression": "true"}}),
            _rule(
                ref="200",
                action="deny(403)",
                match={"expr": {"expression": "origin.region_code == 'CN'"}},
            ),
        ]
        assert "GA103" in _ids(validate_rules(rules))

    def test_ga103_lower_priority_not_flagged(self):
        rules = [
            _rule(
                ref="50",
                action="deny(403)",
                match={"expr": {"expression": "origin.region_code == 'CN'"}},
            ),
            _rule(ref="100", action="allow", match={"expr": {"expression": "true"}}),
        ]
        # Only priority 50 rule's ref should NOT be flagged
        ga103_results = [r for r in validate_rules(rules) if r.rule_id == "GA103"]
        assert all(r.ref != "50" for r in ga103_results)

    def test_ga103_no_match_all_no_warning(self):
        rules = [
            _rule(
                ref="100",
                action="deny(403)",
                match={"expr": {"expression": "origin.region_code == 'CN'"}},
            ),
            _rule(
                ref="200",
                action="allow",
                match={"expr": {"expression": "origin.region_code == 'US'"}},
            ),
        ]
        assert "GA103" not in _ids(validate_rules(rules))

    def test_ga103_whitespace_in_true(self):
        rules = [
            _rule(ref="100", action="allow", match={"expr": {"expression": "  true  "}}),
            _rule(
                ref="200",
                action="deny(403)",
                match={"expr": {"expression": "origin.ip == '1.2.3.4'"}},
            ),
        ]
        assert "GA103" in _ids(validate_rules(rules))


class TestDuplicateExpressions:
    def test_ga104_duplicate(self):
        rules = [
            _rule(ref="100", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
            _rule(ref="200", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
        ]
        assert "GA104" in _ids(validate_rules(rules))

    def test_ga104_whitespace_normalized(self):
        rules = [
            _rule(ref="100", match={"expr": {"expression": "origin.region_code  ==  'CN'"}}),
            _rule(ref="200", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
        ]
        assert "GA104" in _ids(validate_rules(rules))

    def test_ga104_different_expressions(self):
        rules = [
            _rule(ref="100", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
            _rule(ref="200", match={"expr": {"expression": "origin.region_code == 'RU'"}}),
        ]
        assert "GA104" not in _ids(validate_rules(rules))


# ---------------------------------------------------------------------------
# GA200–GA201  Action checks
# ---------------------------------------------------------------------------


class TestActions:
    @pytest.mark.parametrize(
        "action",
        [
            "allow",
            "deny(403)",
            "deny(404)",
            "deny(502)",
            "throttle",
            "rate_based_ban",
            "redirect",
        ],
    )
    def test_ga200_valid_actions(self, action):
        r = _rule(action=action)
        if action in ("throttle", "rate_based_ban"):
            r["rate_limit_options"] = {
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            }
        if action == "redirect":
            r["redirect_options"] = {"type": "GOOGLE_RECAPTCHA"}
        assert "GA200" not in _ids(validate_rules([r]))

    def test_ga200_invalid_action(self):
        assert "GA200" in _ids(validate_rules([_rule(action="block")]))

    def test_ga200_deny_without_parens(self):
        assert "GA200" in _ids(validate_rules([_rule(action="deny")]))

    def test_ga201_invalid_deny_status(self):
        assert "GA201" in _ids(validate_rules([_rule(action="deny(500)")]))

    def test_ga201_valid_deny_no_201(self):
        assert "GA201" not in _ids(validate_rules([_rule(action="deny(403)")]))

    def test_ga201_deny_200(self):
        assert "GA201" in _ids(validate_rules([_rule(action="deny(200)")]))


# ---------------------------------------------------------------------------
# GA300–GA306  Match checks
# ---------------------------------------------------------------------------


class TestMatch:
    def test_ga300_both_expr_and_config(self):
        match = {
            "expr": {"expression": "true"},
            "config": {"src_ip_ranges": ["1.2.3.0/24"]},
        }
        assert "GA300" in _ids(validate_rules([_rule(match=match)]))

    def test_ga300_neither_expr_nor_config(self):
        assert "GA300" in _ids(validate_rules([_rule(match={})]))

    def test_ga300_expr_only_ok(self):
        match = {"expr": {"expression": "true"}}
        assert "GA300" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga300_config_only_ok(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA300" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga300_versioned_expr_counts_as_config(self):
        match = {"versioned_expr": "SRC_IPS_V1"}
        assert "GA300" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga301_invalid_cidr(self):
        match = {"config": {"src_ip_ranges": ["not-a-cidr"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA301" in _ids(validate_rules([_rule(match=match)]))

    def test_ga301_valid_cidr(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "2001:4860::/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert "GA301" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga301_host_address(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.8/32"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA301" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga302_cel_syntax_error(self):
        match = {"expr": {"expression": "((("}}
        assert "GA302" in _ids(validate_rules([_rule(match=match)]))

    def test_ga302_cel_valid(self):
        match = {"expr": {"expression": "true"}}
        assert "GA302" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga302_cel_function_call(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert "GA302" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga303_unknown_waf_rule_set(self):
        match = {"expr": {"expression": "evaluatePreconfiguredWaf('unknown-v1-stable')"}}
        assert "GA303" in _ids(validate_rules([_rule(match=match)]))

    def test_ga303_known_waf_rule_set(self):
        match = {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}}
        assert "GA303" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga303_known_xss(self):
        match = {"expr": {"expression": "evaluatePreconfiguredExpr('xss-v33-stable')"}}
        assert "GA303" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga303_multiple_preconfigured(self):
        expr = "evaluatePreconfiguredWaf('sqli-v33-stable') && evaluatePreconfiguredWaf('bogus-v1')"
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        ga303_count = _ids(results).count("GA303")
        assert ga303_count == 1  # sqli is known, bogus is not


class TestCelLength:
    def test_ga304_exceeds_max(self):
        match = {"expr": {"expression": "x" * 2049}}
        results = validate_rules([_rule(match=match)])
        assert "GA304" in _ids(results)

    def test_ga304_at_limit(self):
        # 2048 chars starting with valid CEL
        expr = "true" + " " * 2044
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        assert "GA304" not in _ids(results)

    def test_ga304_under_limit(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert "GA304" not in _ids(validate_rules([_rule(match=match)]))


class TestCidrChecks:
    def test_ga305_overlapping(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.0.0/16", "8.8.8.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert "GA305" in _ids(validate_rules([_rule(match=match)]))

    def test_ga305_duplicate(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "8.8.8.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert "GA305" in _ids(validate_rules([_rule(match=match)]))

    def test_ga305_no_overlap(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "1.1.1.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert "GA305" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga305_ipv4_ipv6_no_overlap(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "2001:db8::/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert "GA305" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga306_slash_zero_ipv4(self):
        match = {"config": {"src_ip_ranges": ["0.0.0.0/0"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA306" in _ids(validate_rules([_rule(match=match)]))

    def test_ga306_slash_zero_ipv6(self):
        match = {"config": {"src_ip_ranges": ["::/0"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA306" in _ids(validate_rules([_rule(match=match)]))

    def test_ga306_not_slash_zero(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA306" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga503_private_rfc1918(self):
        match = {"config": {"src_ip_ranges": ["10.0.0.0/8"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA503" in _ids(validate_rules([_rule(match=match)]))

    def test_ga503_private_172(self):
        match = {"config": {"src_ip_ranges": ["172.16.0.0/12"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA503" in _ids(validate_rules([_rule(match=match)]))

    def test_ga503_private_192(self):
        match = {"config": {"src_ip_ranges": ["192.168.1.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA503" in _ids(validate_rules([_rule(match=match)]))

    def test_ga503_loopback(self):
        match = {"config": {"src_ip_ranges": ["127.0.0.1/32"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA503" in _ids(validate_rules([_rule(match=match)]))

    def test_ga503_public_not_flagged(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA503" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga503_ipv6_ula(self):
        match = {"config": {"src_ip_ranges": ["fd00::/8"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA503" in _ids(validate_rules([_rule(match=match)]))


# ---------------------------------------------------------------------------
# GA400–GA408  Rate limit options
# ---------------------------------------------------------------------------


class TestRateLimitOptions:
    def test_ga400_throttle_missing_rate_limit(self):
        assert "GA400" in _ids(validate_rules([_rule(action="throttle")]))

    def test_ga400_rate_based_ban_missing_rate_limit(self):
        assert "GA400" in _ids(validate_rules([_rule(action="rate_based_ban")]))

    def test_ga400_throttle_with_rate_limit(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA400" not in _ids(validate_rules([r]))

    def test_ga403_missing_conform_action(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        results = validate_rules([r])
        ga403 = [x for x in results if x.rule_id == "GA403"]
        assert len(ga403) == 1
        assert "conform_action" in ga403[0].field

    def test_ga403_missing_exceed_action(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        results = validate_rules([r])
        ga403 = [x for x in results if x.rule_id == "GA403"]
        assert len(ga403) == 1
        assert "exceed_action" in ga403[0].field

    def test_ga403_missing_threshold(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
            },
        )
        results = validate_rules([r])
        ga403 = [x for x in results if x.rule_id == "GA403"]
        assert len(ga403) == 1
        assert "rate_limit_threshold" in ga403[0].field

    def test_ga403_empty_options(self):
        r = _rule(action="throttle", rate_limit_options={})
        results = validate_rules([r])
        ga403_count = _ids(results).count("GA403")
        assert ga403_count == 3  # All 3 required fields missing

    def test_ga405_conform_action_not_allow(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "deny-403",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA405" in _ids(validate_rules([r]))

    def test_ga405_conform_action_allow_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA405" not in _ids(validate_rules([r]))

    @pytest.mark.parametrize("ea", ["deny-403", "deny-404", "deny-429", "deny-502", "redirect"])
    def test_ga406_valid_exceed_actions(self, ea):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": ea,
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA406" not in _ids(validate_rules([r]))

    def test_ga406_invalid_exceed_action(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "block",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA406" in _ids(validate_rules([r]))

    @pytest.mark.parametrize("interval", [10, 30, 60, 120, 300, 600, 3600])
    def test_ga407_valid_intervals(self, interval):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": interval},
            },
        )
        assert "GA407" not in _ids(validate_rules([r]))

    def test_ga407_invalid_interval(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 45},
            },
        )
        assert "GA407" in _ids(validate_rules([r]))

    def test_ga408_count_too_high_throttle(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 1_000_001, "interval_sec": 60},
            },
        )
        assert "GA408" in _ids(validate_rules([r]))

    def test_ga408_count_at_max_throttle(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 1_000_000, "interval_sec": 60},
            },
        )
        assert "GA408" not in _ids(validate_rules([r]))

    def test_ga408_count_too_high_rate_based_ban(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 10_001, "interval_sec": 60},
            },
        )
        assert "GA408" in _ids(validate_rules([r]))

    def test_ga408_count_at_max_rate_based_ban(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 10_000, "interval_sec": 60},
            },
        )
        assert "GA408" not in _ids(validate_rules([r]))

    def test_ga408_count_zero(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 0, "interval_sec": 60},
            },
        )
        assert "GA408" in _ids(validate_rules([r]))

    def test_ga408_count_bool(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": True, "interval_sec": 60},
            },
        )
        assert "GA408" in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# GA401–GA404  Redirect options
# ---------------------------------------------------------------------------


class TestRedirectOptions:
    def test_ga401_redirect_missing_options(self):
        assert "GA401" in _ids(validate_rules([_rule(action="redirect")]))

    def test_ga401_redirect_with_options(self):
        r = _rule(action="redirect", redirect_options={"type": "GOOGLE_RECAPTCHA"})
        assert "GA401" not in _ids(validate_rules([r]))

    def test_ga402_invalid_redirect_type(self):
        r = _rule(action="redirect", redirect_options={"type": "INVALID"})
        assert "GA402" in _ids(validate_rules([r]))

    @pytest.mark.parametrize("rtype", ["GOOGLE_RECAPTCHA", "EXTERNAL_302"])
    def test_ga402_valid_redirect_types(self, rtype):
        r = _rule(action="redirect", redirect_options={"type": rtype, "target": "https://x.com"})
        assert "GA402" not in _ids(validate_rules([r]))

    def test_ga402_no_type_key_no_error(self):
        r = _rule(action="redirect", redirect_options={})
        assert "GA402" not in _ids(validate_rules([r]))

    def test_ga404_external_302_missing_target(self):
        r = _rule(action="redirect", redirect_options={"type": "EXTERNAL_302"})
        assert "GA404" in _ids(validate_rules([r]))

    def test_ga404_external_302_with_target(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "https://example.com"},
        )
        assert "GA404" not in _ids(validate_rules([r]))

    def test_ga404_recaptcha_no_target_ok(self):
        r = _rule(action="redirect", redirect_options={"type": "GOOGLE_RECAPTCHA"})
        assert "GA404" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# GA500  Description length
# ---------------------------------------------------------------------------


class TestDescription:
    def test_ga500_too_long(self):
        r = _rule(description="x" * 1025)
        assert "GA500" in _ids(validate_rules([r]))

    def test_ga500_at_limit(self):
        r = _rule(description="x" * 1024)
        assert "GA500" not in _ids(validate_rules([r]))

    def test_ga500_no_description(self):
        assert "GA500" not in _ids(validate_rules([_rule()]))


# ---------------------------------------------------------------------------
# GA310–GA314  Expression / match deep validation
# ---------------------------------------------------------------------------


class TestMatchDeep:
    # --- GA310: Unknown field reference ---

    def test_ga310_unknown_field(self):
        match = {"expr": {"expression": "bogus.field == 'x'"}}
        assert "GA310" in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_origin_ip(self):
        match = {"expr": {"expression": "origin.ip == '1.2.3.4'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_request_headers(self):
        match = {"expr": {"expression": "request.headers['X-Foo'] == 'bar'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_request_method(self):
        match = {"expr": {"expression": "request.method == 'GET'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_request_path(self):
        match = {"expr": {"expression": "request.path.startsWith('/api')"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_request_scheme(self):
        match = {"expr": {"expression": "request.scheme == 'https'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_request_query(self):
        match = {"expr": {"expression": "request.query.contains('foo')"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_request_url(self):
        match = {"expr": {"expression": "request.url.contains('/api')"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_origin_region_code(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_origin_asn(self):
        match = {"expr": {"expression": "origin.asn == 15169"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_origin_user_ip(self):
        match = {"expr": {"expression": "origin.user_ip == '1.2.3.4'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_origin_tls_ja3(self):
        match = {"expr": {"expression": "origin.tls_ja3_fingerprint == 'abc'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_origin_tls_ja4(self):
        match = {"expr": {"expression": "origin.tls_ja4_fingerprint == 'abc'"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_token_recaptcha_action(self):
        match = {"expr": {"expression": "token.recaptcha_action.score > 0.5"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_token_recaptcha_session(self):
        match = {"expr": {"expression": "token.recaptcha_session.score > 0.5"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_known_token_recaptcha_exemption(self):
        match = {"expr": {"expression": "token.recaptcha_exemption.valid == true"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_multiple_unknown(self):
        match = {"expr": {"expression": "bogus.one == 'x' && fake.two == 'y'"}}
        results = validate_rules([_rule(match=match)])
        ga310 = [r for r in results if r.rule_id == "GA310"]
        assert len(ga310) == 2

    def test_ga310_same_unknown_field_deduped(self):
        match = {"expr": {"expression": "bogus.field == 'x' || bogus.field == 'y'"}}
        results = validate_rules([_rule(match=match)])
        ga310 = [r for r in results if r.rule_id == "GA310"]
        assert len(ga310) == 1

    def test_ga310_no_false_positive_on_true(self):
        """'true' alone has no dotted field references."""
        match = {"expr": {"expression": "true"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    # --- GA311: Unknown function ---

    def test_ga311_unknown_function(self):
        match = {"expr": {"expression": "unknownFunc(origin.ip)"}}
        assert "GA311" in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_contains(self):
        match = {"expr": {"expression": "request.path.contains('/api')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_startsWith(self):
        match = {"expr": {"expression": "request.path.startsWith('/api')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_endsWith(self):
        match = {"expr": {"expression": "request.path.endsWith('.html')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_matches(self):
        match = {"expr": {"expression": "request.path.matches('.*api.*')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_lower(self):
        match = {"expr": {"expression": "request.method.lower() == 'get'"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_upper(self):
        match = {"expr": {"expression": "request.method.upper() == 'GET'"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_base64Decode(self):
        match = {"expr": {"expression": "request.headers['auth'].base64Decode() == 'x'"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_inIpRange(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '1.0.0.0/8')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_size(self):
        match = {"expr": {"expression": "size(request.query) > 100"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_int(self):
        match = {"expr": {"expression": "int(request.headers['x']) > 100"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_evaluatePreconfiguredWaf(self):
        match = {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_evaluatePreconfiguredExpr(self):
        match = {"expr": {"expression": "evaluatePreconfiguredExpr('xss-v33-stable')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_known_has(self):
        match = {"expr": {"expression": "has(request.headers['X-Custom'])"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_deduped(self):
        match = {"expr": {"expression": "badFunc(1) || badFunc(2)"}}
        results = validate_rules([_rule(match=match)])
        ga311 = [r for r in results if r.rule_id == "GA311"]
        assert len(ga311) == 1

    # --- GA310/GA311: false positive prevention (string literal stripping) ---

    def test_ga310_no_false_positive_in_string_literal(self):
        """Field-like text inside quoted strings should not trigger GA310."""
        match = {"expr": {"expression": "request.path.contains('origin.ip')"}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_no_false_positive_in_header_subscript(self):
        """Header key subscripts should not be extracted as field references."""
        match = {"expr": {"expression": 'request.headers["origin.ip.test"]'}}
        assert "GA310" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga310_real_field_outside_string_still_caught(self):
        """Unknown field outside a string is still flagged even if strings are present."""
        match = {"expr": {"expression": "unknown.field == 'origin.ip'"}}
        assert "GA310" in _ids(validate_rules([_rule(match=match)]))

    def test_ga311_no_false_positive_in_string_literal(self):
        """Function-like text inside quoted strings should not trigger GA311."""
        match = {"expr": {"expression": "request.path.contains('badFunc()')"}}
        assert "GA311" not in _ids(validate_rules([_rule(match=match)]))

    # --- GA312: Invalid versioned_expr ---

    def test_ga312_invalid_versioned_expr(self):
        match = {"versioned_expr": "BOGUS", "config": {"src_ip_ranges": ["1.2.3.0/24"]}}
        assert "GA312" in _ids(validate_rules([_rule(match=match)]))

    def test_ga312_valid_src_ips_v1(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": {"src_ip_ranges": ["1.2.3.0/24"]}}
        assert "GA312" not in _ids(validate_rules([_rule(match=match)]))

    # --- GA313: Missing config with versioned_expr ---

    def test_ga313_versioned_expr_no_config(self):
        match = {"versioned_expr": "SRC_IPS_V1"}
        assert "GA313" in _ids(validate_rules([_rule(match=match)]))

    def test_ga313_versioned_expr_config_no_ranges(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": {}}
        assert "GA313" in _ids(validate_rules([_rule(match=match)]))

    def test_ga313_versioned_expr_config_not_dict(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": "invalid"}
        assert "GA313" in _ids(validate_rules([_rule(match=match)]))

    def test_ga313_versioned_expr_with_ranges_ok(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": {"src_ip_ranges": ["1.2.3.0/24"]}}
        assert "GA313" not in _ids(validate_rules([_rule(match=match)]))

    # --- GA314: Empty match conditions ---

    def test_ga314_empty_expression(self):
        match = {"expr": {"expression": ""}}
        assert "GA314" in _ids(validate_rules([_rule(match=match)]))

    def test_ga314_whitespace_only_expression(self):
        match = {"expr": {"expression": "   "}}
        assert "GA314" in _ids(validate_rules([_rule(match=match)]))

    def test_ga314_tab_only_expression(self):
        match = {"expr": {"expression": "\t\n"}}
        assert "GA314" in _ids(validate_rules([_rule(match=match)]))

    def test_ga314_empty_src_ip_ranges(self):
        match = {"config": {"src_ip_ranges": []}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA314" in _ids(validate_rules([_rule(match=match)]))

    def test_ga314_nonempty_expression_ok(self):
        match = {"expr": {"expression": "true"}}
        assert "GA314" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga314_nonempty_ranges_ok(self):
        match = {"config": {"src_ip_ranges": ["1.2.3.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert "GA314" not in _ids(validate_rules([_rule(match=match)]))


# ---------------------------------------------------------------------------
# GA420–GA426  Rate limit deep validation
# ---------------------------------------------------------------------------


class TestRateLimitDeep:
    def _rl_rule(self, **rlo_overrides):
        """Build a rate-limit rule with overrides to rate_limit_options."""
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
        }
        rlo.update(rlo_overrides)
        return _rule(action="throttle", rate_limit_options=rlo)

    def _ban_rule(self, **rlo_overrides):
        """Build a rate_based_ban rule with overrides to rate_limit_options."""
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            "ban_duration_sec": 120,
        }
        rlo.update(rlo_overrides)
        return _rule(action="rate_based_ban", rate_limit_options=rlo)

    # --- GA420: rate_limit_threshold missing subfields ---

    def test_ga420_threshold_not_dict(self):
        r = self._rl_rule(rate_limit_threshold="invalid")
        assert "GA420" in _ids(validate_rules([r]))

    def test_ga420_threshold_missing_count(self):
        r = self._rl_rule(rate_limit_threshold={"interval_sec": 60})
        assert "GA420" in _ids(validate_rules([r]))

    def test_ga420_threshold_missing_interval_sec(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100})
        assert "GA420" in _ids(validate_rules([r]))

    def test_ga420_threshold_missing_both(self):
        r = self._rl_rule(rate_limit_threshold={})
        results = validate_rules([r])
        ga420 = [x for x in results if x.rule_id == "GA420"]
        assert len(ga420) == 2

    def test_ga420_threshold_complete_ok(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": 60})
        assert "GA420" not in _ids(validate_rules([r]))

    # --- GA421: Invalid types ---

    def test_ga421_count_is_string(self):
        r = self._rl_rule(rate_limit_threshold={"count": "100", "interval_sec": 60})
        assert "GA421" in _ids(validate_rules([r]))

    def test_ga421_count_is_bool(self):
        r = self._rl_rule(rate_limit_threshold={"count": True, "interval_sec": 60})
        assert "GA421" in _ids(validate_rules([r]))

    def test_ga421_interval_is_string(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": "60"})
        assert "GA421" in _ids(validate_rules([r]))

    def test_ga421_interval_is_bool(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": False})
        assert "GA421" in _ids(validate_rules([r]))

    def test_ga421_both_valid_ints_ok(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": 60})
        assert "GA421" not in _ids(validate_rules([r]))

    # --- GA422: enforce_on_key for rate_based_ban with redirect ---

    def test_ga422_rate_based_ban_redirect_no_key(self):
        r = self._ban_rule(exceed_action="redirect")
        assert "GA422" in _ids(validate_rules([r]))

    def test_ga422_rate_based_ban_redirect_with_key(self):
        r = self._ban_rule(exceed_action="redirect", enforce_on_key="IP")
        assert "GA422" not in _ids(validate_rules([r]))

    def test_ga422_throttle_redirect_no_key_no_warning(self):
        r = self._rl_rule(exceed_action="redirect")
        assert "GA422" not in _ids(validate_rules([r]))

    def test_ga422_rate_based_ban_deny_no_key_no_warning(self):
        r = self._ban_rule(exceed_action="deny-429")
        assert "GA422" not in _ids(validate_rules([r]))

    # --- GA423: Invalid enforce_on_key ---

    @pytest.mark.parametrize(
        "key",
        ["IP", "ALL", "HTTP_HEADER", "XFF_IP", "HTTP_COOKIE", "HTTP_PATH", "SNI", "REGION_CODE"],
    )
    def test_ga423_valid_keys(self, key):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            "enforce_on_key": key,
        }
        if key in ("HTTP_HEADER", "HTTP_COOKIE"):
            rlo["enforce_on_key_name"] = "X-Something"
        r = _rule(action="throttle", rate_limit_options=rlo)
        assert "GA423" not in _ids(validate_rules([r]))

    def test_ga423_invalid_key(self):
        r = self._rl_rule(enforce_on_key="INVALID")
        assert "GA423" in _ids(validate_rules([r]))

    # --- GA424: enforce_on_key_name required ---

    def test_ga424_http_header_no_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER")
        assert "GA424" in _ids(validate_rules([r]))

    def test_ga424_http_cookie_no_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE")
        assert "GA424" in _ids(validate_rules([r]))

    def test_ga424_http_header_with_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X-Custom")
        assert "GA424" not in _ids(validate_rules([r]))

    def test_ga424_http_cookie_with_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE", enforce_on_key_name="session")
        assert "GA424" not in _ids(validate_rules([r]))

    def test_ga424_ip_no_name_ok(self):
        r = self._rl_rule(enforce_on_key="IP")
        assert "GA424" not in _ids(validate_rules([r]))

    # --- GA425: ban_duration_sec required for rate_based_ban ---

    def test_ga425_rate_based_ban_no_ban_duration(self):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
        }
        r = _rule(action="rate_based_ban", rate_limit_options=rlo)
        assert "GA425" in _ids(validate_rules([r]))

    def test_ga425_rate_based_ban_with_ban_duration(self):
        r = self._ban_rule(ban_duration_sec=120)
        assert "GA425" not in _ids(validate_rules([r]))

    def test_ga425_throttle_no_ban_duration_ok(self):
        r = self._rl_rule()
        assert "GA425" not in _ids(validate_rules([r]))

    # --- GA426: Invalid ban_duration_sec ---

    def test_ga426_zero(self):
        r = self._ban_rule(ban_duration_sec=0)
        assert "GA426" in _ids(validate_rules([r]))

    def test_ga426_negative(self):
        r = self._ban_rule(ban_duration_sec=-10)
        assert "GA426" in _ids(validate_rules([r]))

    def test_ga426_bool(self):
        r = self._ban_rule(ban_duration_sec=True)
        assert "GA426" in _ids(validate_rules([r]))

    def test_ga426_string(self):
        r = self._ban_rule(ban_duration_sec="120")
        assert "GA426" in _ids(validate_rules([r]))

    def test_ga426_positive_int_ok(self):
        r = self._ban_rule(ban_duration_sec=120)
        assert "GA426" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# GA429, GA431  Action parameter validation
# ---------------------------------------------------------------------------


class TestActionParams:
    # --- GA429: ban_duration_sec on throttle ---

    def test_ga429_throttle_with_ban_duration(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_duration_sec": 120,
            },
        )
        assert "GA429" in _ids(validate_rules([r]))

    def test_ga429_rate_based_ban_with_ban_duration_ok(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_duration_sec": 120,
            },
        )
        assert "GA429" not in _ids(validate_rules([r]))

    def test_ga429_throttle_without_ban_duration_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA429" not in _ids(validate_rules([r]))

    # --- GA431: redirect exceed_action without redirect options ---

    def test_ga431_redirect_exceed_no_redirect_options(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA431" in _ids(validate_rules([r]))

    def test_ga431_redirect_exceed_with_redirect_options(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "https://x.com"},
            },
        )
        assert "GA431" not in _ids(validate_rules([r]))

    def test_ga431_deny_exceed_no_redirect_options_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert "GA431" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# GA105, GA108  Cross-rule analysis
# ---------------------------------------------------------------------------


class TestCrossRuleAnalysis:
    # --- GA105: Inconsistent enforce_on_key ---

    def test_ga105_same_key_no_warning(self):
        r1 = _rule(
            ref="100",
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "enforce_on_key": "IP",
            },
        )
        r2 = _rule(
            ref="200",
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 50, "interval_sec": 60},
                "enforce_on_key": "IP",
            },
        )
        assert "GA105" not in _ids(validate_rules([r1, r2]))

    def test_ga105_different_keys_warning(self):
        r1 = _rule(
            ref="100",
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "enforce_on_key": "IP",
            },
        )
        r2 = _rule(
            ref="200",
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 50, "interval_sec": 60},
                "enforce_on_key": "XFF_IP",
                "ban_duration_sec": 120,
            },
        )
        assert "GA105" in _ids(validate_rules([r1, r2]))

    def test_ga105_single_rule_no_warning(self):
        r1 = _rule(
            ref="100",
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "enforce_on_key": "IP",
            },
        )
        assert "GA105" not in _ids(validate_rules([r1]))

    def test_ga105_no_enforce_on_key_no_warning(self):
        r1 = _rule(
            ref="100",
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        r2 = _rule(
            ref="200",
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 50, "interval_sec": 60},
            },
        )
        assert "GA105" not in _ids(validate_rules([r1, r2]))

    # --- GA108: Duplicate preconfigured WAF rule set ---

    def test_ga108_same_waf_ruleset_two_rules(self):
        r1 = _rule(
            ref="100",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}},
        )
        r2 = _rule(
            ref="200",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}},
        )
        assert "GA108" in _ids(validate_rules([r1, r2]))

    def test_ga108_different_waf_rulesets_ok(self):
        r1 = _rule(
            ref="100",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}},
        )
        r2 = _rule(
            ref="200",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('xss-v33-stable')"}},
        )
        assert "GA108" not in _ids(validate_rules([r1, r2]))

    def test_ga108_single_rule_no_warning(self):
        r1 = _rule(
            ref="100",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}},
        )
        assert "GA108" not in _ids(validate_rules([r1]))

    def test_ga108_expr_variant(self):
        """evaluatePreconfiguredExpr also tracked."""
        r1 = _rule(
            ref="100",
            match={"expr": {"expression": "evaluatePreconfiguredExpr('xss-v33-stable')"}},
        )
        r2 = _rule(
            ref="200",
            match={"expr": {"expression": "evaluatePreconfiguredExpr('xss-v33-stable')"}},
        )
        assert "GA108" in _ids(validate_rules([r1, r2]))


# ---------------------------------------------------------------------------
# GA600  Preview mode
# ---------------------------------------------------------------------------


class TestPreview:
    def test_ga600_preview_true(self):
        r = _rule(preview=True)
        assert "GA600" in _ids(validate_rules([r]))

    def test_ga600_preview_false(self):
        r = _rule(preview=False)
        assert "GA600" not in _ids(validate_rules([r]))

    def test_ga600_no_preview_key(self):
        assert "GA600" not in _ids(validate_rules([_rule()]))

    def test_ga600_preview_none(self):
        r = _rule(preview=None)
        assert "GA600" not in _ids(validate_rules([r]))

    def test_ga600_preview_truthy_string_not_flagged(self):
        """Only boolean True triggers GA600, not truthy strings."""
        r = _rule(preview="yes")
        assert "GA600" not in _ids(validate_rules([r]))

    def test_ga600_severity_is_info(self):
        from octorules.linter.engine import Severity

        r = _rule(preview=True)
        results = validate_rules([r])
        ga600 = [x for x in results if x.rule_id == "GA600"]
        assert ga600[0].severity == Severity.INFO

    def test_ga600_field_set(self):
        r = _rule(preview=True)
        results = validate_rules([r])
        ga600 = [x for x in results if x.rule_id == "GA600"]
        assert ga600[0].field == "preview"


# ---------------------------------------------------------------------------
# GA601  Always-true expression
# ---------------------------------------------------------------------------


class TestAlwaysTrue:
    def test_ga601_expression_true(self):
        match = {"expr": {"expression": "true"}}
        assert "GA601" in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_expression_true_uppercase(self):
        match = {"expr": {"expression": "TRUE"}}
        assert "GA601" in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_expression_true_whitespace(self):
        match = {"expr": {"expression": "  true  "}}
        assert "GA601" in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_expression_true_parenthesized(self):
        match = {"expr": {"expression": "((true))"}}
        assert "GA601" in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_normal_expression_not_flagged(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert "GA601" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_src_ip_ranges_wildcard(self):
        match = {
            "versioned_expr": "SRC_IPS_V1",
            "config": {"src_ip_ranges": ["*"]},
        }
        assert "GA601" in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_src_ip_ranges_non_wildcard(self):
        match = {
            "versioned_expr": "SRC_IPS_V1",
            "config": {"src_ip_ranges": ["8.8.8.0/24"]},
        }
        assert "GA601" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_src_ip_ranges_wildcard_wrong_versioned_expr(self):
        """Only SRC_IPS_V1 with ['*'] triggers GA601."""
        match = {
            "versioned_expr": "BOGUS",
            "config": {"src_ip_ranges": ["*"]},
        }
        assert "GA601" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga601_severity_is_warning(self):
        from octorules.linter.engine import Severity

        match = {"expr": {"expression": "true"}}
        results = validate_rules([_rule(match=match)])
        ga601 = [x for x in results if x.rule_id == "GA601"]
        assert ga601[0].severity == Severity.WARNING

    def test_ga601_field_set_for_cel(self):
        match = {"expr": {"expression": "true"}}
        results = validate_rules([_rule(match=match)])
        ga601 = [x for x in results if x.rule_id == "GA601"]
        assert ga601[0].field == "match.expr.expression"

    def test_ga601_field_set_for_ip_wildcard(self):
        match = {
            "versioned_expr": "SRC_IPS_V1",
            "config": {"src_ip_ranges": ["*"]},
        }
        results = validate_rules([_rule(match=match)])
        ga601 = [x for x in results if x.rule_id == "GA601"]
        assert ga601[0].field == "match.config.src_ip_ranges"


# ---------------------------------------------------------------------------
# GA602  Always-false expression
# ---------------------------------------------------------------------------


class TestAlwaysFalse:
    def test_ga602_expression_false(self):
        match = {"expr": {"expression": "false"}}
        assert "GA602" in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_expression_false_uppercase(self):
        match = {"expr": {"expression": "FALSE"}}
        assert "GA602" in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_expression_false_whitespace(self):
        match = {"expr": {"expression": "  false  "}}
        assert "GA602" in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_expression_false_parenthesized(self):
        match = {"expr": {"expression": "((false))"}}
        assert "GA602" in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_normal_expression_not_flagged(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert "GA602" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_true_not_flagged(self):
        match = {"expr": {"expression": "true"}}
        assert "GA602" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_severity_is_warning(self):
        from octorules.linter.engine import Severity

        match = {"expr": {"expression": "false"}}
        results = validate_rules([_rule(match=match)])
        ga602 = [x for x in results if x.rule_id == "GA602"]
        assert ga602[0].severity == Severity.WARNING

    def test_ga602_field_set(self):
        match = {"expr": {"expression": "false"}}
        results = validate_rules([_rule(match=match)])
        ga602 = [x for x in results if x.rule_id == "GA602"]
        assert ga602[0].field == "match.expr.expression"

    def test_ga602_empty_expression_not_flagged(self):
        """Empty expression is GA314, not GA602."""
        match = {"expr": {"expression": ""}}
        assert "GA602" not in _ids(validate_rules([_rule(match=match)]))

    def test_ga602_match_not_dict_no_crash(self):
        assert "GA602" not in _ids(validate_rules([_rule(match="invalid")]))


# ---------------------------------------------------------------------------
# Integration / edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_multiple_errors_same_rule(self):
        r = {"action": "invalid"}
        ids = _ids(validate_rules([r]))
        assert "GA001" in ids
        assert "GA200" in ids
        assert "GA003" in ids

    def test_match_not_dict_no_crash(self):
        results = validate_rules([_rule(match="invalid")])
        assert "GA300" not in _ids(results)

    def test_config_not_dict_no_crash(self):
        match = {"config": "invalid", "versioned_expr": "SRC_IPS_V1"}
        results = validate_rules([_rule(match=match)])
        assert "GA301" not in _ids(results)

    def test_expr_not_dict_no_crash(self):
        match = {"expr": "invalid"}
        results = validate_rules([_rule(match=match)])
        assert "GA302" not in _ids(results)

    def test_match_none_triggers_ga003(self):
        r = _rule()
        r["match"] = None
        assert "GA003" in _ids(validate_rules([r]))

    def test_rate_limit_options_not_dict_no_crash(self):
        r = _rule(action="throttle", rate_limit_options="invalid")
        results = validate_rules([r])
        assert "GA403" not in _ids(results)

    def test_deep_checks_skip_when_match_not_dict(self):
        results = validate_rules([_rule(match="invalid")])
        assert "GA312" not in _ids(results)
        assert "GA313" not in _ids(results)
        assert "GA314" not in _ids(results)
        assert "GA310" not in _ids(results)
        assert "GA311" not in _ids(results)

    def test_deep_checks_skip_when_match_none(self):
        r = _rule()
        r["match"] = None
        results = validate_rules([r])
        assert "GA312" not in _ids(results)

    def test_rate_limit_deep_skip_when_options_not_dict(self):
        r = _rule(action="throttle", rate_limit_options="invalid")
        results = validate_rules([r])
        assert "GA420" not in _ids(results)
        assert "GA421" not in _ids(results)
        assert "GA423" not in _ids(results)

    def test_action_params_skip_when_options_not_dict(self):
        r = _rule(action="throttle", rate_limit_options=42)
        results = validate_rules([r])
        assert "GA429" not in _ids(results)
        assert "GA431" not in _ids(results)

    def test_ga310_no_crash_on_non_string_expression(self):
        """expression not a string should not crash the deep match check."""
        match = {"expr": {"expression": 42}}
        results = validate_rules([_rule(match=match)])
        assert "GA310" not in _ids(results)

    def test_ga314_expression_not_string_no_crash(self):
        match = {"expr": {"expression": None}}
        results = validate_rules([_rule(match=match)])
        assert "GA314" not in _ids(results)
