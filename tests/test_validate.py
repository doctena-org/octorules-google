"""Tests for Google Cloud Armor rule validation."""

import pytest
from octorules.linter.engine import LintResult
from octorules.testing.lint import assert_lint, assert_no_lint

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
# GA020  Unknown top-level rule fields
# ---------------------------------------------------------------------------
class TestUnknownFields:
    def test_ga020_unknown_field(self):
        r = _rule(bogus_field="x")
        assert_lint(validate_rules([r]), "GA020")

    def test_ga020_multiple_unknown_fields(self):
        r = _rule(foo="a", bar="b")
        results = validate_rules([r])
        ga020_results = [r for r in results if r.rule_id == "GA020"]
        fields = {r.field for r in ga020_results}
        assert "foo" in fields
        assert "bar" in fields

    def test_ga020_severity_is_error(self):
        from octorules.linter.engine import Severity

        r = _rule(unknown="x")
        results = validate_rules([r])
        ga020_results = [r for r in results if r.rule_id == "GA020"]
        assert ga020_results[0].severity == Severity.ERROR

    def test_ga020_valid_fields_not_flagged(self):
        r = _rule(
            description="test",
            preview=True,
            header_action={"requestHeadersToAdds": []},
        )
        assert_no_lint(validate_rules([r]), "GA020")

    def test_ga020_kind_not_flagged(self):
        """'kind' is an API field preserved during normalization."""
        r = _rule(kind="compute#securityPolicyRule")
        assert_no_lint(validate_rules([r]), "GA020")

    def test_ga020_rate_limit_options_not_flagged(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_no_lint(validate_rules([r]), "GA020")

    def test_ga020_redirect_options_not_flagged(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "GOOGLE_RECAPTCHA"},
        )
        assert_no_lint(validate_rules([r]), "GA020")

    def test_ga020_network_match_not_flagged(self):
        r = _rule(network_match={"src_ip_ranges": ["10.0.0.0/8"]})
        assert_no_lint(validate_rules([r]), "GA020")

    def test_ga020_preconfigured_waf_config_not_flagged(self):
        r = _rule(preconfigured_waf_config={"waf_rules": []})
        assert_no_lint(validate_rules([r]), "GA020")

    def test_ga020_message_includes_field_name(self):
        r = _rule(typo_field="val")
        results = validate_rules([r])
        ga020 = [r for r in results if r.rule_id == "GA020"]
        assert "typo_field" in ga020[0].message


# ---------------------------------------------------------------------------
# GA001-GA003  Structural checks
# ---------------------------------------------------------------------------
class TestStructural:
    def test_ga001_missing_ref(self):
        r = _rule()
        del r["ref"]
        assert_lint(validate_rules([r]), "GA001")

    def test_ga001_empty_ref(self):
        assert_lint(validate_rules([_rule(ref="")]), "GA001")

    def test_ga002_missing_action(self):
        r = _rule()
        del r["action"]
        assert_lint(validate_rules([r]), "GA002")

    def test_ga002_empty_action(self):
        assert_lint(validate_rules([_rule(action="")]), "GA002")

    def test_ga003_missing_match(self):
        r = _rule()
        del r["match"]
        assert_lint(validate_rules([r]), "GA003")


# ---------------------------------------------------------------------------
# GA100-GA104  Priority & cross-rule checks
# ---------------------------------------------------------------------------
class TestPriority:
    def test_ga100_not_integer_string(self):
        assert_lint(validate_rules([_rule(ref="abc")]), "GA100")

    def test_ga100_negative(self):
        assert_lint(validate_rules([_rule(ref="-1")]), "GA100")

    def test_ga100_float_string(self):
        assert_lint(validate_rules([_rule(ref="1.5")]), "GA100")

    def test_ga100_zero_accepted(self):
        assert_no_lint(validate_rules([_rule(ref="0")]), "GA100")

    def test_ga101_out_of_range(self):
        assert_lint(validate_rules([_rule(ref="2147483647")]), "GA101")

    def test_ga101_max_valid(self):
        assert_no_lint(validate_rules([_rule(ref="2147483646")]), "GA101")

    def test_ga102_duplicate(self):
        a = _rule(ref="100")
        b = _rule(ref="100")
        assert_lint(validate_rules([a, b]), "GA102")

    def test_ga102_no_false_positive(self):
        a = _rule(ref="100")
        b = _rule(ref="200")
        assert_no_lint(validate_rules([a, b]), "GA102")


# ---------------------------------------------------------------------------
# GA005  Duplicate ref within phase
# ---------------------------------------------------------------------------
class TestDuplicateRef:
    def test_ga005_duplicate_ref(self):
        a = _rule(ref="100")
        b = _rule(ref="100")
        ids = _ids(validate_rules([a, b]))
        assert "GA005" in ids

    def test_ga005_no_false_positive(self):
        a = _rule(ref="100")
        b = _rule(ref="200")
        assert_no_lint(validate_rules([a, b]), "GA005")

    def test_ga005_fires_once_for_triple(self):
        """Three identical refs should emit GA005 only once (on second occurrence)."""
        rules = [_rule(ref="100"), _rule(ref="100"), _rule(ref="100")]
        ga005 = [r for r in validate_rules(rules) if r.rule_id == "GA005"]
        assert len(ga005) == 1

    def test_ga005_empty_ref_ignored(self):
        """Rules with missing ref should not trigger GA005."""
        a = _rule()
        del a["ref"]
        b = _rule()
        del b["ref"]
        assert_no_lint(validate_rules([a, b]), "GA005")

    def test_ga005_ref_in_result(self):
        a = _rule(ref="999")
        b = _rule(ref="999")
        results = [r for r in validate_rules([a, b]) if r.rule_id == "GA005"]
        assert results[0].ref == "999"


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
        assert_lint(validate_rules(rules), "GA103")

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
        assert_no_lint(validate_rules(rules), "GA103")

    def test_ga103_whitespace_in_true(self):
        rules = [
            _rule(ref="100", action="allow", match={"expr": {"expression": "  true  "}}),
            _rule(
                ref="200",
                action="deny(403)",
                match={"expr": {"expression": "origin.ip == '1.2.3.4'"}},
            ),
        ]
        assert_lint(validate_rules(rules), "GA103")


class TestDuplicateExpressions:
    def test_ga104_duplicate(self):
        rules = [
            _rule(ref="100", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
            _rule(ref="200", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
        ]
        assert_lint(validate_rules(rules), "GA104")

    def test_ga104_whitespace_normalized(self):
        rules = [
            _rule(ref="100", match={"expr": {"expression": "origin.region_code  ==  'CN'"}}),
            _rule(ref="200", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
        ]
        assert_lint(validate_rules(rules), "GA104")

    def test_ga104_different_expressions(self):
        rules = [
            _rule(ref="100", match={"expr": {"expression": "origin.region_code == 'CN'"}}),
            _rule(ref="200", match={"expr": {"expression": "origin.region_code == 'RU'"}}),
        ]
        assert_no_lint(validate_rules(rules), "GA104")


# ---------------------------------------------------------------------------
# GA200-GA201  Action checks
# ---------------------------------------------------------------------------
class TestActions:
    @pytest.mark.parametrize(
        "action",
        [
            "allow",
            "deny(403)",
            "deny(404)",
            "deny(429)",
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
        assert_no_lint(validate_rules([r]), "GA200")

    def test_ga200_invalid_action(self):
        assert_lint(validate_rules([_rule(action="block")]), "GA200")

    def test_ga200_deny_without_parens(self):
        assert_lint(validate_rules([_rule(action="deny")]), "GA200")

    def test_ga200_bare_deny_targeted_suggestion(self):
        """Bare 'deny' produces GA200 with the targeted status-code suggestion."""
        results = validate_rules([_rule(action="deny")])
        ga200 = [r for r in results if r.rule_id == "GA200"]
        assert len(ga200) == 1
        assert ga200[0].suggestion == "deny requires a status code, e.g. deny(403)"

    def test_ga200_invalid_action_generic_suggestion(self):
        """Non-deny invalid action gets the generic suggestion, not the targeted one."""
        results = validate_rules([_rule(action="block")])
        ga200 = [r for r in results if r.rule_id == "GA200"]
        assert len(ga200) == 1
        assert "deny requires a status code" not in ga200[0].suggestion
        assert "Valid actions:" in ga200[0].suggestion

    def test_ga201_invalid_deny_status(self):
        assert_lint(validate_rules([_rule(action="deny(500)")]), "GA201")

    def test_ga201_valid_deny_no_201(self):
        assert_no_lint(validate_rules([_rule(action="deny(403)")]), "GA201")

    def test_ga201_deny_200(self):
        assert_lint(validate_rules([_rule(action="deny(200)")]), "GA201")

    def test_ga201_deny_429_valid(self):
        """deny(429) is a valid deny status and should not trigger GA201."""
        assert_no_lint(validate_rules([_rule(action="deny(429)")]), "GA201")


# ---------------------------------------------------------------------------
# GA300-GA306  Match checks
# ---------------------------------------------------------------------------
class TestMatch:
    def test_ga300_both_expr_and_config(self):
        match = {
            "expr": {"expression": "true"},
            "config": {"src_ip_ranges": ["1.2.3.0/24"]},
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA300")

    def test_ga300_neither_expr_nor_config(self):
        assert_lint(validate_rules([_rule(match={})]), "GA300")

    def test_ga300_expr_only_ok(self):
        match = {"expr": {"expression": "true"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA300")

    def test_ga300_config_only_ok(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA300")

    def test_ga300_versioned_expr_counts_as_config(self):
        match = {"versioned_expr": "SRC_IPS_V1"}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA300")

    def test_ga301_invalid_cidr(self):
        match = {"config": {"src_ip_ranges": ["not-a-cidr"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA301")

    def test_ga301_valid_cidr(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "2001:4860::/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA301")

    def test_ga301_host_address(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.8/32"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA301")

    def test_ga302_cel_syntax_error(self):
        match = {"expr": {"expression": "((("}}
        assert_lint(validate_rules([_rule(match=match)]), "GA302")

    def test_ga302_cel_valid(self):
        match = {"expr": {"expression": "true"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA302")

    def test_ga302_cel_function_call(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA302")

    def test_ga303_unknown_waf_rule_set(self):
        match = {"expr": {"expression": "evaluatePreconfiguredWaf('unknown-v1-stable')"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA303")

    def test_ga303_known_waf_rule_set(self):
        match = {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA303")

    def test_ga303_known_xss(self):
        match = {"expr": {"expression": "evaluatePreconfiguredExpr('xss-v33-stable')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA303")

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
        assert_lint(results, "GA304")

    def test_ga304_at_limit(self):
        # 2048 chars starting with valid CEL
        expr = "true" + " " * 2044
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA304")

    def test_ga304_under_limit(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA304")


class TestCidrChecks:
    def test_ga305_overlapping(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.0.0/16", "8.8.8.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA305")

    def test_ga305_duplicate(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "8.8.8.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA305")

    def test_ga305_no_overlap(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "1.1.1.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA305")

    def test_ga305_ipv4_ipv6_no_overlap(self):
        match = {
            "config": {"src_ip_ranges": ["8.8.8.0/24", "2001:db8::/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA305")

    def test_ga306_slash_zero_ipv4(self):
        match = {"config": {"src_ip_ranges": ["0.0.0.0/0"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA306")

    def test_ga306_slash_zero_ipv6(self):
        match = {"config": {"src_ip_ranges": ["::/0"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA306")

    def test_ga306_not_slash_zero(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA306")

    def test_ga503_private_rfc1918(self):
        match = {"config": {"src_ip_ranges": ["10.0.0.0/8"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_private_172(self):
        match = {"config": {"src_ip_ranges": ["172.16.0.0/12"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_private_192(self):
        match = {"config": {"src_ip_ranges": ["192.168.1.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_loopback(self):
        match = {"config": {"src_ip_ranges": ["127.0.0.1/32"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_public_not_flagged(self):
        match = {"config": {"src_ip_ranges": ["8.8.8.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_ipv6_ula(self):
        match = {"config": {"src_ip_ranges": ["fd00::/8"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_cgnat(self):
        """CGNAT range (100.64.0.0/10) should be flagged as reserved."""
        match = {"config": {"src_ip_ranges": ["100.64.1.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA503")
        ga503 = [r for r in results if r.rule_id == "GA503"]
        assert "CGNAT" in ga503[0].message

    def test_ga503_documentation_rfc5737(self):
        """RFC 5737 documentation addresses should be flagged."""
        match = {
            "config": {"src_ip_ranges": ["192.0.2.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA503")
        ga503 = [r for r in results if r.rule_id == "GA503"]
        assert "documentation" in ga503[0].message

    def test_ga503_benchmark_testing(self):
        """RFC 2544 benchmark testing addresses should be flagged."""
        match = {
            "config": {"src_ip_ranges": ["198.18.0.0/15"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    def test_ga503_ipv6_documentation(self):
        """IPv6 documentation prefix (2001:db8::/32) should be flagged."""
        match = {
            "config": {"src_ip_ranges": ["2001:db8::/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA503")
        ga503 = [r for r in results if r.rule_id == "GA503"]
        assert "documentation" in ga503[0].message

    def test_ga503_multicast(self):
        """Multicast range (224.0.0.0/4) should be flagged."""
        match = {
            "config": {"src_ip_ranges": ["224.0.0.0/4"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA503")

    # --- GA307: CIDR host bits normalization warning ---

    def test_ga307_host_bits_set(self):
        """CIDR with host bits set emits GA307 warning about normalization."""
        match = {
            "config": {"src_ip_ranges": ["10.0.0.1/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        ids = _ids(results)
        assert "GA307" in ids
        assert "GA301" not in ids
        ga307 = [r for r in results if r.rule_id == "GA307"]
        assert "10.0.0.0/24" in ga307[0].message

    def test_ga307_no_host_bits(self):
        """CIDR without host bits set does not emit GA307."""
        match = {
            "config": {"src_ip_ranges": ["10.0.0.0/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA307")

    def test_ga307_host_address_no_warning(self):
        """/32 host address is exact — no normalization needed."""
        match = {
            "config": {"src_ip_ranges": ["10.0.0.1/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA307")

    def test_ga307_ipv6_host_bits(self):
        """IPv6 CIDR with host bits set emits GA307."""
        match = {
            "config": {"src_ip_ranges": ["2001:db8::1/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        ids = _ids(results)
        assert "GA307" in ids
        assert "GA301" not in ids

    def test_ga307_invalid_cidr_still_ga301(self):
        """Completely invalid CIDR still produces GA301, not GA307."""
        match = {
            "config": {"src_ip_ranges": ["not-a-cidr"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        ids = _ids(validate_rules([_rule(match=match)]))
        assert "GA301" in ids
        assert "GA307" not in ids

    def test_ga307_suggestion_contains_normalized(self):
        """GA307 suggestion includes the normalized CIDR."""
        match = {
            "config": {"src_ip_ranges": ["192.168.1.5/24"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        ga307 = [r for r in results if r.rule_id == "GA307"]
        assert len(ga307) == 1
        assert "192.168.1.0/24" in ga307[0].suggestion

    # --- GA305: extra coverage for sweep-line implementation ---

    def test_ga305_ipv6_overlap(self):
        """GA305: IPv6 containment is detected the same as IPv4."""
        match = {
            "config": {"src_ip_ranges": ["2001:db8::/32", "2001:db8:1234::/48"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA305")

    def test_ga305_adjacent_not_overlapping(self):
        """GA305: adjacent /9s (10.0.0.0/9 and 10.128.0.0/9) do not overlap."""
        match = {
            "config": {"src_ip_ranges": ["10.0.0.0/9", "10.128.0.0/9"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA305")

    def test_ga305_catch_all_v4_excluded(self):
        """GA305 skips 0.0.0.0/0 — that is GA306's job, not an overlap finding."""
        match = {
            "config": {"src_ip_ranges": ["0.0.0.0/0", "10.0.0.0/8"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA305")
        assert_lint(results, "GA306")

    def test_ga305_catch_all_v6_excluded(self):
        """GA305 skips ::/0 — that is GA306's job, not an overlap finding."""
        match = {
            "config": {"src_ip_ranges": ["::/0", "2001:db8::/32"]},
            "versioned_expr": "SRC_IPS_V1",
        }
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA305")
        assert_lint(results, "GA306")

    def test_ga305_sweep_line_fast_on_large_input(self):
        """GA305 must be O(n log n): 1000 disjoint /32s lint in well under a second.

        Locks in the sweep-line rewrite. The previous O(n²) pairwise check
        scaled badly on real-world IP lists.
        """
        import time

        cidrs = [f"10.{i // 256}.{i % 256}.0/32" for i in range(1000)]
        match = {
            "config": {"src_ip_ranges": cidrs},
            "versioned_expr": "SRC_IPS_V1",
        }
        start = time.perf_counter()
        results = validate_rules([_rule(match=match)])
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"GA305 sweep-line too slow: {elapsed:.3f}s for 1000 entries"
        assert_no_lint(results, "GA305")


# ---------------------------------------------------------------------------
# GA400-GA407  Rate limit options
# ---------------------------------------------------------------------------
class TestRateLimitOptions:
    def test_ga400_throttle_missing_rate_limit(self):
        assert_lint(validate_rules([_rule(action="throttle")]), "GA400")

    def test_ga400_rate_based_ban_missing_rate_limit(self):
        assert_lint(validate_rules([_rule(action="rate_based_ban")]), "GA400")

    def test_ga400_throttle_with_rate_limit(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_no_lint(validate_rules([r]), "GA400")

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
        assert_lint(validate_rules([r]), "GA405")

    def test_ga405_conform_action_allow_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_no_lint(validate_rules([r]), "GA405")

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
        assert_no_lint(validate_rules([r]), "GA406")

    def test_ga406_invalid_exceed_action(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "block",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_lint(validate_rules([r]), "GA406")

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
        assert_no_lint(validate_rules([r]), "GA407")

    def test_ga407_invalid_interval(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 45},
            },
        )
        assert_lint(validate_rules([r]), "GA407")

    def test_ga408_removed_count_validated_by_ga421_only(self):
        """Count range/type is now checked by GA421, not GA408.

        GA408 was removed to avoid duplicate diagnostics. Verify that
        count issues produce GA421 instead.
        """
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 0, "interval_sec": 60},
            },
        )
        results = validate_rules([r])
        assert_no_lint(results, "GA408")
        assert_lint(results, "GA421")


# ---------------------------------------------------------------------------
# GA401-GA404  Redirect options
# ---------------------------------------------------------------------------
class TestRedirectOptions:
    def test_ga401_redirect_missing_options(self):
        assert_lint(validate_rules([_rule(action="redirect")]), "GA401")

    def test_ga401_redirect_with_options(self):
        r = _rule(action="redirect", redirect_options={"type": "GOOGLE_RECAPTCHA"})
        assert_no_lint(validate_rules([r]), "GA401")

    def test_ga402_invalid_redirect_type(self):
        r = _rule(action="redirect", redirect_options={"type": "INVALID"})
        assert_lint(validate_rules([r]), "GA402")

    @pytest.mark.parametrize("rtype", ["GOOGLE_RECAPTCHA", "EXTERNAL_302"])
    def test_ga402_valid_redirect_types(self, rtype):
        r = _rule(action="redirect", redirect_options={"type": rtype, "target": "https://x.com"})
        assert_no_lint(validate_rules([r]), "GA402")

    def test_ga402_no_type_key_no_error(self):
        r = _rule(action="redirect", redirect_options={})
        assert_no_lint(validate_rules([r]), "GA402")

    def test_ga404_external_302_missing_target(self):
        r = _rule(action="redirect", redirect_options={"type": "EXTERNAL_302"})
        assert_lint(validate_rules([r]), "GA404")

    def test_ga404_external_302_with_target(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "https://example.com"},
        )
        assert_no_lint(validate_rules([r]), "GA404")

    def test_ga404_recaptcha_no_target_ok(self):
        r = _rule(action="redirect", redirect_options={"type": "GOOGLE_RECAPTCHA"})
        assert_no_lint(validate_rules([r]), "GA404")


# ---------------------------------------------------------------------------
# GA500  Description length
# ---------------------------------------------------------------------------
class TestDescription:
    def test_ga500_too_long(self):
        r = _rule(description="x" * 1025)
        assert_lint(validate_rules([r]), "GA500")

    def test_ga500_at_limit(self):
        r = _rule(description="x" * 1024)
        assert_no_lint(validate_rules([r]), "GA500")

    def test_ga500_no_description(self):
        assert_no_lint(validate_rules([_rule()]), "GA500")


# ---------------------------------------------------------------------------
# GA310-GA314  Expression / match deep validation
# ---------------------------------------------------------------------------
class TestMatchDeep:
    # --- GA310: Unknown field reference ---

    def test_ga310_unknown_field(self):
        match = {"expr": {"expression": "bogus.field == 'x'"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_origin_ip(self):
        match = {"expr": {"expression": "origin.ip == '1.2.3.4'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_headers(self):
        match = {"expr": {"expression": "request.headers['X-Foo'] == 'bar'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_method(self):
        match = {"expr": {"expression": "request.method == 'GET'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_path(self):
        match = {"expr": {"expression": "request.path.startsWith('/api')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_scheme(self):
        match = {"expr": {"expression": "request.scheme == 'https'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_query(self):
        match = {"expr": {"expression": "request.query.contains('foo')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_url(self):
        match = {"expr": {"expression": "request.url.contains('/api')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_origin_region_code(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_origin_asn(self):
        match = {"expr": {"expression": "origin.asn == 15169"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_origin_user_ip(self):
        match = {"expr": {"expression": "origin.user_ip == '1.2.3.4'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_origin_tls_ja3(self):
        match = {"expr": {"expression": "origin.tls_ja3_fingerprint == 'abc'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_origin_tls_ja4(self):
        match = {"expr": {"expression": "origin.tls_ja4_fingerprint == 'abc'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_token_recaptcha_action(self):
        match = {"expr": {"expression": "token.recaptcha_action.score > 0.5"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_token_recaptcha_session(self):
        match = {"expr": {"expression": "token.recaptcha_session.score > 0.5"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_token_recaptcha_exemption(self):
        match = {"expr": {"expression": "token.recaptcha_exemption.valid == true"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_known_request_host(self):
        match = {"expr": {"expression": "request.host == 'example.com'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

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
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    # --- GA311: Unknown function ---

    def test_ga311_unknown_function(self):
        match = {"expr": {"expression": "unknownFunc(origin.ip)"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_contains(self):
        match = {"expr": {"expression": "request.path.contains('/api')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_startsWith(self):
        match = {"expr": {"expression": "request.path.startsWith('/api')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_endsWith(self):
        match = {"expr": {"expression": "request.path.endsWith('.html')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_matches(self):
        match = {"expr": {"expression": "request.path.matches('.*api.*')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_lower(self):
        match = {"expr": {"expression": "request.method.lower() == 'get'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_upper(self):
        match = {"expr": {"expression": "request.method.upper() == 'GET'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_base64Decode(self):
        match = {"expr": {"expression": "request.headers['auth'].base64Decode() == 'x'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_inIpRange(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '1.0.0.0/8')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_size(self):
        match = {"expr": {"expression": "size(request.query) > 100"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_int(self):
        match = {"expr": {"expression": "int(request.headers['x']) > 100"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluatePreconfiguredWaf(self):
        match = {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluatePreconfiguredExpr(self):
        match = {"expr": {"expression": "evaluatePreconfiguredExpr('xss-v33-stable')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_has(self):
        match = {"expr": {"expression": "has(request.headers['X-Custom'])"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluateThreatIntelligence(self):
        match = {"expr": {"expression": "evaluateThreatIntelligence('iplist-known-malicious-ips')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluateThreatIntelligenceWithExcl(self):
        expr = "evaluateThreatIntelligenceWithExcl('iplist-known-malicious-ips', ['1.2.3.0/24'])"
        match = {"expr": {"expression": expr}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluateJsonPath(self):
        match = {"expr": {"expression": "evaluateJsonPath(request.body, '$.user')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluateAdaptiveProtection(self):
        match = {"expr": {"expression": "evaluateAdaptiveProtection()"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_evaluateAdaptiveProtectionAutoDeploy(self):
        match = {"expr": {"expression": "evaluateAdaptiveProtectionAutoDeploy()"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_urlDecode(self):
        match = {"expr": {"expression": "request.path.urlDecode().contains('/admin')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_known_htmlDecode(self):
        match = {"expr": {"expression": "request.body.htmlDecode().contains('<script')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    def test_ga311_deduped(self):
        match = {"expr": {"expression": "badFunc(1) || badFunc(2)"}}
        results = validate_rules([_rule(match=match)])
        ga311 = [r for r in results if r.rule_id == "GA311"]
        assert len(ga311) == 1

    # --- GA310/GA311: false positive prevention (string literal stripping) ---

    def test_ga310_no_false_positive_in_string_literal(self):
        """Field-like text inside quoted strings should not trigger GA310."""
        match = {"expr": {"expression": "request.path.contains('origin.ip')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_no_false_positive_in_header_subscript(self):
        """Header key subscripts should not be extracted as field references."""
        match = {"expr": {"expression": 'request.headers["origin.ip.test"]'}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga310_real_field_outside_string_still_caught(self):
        """Unknown field outside a string is still flagged even if strings are present."""
        match = {"expr": {"expression": "unknown.field == 'origin.ip'"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA310")

    def test_ga311_no_false_positive_in_string_literal(self):
        """Function-like text inside quoted strings should not trigger GA311."""
        match = {"expr": {"expression": "request.path.contains('badFunc()')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA311")

    # --- GA312: Invalid versioned_expr ---

    def test_ga312_invalid_versioned_expr(self):
        match = {"versioned_expr": "BOGUS", "config": {"src_ip_ranges": ["1.2.3.0/24"]}}
        assert_lint(validate_rules([_rule(match=match)]), "GA312")

    def test_ga312_valid_src_ips_v1(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": {"src_ip_ranges": ["1.2.3.0/24"]}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA312")

    # --- GA313: Missing config with versioned_expr ---

    def test_ga313_versioned_expr_no_config(self):
        match = {"versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA313")

    def test_ga313_versioned_expr_config_no_ranges(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": {}}
        assert_lint(validate_rules([_rule(match=match)]), "GA313")

    def test_ga313_versioned_expr_config_not_dict(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": "invalid"}
        assert_lint(validate_rules([_rule(match=match)]), "GA313")

    def test_ga313_versioned_expr_with_ranges_ok(self):
        match = {"versioned_expr": "SRC_IPS_V1", "config": {"src_ip_ranges": ["1.2.3.0/24"]}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA313")

    # --- GA314: Empty match conditions ---

    def test_ga314_empty_expression(self):
        match = {"expr": {"expression": ""}}
        assert_lint(validate_rules([_rule(match=match)]), "GA314")

    def test_ga314_whitespace_only_expression(self):
        match = {"expr": {"expression": "   "}}
        assert_lint(validate_rules([_rule(match=match)]), "GA314")

    def test_ga314_tab_only_expression(self):
        match = {"expr": {"expression": "\t\n"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA314")

    def test_ga314_empty_src_ip_ranges(self):
        match = {"config": {"src_ip_ranges": []}, "versioned_expr": "SRC_IPS_V1"}
        assert_lint(validate_rules([_rule(match=match)]), "GA314")

    def test_ga314_nonempty_expression_ok(self):
        match = {"expr": {"expression": "true"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA314")

    def test_ga314_nonempty_ranges_ok(self):
        match = {"config": {"src_ip_ranges": ["1.2.3.0/24"]}, "versioned_expr": "SRC_IPS_V1"}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA314")


# ---------------------------------------------------------------------------
# GA420-GA426  Rate limit deep validation
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
        assert_lint(validate_rules([r]), "GA420")

    def test_ga420_threshold_missing_count(self):
        r = self._rl_rule(rate_limit_threshold={"interval_sec": 60})
        assert_lint(validate_rules([r]), "GA420")

    def test_ga420_threshold_missing_interval_sec(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100})
        assert_lint(validate_rules([r]), "GA420")

    def test_ga420_threshold_missing_both(self):
        r = self._rl_rule(rate_limit_threshold={})
        results = validate_rules([r])
        ga420 = [x for x in results if x.rule_id == "GA420"]
        assert len(ga420) == 2

    def test_ga420_threshold_complete_ok(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": 60})
        assert_no_lint(validate_rules([r]), "GA420")

    # --- GA421: Invalid types ---

    def test_ga421_count_is_string(self):
        r = self._rl_rule(rate_limit_threshold={"count": "100", "interval_sec": 60})
        assert_lint(validate_rules([r]), "GA421")

    def test_ga421_count_is_bool(self):
        r = self._rl_rule(rate_limit_threshold={"count": True, "interval_sec": 60})
        assert_lint(validate_rules([r]), "GA421")

    def test_ga421_interval_is_string(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": "60"})
        assert_lint(validate_rules([r]), "GA421")

    def test_ga421_interval_is_bool(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": False})
        assert_lint(validate_rules([r]), "GA421")

    def test_ga421_both_valid_ints_ok(self):
        r = self._rl_rule(rate_limit_threshold={"count": 100, "interval_sec": 60})
        assert_no_lint(validate_rules([r]), "GA421")

    # --- GA422: enforce_on_key for rate_based_ban with redirect ---

    def test_ga422_rate_based_ban_redirect_no_key(self):
        r = self._ban_rule(exceed_action="redirect")
        assert_lint(validate_rules([r]), "GA422")

    def test_ga422_rate_based_ban_redirect_with_key(self):
        r = self._ban_rule(exceed_action="redirect", enforce_on_key="IP")
        assert_no_lint(validate_rules([r]), "GA422")

    def test_ga422_throttle_redirect_no_key_no_warning(self):
        r = self._rl_rule(exceed_action="redirect")
        assert_no_lint(validate_rules([r]), "GA422")

    def test_ga422_rate_based_ban_deny_no_key_no_warning(self):
        r = self._ban_rule(exceed_action="deny-429")
        assert_no_lint(validate_rules([r]), "GA422")

    # --- GA423: Invalid enforce_on_key ---

    @pytest.mark.parametrize(
        "key",
        [
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
        ],
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
        assert_no_lint(validate_rules([r]), "GA423")

    def test_ga423_invalid_key(self):
        r = self._rl_rule(enforce_on_key="INVALID")
        assert_lint(validate_rules([r]), "GA423")

    # --- GA424: enforce_on_key_name required ---

    def test_ga424_http_header_no_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER")
        assert_lint(validate_rules([r]), "GA424")

    def test_ga424_http_cookie_no_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE")
        assert_lint(validate_rules([r]), "GA424")

    def test_ga424_http_header_with_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X-Custom")
        assert_no_lint(validate_rules([r]), "GA424")

    def test_ga424_http_cookie_with_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE", enforce_on_key_name="session")
        assert_no_lint(validate_rules([r]), "GA424")

    def test_ga424_ip_no_name_ok(self):
        r = self._rl_rule(enforce_on_key="IP")
        assert_no_lint(validate_rules([r]), "GA424")

    # --- GA425: ban_duration_sec required for rate_based_ban ---

    def test_ga425_rate_based_ban_no_ban_duration(self):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
        }
        r = _rule(action="rate_based_ban", rate_limit_options=rlo)
        assert_lint(validate_rules([r]), "GA425")

    def test_ga425_rate_based_ban_with_ban_duration(self):
        r = self._ban_rule(ban_duration_sec=120)
        assert_no_lint(validate_rules([r]), "GA425")

    def test_ga425_throttle_no_ban_duration_ok(self):
        r = self._rl_rule()
        assert_no_lint(validate_rules([r]), "GA425")

    # --- GA426: Invalid ban_duration_sec ---

    def test_ga426_zero(self):
        r = self._ban_rule(ban_duration_sec=0)
        assert_lint(validate_rules([r]), "GA426")

    def test_ga426_negative(self):
        r = self._ban_rule(ban_duration_sec=-10)
        assert_lint(validate_rules([r]), "GA426")

    def test_ga426_bool(self):
        r = self._ban_rule(ban_duration_sec=True)
        assert_lint(validate_rules([r]), "GA426")

    def test_ga426_string(self):
        r = self._ban_rule(ban_duration_sec="120")
        assert_lint(validate_rules([r]), "GA426")

    def test_ga426_positive_int_ok(self):
        r = self._ban_rule(ban_duration_sec=120)
        assert_no_lint(validate_rules([r]), "GA426")

    # --- GA427: ban_duration_sec exceeds maximum ---

    def test_ga427_exceeds_max(self):
        r = self._ban_rule(ban_duration_sec=3601)
        assert_lint(validate_rules([r]), "GA427")

    def test_ga427_at_max(self):
        r = self._ban_rule(ban_duration_sec=3600)
        assert_no_lint(validate_rules([r]), "GA427")

    def test_ga427_well_under_max(self):
        r = self._ban_rule(ban_duration_sec=120)
        assert_no_lint(validate_rules([r]), "GA427")

    def test_ga427_way_over_max(self):
        r = self._ban_rule(ban_duration_sec=86400)
        assert_lint(validate_rules([r]), "GA427")

    # --- GA430: ban_duration_sec very short ---

    def test_ga430_very_short(self):
        r = self._ban_rule(ban_duration_sec=10)
        assert_lint(validate_rules([r]), "GA430")

    def test_ga430_boundary_59(self):
        """59 seconds is below the 60s threshold — should trigger."""
        r = self._ban_rule(ban_duration_sec=59)
        assert_lint(validate_rules([r]), "GA430")

    def test_ga430_at_60_ok(self):
        r = self._ban_rule(ban_duration_sec=60)
        assert_no_lint(validate_rules([r]), "GA430")

    def test_ga427_not_triggered_for_invalid_type(self):
        """GA426 fires for non-int, GA427 should not also fire."""
        r = self._ban_rule(ban_duration_sec="9999")
        assert_lint(validate_rules([r]), "GA426")
        assert_no_lint(validate_rules([r]), "GA427")

    def test_ga427_not_triggered_for_negative(self):
        """GA426 fires for <= 0, GA427 should not also fire."""
        r = self._ban_rule(ban_duration_sec=-1)
        assert_lint(validate_rules([r]), "GA426")
        assert_no_lint(validate_rules([r]), "GA427")

    # --- GA428: enforce_on_key_name content validation ---

    def test_ga428_empty_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="")
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_too_long(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X" * 129)
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_at_max_length(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X" * 128)
        assert_no_lint(validate_rules([r]), "GA428")

    def test_ga428_control_chars(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X-Bad\x00")
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_tab_control_char(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X-Bad\t")
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_spaces(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X Bad Header")
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_invalid_header_chars(self):
        """RFC 7230: header names must be tchar only. Parentheses are not allowed."""
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X-Bad(Header)")
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_valid_header_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_HEADER", enforce_on_key_name="X-Custom-Header")
        assert_no_lint(validate_rules([r]), "GA428")

    def test_ga428_valid_cookie_name(self):
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE", enforce_on_key_name="session_id")
        assert_no_lint(validate_rules([r]), "GA428")

    def test_ga428_cookie_spaces_flagged(self):
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE", enforce_on_key_name="bad cookie")
        assert_lint(validate_rules([r]), "GA428")

    def test_ga428_cookie_no_rfc7230_check(self):
        """RFC 7230 header-name check only applies to HTTP_HEADER, not HTTP_COOKIE."""
        r = self._rl_rule(enforce_on_key="HTTP_COOKIE", enforce_on_key_name="session(id)")
        assert_no_lint(validate_rules([r]), "GA428")

    def test_ga428_ip_key_not_checked(self):
        """GA428 only applies to HTTP_HEADER/HTTP_COOKIE, not other key types."""
        r = self._rl_rule(enforce_on_key="IP", enforce_on_key_name="anything")
        assert_no_lint(validate_rules([r]), "GA428")


# ---------------------------------------------------------------------------
# GA429, GA431, GA432  Action parameter validation
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
        assert_lint(validate_rules([r]), "GA429")

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
        assert_no_lint(validate_rules([r]), "GA429")

    def test_ga429_throttle_without_ban_duration_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_no_lint(validate_rules([r]), "GA429")

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
        assert_lint(validate_rules([r]), "GA431")

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
        assert_no_lint(validate_rules([r]), "GA431")

    def test_ga431_deny_exceed_no_redirect_options_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_no_lint(validate_rules([r]), "GA431")

    # --- GA432: Conflicting rate-limit options ---

    def test_ga432_exceed_redirect_options_without_redirect_action(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "https://x.com"},
            },
        )
        assert_lint(validate_rules([r]), "GA432")

    def test_ga432_exceed_redirect_options_with_redirect_action_ok(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "https://x.com"},
            },
        )
        assert_no_lint(validate_rules([r]), "GA432")

    def test_ga432_ban_threshold_without_rate_limit_threshold(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "ban_threshold": {"count": 5, "interval_sec": 60},
                "ban_duration_sec": 120,
            },
        )
        assert_lint(validate_rules([r]), "GA432")

    def test_ga432_ban_threshold_with_rate_limit_threshold_ok(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_threshold": {"count": 5, "interval_sec": 60},
                "ban_duration_sec": 120,
            },
        )
        assert_no_lint(validate_rules([r]), "GA432")

    def test_ga432_no_exceed_redirect_options_no_error(self):
        """Absence of exceed_redirect_options should not trigger GA432."""
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            },
        )
        assert_no_lint(validate_rules([r]), "GA432")


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
        assert_no_lint(validate_rules([r1, r2]), "GA105")

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
        assert_lint(validate_rules([r1, r2]), "GA105")

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
        assert_no_lint(validate_rules([r1]), "GA105")

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
        assert_no_lint(validate_rules([r1, r2]), "GA105")

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
        assert_lint(validate_rules([r1, r2]), "GA108")

    def test_ga108_different_waf_rulesets_ok(self):
        r1 = _rule(
            ref="100",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}},
        )
        r2 = _rule(
            ref="200",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('xss-v33-stable')"}},
        )
        assert_no_lint(validate_rules([r1, r2]), "GA108")

    def test_ga108_single_rule_no_warning(self):
        r1 = _rule(
            ref="100",
            match={"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}},
        )
        assert_no_lint(validate_rules([r1]), "GA108")

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
        assert_lint(validate_rules([r1, r2]), "GA108")


# ---------------------------------------------------------------------------
# GA600  Preview mode
# ---------------------------------------------------------------------------
class TestPreview:
    def test_ga600_preview_true(self):
        r = _rule(preview=True)
        assert_lint(validate_rules([r]), "GA600")

    def test_ga600_preview_false(self):
        r = _rule(preview=False)
        assert_no_lint(validate_rules([r]), "GA600")

    def test_ga600_no_preview_key(self):
        assert_no_lint(validate_rules([_rule()]), "GA600")

    def test_ga600_preview_none(self):
        r = _rule(preview=None)
        assert_no_lint(validate_rules([r]), "GA600")

    def test_ga600_preview_truthy_string_not_flagged(self):
        """Only boolean True triggers GA600, not truthy strings."""
        r = _rule(preview="yes")
        assert_no_lint(validate_rules([r]), "GA600")

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
        assert_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_expression_true_uppercase(self):
        match = {"expr": {"expression": "TRUE"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_expression_true_whitespace(self):
        match = {"expr": {"expression": "  true  "}}
        assert_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_expression_true_parenthesized(self):
        match = {"expr": {"expression": "((true))"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_normal_expression_not_flagged(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_src_ip_ranges_wildcard(self):
        match = {
            "versioned_expr": "SRC_IPS_V1",
            "config": {"src_ip_ranges": ["*"]},
        }
        assert_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_src_ip_ranges_non_wildcard(self):
        match = {
            "versioned_expr": "SRC_IPS_V1",
            "config": {"src_ip_ranges": ["8.8.8.0/24"]},
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA601")

    def test_ga601_src_ip_ranges_wildcard_wrong_versioned_expr(self):
        """Only SRC_IPS_V1 with ['*'] triggers GA601."""
        match = {
            "versioned_expr": "BOGUS",
            "config": {"src_ip_ranges": ["*"]},
        }
        assert_no_lint(validate_rules([_rule(match=match)]), "GA601")

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
        assert_lint(validate_rules([_rule(match=match)]), "GA602")

    def test_ga602_expression_false_uppercase(self):
        match = {"expr": {"expression": "FALSE"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA602")

    def test_ga602_expression_false_whitespace(self):
        match = {"expr": {"expression": "  false  "}}
        assert_lint(validate_rules([_rule(match=match)]), "GA602")

    def test_ga602_expression_false_parenthesized(self):
        match = {"expr": {"expression": "((false))"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA602")

    def test_ga602_normal_expression_not_flagged(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA602")

    def test_ga602_true_not_flagged(self):
        match = {"expr": {"expression": "true"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA602")

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
        assert_no_lint(validate_rules([_rule(match=match)]), "GA602")

    def test_ga602_match_not_dict_no_crash(self):
        assert_no_lint(validate_rules([_rule(match="invalid")]), "GA602")


# ---------------------------------------------------------------------------
# GA603  Rule is disabled (enabled: false)
# ---------------------------------------------------------------------------
class TestDisabled:
    def test_ga603_enabled_false(self):
        r = _rule(enabled=False)
        assert_lint(validate_rules([r]), "GA603")

    def test_ga603_enabled_true(self):
        r = _rule(enabled=True)
        assert_no_lint(validate_rules([r]), "GA603")

    def test_ga603_no_enabled_key(self):
        assert_no_lint(validate_rules([_rule()]), "GA603")

    def test_ga603_enabled_none(self):
        r = _rule(enabled=None)
        assert_no_lint(validate_rules([r]), "GA603")

    def test_ga603_enabled_zero_not_flagged(self):
        """Only boolean False triggers GA603, not falsy values like 0."""
        r = _rule(enabled=0)
        assert_no_lint(validate_rules([r]), "GA603")

    def test_ga603_severity_is_info(self):
        from octorules.linter.engine import Severity

        r = _rule(enabled=False)
        results = validate_rules([r])
        ga603 = [x for x in results if x.rule_id == "GA603"]
        assert ga603[0].severity == Severity.INFO

    def test_ga603_field_set(self):
        r = _rule(enabled=False)
        results = validate_rules([r])
        ga603 = [x for x in results if x.rule_id == "GA603"]
        assert ga603[0].field == "enabled"


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
        assert_no_lint(results, "GA300")

    def test_config_not_dict_no_crash(self):
        match = {"config": "invalid", "versioned_expr": "SRC_IPS_V1"}
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA301")

    def test_expr_not_dict_no_crash(self):
        match = {"expr": "invalid"}
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA302")

    def test_match_none_triggers_ga003(self):
        r = _rule()
        r["match"] = None
        assert_lint(validate_rules([r]), "GA003")

    def test_rate_limit_options_not_dict_no_crash(self):
        r = _rule(action="throttle", rate_limit_options="invalid")
        results = validate_rules([r])
        assert_no_lint(results, "GA403")

    def test_deep_checks_skip_when_match_not_dict(self):
        results = validate_rules([_rule(match="invalid")])
        assert_no_lint(results, "GA312")
        assert_no_lint(results, "GA313")
        assert_no_lint(results, "GA314")
        assert_no_lint(results, "GA310")
        assert_no_lint(results, "GA311")

    def test_deep_checks_skip_when_match_none(self):
        r = _rule()
        r["match"] = None
        results = validate_rules([r])
        assert_no_lint(results, "GA312")

    def test_rate_limit_deep_skip_when_options_not_dict(self):
        r = _rule(action="throttle", rate_limit_options="invalid")
        results = validate_rules([r])
        assert_no_lint(results, "GA420")
        assert_no_lint(results, "GA421")
        assert_no_lint(results, "GA423")

    def test_action_params_skip_when_options_not_dict(self):
        r = _rule(action="throttle", rate_limit_options=42)
        results = validate_rules([r])
        assert_no_lint(results, "GA429")
        assert_no_lint(results, "GA431")
        assert_no_lint(results, "GA432")

    def test_ga310_no_crash_on_non_string_expression(self):
        """expression not a string should not crash the deep match check."""
        match = {"expr": {"expression": 42}}
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA310")

    def test_ga314_expression_not_string_no_crash(self):
        match = {"expr": {"expression": None}}
        results = validate_rules([_rule(match=match)])
        assert_no_lint(results, "GA314")


# ---------------------------------------------------------------------------
# GA409  Redirect target must be valid URL for EXTERNAL_302
# ---------------------------------------------------------------------------
class TestGA409:
    def test_ga409_external_302_invalid_url(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "/relative/path"},
        )
        assert_lint(validate_rules([r]), "GA409")

    def test_ga409_external_302_ftp_url(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "ftp://example.com"},
        )
        assert_lint(validate_rules([r]), "GA409")

    def test_ga409_external_302_https_ok(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "https://example.com"},
        )
        assert_no_lint(validate_rules([r]), "GA409")

    def test_ga409_external_302_http_ok(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "http://example.com"},
        )
        assert_no_lint(validate_rules([r]), "GA409")

    def test_ga409_recaptcha_no_target_check(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "GOOGLE_RECAPTCHA"},
        )
        assert_no_lint(validate_rules([r]), "GA409")


# ---------------------------------------------------------------------------
# GA433  Redirect URL length
# ---------------------------------------------------------------------------
class TestGA433:
    def test_ga433_url_too_long(self):
        long_url = "https://example.com/" + "a" * 1010
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": long_url},
        )
        assert_lint(validate_rules([r]), "GA433")

    def test_ga433_url_at_limit(self):
        url = "https://example.com/" + "a" * 1004  # exactly 1024
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": url},
        )
        assert_no_lint(validate_rules([r]), "GA433")

    def test_ga433_short_url_ok(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "https://example.com/short"},
        )
        assert_no_lint(validate_rules([r]), "GA433")


# ---------------------------------------------------------------------------
# GA410  ban_threshold structure validation
# ---------------------------------------------------------------------------
class TestGA410:
    def _ban_rule_with_bt(self, **bt_overrides):
        bt = {"count": 5, "interval_sec": 60}
        bt.update(bt_overrides)
        return _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_threshold": bt,
                "ban_duration_sec": 120,
            },
        )

    def test_ga410_valid_ban_threshold(self):
        r = self._ban_rule_with_bt(count=5, interval_sec=60)
        assert_no_lint(validate_rules([r]), "GA410")

    def test_ga410_not_dict(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_threshold": "invalid",
                "ban_duration_sec": 120,
            },
        )
        assert_lint(validate_rules([r]), "GA410")

    def test_ga410_missing_count(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_threshold": {"interval_sec": 60},
                "ban_duration_sec": 120,
            },
        )
        results = validate_rules([r])
        ga410 = [x for x in results if x.rule_id == "GA410"]
        assert any("count" in x.message for x in ga410)

    def test_ga410_count_zero(self):
        r = self._ban_rule_with_bt(count=0)
        assert_lint(validate_rules([r]), "GA410")

    def test_ga410_count_negative(self):
        r = self._ban_rule_with_bt(count=-1)
        assert_lint(validate_rules([r]), "GA410")

    def test_ga410_count_bool(self):
        r = self._ban_rule_with_bt(count=True)
        assert_lint(validate_rules([r]), "GA410")

    def test_ga410_invalid_interval(self):
        r = self._ban_rule_with_bt(interval_sec=45)
        assert_lint(validate_rules([r]), "GA410")

    def test_ga410_missing_interval(self):
        r = _rule(
            action="rate_based_ban",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "deny-429",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "ban_threshold": {"count": 5},
                "ban_duration_sec": 120,
            },
        )
        results = validate_rules([r])
        ga410 = [x for x in results if x.rule_id == "GA410"]
        assert any("interval_sec" in x.message for x in ga410)


# ---------------------------------------------------------------------------
# GA411  exceed_redirect_options.type validation
# ---------------------------------------------------------------------------
class TestGA411:
    def test_ga411_invalid_type(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "INVALID", "target": "https://x.com"},
            },
        )
        assert_lint(validate_rules([r]), "GA411")

    def test_ga411_valid_external_302(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "https://x.com"},
            },
        )
        assert_no_lint(validate_rules([r]), "GA411")

    def test_ga411_valid_recaptcha(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "GOOGLE_RECAPTCHA"},
            },
        )
        assert_no_lint(validate_rules([r]), "GA411")


# ---------------------------------------------------------------------------
# GA412  exceed_redirect_options.target URL validation for EXTERNAL_302
# ---------------------------------------------------------------------------
class TestGA412:
    def test_ga412_invalid_url(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "/relative"},
            },
        )
        assert_lint(validate_rules([r]), "GA412")

    def test_ga412_valid_url(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "https://x.com"},
            },
        )
        assert_no_lint(validate_rules([r]), "GA412")

    def test_ga412_recaptcha_no_url_check(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "GOOGLE_RECAPTCHA"},
            },
        )
        assert_no_lint(validate_rules([r]), "GA412")


# ---------------------------------------------------------------------------
# GA413  Invalid regex pattern in CEL matches()
# ---------------------------------------------------------------------------
class TestGA413:
    def test_ga413_invalid_regex(self):
        match = {"expr": {"expression": "request.path.matches('[invalid')"}}
        assert_lint(validate_rules([_rule(match=match)]), "GA413")

    def test_ga413_valid_regex(self):
        match = {"expr": {"expression": "request.path.matches('.*api.*')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA413")

    def test_ga413_multiple_matches_one_bad(self):
        expr = "request.path.matches('.*api.*') && request.query.matches('[bad')"
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        ga413 = [r for r in results if r.rule_id == "GA413"]
        assert len(ga413) == 1

    def test_ga413_no_matches_call(self):
        match = {"expr": {"expression": "origin.ip == '1.2.3.4'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA413")


# ---------------------------------------------------------------------------
# GA414  enforce_on_key_configs structure validation
# ---------------------------------------------------------------------------
class TestGA414:
    def _rl_rule_with_configs(self, configs, **extra):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            "enforce_on_key_configs": configs,
        }
        rlo.update(extra)
        return _rule(action="throttle", rate_limit_options=rlo)

    def test_ga414_valid_configs(self):
        configs = [{"enforce_on_key_type": "IP"}]
        r = self._rl_rule_with_configs(configs)
        assert_no_lint(validate_rules([r]), "GA414")

    def test_ga414_not_list(self):
        r = self._rl_rule_with_configs("invalid")
        assert_lint(validate_rules([r]), "GA414")

    def test_ga414_too_many_entries(self):
        configs = [
            {"enforce_on_key_type": "IP"},
            {"enforce_on_key_type": "HTTP_HEADER", "enforce_on_key_name": "X-A"},
            {"enforce_on_key_type": "HTTP_COOKIE", "enforce_on_key_name": "c"},
            {"enforce_on_key_type": "XFF_IP"},
        ]
        r = self._rl_rule_with_configs(configs)
        assert_lint(validate_rules([r]), "GA414")

    def test_ga414_entry_not_dict(self):
        configs = ["invalid"]
        r = self._rl_rule_with_configs(configs)
        assert_lint(validate_rules([r]), "GA414")

    def test_ga414_entry_missing_type(self):
        configs = [{"enforce_on_key_name": "X-Foo"}]
        r = self._rl_rule_with_configs(configs)
        assert_lint(validate_rules([r]), "GA414")

    def test_ga414_mutually_exclusive_with_enforce_on_key(self):
        configs = [{"enforce_on_key_type": "IP"}]
        r = self._rl_rule_with_configs(configs, enforce_on_key="IP")
        assert_lint(validate_rules([r]), "GA414")

    def test_ga414_three_entries_ok(self):
        configs = [
            {"enforce_on_key_type": "IP"},
            {"enforce_on_key_type": "HTTP_HEADER", "enforce_on_key_name": "X-A"},
            {"enforce_on_key_type": "HTTP_COOKIE", "enforce_on_key_name": "c"},
        ]
        r = self._rl_rule_with_configs(configs)
        assert_no_lint(validate_rules([r]), "GA414")


# ---------------------------------------------------------------------------
# GA415  Duplicate enforce_on_key_configs entries
# ---------------------------------------------------------------------------
class TestGA415:
    def _rl_rule_with_configs(self, configs):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            "enforce_on_key_configs": configs,
        }
        return _rule(action="throttle", rate_limit_options=rlo)

    def test_ga415_duplicate_type(self):
        configs = [
            {"enforce_on_key_type": "IP"},
            {"enforce_on_key_type": "IP"},
        ]
        r = self._rl_rule_with_configs(configs)
        assert_lint(validate_rules([r]), "GA415")

    def test_ga415_no_duplicates(self):
        configs = [
            {"enforce_on_key_type": "IP"},
            {"enforce_on_key_type": "XFF_IP"},
        ]
        r = self._rl_rule_with_configs(configs)
        assert_no_lint(validate_rules([r]), "GA415")

    def test_ga415_single_entry_no_warning(self):
        configs = [{"enforce_on_key_type": "IP"}]
        r = self._rl_rule_with_configs(configs)
        assert_no_lint(validate_rules([r]), "GA415")


# ---------------------------------------------------------------------------
# GA416  Preconfigured WAF sensitivity level 0-4
# ---------------------------------------------------------------------------
class TestGA416:
    def test_ga416_sensitivity_too_high(self):
        expr = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 5})"
        match = {"expr": {"expression": expr}}
        assert_lint(validate_rules([_rule(match=match)]), "GA416")

    def test_ga416_sensitivity_valid_4(self):
        expr = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 4})"
        match = {"expr": {"expression": expr}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA416")

    def test_ga416_sensitivity_valid_0(self):
        expr = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 0})"
        match = {"expr": {"expression": expr}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA416")

    def test_ga416_no_sensitivity(self):
        expr = "evaluatePreconfiguredWaf('sqli-v33-stable')"
        match = {"expr": {"expression": expr}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA416")

    def test_ga416_preconfigured_expr_variant(self):
        expr = "evaluatePreconfiguredExpr('xss-v33-stable', {'sensitivity': 9})"
        match = {"expr": {"expression": expr}}
        assert_lint(validate_rules([_rule(match=match)]), "GA416")

    def test_ga416_sensitivity_with_nested_dict(self):
        expr = (
            "evaluatePreconfiguredWaf('sqli-v33-stable',"
            " {'sensitivity': 5, 'opt_out_rule_ids': ['rule1']})"
        )
        match = {"expr": {"expression": expr}}
        assert_lint(validate_rules([_rule(match=match)]), "GA416")

    def test_ga416_sensitivity_with_nested_dict_valid(self):
        expr = (
            "evaluatePreconfiguredWaf('sqli-v33-stable',"
            " {'sensitivity': 3, 'opt_out_rule_ids': ['rule1']})"
        )
        match = {"expr": {"expression": expr}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA416")


# ---------------------------------------------------------------------------
# GA418  Invalid header name in CEL bracket access
# ---------------------------------------------------------------------------
class TestGA418:
    def test_ga418_valid_header(self):
        match = {"expr": {"expression": "request.headers['X-Custom-Header'] == 'v'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA418")

    def test_ga418_invalid_header_space(self):
        match = {"expr": {"expression": 'request.headers["Bad Header"] == "v"'}}
        assert_lint(validate_rules([_rule(match=match)]), "GA418")

    def test_ga418_invalid_header_paren(self):
        match = {"expr": {"expression": 'request.headers["X-Bad(Header)"] == "v"'}}
        assert_lint(validate_rules([_rule(match=match)]), "GA418")

    def test_ga418_deduped(self):
        expr = 'request.headers["Bad Header"] == "a" || request.headers["Bad Header"] == "b"'
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        ga418 = [r for r in results if r.rule_id == "GA418"]
        assert len(ga418) == 1

    def test_ga418_double_quoted(self):
        match = {"expr": {"expression": 'request.headers["Content-Type"] == "text/html"'}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA418")


# ---------------------------------------------------------------------------
# GA419  Empty or whitespace-only redirect target
# ---------------------------------------------------------------------------
class TestGA419:
    def test_ga419_empty_redirect_target(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": ""},
        )
        assert_lint(validate_rules([r]), "GA419")

    def test_ga419_whitespace_redirect_target(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "   "},
        )
        assert_lint(validate_rules([r]), "GA419")

    def test_ga419_non_empty_ok(self):
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "https://example.com"},
        )
        assert_no_lint(validate_rules([r]), "GA419")

    def test_ga419_exceed_redirect_empty_target(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": ""},
            },
        )
        assert_lint(validate_rules([r]), "GA419")

    def test_ga419_exceed_redirect_whitespace_target(self):
        r = _rule(
            action="throttle",
            rate_limit_options={
                "conform_action": "allow",
                "exceed_action": "redirect",
                "rate_limit_threshold": {"count": 100, "interval_sec": 60},
                "exceed_redirect_options": {"type": "EXTERNAL_302", "target": "  "},
            },
        )
        assert_lint(validate_rules([r]), "GA419")


# ---------------------------------------------------------------------------
# GA315  Country code validation in CEL
# ---------------------------------------------------------------------------
class TestGA315:
    def test_ga315_valid_country_code(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA315")

    def test_ga315_valid_country_code_double_quote(self):
        match = {"expr": {"expression": 'origin.region_code == "DE"'}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA315")

    def test_ga315_lowercase_warning(self):
        match = {"expr": {"expression": "origin.region_code == 'us'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1
        assert "uppercase" in ga315[0].message.lower()

    def test_ga315_three_letter_code(self):
        match = {"expr": {"expression": "origin.region_code == 'USA'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1
        assert "2 letters" in ga315[0].message

    def test_ga315_single_letter_code(self):
        match = {"expr": {"expression": "origin.region_code == 'U'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1
        assert "2 letters" in ga315[0].message

    def test_ga315_in_list_all_valid(self):
        match = {"expr": {"expression": 'origin.region_code in ["US", "CA", "GB"]'}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA315")

    def test_ga315_in_list_one_bad(self):
        match = {"expr": {"expression": 'origin.region_code in ["US", "XYZ"]'}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1

    def test_ga315_mixed_case_in_list(self):
        match = {"expr": {"expression": 'origin.region_code in ["us", "CA"]'}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1
        assert "uppercase" in ga315[0].message.lower()

    def test_ga315_no_region_code_no_warning(self):
        match = {"expr": {"expression": "origin.ip == '1.2.3.4'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA315")

    def test_ga315_deduped(self):
        match = {"expr": {"expression": "origin.region_code == 'us' || origin.region_code == 'us'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1


# ---------------------------------------------------------------------------
# GA316  HTTP method validation in CEL
# ---------------------------------------------------------------------------
class TestGA316:
    def test_ga316_valid_method(self):
        match = {"expr": {"expression": "request.method == 'GET'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA316")

    @pytest.mark.parametrize(
        "method",
        ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"],
    )
    def test_ga316_all_valid_methods(self, method):
        match = {"expr": {"expression": f"request.method == '{method}'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA316")

    def test_ga316_typo_gett(self):
        match = {"expr": {"expression": "request.method == 'GETT'"}}
        results = validate_rules([_rule(match=match)])
        ga316 = [r for r in results if r.rule_id == "GA316"]
        assert len(ga316) == 1
        assert "GET" in ga316[0].message

    def test_ga316_unknown_method(self):
        match = {"expr": {"expression": "request.method == 'PURGE'"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA316")

    def test_ga316_in_list_valid(self):
        match = {"expr": {"expression": 'request.method in ["GET", "POST"]'}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA316")

    def test_ga316_in_list_one_bad(self):
        match = {"expr": {"expression": 'request.method in ["GET", "POSTT"]'}}
        results = validate_rules([_rule(match=match)])
        ga316 = [r for r in results if r.rule_id == "GA316"]
        assert len(ga316) == 1
        assert "POST" in ga316[0].message

    def test_ga316_deduped(self):
        match = {"expr": {"expression": "request.method == 'GETT' || request.method == 'GETT'"}}
        results = validate_rules([_rule(match=match)])
        ga316 = [r for r in results if r.rule_id == "GA316"]
        assert len(ga316) == 1

    def test_ga316_no_method_comparison_no_warning(self):
        match = {"expr": {"expression": "origin.ip == '1.2.3.4'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA316")


# ---------------------------------------------------------------------------
# GA317  CIDR validation in inIpRange()
# ---------------------------------------------------------------------------
class TestGA317:
    def test_ga317_valid_cidr(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '1.2.3.0/24')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA317")

    def test_ga317_valid_ipv6_cidr(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '2001:db8::/32')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA317")

    def test_ga317_invalid_cidr(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, 'not-a-cidr')"}}
        results = validate_rules([_rule(match=match)])
        ga317 = [r for r in results if r.rule_id == "GA317"]
        assert len(ga317) == 1

    def test_ga317_invalid_cidr_bad_prefix(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '1.2.3.4/99')"}}
        results = validate_rules([_rule(match=match)])
        ga317 = [r for r in results if r.rule_id == "GA317"]
        assert len(ga317) == 1

    def test_ga320_private_range(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '192.168.1.0/24')"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA320")

    def test_ga320_loopback(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '127.0.0.1/32')"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA320")

    def test_ga320_rfc1918_10(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '10.0.0.0/8')"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA320")

    def test_ga320_public_no_warning(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, '8.8.8.0/24')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA320")

    def test_ga320_ipv6_ula(self):
        match = {"expr": {"expression": "inIpRange(origin.ip, 'fd00::/8')"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA320")

    def test_ga320_cgnat(self):
        """CGNAT range should be flagged in inIpRange expressions."""
        match = {"expr": {"expression": "inIpRange(origin.ip, '100.64.1.1/32')"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA320")

    def test_ga320_documentation_rfc5737(self):
        """RFC 5737 documentation range should be flagged."""
        match = {"expr": {"expression": "inIpRange(origin.ip, '198.51.100.0/24')"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA320")

    def test_ga317_double_quoted(self):
        match = {"expr": {"expression": 'inIpRange(origin.ip, "8.8.8.0/24")'}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA317")

    def test_ga317_user_ip(self):
        match = {"expr": {"expression": "inIpRange(origin.user_ip, '1.2.3.0/24')"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA317")


# ---------------------------------------------------------------------------
# GA318  CEL type mismatch detection
# ---------------------------------------------------------------------------
class TestGA318:
    def test_ga318_string_field_with_int(self):
        match = {"expr": {"expression": "origin.ip == 42"}}
        results = validate_rules([_rule(match=match)])
        ga318 = [r for r in results if r.rule_id == "GA318"]
        assert len(ga318) == 1
        assert "string" in ga318[0].message
        assert "int" in ga318[0].message

    def test_ga318_int_field_with_string(self):
        match = {"expr": {"expression": "origin.asn == '15169'"}}
        results = validate_rules([_rule(match=match)])
        ga318 = [r for r in results if r.rule_id == "GA318"]
        assert len(ga318) == 1
        assert "int" in ga318[0].message
        assert "string" in ga318[0].message

    def test_ga318_string_field_with_string_ok(self):
        match = {"expr": {"expression": "origin.ip == '1.2.3.4'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA318")

    def test_ga318_int_field_with_int_ok(self):
        match = {"expr": {"expression": "origin.asn == 15169"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA318")

    def test_ga318_request_method_with_int(self):
        match = {"expr": {"expression": "request.method == 42"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA318")

    def test_ga318_origin_region_code_with_int(self):
        match = {"expr": {"expression": "origin.region_code == 42"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA318")

    def test_ga318_unknown_field_no_warning(self):
        match = {"expr": {"expression": "custom.field == 42"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA318")

    def test_ga318_deduped(self):
        match = {"expr": {"expression": "origin.ip == 42 || origin.ip == 42"}}
        results = validate_rules([_rule(match=match)])
        ga318 = [r for r in results if r.rule_id == "GA318"]
        assert len(ga318) == 1

    def test_ga318_comparison_operators(self):
        """origin.asn > 'string' is a type mismatch."""
        match = {"expr": {"expression": "origin.asn > '100'"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA318")

    def test_ga318_request_path_with_int(self):
        match = {"expr": {"expression": "request.path == 42"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA318")


# ---------------------------------------------------------------------------
# GA319  Case sensitivity reminder
# ---------------------------------------------------------------------------
class TestGA319:
    def test_ga319_mixed_case_path(self):
        match = {"expr": {"expression": "request.path == '/Admin'"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA319")

    def test_ga319_all_lowercase_path_no_warning(self):
        match = {"expr": {"expression": "request.path == '/admin'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA319")

    def test_ga319_all_uppercase_path_no_warning(self):
        match = {"expr": {"expression": "request.path == '/ADMIN'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA319")

    def test_ga319_mixed_case_host(self):
        match = {"expr": {"expression": "request.host == 'Example.COM'"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA319")
        assert_no_lint(results, "GA310")

    def test_ga319_mixed_case_query(self):
        match = {"expr": {"expression": "request.query == 'fooBar'"}}
        results = validate_rules([_rule(match=match)])
        assert_lint(results, "GA319")

    def test_ga319_method_no_warning(self):
        """request.method is always uppercase — don't warn."""
        match = {"expr": {"expression": "request.method == 'Get'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA319")

    def test_ga319_region_code_no_warning(self):
        """origin.region_code is always uppercase — don't warn."""
        match = {"expr": {"expression": "origin.region_code == 'Us'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA319")

    def test_ga319_severity_is_info(self):
        from octorules.linter.engine import Severity

        match = {"expr": {"expression": "request.path == '/Admin'"}}
        results = validate_rules([_rule(match=match)])
        ga319 = [r for r in results if r.rule_id == "GA319"]
        assert ga319[0].severity == Severity.INFO

    def test_ga319_deduped(self):
        match = {"expr": {"expression": "request.path == '/Admin' || request.path == '/Admin'"}}
        results = validate_rules([_rule(match=match)])
        ga319 = [r for r in results if r.rule_id == "GA319"]
        assert len(ga319) == 1

    def test_ga319_slash_only_no_warning(self):
        """All-lowercase path should not trigger."""
        match = {"expr": {"expression": "request.path == '/'"}}
        assert_no_lint(validate_rules([_rule(match=match)]), "GA319")


# ---------------------------------------------------------------------------
# GA502  Tier-aware rule count limits
# ---------------------------------------------------------------------------
class TestGA502:
    def test_ga502_standard_under_limit(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(256)]
        assert_no_lint(validate_rule_count(rules, plan_tier="standard"), "GA502")

    def test_ga502_standard_over_limit(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(257)]
        results = validate_rule_count(rules, plan_tier="standard")
        assert_lint(results, "GA502")
        assert "257" in results[0].message
        assert "256" in results[0].message

    def test_ga502_plus_over_limit(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(513)]
        results = validate_rule_count(rules, plan_tier="plus")
        assert_lint(results, "GA502")

    def test_ga502_plus_at_limit(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(512)]
        assert_no_lint(validate_rule_count(rules, plan_tier="plus"), "GA502")

    def test_ga502_enterprise_over_limit(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(1025)]
        results = validate_rule_count(rules, plan_tier="enterprise")
        assert_lint(results, "GA502")

    def test_ga502_enterprise_at_limit(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(1024)]
        assert_no_lint(validate_rule_count(rules, plan_tier="enterprise"), "GA502")

    def test_ga502_enterprise_default(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(100)]
        assert_no_lint(validate_rule_count(rules), "GA502")

    def test_ga502_unknown_tier_no_crash(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(2000)]
        assert_no_lint(validate_rule_count(rules, plan_tier="unknown"), "GA502")

    def test_ga502_case_insensitive_tier(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(257)]
        assert_lint(validate_rule_count(rules, plan_tier="Standard"), "GA502")

    def test_ga502_phase_passed_through(self):
        from octorules_google.validate import validate_rule_count

        rules = [_rule(ref=str(i)) for i in range(257)]
        results = validate_rule_count(
            rules, plan_tier="standard", phase="gcloud_armor_custom_rules"
        )
        assert results[0].phase == "gcloud_armor_custom_rules"


# ---------------------------------------------------------------------------
# GA501  Regex rule count per policy
# ---------------------------------------------------------------------------
class TestGA501:
    def _regex_rule(self, ref, pattern=".*"):
        return _rule(
            ref=ref,
            match={"expr": {"expression": f'request.path.matches("{pattern}")'}},
        )

    def _plain_rule(self, ref):
        return _rule(ref=ref, match={"expr": {"expression": "true"}})

    def test_ga501_under_limit(self):
        from octorules_google.validate import validate_regex_rule_count

        rules = [self._regex_rule(str(i)) for i in range(10)]
        assert_no_lint(validate_regex_rule_count(rules), "GA501")

    def test_ga501_over_limit(self):
        from octorules_google.validate import validate_regex_rule_count

        rules = [self._regex_rule(str(i)) for i in range(11)]
        results = validate_regex_rule_count(rules)
        assert_lint(results, "GA501")
        assert "11" in results[0].message
        assert "10" in results[0].message

    def test_ga501_at_limit(self):
        from octorules_google.validate import validate_regex_rule_count

        rules = [self._regex_rule(str(i)) for i in range(10)]
        assert_no_lint(validate_regex_rule_count(rules), "GA501")

    def test_ga501_mixed_rules(self):
        """Only rules with matches() count toward the limit."""
        from octorules_google.validate import validate_regex_rule_count

        regex_rules = [self._regex_rule(str(i)) for i in range(8)]
        plain_rules = [self._plain_rule(str(i + 100)) for i in range(20)]
        assert_no_lint(validate_regex_rule_count(regex_rules + plain_rules), "GA501")

    def test_ga501_mixed_over_limit(self):
        from octorules_google.validate import validate_regex_rule_count

        regex_rules = [self._regex_rule(str(i)) for i in range(11)]
        plain_rules = [self._plain_rule(str(i + 100)) for i in range(5)]
        results = validate_regex_rule_count(regex_rules + plain_rules)
        assert_lint(results, "GA501")

    def test_ga501_non_regex_not_counted(self):
        """Rules without matches() in expression are not regex rules."""
        from octorules_google.validate import validate_regex_rule_count

        rules = [self._plain_rule(str(i)) for i in range(50)]
        assert_no_lint(validate_regex_rule_count(rules), "GA501")

    def test_ga501_versioned_expr_not_counted(self):
        """Rules using versioned_expr (SRC_IPS_V1) are not regex rules."""
        from octorules_google.validate import validate_regex_rule_count

        rules = [
            _rule(
                ref=str(i),
                match={
                    "versioned_expr": "SRC_IPS_V1",
                    "config": {"src_ip_ranges": ["1.2.3.4/32"]},
                },
            )
            for i in range(15)
        ]
        assert_no_lint(validate_regex_rule_count(rules), "GA501")

    def test_ga501_severity_is_warning(self):
        from octorules.linter.engine import Severity

        from octorules_google.validate import validate_regex_rule_count

        rules = [self._regex_rule(str(i)) for i in range(11)]
        results = validate_regex_rule_count(rules)
        assert results[0].severity == Severity.WARNING

    def test_ga501_phase_passed_through(self):
        from octorules_google.validate import validate_regex_rule_count

        rules = [self._regex_rule(str(i)) for i in range(11)]
        results = validate_regex_rule_count(rules, phase="gcloud_armor_custom_rules")
        assert results[0].phase == "gcloud_armor_custom_rules"

    def test_ga501_single_quoted_matches(self):
        """matches() with single-quoted pattern should count."""
        from octorules_google.validate import validate_regex_rule_count

        rules = [
            _rule(
                ref=str(i),
                match={"expr": {"expression": "request.path.matches('.*')"}},
            )
            for i in range(11)
        ]
        assert_lint(validate_regex_rule_count(rules), "GA501")

    def test_ga501_expr_as_string(self):
        """Handle expr as a plain string (shorthand form)."""
        from octorules_google.validate import validate_regex_rule_count

        rules = [
            _rule(
                ref=str(i),
                match={"expr": f'request.path.matches("{i}.*")'},
            )
            for i in range(11)
        ]
        assert_lint(validate_regex_rule_count(rules), "GA501")


class TestResultFactory:
    """Tests for the _result() LintResult factory helper."""

    def test_creates_lint_result_with_required_fields(self):
        """Factory returns a LintResult with all required fields set."""
        from octorules.linter.engine import LintResult, Severity

        from octorules_google.validate import _result

        r = _result("GC001", Severity.ERROR, "test message", "custom_rules", "ref1")
        assert isinstance(r, LintResult)
        assert r.rule_id == "GC001"
        assert r.severity == Severity.ERROR
        assert r.message == "test message"
        assert r.phase == "custom_rules"
        assert r.ref == "ref1"

    def test_default_optional_fields(self):
        """Factory defaults field and suggestion to empty strings."""
        from octorules.linter.engine import Severity

        from octorules_google.validate import _result

        r = _result("GC002", Severity.WARNING, "msg", "rate_based")
        assert r.ref == ""
        assert r.field == ""
        assert r.suggestion == ""

    def test_optional_fields_passthrough(self):
        """Factory passes field and suggestion through to LintResult."""
        from octorules.linter.engine import Severity

        from octorules_google.validate import _result

        r = _result(
            "GC003",
            Severity.INFO,
            "msg",
            "managed",
            field="action",
            suggestion="use block",
        )
        assert r.field == "action"
        assert r.suggestion == "use block"


class TestParsePriority:
    """Tests for the _parse_priority() helper."""

    def test_valid_integer(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("100") == 100

    def test_zero(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("0") == 0

    def test_negative(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("-1") == -1

    def test_large_number(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("2147483647") == 2147483647

    def test_invalid_string(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("not-a-number") is None

    def test_float_string(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("100.5") is None

    def test_empty_string(self):
        from octorules_google.validate import _parse_priority

        assert _parse_priority("") is None


# ---------------------------------------------------------------------------
# _is_strict_int helper
# ---------------------------------------------------------------------------
class TestIsStrictInt:
    def test_true_for_int(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(42) is True

    def test_false_for_bool_true(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(True) is False

    def test_false_for_bool_false(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(False) is False

    def test_false_for_string(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int("42") is False

    def test_false_for_float(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(3.14) is False

    def test_false_for_none(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(None) is False

    def test_true_for_zero(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(0) is True

    def test_true_for_negative(self):
        from octorules_google.validate import _is_strict_int

        assert _is_strict_int(-1) is True


# ---------------------------------------------------------------------------
# GA421 range validation
# ---------------------------------------------------------------------------
class TestGA421Range:
    def _rl_rule(self, action="throttle", **rlo_overrides):
        """Build a rate-limit rule with overrides to rate_limit_options."""
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
        }
        rlo.update(rlo_overrides)
        return _rule(action=action, rate_limit_options=rlo)

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

    def test_ga421_count_zero(self):
        r = self._rl_rule(rate_limit_threshold={"count": 0, "interval_sec": 60})
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 1
        assert "got 0" in ga421[0].message

    def test_ga421_count_negative(self):
        r = self._rl_rule(rate_limit_threshold={"count": -1, "interval_sec": 60})
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 1
        assert "got -1" in ga421[0].message

    def test_ga421_count_too_high_rate_based_ban(self):
        r = self._ban_rule(rate_limit_threshold={"count": 10_001, "interval_sec": 60})
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 1
        assert "10,000" in ga421[0].message
        assert "rate_based_ban" in ga421[0].message

    def test_ga421_count_too_high_throttle(self):
        r = self._rl_rule(
            action="throttle",
            rate_limit_threshold={"count": 1_000_001, "interval_sec": 60},
        )
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 1
        assert "1,000,000" in ga421[0].message
        assert "throttle" in ga421[0].message

    def test_ga421_count_at_max_rate_based_ban_ok(self):
        r = self._ban_rule(rate_limit_threshold={"count": 10_000, "interval_sec": 60})
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 0

    def test_ga421_count_at_max_throttle_ok(self):
        r = self._rl_rule(
            action="throttle",
            rate_limit_threshold={"count": 1_000_000, "interval_sec": 60},
        )
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 0

    def test_ga421_count_one_ok(self):
        r = self._rl_rule(rate_limit_threshold={"count": 1, "interval_sec": 60})
        results = validate_rules([r])
        ga421 = [x for x in results if x.rule_id == "GA421"]
        assert len(ga421) == 0


# ---------------------------------------------------------------------------
# GA413 regex length check
# ---------------------------------------------------------------------------
class TestGA413Length:
    def test_ga413_long_pattern(self):
        long_pattern = "a" * 600
        expr = f"request.path.matches('{long_pattern}')"
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        ga413 = [r for r in results if r.rule_id == "GA413"]
        assert len(ga413) == 1
        assert "too long" in ga413[0].message
        assert "600 chars" in ga413[0].message

    def test_ga413_pattern_at_limit_ok(self):
        pattern = "a" * 512
        expr = f"request.path.matches('{pattern}')"
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        ga413 = [r for r in results if r.rule_id == "GA413"]
        assert len(ga413) == 0

    def test_ga413_long_pattern_skips_compile(self):
        """A long pattern that would be invalid regex should fire length, not compile error."""
        long_bad_pattern = "[" * 600
        expr = f"request.path.matches('{long_bad_pattern}')"
        match = {"expr": {"expression": expr}}
        results = validate_rules([_rule(match=match)])
        ga413 = [r for r in results if r.rule_id == "GA413"]
        assert len(ga413) == 1
        assert "too long" in ga413[0].message


# ---------------------------------------------------------------------------
# GA315 suggestion field
# ---------------------------------------------------------------------------
class TestGA315Suggestion:
    def test_ga315_lowercase_has_suggestion(self):
        match = {"expr": {"expression": "origin.region_code == 'us'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1
        assert ga315[0].suggestion == "Replace 'us' with 'US'"

    def test_ga315_mixed_case_has_suggestion(self):
        match = {"expr": {"expression": "origin.region_code == 'De'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 1
        assert ga315[0].suggestion == "Replace 'De' with 'DE'"

    def test_ga315_uppercase_no_suggestion(self):
        match = {"expr": {"expression": "origin.region_code == 'US'"}}
        results = validate_rules([_rule(match=match)])
        ga315 = [r for r in results if r.rule_id == "GA315"]
        assert len(ga315) == 0


# ---------------------------------------------------------------------------
# CEL edge case tests
# ---------------------------------------------------------------------------
class TestCELEdgeCases:
    """Edge case tests for CEL expression validation."""

    def test_ga302_escaped_quotes_in_expression(self):
        """GA302 should not fire on valid CEL with escaped quotes."""
        rule = _rule(match={"expr": {"expression": 'request.path.matches("test\\\\"quote")'}})
        results = validate_rules([rule])
        ga302 = [r for r in results if r.rule_id == "GA302"]
        from octorules.linter.engine import Severity

        # This should either pass or fail gracefully, not crash
        assert (
            all(r.severity in (Severity.ERROR, Severity.WARNING) for r in ga302) or len(ga302) == 0
        )

    def test_ga301_cidr_leading_zeros(self):
        """GA301 should handle CIDR with leading zeros without crashing."""
        rule = _rule(match={"expr": {"expression": 'inIpRange(origin.ip, "192.168.001.0/24")'}})
        results = validate_rules([rule])
        # Leading zeros are technically valid but unusual — check behavior
        # (no assertion on exact outcome, just verify no crash)
        assert isinstance(results, list)

    def test_ga302_expression_at_2048_boundary(self):
        """GA304 should not fire at expressions of exactly 2048 chars."""
        prefix = 'request.path == "'
        suffix = '"'
        padding = "x" * (2048 - len(prefix) - len(suffix))
        expr = prefix + padding + suffix
        assert len(expr) == 2048
        rule = _rule(match={"expr": {"expression": expr}})
        results = validate_rules([rule])
        # At exactly 2048, should NOT fire the length check
        ga304 = [r for r in results if r.rule_id == "GA304"]
        assert len(ga304) == 0

    def test_ga302_expression_at_2049_boundary(self):
        """GA304 should fire at 2049 chars."""
        prefix = 'request.path == "'
        suffix = '"'
        padding = "x" * (2049 - len(prefix) - len(suffix))
        expr = prefix + padding + suffix
        assert len(expr) == 2049
        rule = _rule(match={"expr": {"expression": expr}})
        results = validate_rules([rule])
        ga304 = [r for r in results if r.rule_id == "GA304"]
        assert len(ga304) == 1


# ---------------------------------------------------------------------------
# GA409  URL validation (improved host check)
# ---------------------------------------------------------------------------
class TestGA409URLValidation:
    """Tests for GA409 EXTERNAL_302 URL validation."""

    def test_valid_url_accepted(self):
        """Valid HTTPS URL should not trigger GA409."""
        r = _rule(
            action="redirect",
            redirect_options={
                "type": "EXTERNAL_302",
                "target": "https://example.com/path",
            },
        )
        ga409 = [x for x in validate_rules([r]) if x.rule_id == "GA409"]
        assert len(ga409) == 0

    def test_missing_host_rejected(self):
        """URL with scheme but no host should trigger GA409."""
        r = _rule(
            action="redirect",
            redirect_options={"type": "EXTERNAL_302", "target": "https://"},
        )
        ga409 = [x for x in validate_rules([r]) if x.rule_id == "GA409"]
        assert len(ga409) == 1
        assert "host" in ga409[0].message.lower()

    def test_no_scheme_rejected(self):
        """URL without scheme should trigger GA409."""
        r = _rule(
            action="redirect",
            redirect_options={
                "type": "EXTERNAL_302",
                "target": "example.com/path",
            },
        )
        ga409 = [x for x in validate_rules([r]) if x.rule_id == "GA409"]
        assert len(ga409) == 1

    def test_http_with_host_accepted(self):
        """Valid HTTP URL should not trigger GA409."""
        r = _rule(
            action="redirect",
            redirect_options={
                "type": "EXTERNAL_302",
                "target": "http://example.com/path",
            },
        )
        ga409 = [x for x in validate_rules([r]) if x.rule_id == "GA409"]
        assert len(ga409) == 0

    def test_https_with_port_accepted(self):
        """HTTPS URL with port should not trigger GA409."""
        r = _rule(
            action="redirect",
            redirect_options={
                "type": "EXTERNAL_302",
                "target": "https://example.com:8443/path",
            },
        )
        ga409 = [x for x in validate_rules([r]) if x.rule_id == "GA409"]
        assert len(ga409) == 0


# ---------------------------------------------------------------------------
# GA103  Dead rules: parenthesized and IP-wildcard match-all detection
# ---------------------------------------------------------------------------
class TestDeadRulesExtended:
    """GA103 should detect parenthesized 'true' and IP-wildcard match-all."""

    def test_ga103_parenthesized_true(self):
        """Rules after ((true)) match-all are unreachable."""
        rules = [
            _rule(ref="100", action="allow", match={"expr": {"expression": "((true))"}}),
            _rule(
                ref="200",
                action="deny(403)",
                match={"expr": {"expression": "origin.region_code == 'CN'"}},
            ),
        ]
        assert_lint(validate_rules(rules), "GA103")

    def test_ga103_deeply_parenthesized_true(self):
        """Rules after (((true))) match-all are unreachable."""
        rules = [
            _rule(ref="100", action="allow", match={"expr": {"expression": "(((true)))"}}),
            _rule(
                ref="200",
                action="deny(403)",
                match={"expr": {"expression": "origin.ip == '1.2.3.4'"}},
            ),
        ]
        assert_lint(validate_rules(rules), "GA103")

    def test_ga103_ip_wildcard_match_all(self):
        """Rules after SRC_IPS_V1 with ['*'] are unreachable."""
        rules = [
            _rule(
                ref="100",
                action="allow",
                match={
                    "versioned_expr": "SRC_IPS_V1",
                    "config": {"src_ip_ranges": ["*"]},
                },
            ),
            _rule(
                ref="200",
                action="deny(403)",
                match={"expr": {"expression": "origin.region_code == 'CN'"}},
            ),
        ]
        assert_lint(validate_rules(rules), "GA103")

    def test_ga103_ip_wildcard_non_wildcard_not_flagged(self):
        """SRC_IPS_V1 with specific IPs is not a match-all."""
        rules = [
            _rule(
                ref="100",
                action="deny(403)",
                match={
                    "versioned_expr": "SRC_IPS_V1",
                    "config": {"src_ip_ranges": ["10.0.0.0/8"]},
                },
            ),
            _rule(
                ref="200",
                action="allow",
                match={"expr": {"expression": "origin.region_code == 'US'"}},
            ),
        ]
        assert_no_lint(validate_rules(rules), "GA103")

    def test_ga103_lower_priority_before_parenthesized_not_flagged(self):
        """Rules with lower priority than parenthesized match-all are not flagged."""
        rules = [
            _rule(
                ref="50",
                action="deny(403)",
                match={"expr": {"expression": "origin.region_code == 'CN'"}},
            ),
            _rule(ref="100", action="allow", match={"expr": {"expression": "((true))"}}),
        ]
        ga103_results = [r for r in validate_rules(rules) if r.rule_id == "GA103"]
        assert all(r.ref != "50" for r in ga103_results)


# ---------------------------------------------------------------------------
# GA408/GA421  No duplicate diagnostics for count range
# ---------------------------------------------------------------------------
class TestGA408GA421NoDuplicate:
    """Verify count-range issues produce exactly one diagnostic, not both GA408 and GA421."""

    def _rl_rule(self, action="throttle", **rlo_overrides):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
        }
        rlo.update(rlo_overrides)
        return _rule(action=action, rate_limit_options=rlo)

    def test_count_zero_only_ga421(self):
        """count=0 should produce GA421 but NOT GA408."""
        r = self._rl_rule(rate_limit_threshold={"count": 0, "interval_sec": 60})
        results = validate_rules([r])
        ids = _ids(results)
        assert "GA421" in ids
        assert "GA408" not in ids

    def test_count_negative_only_ga421(self):
        """count=-1 should produce GA421 but NOT GA408."""
        r = self._rl_rule(rate_limit_threshold={"count": -1, "interval_sec": 60})
        results = validate_rules([r])
        ids = _ids(results)
        assert "GA421" in ids
        assert "GA408" not in ids

    def test_count_bool_only_ga421(self):
        """count=True (bool, not int) should produce GA421 but NOT GA408."""
        r = self._rl_rule(rate_limit_threshold={"count": True, "interval_sec": 60})
        results = validate_rules([r])
        ids = _ids(results)
        assert "GA421" in ids
        assert "GA408" not in ids

    def test_count_string_only_ga421(self):
        """count='100' (string, not int) should produce GA421 but NOT GA408."""
        r = self._rl_rule(rate_limit_threshold={"count": "100", "interval_sec": 60})
        results = validate_rules([r])
        ids = _ids(results)
        assert "GA421" in ids
        assert "GA408" not in ids

    def test_count_too_high_only_ga421(self):
        """count > max should produce GA421 but NOT GA408."""
        r = self._rl_rule(rate_limit_threshold={"count": 1_000_001, "interval_sec": 60})
        results = validate_rules([r])
        ids = _ids(results)
        assert "GA421" in ids
        assert "GA408" not in ids


# ---------------------------------------------------------------------------
# GA423  enforce_on_key_type validation within enforce_on_key_configs
# ---------------------------------------------------------------------------
class TestGA423InConfigs:
    def _rl_rule_with_configs(self, configs, **extra):
        rlo = {
            "conform_action": "allow",
            "exceed_action": "deny-429",
            "rate_limit_threshold": {"count": 100, "interval_sec": 60},
            "enforce_on_key_configs": configs,
        }
        rlo.update(extra)
        return _rule(action="throttle", rate_limit_options=rlo)

    def test_ga423_valid_key_type_in_configs(self):
        configs = [{"enforce_on_key_type": "IP"}]
        r = self._rl_rule_with_configs(configs)
        assert_no_lint(validate_rules([r]), "GA423")

    def test_ga423_invalid_key_type_in_configs(self):
        configs = [{"enforce_on_key_type": "BOGUS"}]
        r = self._rl_rule_with_configs(configs)
        results = validate_rules([r])
        assert_lint(results, "GA423")
        ga423 = [r for r in results if r.rule_id == "GA423"]
        assert "BOGUS" in ga423[0].message

    def test_ga423_multiple_configs_mixed(self):
        """One valid, one invalid key type in configs."""
        configs = [
            {"enforce_on_key_type": "IP"},
            {"enforce_on_key_type": "INVALID"},
        ]
        r = self._rl_rule_with_configs(configs)
        results = validate_rules([r])
        ga423 = [r for r in results if r.rule_id == "GA423"]
        assert len(ga423) == 1
        assert "INVALID" in ga423[0].message

    def test_ga423_all_valid_key_types_in_configs(self):
        """All known key types pass validation."""
        from octorules_google.validate import _VALID_ENFORCE_ON_KEYS

        for key_type in sorted(_VALID_ENFORCE_ON_KEYS):
            configs = [{"enforce_on_key_type": key_type}]
            r = self._rl_rule_with_configs(configs)
            assert_no_lint(validate_rules([r]), "GA423")


# ---------------------------------------------------------------------------
# GA325  header_action sub-structure validation
# ---------------------------------------------------------------------------
class TestGA325:
    def test_ga325_valid_header_action(self):
        r = _rule(
            header_action={
                "request_headers_to_adds": [
                    {"header_name": "X-Foo", "header_value": "bar"},
                ]
            }
        )
        assert_no_lint(validate_rules([r]), "GA325")

    def test_ga325_header_action_not_dict(self):
        r = _rule(header_action="invalid")
        assert_lint(validate_rules([r]), "GA325")

    def test_ga325_request_headers_to_adds_not_list(self):
        r = _rule(header_action={"request_headers_to_adds": "invalid"})
        assert_lint(validate_rules([r]), "GA325")

    def test_ga325_entry_not_dict(self):
        r = _rule(header_action={"request_headers_to_adds": ["invalid"]})
        assert_lint(validate_rules([r]), "GA325")

    def test_ga325_entry_missing_header_name(self):
        r = _rule(header_action={"request_headers_to_adds": [{"header_value": "bar"}]})
        results = validate_rules([r])
        ga325 = [r for r in results if r.rule_id == "GA325"]
        assert len(ga325) == 1
        assert "header_name" in ga325[0].message

    def test_ga325_entry_missing_header_value(self):
        r = _rule(header_action={"request_headers_to_adds": [{"header_name": "X-Foo"}]})
        results = validate_rules([r])
        ga325 = [r for r in results if r.rule_id == "GA325"]
        assert len(ga325) == 1
        assert "header_value" in ga325[0].message

    def test_ga325_entry_missing_both_fields(self):
        r = _rule(header_action={"request_headers_to_adds": [{}]})
        results = validate_rules([r])
        ga325 = [r for r in results if r.rule_id == "GA325"]
        assert len(ga325) == 2  # one for header_name, one for header_value

    def test_ga325_no_request_headers_to_adds_ok(self):
        """header_action without request_headers_to_adds is fine."""
        r = _rule(header_action={})
        assert_no_lint(validate_rules([r]), "GA325")

    def test_ga325_empty_list_ok(self):
        """Empty request_headers_to_adds list is fine."""
        r = _rule(header_action={"request_headers_to_adds": []})
        assert_no_lint(validate_rules([r]), "GA325")


# ---------------------------------------------------------------------------
# GA326  network_match sub-structure validation
# ---------------------------------------------------------------------------
class TestGA326:
    def test_ga326_valid_network_match(self):
        r = _rule(network_match={"user_defined_fields": []})
        assert_no_lint(validate_rules([r]), "GA326")

    def test_ga326_network_match_not_dict(self):
        r = _rule(network_match="invalid")
        assert_lint(validate_rules([r]), "GA326")

    def test_ga326_network_match_list(self):
        r = _rule(network_match=["invalid"])
        assert_lint(validate_rules([r]), "GA326")

    def test_ga326_absent_is_ok(self):
        r = _rule()
        assert_no_lint(validate_rules([r]), "GA326")


# ---------------------------------------------------------------------------
# GA327  preconfigured_waf_config sub-structure validation
# ---------------------------------------------------------------------------
class TestGA327:
    def test_ga327_valid_config(self):
        r = _rule(preconfigured_waf_config={"exclusions": [{"target_rule_set": "sqli-v33-stable"}]})
        assert_no_lint(validate_rules([r]), "GA327")

    def test_ga327_config_not_dict(self):
        r = _rule(preconfigured_waf_config="invalid")
        assert_lint(validate_rules([r]), "GA327")

    def test_ga327_exclusions_not_list(self):
        r = _rule(preconfigured_waf_config={"exclusions": "invalid"})
        assert_lint(validate_rules([r]), "GA327")

    def test_ga327_exclusion_not_dict(self):
        r = _rule(preconfigured_waf_config={"exclusions": ["invalid"]})
        assert_lint(validate_rules([r]), "GA327")

    def test_ga327_exclusion_missing_target_rule_set(self):
        r = _rule(preconfigured_waf_config={"exclusions": [{"other": "x"}]})
        results = validate_rules([r])
        ga327 = [r for r in results if r.rule_id == "GA327"]
        assert len(ga327) == 1
        assert "target_rule_set" in ga327[0].message

    def test_ga327_no_exclusions_ok(self):
        """preconfigured_waf_config without exclusions is fine."""
        r = _rule(preconfigured_waf_config={})
        assert_no_lint(validate_rules([r]), "GA327")

    def test_ga327_empty_exclusions_ok(self):
        """Empty exclusions list is fine."""
        r = _rule(preconfigured_waf_config={"exclusions": []})
        assert_no_lint(validate_rules([r]), "GA327")

    def test_ga327_multiple_exclusions_mixed(self):
        """One valid, one invalid exclusion entry."""
        r = _rule(
            preconfigured_waf_config={
                "exclusions": [
                    {"target_rule_set": "sqli-v33-stable"},
                    {"not_target": "xss-v33-stable"},
                ]
            }
        )
        results = validate_rules([r])
        ga327 = [r for r in results if r.rule_id == "GA327"]
        assert len(ga327) == 1


# ---------------------------------------------------------------------------
# GA004: Rule entry is not a dict
# ---------------------------------------------------------------------------
class TestRuleEntryNotDict:
    def test_string_entry(self):
        """Non-dict rule entry produces GA004 error."""
        results = validate_rules(["not a dict"])
        assert_lint(results, "GA004")

    def test_int_entry(self):
        results = validate_rules([42])
        assert_lint(results, "GA004")

    def test_list_entry(self):
        results = validate_rules([[1, 2, 3]])
        assert_lint(results, "GA004")

    def test_mixed_valid_and_invalid(self):
        """Valid dict rules still validated alongside non-dict entries."""
        r = _rule()
        results = validate_rules(["bad", r])
        assert_lint(results, "GA004")
        ga004_count = sum(1 for res in results if res.rule_id == "GA004")
        assert ga004_count == 1
