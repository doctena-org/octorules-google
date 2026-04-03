"""Tests for the Google Cloud Armor lint plugin."""

from octorules.linter.engine import LintContext, Severity
from octorules.linter.plugin import get_registered_plugins
from octorules.linter.rules.registry import RULE_REGISTRY

from octorules_google.linter._plugin import GA_RULE_IDS, google_lint
from octorules_google.linter._rules import GA_RULE_METAS


class TestPluginRegistration:
    def test_plugin_is_registered(self):
        plugins = get_registered_plugins()
        names = [p.name for p in plugins]
        assert "google" in names

    def test_plugin_rule_ids_match_metas(self):
        meta_ids = {r.rule_id for r in GA_RULE_METAS}
        assert GA_RULE_IDS == meta_ids

    def test_all_ga_rules_in_registry(self):
        for rule_id in GA_RULE_IDS:
            assert rule_id in RULE_REGISTRY, f"{rule_id} not in global registry"

    def test_idempotent_registration(self):
        """Calling register_google_linter() again should be a no-op."""
        from octorules_google.linter import register_google_linter

        count_before = len(get_registered_plugins())
        register_google_linter()
        assert len(get_registered_plugins()) == count_before


class TestGoogleLint:
    def test_adds_results_for_invalid_rules(self):
        ctx = LintContext()
        rules_data = {
            "gcloud_armor_custom_rules": [
                {"action": "allow"},  # missing ref and match
            ],
        }
        google_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "GA001" in rule_ids
        assert "GA003" in rule_ids

    def test_skips_non_google_phases(self):
        ctx = LintContext()
        rules_data = {
            "waf_custom_rules": [
                {"action": "invalid"},
            ],
        }
        google_lint(rules_data, ctx)
        assert ctx.results == []

    def test_phase_filtering(self):
        ctx = LintContext(phase_filter=["gcloud_armor_rate_rules"])
        rules_data = {
            "gcloud_armor_custom_rules": [
                {"action": "allow"},  # missing ref, match — but phase filtered out
            ],
            "gcloud_armor_rate_rules": [
                {"ref": "100", "action": "throttle", "match": {"expr": {"expression": "true"}}},
            ],
        }
        google_lint(rules_data, ctx)
        # Should only have results from rate_rules, not custom_rules
        for r in ctx.results:
            assert r.phase == "gcloud_armor_rate_rules"

    def test_skips_non_list_phase_values(self):
        ctx = LintContext()
        rules_data = {
            "gcloud_armor_custom_rules": "not-a-list",
        }
        google_lint(rules_data, ctx)
        assert ctx.results == []

    def test_valid_rules_no_results(self):
        ctx = LintContext()
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "100",
                    "action": "allow",
                    "match": {"expr": {"expression": "origin.region_code == 'US'"}},
                },
            ],
        }
        google_lint(rules_data, ctx)
        assert ctx.results == []

    def test_all_four_phases_processed(self):
        ctx = LintContext()
        bad_rule = {"action": "allow"}  # missing ref and match
        rules_data = {
            "gcloud_armor_custom_rules": [bad_rule],
            "gcloud_armor_rate_rules": [bad_rule],
            "gcloud_armor_preconfigured_rules": [bad_rule],
            "gcloud_armor_redirect_rules": [bad_rule],
        }
        google_lint(rules_data, ctx)
        phases_in_results = {r.phase for r in ctx.results}
        assert "gcloud_armor_custom_rules" in phases_in_results
        assert "gcloud_armor_rate_rules" in phases_in_results
        assert "gcloud_armor_preconfigured_rules" in phases_in_results
        assert "gcloud_armor_redirect_rules" in phases_in_results

    def test_severity_filter_applied(self):
        ctx = LintContext(severity_filter=Severity.ERROR)
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "100",
                    "action": "allow",
                    "match": {
                        "config": {"src_ip_ranges": ["10.0.0.0/8"]},
                        "versioned_expr": "SRC_IPS_V1",
                    },
                },
            ],
        }
        google_lint(rules_data, ctx)
        # GA503 is a WARNING, should be filtered out
        rule_ids = [r.rule_id for r in ctx.results]
        assert "GA503" not in rule_ids
