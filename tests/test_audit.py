"""Tests for the Google Cloud Armor audit IP extractor."""

from octorules_google.audit import _extract_ips


class TestGoogleAuditExtractor:
    def test_extracts_from_src_ip_ranges(self):
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "1000",
                    "action": "deny(403)",
                    "match": {
                        "config": {
                            "src_ip_ranges": ["203.0.113.0/24", "198.51.100.0/24"],
                        },
                        "versioned_expr": "SRC_IPS_V1",
                    },
                }
            ],
        }
        results = _extract_ips(rules_data, "gcloud_armor_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "1000"
        assert results[0].action == "deny(403)"
        assert "203.0.113.0/24" in results[0].ip_ranges
        assert "198.51.100.0/24" in results[0].ip_ranges

    def test_extracts_from_iniprange_cel(self):
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "2000",
                    "action": "deny(403)",
                    "match": {
                        "expr": {
                            "expression": (
                                "inIpRange(origin.ip, '10.0.0.0/8') && request.method == 'POST'"
                            ),
                        }
                    },
                }
            ],
        }
        results = _extract_ips(rules_data, "gcloud_armor_custom_rules")
        assert len(results) == 1
        assert "10.0.0.0/8" in results[0].ip_ranges

    def test_combines_config_and_cel(self):
        """If a rule somehow has both config and expr, collect from both."""
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "3000",
                    "action": "allow",
                    "match": {
                        "config": {"src_ip_ranges": ["10.0.0.0/24"]},
                        "expr": {"expression": "inIpRange(origin.ip, '172.16.0.0/12')"},
                    },
                }
            ],
        }
        results = _extract_ips(rules_data, "gcloud_armor_custom_rules")
        assert len(results) == 1
        assert set(results[0].ip_ranges) == {"10.0.0.0/24", "172.16.0.0/12"}

    def test_skips_wildcard(self):
        """src_ip_ranges=['*'] is a catch-all, not a real CIDR."""
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "4000",
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["*"]}},
                }
            ],
        }
        results = _extract_ips(rules_data, "gcloud_armor_custom_rules")
        assert results == []

    def test_no_match_field(self):
        rules_data = {
            "gcloud_armor_custom_rules": [
                {"ref": "5000", "action": "allow"},
            ],
        }
        assert _extract_ips(rules_data, "gcloud_armor_custom_rules") == []

    def test_ignores_non_google_phases(self):
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "1000",
                    "action": "allow",
                    "match": {"config": {"src_ip_ranges": ["10.0.0.0/8"]}},
                }
            ],
        }
        assert _extract_ips(rules_data, "waf_custom_rules") == []

    def test_multiple_iniprange_calls(self):
        rules_data = {
            "gcloud_armor_custom_rules": [
                {
                    "ref": "6000",
                    "action": "deny(403)",
                    "match": {
                        "expr": {
                            "expression": (
                                "inIpRange(origin.ip, '10.0.0.0/8')"
                                " || inIpRange(origin.ip, '172.16.0.0/12')"
                            ),
                        }
                    },
                }
            ],
        }
        results = _extract_ips(rules_data, "gcloud_armor_custom_rules")
        assert len(results) == 1
        assert set(results[0].ip_ranges) == {"10.0.0.0/8", "172.16.0.0/12"}

    def test_rate_rules_phase(self):
        rules_data = {
            "gcloud_armor_rate_rules": [
                {
                    "ref": "7000",
                    "action": "rate_based_ban",
                    "match": {"config": {"src_ip_ranges": ["192.168.0.0/16"]}},
                }
            ],
        }
        results = _extract_ips(rules_data, "gcloud_armor_rate_rules")
        assert len(results) == 1
        assert results[0].phase_name == "gcloud_armor_rate_rules"
