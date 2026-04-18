"""End-to-end tests for the 'octorules lint' CLI command with the Google provider."""

from pathlib import Path

import pytest
from octorules.cli import build_parser, cmd_lint, main
from octorules.config import Config

# Importing the provider module triggers register_google_linter() at
# module load time, which is what cmd_lint depends on.
import octorules_google  # noqa: F401


@pytest.fixture
def lint_config(tmp_path):
    """Minimal config + rules files exercising Google-specific lint paths."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    # Clean rules — public IPs only.
    (rules_dir / "clean-policy.yaml").write_text(
        "gcloud_armor_custom_rules:\n"
        "  - ref: '1000'\n"
        "    description: Block public bad IP\n"
        "    action: deny(403)\n"
        "    match:\n"
        "      versioned_expr: SRC_IPS_V1\n"
        "      config:\n"
        "        src_ip_ranges:\n"
        "          - 1.2.3.0/24\n"
    )

    # Rules with multiple GA violations.
    (rules_dir / "bad-policy.yaml").write_text(
        "gcloud_armor_custom_rules:\n"
        # GA503: reserved IP in src_ip_ranges.
        "  - ref: '1000'\n"
        "    description: Accidentally block RFC 1918\n"
        "    action: deny(403)\n"
        "    match:\n"
        "      versioned_expr: SRC_IPS_V1\n"
        "      config:\n"
        "        src_ip_ranges:\n"
        "          - 10.0.0.0/8\n"
        # GA306: catch-all /0.
        "  - ref: '1001'\n"
        "    description: Catch-all\n"
        "    action: deny(403)\n"
        "    match:\n"
        "      versioned_expr: SRC_IPS_V1\n"
        "      config:\n"
        "        src_ip_ranges:\n"
        "          - 0.0.0.0/0\n"
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  google:\n"
        "    project: test-project\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  clean-policy:\n"
        "    sources:\n"
        "      - rules\n"
        "  bad-policy:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return Config.from_file(config_file)


class TestBuildParser:
    def test_lint_subcommand_exists(self):
        parser = build_parser()
        args = parser.parse_args(["lint"])
        assert args.command == "lint"

    def test_lint_rule_filter_accepts_ga_codes(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--rule", "GA503", "--rule", "GA306"])
        assert args.lint_rules == ["GA503", "GA306"]


class TestCmdLint:
    def test_clean_rules_exit_0(self, lint_config):
        rc = cmd_lint(lint_config, ["clean-policy"])
        assert rc == 0

    def test_bad_rules_surface_findings(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"])
        captured = capsys.readouterr()
        assert "GA503" in captured.out
        assert "GA306" in captured.out

    def test_json_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"], lint_format="json")
        captured = capsys.readouterr()
        assert '"rule_id"' in captured.out
        assert "GA503" in captured.out

    def test_sarif_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"], lint_format="sarif")
        captured = capsys.readouterr()
        assert '"version": "2.1.0"' in captured.out

    def test_rule_filter_scopes_output(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-policy"], lint_rules=["GA503"])
        captured = capsys.readouterr()
        assert "GA503" in captured.out
        assert "GA306" not in captured.out

    def test_output_file(self, lint_config, tmp_path):
        out_file = str(tmp_path / "lint-report.txt")
        cmd_lint(lint_config, ["bad-policy"], output_file=out_file)
        assert Path(out_file).exists()
        assert "GA" in Path(out_file).read_text()


class TestMainLintCommand:
    def test_main_lint_exits_zero_on_clean(self, lint_config, tmp_path):
        config_file = tmp_path / "config.yaml"
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(config_file), "lint", "--zone", "clean-policy"])
        assert exc_info.value.code == 0
