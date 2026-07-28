"""The shipped ``examples/`` must lint clean.

``examples/`` is executable documentation — users copy-paste from it — and
nothing else in CI reads it.  The tree is excluded from the wheel, so the
repo is its distribution channel: two defect classes reached published
repos this way (bare-string ``lists`` items and a non-string ruleset id)
and were caught only by a hand audit months later.

This is a test rather than a pre-commit hook so that it runs on every
supported Python in CI and cannot be skipped by a missing
``pre-commit install``.
"""

import json
from pathlib import Path

import pytest
from octorules.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

# Findings the examples raise on purpose, as {rule_id: count}.  Errors are
# never expected.  Update this map deliberately: a changed count means an
# example gained or lost a finding, which is exactly the review moment this
# test exists to force.
EXPECTED_NON_ERRORS = {
    "GA503": 2,
    "GA601": 1,
}


def _lint_examples(tmp_path: Path) -> tuple[int, list[dict]]:
    """Lint the examples tree, returning (exit_code, findings)."""
    out = tmp_path / "lint.json"
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--config",
                str(EXAMPLES / "config.yaml"),
                "lint",
                "--format",
                "json",
                "--output",
                str(out),
            ]
        )

    # One JSON document per rules file, concatenated.
    text = out.read_text()
    decoder = json.JSONDecoder()
    findings: list[dict] = []
    idx = 0
    while idx < len(text):
        if text[idx].isspace():
            idx += 1
            continue
        doc, idx = decoder.raw_decode(text, idx)
        findings.extend(doc.get("results", []))
    return exc_info.value.code, findings


def test_examples_lint_without_errors(tmp_path):
    """No ERROR-severity finding may ship in the examples."""
    code, findings = _lint_examples(tmp_path)
    errors = [f for f in findings if f["severity"] == "error"]
    assert not errors, "examples/ has lint errors:\n" + "\n".join(
        f"  {f['rule_id']}: {f['message']}" for f in errors
    )
    assert code == 0


def test_example_findings_are_the_expected_ones(tmp_path):
    """Non-error findings match EXPECTED_NON_ERRORS exactly.

    Guards against a new intentional-looking finding being added without
    anyone acknowledging it.
    """
    _, findings = _lint_examples(tmp_path)
    counts: dict[str, int] = {}
    for f in findings:
        if f["severity"] == "error":
            continue
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
    assert counts == EXPECTED_NON_ERRORS
