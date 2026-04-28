"""Shared fixtures for the Google Cloud Armor linter test suite.

Assertion helpers (``assert_lint``, ``assert_no_lint``) live in
``octorules.testing.lint``; this conftest only ensures Google rules are
registered before tests run.
"""

from octorules_google.linter import register_google_linter

# Ensure Google linter rules are registered before any test in this directory runs.
register_google_linter()
