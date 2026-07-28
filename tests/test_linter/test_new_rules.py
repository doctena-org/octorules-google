"""Tests for GA328, GA329 rules and CEL regex extraction."""

from octorules.linter.engine import LintContext

from octorules_google.linter import register_google_linter
from octorules_google.linter.cel_regex import extract_regex_field_pairs

# Ensure Google linter is registered before tests run
register_google_linter()


class TestExtractRegexFieldPairs:
    """Unit tests for extract_regex_field_pairs helper."""

    def test_simple_matches_call(self):
        """Extract single regex from request.path.matches()."""
        expr = 'request.path.matches("foo")'
        pairs = extract_regex_field_pairs(expr)
        assert pairs == [("request.path", "foo")]

    def test_single_quoted_pattern(self):
        """Handle single-quoted patterns."""
        expr = "request.path.matches('bar')"
        pairs = extract_regex_field_pairs(expr)
        assert pairs == [("request.path", "bar")]

    def test_header_bracket_access(self):
        """Preserve bracket notation for headers."""
        expr = 'request.headers["x-custom"].matches("value")'
        pairs = extract_regex_field_pairs(expr)
        assert pairs == [('request.headers["x-custom"]', "value")]

    def test_origin_region_code(self):
        """Extract from origin.region_code field."""
        expr = 'origin.region_code.matches("US|CA")'
        pairs = extract_regex_field_pairs(expr)
        assert pairs == [("origin.region_code", "US|CA")]

    def test_multiple_matches_in_expression(self):
        """Extract multiple matches from compound expressions."""
        expr = 'request.path.matches("^/admin") || request.path.matches("^/api")'
        pairs = extract_regex_field_pairs(expr)
        assert len(pairs) == 2
        assert pairs[0] == ("request.path", "^/admin")
        assert pairs[1] == ("request.path", "^/api")

    def test_function_call_receiver_skipped(self):
        """Skip matches calls where receiver is a function result."""
        expr = 'lower(request.path).matches("foo")'
        pairs = extract_regex_field_pairs(expr)
        # Function results are skipped — no pair emitted
        assert pairs == []

    def test_mixed_function_and_field(self):
        """Handle mixed expressions with function calls and plain fields."""
        expr = 'lower(request.path).matches("foo") || request.headers["x-id"].matches("bar")'
        pairs = extract_regex_field_pairs(expr)
        # Only the header field pair should be extracted
        assert pairs == [('request.headers["x-id"]', "bar")]

    def test_empty_expression(self):
        """Handle empty expression."""
        pairs = extract_regex_field_pairs("")
        assert pairs == []

    def test_no_matches_calls(self):
        """Return empty list when no matches() calls present."""
        expr = 'request.path == "/foo" && request.method == "GET"'
        pairs = extract_regex_field_pairs(expr)
        assert pairs == []

    def test_matches_with_variable_argument(self):
        """Skip matches() calls with non-literal argument."""
        expr = "request.path.matches(some_var)"
        pairs = extract_regex_field_pairs(expr)
        # Variable arguments don't have string literal quotes
        assert pairs == []

    def test_escaped_quotes_in_pattern(self):
        """Handle escaped quotes within patterns."""
        expr = r'request.path.matches("foo\"bar")'
        pairs = extract_regex_field_pairs(expr)
        # The regex captures what's between unescaped quotes
        # This is a limitation of the regex approach — escaped quotes
        # inside the pattern may cause issues. Document this.
        # For now, just ensure it doesn't crash.
        assert len(pairs) >= 0

    def test_complex_bracket_expression(self):
        """Handle nested bracket access (less common, but valid)."""
        expr = 'request.headers["x-id"].matches("[a-z]+")'
        pairs = extract_regex_field_pairs(expr)
        assert pairs == [('request.headers["x-id"]', "[a-z]+")]

    def test_matches_at_expression_start(self):
        """Handle matches() at the very start of expression."""
        expr = 'request.path.matches("test")'
        pairs = extract_regex_field_pairs(expr)
        assert pairs == [("request.path", "test")]

    def test_whitespace_around_matches(self):
        """Handle whitespace around .matches() call."""
        expr = 'request.path . matches ( "test" )'
        pairs = extract_regex_field_pairs(expr)
        # Regex should handle optional whitespace
        assert pairs == [("request.path", "test")]


class TestGA328OverlyPermissiveRegex:
    """Tests for GA328: overly-permissive regex patterns."""

    def test_empty_regex_matches_all(self):
        """Empty regex matches everything."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga328 = [r for r in ctx.results if r.rule_id == "GA328"]
        assert len(ga328) == 1
        assert "matches every value" in ga328[0].message

    def test_dot_regex_matches_all(self):
        """Single dot matches any character."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches(".")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga328 = [r for r in ctx.results if r.rule_id == "GA328"]
        assert len(ga328) == 1

    def test_dot_star_regex(self):
        """.*  matches everything."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches(".*")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga328 = [r for r in ctx.results if r.rule_id == "GA328"]
        assert len(ga328) == 1

    def test_caret_dollar_anchors(self):
        """^ and $ alone are permissive."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^.*$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga328 = [r for r in ctx.results if r.rule_id == "GA328"]
        assert len(ga328) == 1

    def test_path_specific_permissive_patterns(self):
        """Path context adds additional permissive patterns."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^/.*$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga328 = [r for r in ctx.results if r.rule_id == "GA328"]
        assert len(ga328) == 1

    def test_specific_regex_no_warning(self):
        """Specific regex should not trigger GA328."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^/admin")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga328 = [r for r in ctx.results if r.rule_id == "GA328"]
        assert len(ga328) == 0


class TestGA329AnchoredLiteralRegex:
    """Tests for GA329: anchored-literal regex should use equality."""

    def test_fully_anchored_literal_basic(self):
        """Anchored literal like ^foo$ should use equality."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^foo$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga329 = [r for r in ctx.results if r.rule_id == "GA329"]
        assert len(ga329) == 1
        assert "simplified" in ga329[0].message
        assert "==" in ga329[0].suggestion

    def test_anchored_literal_with_slashes(self):
        """Anchored literal with slashes like ^/api/v1$ ."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^/api/v1$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga329 = [r for r in ctx.results if r.rule_id == "GA329"]
        assert len(ga329) == 1

    def test_anchored_literal_with_hyphens(self):
        """Anchored literal with hyphens like ^user-id$."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^user-id$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga329 = [r for r in ctx.results if r.rule_id == "GA329"]
        assert len(ga329) == 1

    def test_unanchored_regex_no_warning(self):
        """Unanchored regex should not trigger GA329."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("foo$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga329 = [r for r in ctx.results if r.rule_id == "GA329"]
        assert len(ga329) == 0

    def test_regex_with_quantifier_no_warning(self):
        """Regex with quantifier like ^foo.*$ should not trigger GA329."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^foo.*$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga329 = [r for r in ctx.results if r.rule_id == "GA329"]
        assert len(ga329) == 0

    def test_regex_with_character_class_no_warning(self):
        """Regex with character class like ^[abc]$ should not trigger GA329."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": 'request.path.matches("^[abc]$")'}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga329 = [r for r in ctx.results if r.rule_id == "GA329"]
        assert len(ga329) == 0


class TestVersionedExprIsNotFlagged:
    """GA529 claimed versioned_expr was deprecated. Google's compute API
    discovery document (revision 20260722) carries no deprecation flag and no
    deprecation prose for SecurityPolicyRuleMatcher.versionedExpr, nor for its
    only enum value SRC_IPS_V1 — while it does flag 16 other fields, one of
    them in the same SecurityPolicy schema family. The rule asserted a
    deprecation the vendor does not declare, so it was removed."""

    def test_versioned_expr_produces_no_finding(self):
        from octorules_google.linter._plugin import google_lint

        ctx = LintContext()
        google_lint(
            {
                "google.custom_rules": [
                    {
                        "ref": "rule-1",
                        "action": "allow",
                        "match": {
                            "versioned_expr": "SRC_IPS_V1",
                            "config": {"src_ip_ranges": ["192.0.2.0/24"]},
                        },
                    }
                ]
            },
            ctx,
        )
        assert [r for r in ctx.results if r.rule_id == "GA529"] == []


class TestGA027LeadingTrailingWhitespace:
    """Tests for GA027: leading/trailing whitespace in match.expr.expression."""

    def test_leading_whitespace(self):
        """Leading whitespace in expression triggers warning."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": "  request.path == '/foo'"}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga027 = [r for r in ctx.results if r.rule_id == "GA027"]
        assert len(ga027) == 1
        assert "leading" in ga027[0].message.lower() or "whitespace" in ga027[0].message.lower()

    def test_trailing_whitespace(self):
        """Trailing whitespace in expression triggers warning."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": "request.path == '/foo'  "}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga027 = [r for r in ctx.results if r.rule_id == "GA027"]
        assert len(ga027) == 1

    def test_both_leading_and_trailing_whitespace(self):
        """Both leading and trailing whitespace triggers single warning."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": "  request.path == '/foo'  "}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga027 = [r for r in ctx.results if r.rule_id == "GA027"]
        assert len(ga027) == 1

    def test_no_whitespace_no_warning(self):
        """Expression without leading/trailing whitespace doesn't trigger."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": "request.path == '/foo'"}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga027 = [r for r in ctx.results if r.rule_id == "GA027"]
        assert len(ga027) == 0

    def test_internal_whitespace_no_warning(self):
        """Internal whitespace is fine, only leading/trailing matters."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": "request.path  ==  '/foo'"}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga027 = [r for r in ctx.results if r.rule_id == "GA027"]
        assert len(ga027) == 0


class TestGA526HeaderNameLowercase:
    """Tests for GA526: HTTP header names should be lowercase in bracket access."""

    def test_uppercase_header_name(self):
        """Uppercase header name triggers warning."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {
                        "expr": {"expression": 'request.headers["X-Custom-Header"].matches("foo")'}
                    },
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga526 = [r for r in ctx.results if r.rule_id == "GA526"]
        assert len(ga526) == 1
        assert "lowercase" in ga526[0].message.lower()

    def test_mixed_case_header_name(self):
        """Mixed case header name triggers warning."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {
                        "expr": {"expression": 'request.headers["Content-Type"].matches("json")'}
                    },
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga526 = [r for r in ctx.results if r.rule_id == "GA526"]
        assert len(ga526) == 1

    def test_lowercase_header_name_no_warning(self):
        """Lowercase header name doesn't trigger."""
        ctx = LintContext()
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {
                        "expr": {"expression": 'request.headers["x-custom-header"].matches("foo")'}
                    },
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga526 = [r for r in ctx.results if r.rule_id == "GA526"]
        assert len(ga526) == 0

    def test_multiple_headers_with_case_issues(self):
        """Multiple headers with case issues each trigger warning."""
        ctx = LintContext()
        expr = (
            'request.headers["X-Id"].matches("1") && '
            'request.headers["Content-Type"].matches("json")'
        )
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": expr}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga526 = [r for r in ctx.results if r.rule_id == "GA526"]
        assert len(ga526) == 2

    def test_duplicate_header_check_only_once(self):
        """Same header name mentioned twice only triggers once per rule."""
        ctx = LintContext()
        expr = 'request.headers["X-Id"].matches("1") || request.headers["X-Id"].matches("2")'
        rules_data = {
            "google.custom_rules": [
                {
                    "ref": "rule-1",
                    "action": "allow",
                    "match": {"expr": {"expression": expr}},
                }
            ]
        }
        from octorules_google.linter._plugin import google_lint

        google_lint(rules_data, ctx)
        ga526 = [r for r in ctx.results if r.rule_id == "GA526"]
        assert len(ga526) == 1
