"""String-literal awareness in the CEL scanning helpers.

Regression cover for two bugs found in the pre-1.0.0 audit:

* ``extract_regex_field_pairs`` used a naive ``"[^"]*"`` literal pattern, so a
  regex containing an escaped quote extracted nothing at all and GA328/GA329
  silently skipped it.
* ``_parse_single_comparison`` split on the first operator found anywhere in the
  string, including inside a quoted value, so ``a == "x<=y"`` parsed as a ``<=``
  comparison with mangled operands.

The same class of defect applied to every character scanner in the module —
parens and logical operators inside a literal were read as syntax — so the
tests below cover all four entry points, not just the two reported.
"""

from octorules_google.linter.cel_regex import (
    _parse_single_comparison,
    _split_at_operator,
    extract_regex_field_pairs,
    has_mixed_and_or_at_depth_zero,
    strip_string_literals,
)


class TestEscapedQuotesInRegexLiterals:
    """extract_regex_field_pairs must not stop at an escaped quote."""

    def test_escaped_double_quote_is_extracted(self):
        """A pattern containing \\" yields a pair rather than nothing."""
        expr = r'request.path.matches("foo\"bar")'
        assert extract_regex_field_pairs(expr) == [("request.path", r"foo\"bar")]

    def test_escaped_single_quote_is_extracted(self):
        r"""The single-quoted branch is escape-aware too."""
        expr = r"request.path.matches('foo\'bar')"
        assert extract_regex_field_pairs(expr) == [("request.path", r"foo\'bar")]

    def test_escaped_backslash_before_closing_quote(self):
        """A trailing escaped backslash must not swallow the closing quote."""
        expr = r'request.path.matches("foo\\")'
        assert extract_regex_field_pairs(expr) == [("request.path", r"foo\\")]

    def test_plain_pattern_still_works(self):
        """The common case is unaffected by the escape handling."""
        assert extract_regex_field_pairs('request.path.matches("foo")') == [("request.path", "foo")]

    def test_empty_pattern_still_works(self):
        """An empty pattern is still extracted (zero-or-more, not one-or-more)."""
        assert extract_regex_field_pairs('request.path.matches("")') == [("request.path", "")]


class TestOperatorsInsideStringLiterals:
    """_parse_single_comparison must ignore operators inside quoted values."""

    def test_comparison_operator_inside_literal(self):
        """``a == "x<=y"`` is an == comparison, not a <= one."""
        assert _parse_single_comparison('request.path == "a<=b"') == (
            "==",
            "request.path",
            '"a<=b"',
        )

    def test_inequality_inside_literal(self):
        """A != inside the right-hand value does not become the operator."""
        assert _parse_single_comparison('a == "x != y"') == ("==", "a", '"x != y"')

    def test_operands_keep_their_literals(self):
        """The parsed operands are sliced from the original, not the mask."""
        _, lhs, rhs = _parse_single_comparison('origin.region_code == "FR"')
        assert lhs == "origin.region_code"
        assert rhs == '"FR"'

    def test_logical_operator_inside_literal_does_not_reject(self):
        """&& inside a value must not be read as a depth-zero logical operator."""
        assert _parse_single_comparison('a == "x && y"') == ("==", "a", '"x && y"')

    def test_real_logical_operator_still_rejects(self):
        """A genuine depth-zero && still makes this not a single comparison."""
        assert _parse_single_comparison("a == b && c == d") is None

    def test_unbalanced_paren_inside_literal(self):
        """An unmatched paren inside a literal must not corrupt depth tracking."""
        assert _parse_single_comparison('a == "("') == ("==", "a", '"("')

    def test_plain_comparisons_unaffected(self):
        """Ordinary operators still parse, longest-match first."""
        assert _parse_single_comparison("a >= b") == (">=", "a", "b")
        assert _parse_single_comparison("a != b") == ("!=", "a", "b")
        assert _parse_single_comparison("a < b") == ("<", "a", "b")


class TestSplitAtOperatorLiterals:
    """_split_at_operator must not split on operators inside literals."""

    def test_or_inside_literal_does_not_split(self):
        """A || inside a quoted value keeps the operand intact."""
        assert _split_at_operator('a == "x||y" || b == "z"', "||") == [
            'a == "x||y"',
            'b == "z"',
        ]

    def test_and_inside_literal_does_not_split(self):
        """Same for &&."""
        assert _split_at_operator('a == "x&&y" && b == "z"', "&&") == [
            'a == "x&&y"',
            'b == "z"',
        ]

    def test_paren_inside_literal_does_not_shift_depth(self):
        """An open paren in a literal must not hide a real top-level operator."""
        assert _split_at_operator('a == "(" || b == "c"', "||") == ['a == "("', 'b == "c"']

    def test_real_parens_still_group(self):
        """Genuine parentheses still suppress the split."""
        assert _split_at_operator("(a || b) || c", "||") == ["(a || b)", "c"]


class TestMixedAndOrLiterals:
    """has_mixed_and_or_at_depth_zero must ignore operators inside literals."""

    def test_and_inside_literal_is_not_mixed(self):
        """A && in a value with a real || is not a mixed-precedence expression."""
        assert has_mixed_and_or_at_depth_zero('a == "x && y" || b') is False

    def test_genuine_mix_still_detected(self):
        """A real mix at depth zero is still reported."""
        assert has_mixed_and_or_at_depth_zero("a && b || c") is True

    def test_parenthesised_mix_not_flagged(self):
        """Explicit grouping suppresses the finding."""
        assert has_mixed_and_or_at_depth_zero("(a && b) || c") is False


class TestStripStringLiterals:
    """The shared helper is escape-aware and used by both modules."""

    def test_strips_escaped_quote_literal_whole(self):
        """A literal containing an escaped quote is removed in full."""
        assert strip_string_literals(r'a == "x\"y" && b') == "a ==  && b"

    def test_strips_both_quote_styles(self):
        """Single and double quoted literals are both removed."""
        assert strip_string_literals("a == 'x' && b == \"y\"") == "a ==  && b == "

    def test_leaves_unquoted_text(self):
        """Text outside literals is untouched."""
        assert strip_string_literals("request.path == origin.ip") == ("request.path == origin.ip")
