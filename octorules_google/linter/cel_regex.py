"""CEL regex extraction helper for Google Cloud Armor linting.

Provides regex-field pair extraction from CEL expressions, analogous to
wirefilter's regex_field_pairs for Cloudflare. Designed to support lint
rules that need both the regex pattern and the receiver field context.

Also provides general CEL expression scanning helpers for style and logic checks:
- Negated comparisons (!(a == b) → a != b)
- OR chains of same-field equality (a == "x" || a == "y" || ... → a in [...])
- Contradictory/tautological AND/OR chains (always true/false)
- Mixed && and || without parentheses (precedence clarity)
"""

import re


def extract_regex_field_pairs(expr: str) -> list[tuple[str, str]]:
    """Extract (receiver_path, regex_literal) pairs from CEL .matches() calls.

    Scans a Cloud Armor CEL expression for patterns like:
    - request.path.matches("foo") → ("request.path", "foo")
    - request.headers["x-foo"].matches("bar") → ('request.headers["x-foo"]', "bar")
    - origin.region_code.matches("FR") → ("origin.region_code", "FR")

    Returns a list of (receiver, pattern) tuples. The receiver is the
    literal text up to the .matches( call, preserving bracket notation.

    Conservative scope: skips pairs where the receiver is a function call
    (e.g., lower(request.path).matches(...) produces no pair). Also skips
    pairs where the regex argument is not a string literal.

    Args:
        expr: CEL expression string

    Returns:
        List of (receiver_path: str, regex_pattern: str) tuples
    """
    pairs: list[tuple[str, str]] = []

    # Regex to find .matches("...") or .matches('...') calls
    # Captures the quoted pattern and ensures we're at a .matches( boundary
    # Allow optional whitespace around the dot, function name, and parens
    # The pattern handles: .matches(), . matches(), .  matches  (  ), etc.
    # Use * (zero or more) instead of + (one or more) to allow empty patterns
    matches_pattern = re.compile(r"""\s*\.\s*matches\s*\(\s*(?:"([^"]*)"|'([^']*)')\s*\)""")

    for match in matches_pattern.finditer(expr):
        # Get the matched pattern (group 1 or 2 depending on quote style)
        # Use explicit None check to handle empty string patterns
        pattern = match.group(1) if match.group(1) is not None else match.group(2)

        # Find the start of the .matches call
        # The regex may start with \.? so we need to find where the receiver ends
        # It ends before the optional dot/whitespace and 'matches'
        matches_start = match.start()

        # Walk backward from matches_start to find where the dot is (or first whitespace)
        receiver_end = matches_start
        for i in range(matches_start, -1, -1):
            ch = expr[i]
            if ch == ".":
                receiver_end = i
                break
            elif ch not in " \t\n":
                # Hit a non-whitespace, non-dot character — that's where
                # the receiver ends
                receiver_end = i + 1
                break

        # Scan backward to find the start of the receiver expression
        # Track nested parens and brackets to handle bracket access like headers["x-id"]
        receiver_start = 0
        paren_depth = 0
        bracket_depth = 0

        for i in range(receiver_end - 1, -1, -1):
            ch = expr[i]

            # Track nesting depth
            if ch == ")":
                paren_depth += 1
            elif ch == "(":
                if paren_depth > 0:
                    paren_depth -= 1
                else:
                    # Open paren at depth 0 is a function call boundary
                    receiver_start = i + 1
                    break
            elif ch == "]":
                bracket_depth += 1
            elif ch == "[":
                if bracket_depth > 0:
                    bracket_depth -= 1
                # Don't break on '[' — it's part of bracket access syntax

            # Look for boundary characters (operators, logical operators) only
            # when not inside parens/brackets
            if paren_depth == 0 and bracket_depth == 0:
                if ch in " \t\n,|&!=<>+*/-":
                    receiver_start = i + 1
                    break

            # If we've walked to the start, stop
            if i == 0:
                receiver_start = 0
                break

        # Extract the receiver text, stripping whitespace
        if receiver_start < receiver_end:
            receiver = expr[receiver_start:receiver_end].strip()

            # Skip if the receiver is a function call like lower(...)
            if receiver.endswith(")") and _is_function_call(receiver):
                continue

            if receiver:
                pairs.append((receiver, pattern))

    return pairs


def _is_function_call(text: str) -> bool:
    """Check if text is a function-call expression at the top level.

    A function call has the form: word(...) where word is a function name with no
    dots or brackets. We use this to skip patterns like lower(request.path).matches(...)
    where we don't want to emit the pair.
    """
    text = text.strip()

    # If it starts with a word character followed by ( at some depth, check structure
    # Pattern: word ( ... )  with word being [a-zA-Z_][a-zA-Z0-9_]*
    if not text or (not text[0].isalpha() and text[0] != "_"):
        return False

    # Find the first open paren
    paren_pos = text.find("(")
    if paren_pos == -1:
        return False  # No parens = not a function call

    # Check what's before the paren — it should be just an identifier (word)
    prefix = text[:paren_pos].strip()
    # Valid function name: starts with letter or underscore, continues with alnum or underscore
    if not ((prefix and prefix[0].isalpha()) or prefix[0] == "_"):
        return False
    if not all(c.isalnum() or c == "_" for c in prefix):
        return False  # Has invalid characters in function name
    if not text.endswith(")"):
        return False  # Doesn't end with close paren

    # Check balanced parens
    depth = 0
    for i, ch in enumerate(text):
        if i < paren_pos:
            # Before first paren, should just be identifier
            if ch == "(" or ch == ")":
                return False
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth < 0:
            return False
    return depth == 0


def find_negated_comparisons(expr: str) -> list[tuple[int, int, str, str, str]]:
    """Find !(comparison) patterns and extract the inner operator and operands.

    Scans for patterns like !(a == b), !(a != b), !(a > b), etc. at depth zero.
    Returns list of (start_pos, end_pos, operator, lhs, rhs) tuples where operator
    is the inner comparison op (==, !=, <, >, <=, >=).

    Conservative: only returns matches where the inside is a single binary comparison
    (not a complex expression like !(a && b)).

    Args:
        expr: CEL expression string

    Returns:
        List of (start, end, operator, lhs, rhs) tuples
    """
    results = []
    i = 0
    while i < len(expr):
        if expr[i] == "!" and i + 1 < len(expr) and expr[i + 1] == "(":
            # Found potential negated paren expression
            # Scan forward to find matching close paren
            start = i
            paren_depth = 1  # Start at 1 because we're inside !( already
            j = i + 2
            inner_start = i + 2
            while j < len(expr):
                if expr[j] == "(":
                    paren_depth += 1
                elif expr[j] == ")":
                    paren_depth -= 1
                    if paren_depth == 0:
                        # Found the matching close paren
                        inner_expr = expr[inner_start:j].strip()
                        # Try to parse as a single comparison
                        op_match = _parse_single_comparison(inner_expr)
                        if op_match:
                            op, lhs, rhs = op_match
                            results.append((start, j + 1, op, lhs, rhs))
                        break
                j += 1
            i = j + 1
        else:
            i += 1
    return results


def find_or_chains_eq_same_field(expr: str) -> list[tuple[str, list[str]]]:
    """Find || chains of (field == "literal") where N >= 3 operands.

    Scans for patterns like:
    a == "x" || a == "y" || a == "z"

    Returns list of (field, [literal_values]) tuples. Only returns matches
    where all operands use the same field and the same comparison operator (==).
    Only fires for N >= 3 to avoid noise.

    Args:
        expr: CEL expression string

    Returns:
        List of (field, [values]) tuples
    """
    results = []
    # Split by || at depth zero
    or_operands = _split_at_operator(expr, "||")
    if len(or_operands) < 3:
        return results

    # Check if all operands are (field == "literal")
    field_to_values = {}
    for operand in or_operands:
        operand = operand.strip()
        parsed = _parse_single_comparison(operand)
        if not parsed:
            return []  # Not a simple comparison
        op, lhs, rhs = parsed
        if op != "==":
            return []  # Mixed operators
        # Extract field name (lhs)
        field = lhs.strip()
        if not _is_simple_field_ref(field):
            return []  # Complex lhs
        if not _is_string_literal(rhs):
            return []  # Not a string literal on rhs
        value = _extract_string_literal_value(rhs)
        if field not in field_to_values:
            field_to_values[field] = []
        field_to_values[field].append(value)

    # Return all fields that have >= 3 values
    for field, values in field_to_values.items():
        if len(values) >= 3:
            results.append((field, values))

    return results


def find_contradictory_and(expr: str) -> list[tuple[str, list[str]]]:
    """Find AND chains where same field has contradictory == with different literals.

    Example: a == "x" && a == "y" → always false (same field, both ==, different RHS).

    Args:
        expr: CEL expression string

    Returns:
        List of (field, [literal_values]) tuples
    """
    results = []
    and_operands = _split_at_operator(expr, "&&")
    if len(and_operands) < 2:
        return results

    field_to_values = {}
    for operand in and_operands:
        operand = operand.strip()
        parsed = _parse_single_comparison(operand)
        if not parsed:
            return []
        op, lhs, rhs = parsed
        if op != "==":
            return []
        field = lhs.strip()
        if not _is_simple_field_ref(field):
            return []
        if not _is_string_literal(rhs):
            return []
        value = _extract_string_literal_value(rhs)
        if field not in field_to_values:
            field_to_values[field] = []
        field_to_values[field].append(value)

    # Find fields with multiple different values (contradiction)
    for field, values in field_to_values.items():
        if len(values) >= 2 and len(set(values)) > 1:
            results.append((field, list(set(values))))

    return results


def has_mixed_and_or_at_depth_zero(expr: str) -> bool:
    """Check if expr has both && and || at depth zero without explicit parens grouping.

    Pattern: a && b || c or a || b && c at the top level (not within parens).
    This is legal CEL (&& has higher precedence) but can be confusing.

    Returns True only if both operators appear at depth zero and neither
    is already fully parenthesized to disambiguate precedence.

    Args:
        expr: CEL expression string

    Returns:
        True if mixed && and || at depth zero are detected
    """
    depth = 0
    has_and = False
    has_or = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            if i + 1 < len(expr):
                two_char = expr[i : i + 2]
                if two_char == "&&":
                    has_and = True
                elif two_char == "||":
                    has_or = True
        i += 1

    return has_and and has_or


# Helper functions


def _parse_single_comparison(expr: str) -> tuple[str, str, str] | None:
    """Try to parse a single binary comparison and return (op, lhs, rhs).

    Handles: ==, !=, <, >, <=, >=.
    Returns None if not a single comparison.

    Conservative: rejects if there are logical operators (&&, ||) at depth zero.

    Args:
        expr: Expression to parse

    Returns:
        Tuple of (operator, left_side, right_side) or None
    """
    expr = expr.strip()

    # Quick check: if there are logical operators at depth zero, reject
    depth = 0
    for i in range(len(expr)):
        if expr[i] == "(":
            depth += 1
        elif expr[i] == ")":
            depth -= 1
        elif depth == 0:
            if i + 1 < len(expr):
                two_char = expr[i : i + 2]
                if two_char in ("&&", "||"):
                    return None  # Has logical operators at depth zero

    # Try operators in order of specificity (longest first)
    for op in ["<=", ">=", "==", "!=", "<", ">"]:
        parts = expr.split(op, 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            # Check that we're not splitting on a substring of a larger operator
            # (e.g., splitting "<<" on "<")
            idx = expr.find(op)
            if idx > 0:
                # Make sure the character before the op (if any) isn't part of another op
                before = expr[idx - 1] if idx > 0 else ""
                after = expr[idx + len(op)] if idx + len(op) < len(expr) else ""
                # Reject if we'd be splitting something like "==" on a single "="
                if op == "=" and (before == "=" or after == "="):
                    continue
                if op == "<" and (before == "<" or after == "<"):
                    continue
                if op == ">" and (before == ">" or after == ">"):
                    continue
            return (op, parts[0].strip(), parts[1].strip())
    return None


def _split_at_operator(expr: str, op: str) -> list[str]:
    """Split expression by operator at depth zero only.

    Args:
        expr: Expression to split
        op: Operator (e.g., "||", "&&")

    Returns:
        List of operands
    """
    operands = []
    current = []
    depth = 0
    i = 0
    while i < len(expr):
        if expr[i] == "(":
            depth += 1
            current.append(expr[i])
        elif expr[i] == ")":
            depth -= 1
            current.append(expr[i])
        elif depth == 0 and i + len(op) <= len(expr) and expr[i : i + len(op)] == op:
            operands.append("".join(current))
            current = []
            i += len(op) - 1
        else:
            current.append(expr[i])
        i += 1
    operands.append("".join(current))
    return [op.strip() for op in operands if op.strip()]


def _is_simple_field_ref(text: str) -> bool:
    """Check if text is a simple field reference (e.g., request.path, origin.region_code).

    Allows dots and brackets (for header access like request.headers["x-foo"]).
    Rejects function calls.

    Args:
        text: Text to check

    Returns:
        True if simple field reference
    """
    if not text or text[0].isdigit():
        return False
    # Check for function call signature
    if "(" in text:
        return False
    # Simple heuristic: alphanumeric, dots, underscores, brackets
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.[]"-')
    return all(c in allowed for c in text)


def _is_string_literal(text: str) -> bool:
    """Check if text is a string literal (quoted).

    Args:
        text: Text to check

    Returns:
        True if starts and ends with matching quotes
    """
    text = text.strip()
    return (text.startswith('"') and text.endswith('"')) or (
        text.startswith("'") and text.endswith("'")
    )


def _extract_string_literal_value(text: str) -> str:
    """Extract the value from a quoted string literal.

    Args:
        text: Quoted string (e.g., '"foo"' or "'bar'")

    Returns:
        Unquoted value
    """
    text = text.strip()
    if (text.startswith('"') and text.endswith('"')) or (
        text.startswith("'") and text.endswith("'")
    ):
        return text[1:-1]
    return text
