"""The pytest config ignores google.api_core's interpreter advisories."""

import warnings

import pytest


@pytest.mark.parametrize(
    "message",
    [
        "You are using a Python version (3.11.14) which Google will stop supporting in new"
        " releases of google.api_core once it reaches its end of life (2027-10-24).",
        "You are using a Python version (3.11.14) past its end of life.",
        "You are using a non-supported Python version (3.11.14).",
    ],
)
def test_api_core_interpreter_warning_is_ignored(message):
    # filterwarnings = "error" turns an unmatched one into a failure here.
    warnings.warn(message, FutureWarning, stacklevel=1)
