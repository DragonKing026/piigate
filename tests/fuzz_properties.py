"""Coverage-guided fuzzing (Atheris) of the filter's pure functions and the gate's command parsing.

The targets are the property tests of tests/test_properties.py: Hypothesis turns the fuzzer's bytes into the same
generated inputs and runs the same assertions, so a crash or a broken property found by Atheris is a failing test.
Not part of the quick CI suite (needs atheris and a clang-built interpreter module; see README, "Testing"). Run:

    pip install atheris && python3 tests/fuzz_properties.py -max_total_time=60

A failing input is saved by libFuzzer as crash-*; replay it with `python3 tests/fuzz_properties.py crash-…`.
"""

import sys
import unittest
from pathlib import Path

import atheris
from hypothesis import given, strategies as st

with atheris.instrument_imports():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_properties as props


def target(strategy, test):
    """Fuzz target for a one-argument property test: the strategy of the test, its undecorated body."""
    case = test.__self__ if hasattr(test, "__self__") else None
    body = test.hypothesis.inner_test

    @given(strategy)
    def run(value):
        body(case, value)

    return run.hypothesis.fuzz_one_input


TARGETS = [
    target(props.ANY_TEXT, props.TestChecksums().test_iban_validator_never_raises_on_any_text),
    target(props.ANY_TEXT, props.TestDetection().test_detect_never_raises_and_spans_lie_inside_the_text),
    target(props.TOKENISH, props.TestGateParsing().test_expand_braces_is_bounded_and_never_raises),
    target(props.TOKENISH, props.TestGateParsing().test_strip_db_services_is_idempotent),
    target(st.lists(props.TOKENISH, max_size=8), props.TestGateParsing().test_ssh_valid_never_raises),
]


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    TARGETS[fdp.ConsumeIntInRange(0, len(TARGETS) - 1)](fdp.ConsumeBytes(len(data)))


if __name__ == "__main__":
    unittest.TestCase.maxDiff = None
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
