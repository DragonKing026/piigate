"""Property-based tests (Hypothesis) of the pure, deterministic parts of the filter and the gate — on generated data.

They check properties, not examples: no exception on any input, checksum validators accept exactly the numbers built
with the checksum, bounded output, spans inside the text. No Presidio and no network needed. Run:

    pip install --require-hashes -r tests/requirements.txt && python3 -I tests/test_properties.py

Without hypothesis installed the file is skipped (the other suites do not need it). The same properties serve as
fuzz targets: tests/fuzz_properties.py hands them to Atheris (coverage-guided fuzzing).
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

TMP = Path(tempfile.mkdtemp(prefix="piigate-props-"))
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "filter-data")
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "config")

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ImportError:  # the plain suites run without hypothesis
    print("hypothesis not installed — property tests skipped", file=sys.stderr)
    sys.exit(0)

from piigate import config, gate, rules, text, verdict
from piigate.pseudonym_map import PseudonymMap, normalize

settings.register_profile("ci", max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile("ci")

ANY_TEXT = st.text(max_size=300)
# text biased towards the characters the rules and the gate parse
TOKENISH = st.text(alphabet=st.sampled_from(list("abcXYZ019 -./,:;@{}()[]<>|&$'\"\\\n\tąęół")), max_size=200)


def with_pesel_check(first10: list[int]) -> str:
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    check = (10 - sum(d * w for d, w in zip(first10, weights)) % 10) % 10
    return "".join(map(str, first10)) + str(check)


def with_nip_check(first9: list[int]) -> str | None:
    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    check = sum(d * w for d, w in zip(first9, weights)) % 11
    return "".join(map(str, first9)) + str(check) if check < 10 else None  # check digit 10 = no valid NIP


def with_luhn_check(body: list[int]) -> str:
    total = 0
    for i, d in enumerate(reversed(body)):  # the check digit will sit at position 0, so the body starts at 1
        d = d * (2 if (i + 1) % 2 else 1)
        total += d - 9 if d > 9 else d
    return "".join(map(str, body)) + str((10 - total % 10) % 10)


def with_iban_check(country: str, bban: str) -> str:
    rotated = bban + country + "00"
    check = 98 - int("".join(str(int(ch, 36)) for ch in rotated)) % 97
    return f"{country}{check:02d}{bban}"


class TestChecksums(unittest.TestCase):
    @given(st.lists(st.integers(0, 9), min_size=10, max_size=10))
    def test_pesel_accepts_built_numbers_and_rejects_a_wrong_check_digit(self, first10):
        number = with_pesel_check(first10)
        self.assertTrue(rules.pesel_valid(number))
        self.assertFalse(rules.pesel_valid(number[:10] + str((int(number[10]) + 1) % 10)))

    @given(st.lists(st.integers(0, 9), min_size=9, max_size=9))
    def test_nip_accepts_built_numbers_and_rejects_a_wrong_check_digit(self, first9):
        number = with_nip_check(first9)
        if number is None:
            return
        self.assertTrue(rules.nip_valid(number))
        self.assertFalse(rules.nip_valid(number[:9] + str((int(number[9]) + 1) % 10)))

    @given(st.lists(st.integers(0, 9), min_size=12, max_size=18))
    def test_luhn_accepts_built_numbers_and_rejects_a_wrong_check_digit(self, body):
        number = with_luhn_check(body)
        self.assertTrue(rules.luhn_valid(number))
        self.assertFalse(rules.luhn_valid(number[:-1] + str((int(number[-1]) + 1) % 10)))

    @given(st.from_regex(r"[A-Z]{2}", fullmatch=True), st.from_regex(r"[A-Z0-9]{10,30}", fullmatch=True))
    def test_iban_accepts_built_numbers(self, country, bban):
        self.assertTrue(rules.iban_valid(with_iban_check(country, bban)))

    # Contract: detect() passes the validators digits only (it strips everything else with \D first). Outside the
    # contract pesel/nip/luhn raise ValueError on e.g. "000000000000:" or a superscript digit (str.isdigit() is true
    # for it, int() fails) — not reachable from the filter, so the property is stated for the contract input.
    @given(st.from_regex(r"[0-9]{0,30}", fullmatch=True))
    def test_digit_validators_never_raise_on_digits(self, s):
        for check in (rules.pesel_valid, rules.nip_valid, rules.luhn_valid):
            self.assertIsInstance(check(s), bool)

    @given(ANY_TEXT)
    def test_iban_validator_never_raises_on_any_text(self, s):
        self.assertIsInstance(rules.iban_valid(s), bool)


class TestDetection(unittest.TestCase):
    @given(ANY_TEXT)
    def test_detect_never_raises_and_spans_lie_inside_the_text(self, s):
        for f in rules.detect(s):
            self.assertTrue(0 <= f.start <= f.end <= len(s), (f, len(s)))

    @given(st.lists(st.integers(0, 9), min_size=10, max_size=10), st.text(alphabet="abc xyz.,", max_size=20))
    def test_a_valid_pesel_is_always_detected(self, first10, noise):
        number = with_pesel_check(first10)
        found = rules.detect(f"{noise} {number} {noise}")
        self.assertTrue(any(f.type_ in {"PESEL", "NUMBER"} and f.start < f.end for f in found))

    @given(ANY_TEXT)
    def test_detect_with_dates_off_has_no_dates(self, s):
        self.assertFalse([f for f in rules.detect(s, dates="none") if f.type_ == "DATE"])

    @given(ANY_TEXT)
    def test_check_text_counts_are_positive(self, s):
        for label, n in verdict.check_text(s, config.load()).items():
            self.assertIsInstance(label, str)
            self.assertGreater(n, 0)


class TestPseudonymization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = config.load()
        cls.pmap = PseudonymMap()

    @given(st.sampled_from(["PERSON", "PHONE", "PESEL", "NIP", "EMAIL"]), ANY_TEXT)
    def test_normalize_ignores_surrounding_whitespace(self, type_, value):
        a = normalize(type_, value)
        self.assertEqual(normalize(type_, f"  {value}  "), normalize(type_, f" \t{value}\n "))
        if type_ in {"PHONE", "PESEL", "NIP"}:
            self.assertEqual(normalize(type_, a), a)  # digit types: idempotent

    @given(st.text(alphabet="0123456789 -+()", min_size=1, max_size=20))
    def test_the_same_value_gets_the_same_pseudonym(self, value):
        first = self.pmap.pseudonym("PHONE", "PHONE", value)
        self.assertEqual(self.pmap.pseudonym("PHONE", "PHONE", value), first)
        self.assertRegex(first, r"^PHONE_\d+$")

    @given(st.lists(st.integers(0, 9), min_size=10, max_size=10), st.text(alphabet="abc xyz.,\n", max_size=30))
    def test_the_filtered_text_does_not_contain_a_valid_pesel(self, first10, noise):
        number = with_pesel_check(first10)
        result, counter = text.filter_text(
            f"{noise} {number} {noise}", self.cfg, rules_only=True, pseudonym_map=self.pmap
        )
        self.assertNotIn(number, result)
        self.assertTrue(counter)

    @given(ANY_TEXT)
    def test_rules_only_filtering_never_raises_and_no_hit_means_no_change(self, s):
        result, counter = text.filter_text(s, self.cfg, rules_only=True, pseudonym_map=self.pmap)
        if not counter:
            self.assertEqual(result, s)

    @given(ANY_TEXT)
    def test_restoring_text_without_pseudonyms_changes_nothing(self, s):
        if not re.search(r"[A-Z_]+_\d+", s):
            self.assertEqual(self.pmap.reverse(s), s)


class TestGateParsing(unittest.TestCase):
    @given(TOKENISH)
    def test_expand_braces_is_bounded_and_never_raises(self, t):
        result = gate.expand_braces(t)
        self.assertTrue(1 <= len(result) <= 256)
        if "{" not in t:
            self.assertEqual(result, [t])

    @given(st.integers(-20, 20), st.integers(-20, 20))
    def test_expand_braces_numeric_range_covers_both_ends(self, a, b):
        result = gate.expand_braces("x{%d..%d}y" % (a, b))
        self.assertEqual(len(result), abs(a - b) + 1)
        self.assertIn(f"x{a}y", result)
        self.assertIn(f"x{b}y", result)

    @given(st.lists(st.sampled_from(["2", ">&", "1", "ls", "-l", "x"]), max_size=20))
    def test_strip_2to1_only_removes_whole_triples_and_keeps_the_order(self, tokens):
        result = gate.strip_2to1(tokens)
        it = iter(tokens)
        self.assertTrue(all(any(t == u for u in it) for t in result))  # a subsequence of the input
        self.assertEqual((len(tokens) - len(result)) % 3, 0)
        if not any(tokens[i : i + 3] == ["2", ">&", "1"] for i in range(len(tokens))):
            self.assertEqual(result, tokens)

    @given(TOKENISH)
    def test_flat_removes_quotes_and_backslashes_only(self, t):
        self.assertEqual(gate._flat(t), "".join(c for c in t if c not in "\"'\\"))

    @given(TOKENISH)
    def test_strip_db_services_is_idempotent(self, t):
        once = gate.strip_db_services(t)
        self.assertEqual(gate.strip_db_services(once), once)

    @given(st.lists(TOKENISH, max_size=8))
    def test_ssh_valid_never_raises(self, arguments):
        self.assertIsInstance(gate.ssh_valid(arguments), bool)


if __name__ == "__main__":
    unittest.main()
