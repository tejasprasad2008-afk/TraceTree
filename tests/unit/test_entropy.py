"""
Unit tests for monitor.yara._calculate_entropy.

Covers:
- Empty string → 0.0
- Single character → 0.0
- Two equal-probability chars → exactly 1.0
- High-entropy base64-like string → >= 5.0
- Low-entropy repeated char → 0.0
- lru_cache determinism (calling twice returns same result)
- Parametrized known-value assertions using pytest.approx
"""
import math
import pytest

from monitor.yara import _calculate_entropy


# ---------------------------------------------------------------------------
# Basic edge cases
# ---------------------------------------------------------------------------

def test_empty_string_returns_zero():
    assert _calculate_entropy("") == 0.0


def test_single_char_returns_zero():
    assert _calculate_entropy("a") == 0.0


def test_two_equal_chars_returns_one():
    """'ab' has two symbols each with probability 0.5 → H = -2*(0.5*log2(0.5)) = 1.0"""
    result = _calculate_entropy("ab")
    assert result == pytest.approx(1.0, abs=1e-10)


def test_high_entropy_base64_exceeds_threshold():
    """A pseudo-random base64 string of 1000 chars must have entropy >= 5.0."""
    # Use a deterministic but diverse base64-alphabet string to avoid flakiness
    import string, itertools
    alphabet = string.ascii_letters + string.digits + "+/"
    # Cycle through the 64-character alphabet to get uniform-ish distribution
    payload = "".join(itertools.islice(itertools.cycle(alphabet), 1000))
    result = _calculate_entropy(payload)
    assert result >= 5.0, f"Expected entropy >= 5.0, got {result}"


def test_low_entropy_repeated_char():
    """1000 identical chars has zero entropy."""
    assert _calculate_entropy("a" * 1000) == 0.0


def test_cache_returns_consistent_result():
    """Calling twice with identical input must return the same value (lru_cache must not corrupt)."""
    first = _calculate_entropy("hello world test string 123")
    second = _calculate_entropy("hello world test string 123")
    assert first == second


# ---------------------------------------------------------------------------
# Parametrized known-value assertions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("data, expected_approx", [
    # Single char: H = 0
    ("z", 0.0),
    # Two equal chars: H = 1.0
    ("ab", 1.0),
    # Four equal chars: H = 2.0  ("abcd" → 4 symbols, each prob 0.25)
    ("abcd", 2.0),
    # 8 uniform chars: H = 3.0
    ("abcdefgh", 3.0),
    # All-same short string
    ("aaaa", 0.0),
    # Two chars unequal: "aab" → p(a)=2/3, p(b)=1/3
    #   H = -(2/3)*log2(2/3) - (1/3)*log2(1/3) ≈ 0.9183
    ("aab", pytest.approx(-(2/3) * math.log2(2/3) - (1/3) * math.log2(1/3), abs=1e-9)),
])
def test_parametrized_known_values(data, expected_approx):
    result = _calculate_entropy(data)
    assert result == expected_approx, (
        f"_calculate_entropy({data!r}) returned {result}, expected ~{expected_approx}"
    )
