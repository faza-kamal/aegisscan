"""
tests/test_port_parser.py
Unit tests for core/port_parser.py — every edge case.
Run: pytest tests/test_port_parser.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.port_parser import PortParser, PortParseError


@pytest.fixture
def parser():
    return PortParser()


# ── Single port ────────────────────────────────────────────────────────────────

class TestSinglePort:
    def test_min_port(self, parser):              assert parser.parse("1") == [1]
    def test_max_port(self, parser):              assert parser.parse("65535") == [65535]
    def test_common_http(self, parser):           assert parser.parse("80") == [80]
    def test_common_https(self, parser):          assert parser.parse("443") == [443]

    def test_zero_is_invalid(self, parser):
        with pytest.raises(PortParseError, match="out of valid range"):
            parser.parse("0")

    def test_above_max_is_invalid(self, parser):
        with pytest.raises(PortParseError, match="out of valid range"):
            parser.parse("65536")

    def test_negative_port_is_invalid(self, parser):
        with pytest.raises(PortParseError, match="Invalid port token"):
            parser.parse("-80")

    def test_float_is_invalid(self, parser):
        with pytest.raises(PortParseError, match="Invalid port token"):
            parser.parse("80.5")

    def test_alpha_is_invalid(self, parser):
        with pytest.raises(PortParseError, match="Invalid port token"):
            parser.parse("http")


# ── Multiple ports ────────────────────────────────────────────────────────────

class TestMultiplePorts:
    def test_two_ports(self, parser):
        assert parser.parse("80,443") == [80, 443]

    def test_sorted_output(self, parser):
        assert parser.parse("443,22,80") == [22, 80, 443]

    def test_duplicates_removed(self, parser):
        assert parser.parse("80,80,80") == [80]

    def test_mixed_duplicates(self, parser):
        assert parser.parse("80,443,80,443,22") == [22, 80, 443]

    def test_whitespace_stripped(self, parser):
        assert parser.parse("  80 , 443 , 8080  ") == [80, 443, 8080]

    def test_trailing_comma_ignored(self, parser):
        # trailing comma → empty token, should be ignored
        result = parser.parse("80,443,")
        assert result == [80, 443]


# ── Ranges ────────────────────────────────────────────────────────────────────

class TestRanges:
    def test_small_range(self, parser):
        assert parser.parse("80-85") == [80, 81, 82, 83, 84, 85]

    def test_single_element_range(self, parser):
        assert parser.parse("80-80") == [80]

    def test_range_start_gt_end_invalid(self, parser):
        with pytest.raises(PortParseError, match="start > end"):
            parser.parse("100-50")

    def test_range_contains_invalid_port(self, parser):
        with pytest.raises(PortParseError, match="out of valid range"):
            parser.parse("65534-65537")

    def test_range_alpha_invalid(self, parser):
        with pytest.raises(PortParseError):
            parser.parse("a-z")


# ── Mixed format ──────────────────────────────────────────────────────────────

class TestMixed:
    def test_mixed_standard(self, parser):
        result = parser.parse("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_range_and_overlap(self, parser):
        result = parser.parse("80-85,83")
        assert result == [80, 81, 82, 83, 84, 85]  # 83 deduplicated

    def test_all_ports_keyword(self, parser):
        result = parser.parse("-")
        assert result[0] == 1
        assert result[-1] == 65535
        assert len(result) == 65535


# ── Validation helper ─────────────────────────────────────────────────────────

class TestValidate:
    def test_valid_returns_true(self, parser):
        ok, msg = parser.validate("80,443")
        assert ok is True
        assert msg == ""

    def test_invalid_returns_false(self, parser):
        ok, msg = parser.validate("abc")
        assert ok is False
        assert msg != ""

    def test_out_of_range_returns_false(self, parser):
        ok, msg = parser.validate("99999")
        assert ok is False
        assert "99999" in msg


# ── Edge / security ───────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_string(self, parser):
        with pytest.raises(PortParseError, match="empty"):
            parser.parse("")

    def test_only_whitespace(self, parser):
        with pytest.raises(PortParseError, match="empty"):
            parser.parse("   ")

    def test_none_raises_type_error(self, parser):
        with pytest.raises(PortParseError, match="Expected string"):
            parser.parse(None)

    def test_list_raises_type_error(self, parser):
        with pytest.raises(PortParseError, match="Expected string"):
            parser.parse([80, 443])

    def test_injection_attempt(self, parser):
        # SQL-like / shell meta chars should fail as invalid port token
        with pytest.raises(PortParseError):
            parser.parse("80; DROP TABLE scans; --")

    def test_very_long_input(self, parser):
        # Should fail cleanly without hanging
        junk = "x" * 10000
        with pytest.raises(PortParseError):
            parser.parse(junk)


# ── top-N (requires nmap-services data file) ─────────────────────────────────

class TestTopN:
    def test_top10_returns_10_ports(self, parser):
        ports = parser.parse("top10")
        assert len(ports) == 10
        assert all(1 <= p <= 65535 for p in ports)

    def test_top10_sorted(self, parser):
        ports = parser.parse("top10")
        assert ports == sorted(ports)

    def test_top1_returns_one_port(self, parser):
        ports = parser.parse("top1")
        assert len(ports) == 1

    def test_top0_invalid(self, parser):
        with pytest.raises(PortParseError):
            parser.parse("top0")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
