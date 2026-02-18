"""AegisScan Test Suite

Test modules:
    test_port_parser  — Unit tests for core/port_parser.py (all edge cases)
    test_scanner      — Unit tests for OS detection, service fingerprinting,
                        timing profiles and scanner engine
    test_database     — Unit tests for database models and repository
                        (uses in-memory SQLite via pytest tmp_path fixture)
    test_layering     — Static import analysis enforcing architectural
                        layering rules (core / database / dashboard / reporting)

Run all tests:
    pytest tests/ -v

Run standalone (no pytest):
    python3 tests/run_all.py
    python3 tests/run_all.py -v       # verbose
    python3 tests/run_all.py --fast   # skip network tests
"""
