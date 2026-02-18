# Contributing to AegisScan

Thank you for considering a contribution. This document explains the workflow and standards.

## Ground Rules

- Only contribute code for **authorized security research**
- Do not add features that primarily serve offensive/unauthorized use
- Write tests for all new code
- Maintain the layering contract (see Architecture section in README)

## Development Setup

```bash
git clone https://github.com/yourusername/aegisscan.git
cd aegisscan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov
```

## Running Tests

```bash
# Full suite
pytest tests/ -v

# With coverage
pytest tests/ --cov=core --cov=database --cov-report=term-missing

# Layering check only (fast)
pytest tests/test_layering.py -v
```

All PRs must pass **0 layering violations** and **no test regressions**.

## Layering Contract

This is enforced by `tests/test_layering.py` and is non-negotiable:

```
core/      → imports only: utils, data (NO database, dashboard, reporting)
database/  → imports only: utils     (NO core, dashboard, reporting)
dashboard/ → imports only: database.repository, utils  (NO core)
reporting/ → imports only: utils     (NO core, dashboard)
```

If your PR breaks layering, it will not be merged.

## Code Style

- Python 3.8+ compatible
- Type hints on all public functions
- Docstrings on all public classes and methods
- No bare `except:` — always specify exception type
- No `print()` in library code — use `utils/logger.py`

## Adding a New Feature

1. **Core scan logic** → goes in `core/`
2. **Data persistence** → goes in `database/repository.py`
3. **CLI flag** → add to `main.py` argparse
4. **Web endpoint** → add to `dashboard/app.py`

## Pull Request Checklist

- [ ] Tests written and passing
- [ ] `pytest tests/test_layering.py` passes
- [ ] Type hints added
- [ ] Docstrings added
- [ ] `README.md` updated if adding a user-visible feature
- [ ] No credentials, API keys, or secrets in code

## Reporting Security Issues

Do **not** open a public GitHub issue for security vulnerabilities.
Email directly: security@yourdomain.com
