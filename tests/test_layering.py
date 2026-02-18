"""
tests/test_layering.py
Enforce architectural layering:
  core       → may NOT import database, dashboard, reporting
  database   → may NOT import core, dashboard, reporting
  dashboard  → may NOT import core directly
  reporting  → may NOT import core, dashboard directly

Run: pytest tests/test_layering.py -v
"""

import sys, os, ast
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


def get_imports(filepath: Path) -> list[str]:
    """Extract all imported module names from a Python file."""
    try:
        tree = ast.parse(filepath.read_text())
    except SyntaxError:
        return []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def all_py_files(pkg_dir: Path):
    return list(pkg_dir.rglob("*.py"))


FORBIDDEN = {
    "core":      {"database", "dashboard", "reporting"},
    "database":  {"core", "dashboard", "reporting"},
    "dashboard": {"core"},
    "reporting": {"core", "dashboard"},
}


class TestLayering:
    def _check(self, package: str, forbidden: set[str]):
        pkg_dir = ROOT / package
        if not pkg_dir.exists():
            return  # package not yet implemented → skip
        for pyfile in all_py_files(pkg_dir):
            imports = get_imports(pyfile)
            for imp in imports:
                top = imp.split(".")[0]
                assert top not in forbidden, (
                    f"LAYERING VIOLATION in {pyfile.relative_to(ROOT)}: "
                    f"'{package}' imports '{top}' — "
                    f"forbidden packages: {forbidden}"
                )

    def test_core_does_not_import_database(self):
        self._check("core", {"database"})

    def test_core_does_not_import_dashboard(self):
        self._check("core", {"dashboard"})

    def test_core_does_not_import_reporting(self):
        self._check("core", {"reporting"})

    def test_database_does_not_import_core(self):
        self._check("database", {"core"})

    def test_database_does_not_import_dashboard(self):
        self._check("database", {"dashboard"})

    def test_dashboard_does_not_import_core(self):
        self._check("dashboard", {"core"})


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
