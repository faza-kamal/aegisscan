"""AegisScan Dashboard — Public API

Flask-based web dashboard for viewing scan history and live stats.

Usage:
    from dashboard.app import create_app, run_dashboard
    from dashboard.app import hash_password, verify_password
"""
from dashboard.app import create_app, run_dashboard, hash_password, verify_password

__all__ = [
    "create_app",
    "run_dashboard",
    "hash_password",
    "verify_password",
]
