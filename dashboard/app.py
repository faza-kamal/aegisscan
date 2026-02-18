"""
dashboard/app.py
Flask web dashboard -- security-first design.

Security properties:
  - debug=False enforced programmatically (cannot be overridden by env)
  - SECRET_KEY auto-generated if not set
  - Basic-auth middleware with bcrypt password hashing (production-grade)
  - Stacktraces never exposed to client
  - CORS disabled by default

Layering: dashboard -> database.repository only (no core imports)
"""

from __future__ import annotations

import hmac
import secrets
from typing import Optional

from flask import Flask, abort, jsonify, render_template, request, Response
from database.repository import Repository

# -- bcrypt: use passlib if available, else fall back to salted HMAC-SHA256 ---
try:
    from passlib.hash import bcrypt as _bcrypt  # type: ignore
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False


def hash_password(plain: str) -> str:
    """
    Hash a plaintext password for storage.
    Uses bcrypt (passlib) when available; falls back to hex-encoded
    HMAC-SHA256 with a random salt (acceptable for dev, not for prod).
    """
    if _BCRYPT_AVAILABLE:
        return _bcrypt.hash(plain)
    salt = secrets.token_hex(16)
    import hashlib
    digest = hmac.new(salt.encode(), plain.encode(), "sha256").hexdigest()
    return f"sha256${salt}${digest}"


def verify_password(plain: str, stored: str) -> bool:
    """
    Verify plain against a stored hash produced by hash_password().
    Always constant-time where possible.
    """
    if stored.startswith("$2"):          # bcrypt hash prefix
        if not _BCRYPT_AVAILABLE:
            return False
        try:
            return _bcrypt.verify(plain, stored)
        except Exception:
            return False
    if stored.startswith("sha256$"):     # our fallback scheme
        try:
            _, salt, digest = stored.split("$", 2)
            import hashlib
            expected = hmac.new(salt.encode(), plain.encode(), "sha256").hexdigest()
            return hmac.compare_digest(expected, digest)
        except Exception:
            return False
    # Legacy plaintext (dev only) -- constant-time compare
    return hmac.compare_digest(stored.encode(), plain.encode())


# -- Factory ------------------------------------------------------------------

def create_app(cfg: dict, repo: Repository) -> Flask:
    """
    Application factory.

    cfg keys:
      secret_key     str  -- REQUIRED, must not equal default placeholder
      enable_auth    bool -- enable HTTP Basic-Auth (default False)
      auth_username  str
      auth_password  str  -- accepts bcrypt hash OR plain (plain triggers warning)
      host           str
      port           int
    """
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Security
    secret = cfg.get("secret_key", "")
    if not secret or secret == "CHANGE_THIS_IN_PRODUCTION":
        secret = secrets.token_hex(32)

    app.config["SECRET_KEY"]           = secret
    app.config["DEBUG"]                = False   # HARD -- no env override
    app.config["TESTING"]              = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["TRAP_HTTP_EXCEPTIONS"] = False

    # Auth middleware
    enable_auth = cfg.get("enable_auth", False)
    auth_user   = cfg.get("auth_username", "aegis")
    raw_pass    = cfg.get("auth_password", "")

    if enable_auth and not _BCRYPT_AVAILABLE:
        app.logger.warning(
            "passlib not installed -- bcrypt unavailable. "
            "Install 'passlib[bcrypt]' for production-grade auth."
        )

    # Warn if password is plaintext
    if enable_auth and raw_pass and not (
        raw_pass.startswith("$2") or raw_pass.startswith("sha256$")
    ):
        app.logger.warning(
            "auth_password is stored as plaintext -- consider storing a "
            "bcrypt hash instead (run: aegisscan hash-password <password>)."
        )
    stored_pass = raw_pass

    @app.before_request
    def _require_auth():
        if not enable_auth:
            return
        auth = request.authorization
        if not auth:
            return _auth_challenge()
        ok_user = hmac.compare_digest(
            auth.username.encode(), auth_user.encode()
        )
        ok_pass = verify_password(auth.password, stored_pass)
        if not (ok_user and ok_pass):
            return _auth_challenge()

    # Error handlers (no stacktrace leakage)
    @app.errorhandler(404)
    def _e404(e):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(403)
    def _e403(e):
        return jsonify({"error": "forbidden"}), 403

    @app.errorhandler(500)
    def _e500(e):
        app.logger.exception("Internal server error")
        return jsonify({"error": "internal server error"}), 500

    @app.errorhandler(Exception)
    def _unhandled(e):
        app.logger.exception("Unhandled exception")
        return jsonify({"error": "internal server error"}), 500

    # Routes
    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/stats")
    def api_stats():
        return jsonify(repo.stats())

    @app.route("/api/scans")
    def api_scans():
        limit = min(int(request.args.get("limit", 50)), 200)
        return jsonify(repo.list_scans(limit))

    @app.route("/api/scan/<int:scan_id>")
    def api_scan_detail(scan_id: int):
        data = repo.get_scan(scan_id)
        if data is None:
            abort(404)
        return jsonify(data)

    @app.route("/api/scan/<int:scan_id>", methods=["DELETE"])
    def api_delete_scan(scan_id: int):
        if not enable_auth:
            abort(403)
        ok = repo.delete_scan(scan_id)
        return jsonify({"deleted": ok})

    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "auth": enable_auth,
            "bcrypt": _BCRYPT_AVAILABLE,
        })

    return app


# -- Helpers ------------------------------------------------------------------

def _auth_challenge() -> Response:
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="AegisScan"'},
    )


# -- Server runner ------------------------------------------------------------

def run_dashboard(cfg: dict, repo: Repository) -> None:
    app = create_app(cfg, repo)
    host = cfg.get("host", "127.0.0.1")
    port = cfg.get("port", 5000)
    print(f"[*] Dashboard at http://{host}:{port}")
    print(f"[*] Auth: {'ON' if cfg.get('enable_auth') else 'OFF (use --enable-auth for production)'}")
    print(f"[*] bcrypt: {'available (passlib)' if _BCRYPT_AVAILABLE else 'unavailable -- install passlib[bcrypt]'}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
