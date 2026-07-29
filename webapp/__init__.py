"""Flask application factory for NetGuard's local web mode."""

from __future__ import annotations

import secrets
from typing import Any

from flask import Flask

from application.service import NetGuardApplicationService
from version import __version__
from webapp.routes import api, register_error_handlers


def create_app(
    service: NetGuardApplicationService | None = None,
    config: dict[str, Any] | None = None,
) -> Flask:
    """Create one Flask app around one shared application service."""
    app = Flask(__name__)
    app.config.from_mapping(
        DEBUG=False,
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=64 * 1024,
        NETGUARD_HOST="127.0.0.1",
        NETGUARD_PORT=5000,
        NETGUARD_CSRF_TOKEN=secrets.token_urlsafe(32),
        NETGUARD_VERSION=__version__,
    )
    if config:
        app.config.update(config)
    # Debug mode is intentionally unavailable in the local security tool.
    app.config["DEBUG"] = False

    app.extensions["netguard_service"] = (
        service if service is not None else NetGuardApplicationService()
    )
    app.extensions["netguard_owns_service"] = service is None
    app.register_blueprint(api)
    register_error_handlers(app)

    @app.context_processor
    def add_netguard_version():
        return {"netguard_version": app.config["NETGUARD_VERSION"]}

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    return app


__all__ = ["create_app"]
