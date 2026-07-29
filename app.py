"""Local Flask entry point for NetGuard."""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Callable, Mapping

from application.service import NetGuardApplicationService
from version import __version__
from webapp import create_app


logger = logging.getLogger(__name__)
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def _bind_settings(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, int]:
    values = environment if environment is not None else os.environ
    host = values.get("NETGUARD_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST
    raw_port = values.get("NETGUARD_PORT", str(DEFAULT_PORT))
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError("NETGUARD_PORT must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("NETGUARD_PORT must be between 1 and 65535.")
    return host, port


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run_web_application(
    *,
    service: NetGuardApplicationService | None = None,
    run_server: Callable[..., object] | None = None,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Run Flask once and always close the associated service."""
    host, port = _bind_settings(environment)
    application_service = service or NetGuardApplicationService()
    flask_app = create_app(
        application_service,
        {"NETGUARD_HOST": host, "NETGUARD_PORT": port},
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info(
        "NetGuard %s web mode starting at http://%s:%d",
        __version__,
        host,
        port,
    )
    logger.warning("Run only one NetGuard instance at a time.")
    if not _is_loopback_host(host):
        logger.warning(
            "SECURITY WARNING: NetGuard is binding to non-loopback host %s. "
            "The API has no authentication and is intended for localhost use.",
            host,
        )

    runner = run_server or flask_app.run
    try:
        runner(
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
        )
    except KeyboardInterrupt:
        logger.info("Ctrl+C received; stopping NetGuard web mode")
    finally:
        logger.info("Shutting down NetGuard application service")
        application_service.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_web_application())
