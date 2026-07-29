"""Stable database-path selection for normal, development, and legacy use."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import sys


def resolve_database_path(
    *,
    project_root: Path | None = None,
    environment: Mapping[str, str] | None = None,
    platform_name: str | None = None,
    development_mode: bool = False,
) -> Path:
    """Return a stable database path without depending on the launch directory."""
    root = (project_root or Path(__file__).resolve().parents[1]).resolve()
    env = environment if environment is not None else os.environ
    platform = platform_name or sys.platform

    override = env.get("NETGUARD_DB_PATH", "").strip()
    if override:
        configured = Path(override).expanduser()
        return configured.resolve() if configured.is_absolute() else (root / configured).resolve()

    legacy_path = root / "data" / "netguard.db"
    if legacy_path.exists() or development_mode:
        return legacy_path

    if platform.startswith("win"):
        local_app_data = env.get("LOCALAPPDATA", "").strip()
        base = (
            Path(local_app_data)
            if local_app_data
            else Path.home() / "AppData" / "Local"
        )
    else:
        xdg_data_home = env.get("XDG_DATA_HOME", "").strip()
        base = Path(xdg_data_home) if xdg_data_home else Path.home() / ".local" / "share"

    return (base / "NetGuard" / "netguard.db").resolve()
