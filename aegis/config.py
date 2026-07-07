"""Central runtime configuration for AEGIS.

Environment variables (all optional, sane defaults for local runs):

- ``AEGIS_HOME``: base directory for runtime state (default: project root).
- ``AEGIS_POLICY``: gate policy JSON path (default: ``<home>/config/aegis_policy.json``).
- ``AEGIS_LEDGER``: signed ledger JSONL path (default: ``<home>/ledger/aegis-ledger.jsonl``).
- ``AEGIS_API_KEY``: if set, every ``/api/*`` request (except health) must send ``X-API-Key``.
- ``AEGIS_HOST`` / ``AEGIS_PORT``: service bind address (default ``127.0.0.1:8788``).
- ``AEGIS_MAX_BODY_BYTES``: request body limit (default 256 KiB — intents are small).
- ``AEGIS_LOG_DIR`` / ``AEGIS_LOG_LEVEL``: structured log location and level.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else default


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


@dataclass(frozen=True)
class AegisConfig:
    home: Path = field(default_factory=lambda: PROJECT_ROOT)
    policy_path: Path = field(default_factory=lambda: PROJECT_ROOT / "config" / "aegis_policy.json")
    ledger_path: Path = field(default_factory=lambda: PROJECT_ROOT / "ledger" / "aegis-ledger.jsonl")
    api_key: str = ""
    host: str = "127.0.0.1"
    port: int = 8788
    max_body_bytes: int = 262_144
    log_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "logs")
    log_level: str = "INFO"

    @property
    def auth_required(self) -> bool:
        return bool(self.api_key)


def load_config() -> AegisConfig:
    home = _env_path("AEGIS_HOME", PROJECT_ROOT)
    return AegisConfig(
        home=home,
        policy_path=_env_path("AEGIS_POLICY", home / "config" / "aegis_policy.json"),
        ledger_path=_env_path("AEGIS_LEDGER", home / "ledger" / "aegis-ledger.jsonl"),
        api_key=os.environ.get("AEGIS_API_KEY", "").strip(),
        host=os.environ.get("AEGIS_HOST", "127.0.0.1").strip() or "127.0.0.1",
        port=_env_int("AEGIS_PORT", 8788),
        max_body_bytes=_env_int("AEGIS_MAX_BODY_BYTES", 262_144, minimum=1024),
        log_dir=_env_path("AEGIS_LOG_DIR", home / "logs"),
        log_level=os.environ.get("AEGIS_LOG_LEVEL", "INFO").strip().upper() or "INFO",
    )
