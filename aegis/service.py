"""AEGIS gate as a local HTTP service.

Security design decision: the HTTP API exposes **decisions only**
(``POST /api/gate``). Actual command execution (``run``) is intentionally
CLI-only so a compromised network client can never turn AEGIS into a remote
shell. The service can optionally record decisions in the signed ledger.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import AegisConfig, load_config
from .gate import decide
from .ledger import append_record, verify_ledger
from .models import ToolIntent
from .observability import Metrics, setup_logging
from .policy import GatePolicy, load_policy
from .version import __version__


class Handler(BaseHTTPRequestHandler):
    config: AegisConfig | None = None
    policy: GatePolicy | None = None
    metrics: Metrics | None = None
    logger: logging.Logger | None = None

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Aegis-Version", __version__)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        key = self.config.api_key if self.config else ""
        if not key:
            return True
        provided = self.headers.get("X-API-Key", "")
        return hmac.compare_digest(provided.encode("utf-8"), key.encode("utf-8"))

    def _log_event(self, level: int, message: str, **event: object) -> None:
        if self.logger is not None:
            self.logger.log(level, message, extra={"event": event})

    def _drain_body(self, length: int, cap: int = 16_777_216) -> None:
        """Read and discard the request body so the client can finish sending
        before we return an error response (avoids TCP resets on Windows)."""
        remaining = min(length, cap)
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            payload = {
                "ok": True,
                "service": "aegis",
                "version": __version__,
                "auth_required": bool(self.config and self.config.api_key),
            }
            if self.metrics is not None:
                payload["uptime_s"] = round(time.time() - self.metrics.started_at, 3)
            self._send_json(200, payload)
            return
        if not self._authorized():
            if self.metrics is not None:
                self.metrics.inc("http_unauthorized")
            self._send_json(401, {"ok": False, "error": "missing or invalid X-API-Key"})
            return
        if path == "/api/version":
            self._send_json(200, {"service": "aegis", "version": __version__})
            return
        if path == "/api/metrics":
            self._send_json(200, self.metrics.snapshot() if self.metrics else {})
            return
        if path == "/api/ledger/verify":
            ledger = self.config.ledger_path if self.config else None
            self._send_json(200, verify_ledger(ledger) if ledger else {"ok": False, "error": "no ledger configured"})
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/gate":
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        if not self._authorized():
            if self.metrics is not None:
                self.metrics.inc("http_unauthorized")
            self._send_json(401, {"ok": False, "error": "missing or invalid X-API-Key"})
            return
        max_body = self.config.max_body_bytes if self.config else 262_144
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > max_body:
            if self.metrics is not None:
                self.metrics.inc("http_payload_too_large")
            self._drain_body(length)
            self._send_json(413, {"ok": False, "error": f"body exceeds {max_body} bytes"})
            return
        started = time.perf_counter()
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            intent = ToolIntent.from_dict(data)
            decision = decide(intent, policy=self.policy)
            payload = {"ok": True, "intent": intent.to_dict(), "decision": decision.to_dict()}
            if bool(data.get("record")) and self.config is not None:
                payload["ledger"] = append_record(
                    {"intent": intent.to_dict(), "decision": decision.to_dict(), "source": "http"},
                    ledger_path=self.config.ledger_path,
                )
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if self.metrics is not None:
                self.metrics.inc("http_requests_total")
                self.metrics.inc(f"decision_{decision.action.lower()}")
                self.metrics.observe_ms(elapsed_ms)
            self._log_event(logging.INFO, "gate", status=200, ms=round(elapsed_ms, 3), action=decision.action, tool=intent.tool)
            self._send_json(200, payload)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if self.metrics is not None:
                self.metrics.inc("http_errors_total")
                self.metrics.observe_ms(elapsed_ms)
            self._log_event(logging.WARNING, "gate_error", status=400, ms=round(elapsed_ms, 3), error=str(exc))
            self._send_json(400, {"ok": False, "error": str(exc)})

    def log_message(self, format: str, *args: object) -> None:
        return


def create_server(host: str | None = None, port: int | None = None, config: AegisConfig | None = None) -> ThreadingHTTPServer:
    """Build a configured (not yet serving) HTTP server. Port 0 → ephemeral."""
    cfg = config or load_config()
    Handler.config = cfg
    Handler.policy = load_policy(cfg.policy_path)
    Handler.metrics = Metrics("aegis", __version__)
    Handler.logger = setup_logging("aegis.service", cfg.log_dir, cfg.log_level)
    bind_host = host if host is not None else cfg.host
    bind_port = port if port is not None else cfg.port
    return ThreadingHTTPServer((bind_host, bind_port), Handler)


def run_server(host: str | None = None, port: int | None = None) -> None:
    server = create_server(host=host, port=port)
    actual_host, actual_port = server.server_address[0], server.server_address[1]
    print(f"AEGIS service v{__version__}: http://{actual_host}:{actual_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
