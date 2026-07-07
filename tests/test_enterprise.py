"""Enterprise-layer tests: config, metrics, hardened HTTP gate service."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from aegis.config import load_config
from aegis.observability import Metrics, teardown_logging
from aegis.service import Handler, create_server
from aegis.version import __version__


class ConfigTests(unittest.TestCase):
    KEYS = ("AEGIS_HOME", "AEGIS_POLICY", "AEGIS_API_KEY", "AEGIS_PORT", "AEGIS_MAX_BODY_BYTES")

    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in self.KEYS}

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_defaults(self) -> None:
        for key in self.KEYS:
            os.environ.pop(key, None)
        cfg = load_config()
        self.assertEqual(cfg.port, 8788)
        self.assertFalse(cfg.auth_required)
        self.assertTrue(str(cfg.policy_path).endswith("aegis_policy.json"))

    def test_env_overrides(self) -> None:
        os.environ["AEGIS_API_KEY"] = "k"
        os.environ["AEGIS_PORT"] = "9999"
        os.environ["AEGIS_MAX_BODY_BYTES"] = "4096"
        cfg = load_config()
        self.assertTrue(cfg.auth_required)
        self.assertEqual(cfg.port, 9999)
        self.assertEqual(cfg.max_body_bytes, 4096)

    def test_invalid_port_falls_back(self) -> None:
        os.environ["AEGIS_PORT"] = "abc"
        self.assertEqual(load_config().port, 8788)


class MetricsTests(unittest.TestCase):
    def test_percentiles_ordered(self) -> None:
        metrics = Metrics("aegis", __version__)
        for value in range(1, 51):
            metrics.observe_ms(float(value))
        metrics.inc("decision_block", 3)
        snap = metrics.snapshot()
        self.assertEqual(snap["counters"]["decision_block"], 3)
        self.assertLessEqual(snap["latency_ms"]["p50"], snap["latency_ms"]["p95"])
        self.assertLessEqual(snap["latency_ms"]["p95"], snap["latency_ms"]["p99"])


class ServiceTestBase(unittest.TestCase):
    api_key = ""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        tmp_path = Path(self._tmp.name)
        os.environ["AEGIS_API_KEY"] = self.api_key
        os.environ["AEGIS_LOG_DIR"] = str(tmp_path / "logs")
        os.environ["AEGIS_LEDGER"] = str(tmp_path / "ledger.jsonl")
        self.server = create_server(host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        for key in ("AEGIS_API_KEY", "AEGIS_LOG_DIR", "AEGIS_LEDGER"):
            os.environ.pop(key, None)
        if Handler.logger is not None:
            teardown_logging(Handler.logger)
            Handler.logger = None
        self._tmp.cleanup()

    def request(self, path: str, payload: dict | None = None, headers: dict | None = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data, headers=headers or {})
        if data is not None:
            request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))


class OpenServiceTests(ServiceTestBase):
    api_key = ""

    def test_health(self) -> None:
        status, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], __version__)
        self.assertFalse(body["auth_required"])

    def test_gate_allows_readonly_command(self) -> None:
        intent = {"tool": "shell", "command": "git status", "cwd": "C:/Projects/aegis_local", "reason": "check repo state"}
        status, body = self.request("/api/gate", intent)
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"]["action"], "ALLOW")

    def test_gate_blocks_destructive_command(self) -> None:
        intent = {"tool": "shell", "command": "rm -rf /", "cwd": "C:/Projects/aegis_local", "reason": "cleanup"}
        status, body = self.request("/api/gate", intent)
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"]["action"], "BLOCK")

    def test_metrics_track_decisions(self) -> None:
        intent = {"tool": "shell", "command": "git status", "cwd": "C:/Projects/aegis_local"}
        self.request("/api/gate", intent)
        status, metrics = self.request("/api/metrics")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(metrics["counters"].get("http_requests_total", 0), 1)
        self.assertGreaterEqual(metrics["latency_ms"]["samples"], 1)


class AuthServiceTests(ServiceTestBase):
    api_key = "aegis-secret-9"

    def test_rejects_missing_key(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("/api/gate", {"tool": "shell", "command": "git status", "cwd": "C:/Projects"})
        self.assertEqual(ctx.exception.code, 401)

    def test_accepts_valid_key(self) -> None:
        status, body = self.request(
            "/api/gate",
            {"tool": "shell", "command": "git status", "cwd": "C:/Projects"},
            headers={"X-API-Key": "aegis-secret-9"},
        )
        self.assertEqual(status, 200)
        self.assertIn(body["decision"]["action"], {"ALLOW", "REVIEW", "BLOCK", "QUARANTINE"})

    def test_health_open_for_probes(self) -> None:
        status, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["auth_required"])

    def test_oversized_body_rejected(self) -> None:
        intent = {"tool": "shell", "command": "git status", "cwd": "C:/Projects", "reason": "x" * 400_000}
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("/api/gate", intent, headers={"X-API-Key": "aegis-secret-9"})
        self.assertEqual(ctx.exception.code, 413)


if __name__ == "__main__":
    unittest.main()
