from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gate import decide
from .ledger import append_record
from .models import GateDecision, ToolIntent
from .policy import GatePolicy, command_allowed, cwd_allowed, load_policy, split_command


@dataclass
class RunResult:
    intent: ToolIntent
    decision: GateDecision
    executed: bool
    returncode: int | None
    stdout: str
    stderr: str
    elapsed_seconds: float
    ledger: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent.to_dict(),
            "decision": self.decision.to_dict(),
            "executed": self.executed,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "ledger": self.ledger,
        }


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n[TRUNCATED]"


def run_intent(
    intent: ToolIntent,
    *,
    policy: GatePolicy | None = None,
    ledger_path: str | Path = "ledger/aegis-ledger.jsonl",
    record: bool = True,
) -> RunResult:
    policy = policy or load_policy()
    decision = decide(intent, policy=policy)
    started = time.perf_counter()
    stdout = ""
    stderr = ""
    returncode: int | None = None
    executed = False

    if decision.action == "ALLOW":
        cwd_ok, resolved_cwd = cwd_allowed(intent.cwd, policy)
        allowed, _reason, max_seconds = command_allowed(intent.command, policy)
        if not cwd_ok or not allowed:
            decision = GateDecision("BLOCK", "تغيرت السياسة بين القرار والتنفيذ.")
        else:
            argv = split_command(intent.command)
            timeout = min(float(intent.timeout_seconds), max_seconds)
            try:
                completed = subprocess.run(
                    argv,
                    cwd=str(resolved_cwd),
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=timeout,
                )
                executed = True
                returncode = completed.returncode
                stdout = _clip(completed.stdout, policy.max_output_chars)
                stderr = _clip(completed.stderr, policy.max_output_chars)
            except subprocess.TimeoutExpired as exc:
                executed = True
                returncode = None
                stdout = _clip(exc.stdout or "", policy.max_output_chars)
                stderr = _clip(f"timeout after {timeout}s\n{exc.stderr or ''}", policy.max_output_chars)
            except FileNotFoundError as exc:
                decision = GateDecision("BLOCK", f"البرنامج غير موجود: {exc.filename}")
            except Exception as exc:
                decision = GateDecision("BLOCK", f"فشل التنفيذ الآمن: {exc!r}")

    elapsed = time.perf_counter() - started
    result = RunResult(intent, decision, executed, returncode, stdout, stderr, elapsed)
    if record:
        payload = {
            "kind": "run",
            "intent": intent.to_dict(),
            "decision": decision.to_dict(),
            "execution": {
                "executed": executed,
                "returncode": returncode,
                "stdout_hash": None if not stdout else __import__("hashlib").sha256(stdout.encode("utf-8")).hexdigest(),
                "stderr_hash": None if not stderr else __import__("hashlib").sha256(stderr.encode("utf-8")).hexdigest(),
                "elapsed_seconds": round(elapsed, 4),
            },
        }
        result.ledger = append_record(payload, ledger_path=ledger_path)
    return result
