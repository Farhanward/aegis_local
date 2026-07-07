from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolIntent:
    tool: str
    command: str
    reason: str = ""
    agent: str = "unknown"
    context: dict[str, Any] = field(default_factory=dict)
    cwd: str = "."
    timeout_seconds: float = 10.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolIntent":
        return cls(
            tool=str(data.get("tool") or "shell"),
            command=str(data.get("command") or ""),
            reason=str(data.get("reason") or ""),
            agent=str(data.get("agent") or "unknown"),
            context=dict(data.get("context") or {}),
            cwd=str(data.get("cwd") or "."),
            timeout_seconds=float(data.get("timeout_seconds") or 10.0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "command": self.command,
            "reason": self.reason,
            "agent": self.agent,
            "context": self.context,
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class GateDecision:
    action: str
    reason: str
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "reason": self.reason, "findings": self.findings}
