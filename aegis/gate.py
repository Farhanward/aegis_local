from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from .models import GateDecision, ToolIntent
from .policy import GatePolicy, command_allowed, cwd_allowed, load_policy


ALLOWED_READONLY = [
    re.compile(r"^python\s+--version$", re.I),
    re.compile(r"^git\s+status(?:\s+--short)?$", re.I),
    re.compile(r"^docker\s+ps(?:\s+.*)?$", re.I),
    re.compile(r"^(dir|ls)(?:\s+.*)?$", re.I),
]
FALLBACK_BLOCK = re.compile(
    r"(rm\s+-rf\s+/|docker\s+rm\s+-f|format\s+[a-z]:|Remove-Item\b.+-Recurse|del\s+/s|/var/run/docker\.sock|\.env\b|id_rsa|private_key)",
    re.I,
)
_ALMUNAA_IMPORTS: tuple[Any, Any, Any] | None = None
_MODEL_CACHE: dict[str, Any] = {}


def _load_almunaa():
    global _ALMUNAA_IMPORTS
    if _ALMUNAA_IMPORTS is not None:
        return _ALMUNAA_IMPORTS
    try:
        from almunaa.core import scan_event
        from almunaa.lexical_model import LexicalModel
        from almunaa.models import AgentEvent

        _ALMUNAA_IMPORTS = (scan_event, AgentEvent, LexicalModel)
        return _ALMUNAA_IMPORTS
    except Exception:
        sibling = Path(__file__).resolve().parents[2] / "almunaa"
        if sibling.exists():
            sys.path.insert(0, str(sibling))
            try:
                from almunaa.core import scan_event
                from almunaa.lexical_model import LexicalModel
                from almunaa.models import AgentEvent

                _ALMUNAA_IMPORTS = (scan_event, AgentEvent, LexicalModel)
                return _ALMUNAA_IMPORTS
            except Exception:
                return None, None, None
    return None, None, None


def _readonly_allowed(command: str) -> bool:
    return any(pattern.search(command.strip()) for pattern in ALLOWED_READONLY)


def _load_almunaa_model(policy: GatePolicy, LexicalModel):
    if LexicalModel is None or policy.almunaa_model_path is None:
        return None
    cache_key = str(policy.almunaa_model_path.resolve(strict=False))
    if cache_key in _MODEL_CACHE:
        return _MODEL_CACHE[cache_key]
    try:
        if policy.almunaa_model_path.exists():
            _MODEL_CACHE[cache_key] = LexicalModel.load(policy.almunaa_model_path)
            return _MODEL_CACHE[cache_key]
    except Exception:
        return None
    return None


def _should_use_lexical_model(text: str) -> bool:
    clean = text.strip()
    if len(clean) < 30:
        return False
    latin = sum(1 for char in clean.lower() if "a" <= char <= "z")
    return latin >= 12


def decide(intent: ToolIntent, policy: GatePolicy | None = None) -> GateDecision:
    policy = policy or load_policy()
    if not intent.command.strip():
        return GateDecision("BLOCK", "الأمر فارغ.")
    cwd_ok, resolved_cwd = cwd_allowed(intent.cwd, policy)
    if not cwd_ok:
        return GateDecision("BLOCK", f"مجلد التنفيذ خارج الجذور المسموحة: {resolved_cwd}")

    allowed, policy_reason, _max_seconds = command_allowed(intent.command, policy)
    if not allowed:
        if policy_reason.startswith("يطابق نمط منع"):
            return GateDecision("BLOCK", policy_reason)
        return GateDecision("REVIEW", policy_reason)

    scan_event, AgentEvent, LexicalModel = _load_almunaa()
    if scan_event and AgentEvent:
        lexical_model = _load_almunaa_model(policy, LexicalModel) if _should_use_lexical_model(intent.reason) else None
        event = AgentEvent.from_dict(
            {
                "kind": "tool_call",
                "agent": intent.agent,
                "content": intent.reason,
                "tool": {"name": intent.tool, "command": intent.command},
                "context": {**intent.context, "cwd": str(resolved_cwd)},
            }
        )
        result = scan_event(event, write_ledger=False, write_quarantine=False, lexical_model=lexical_model)
        if result.action in {"BLOCK", "QUARANTINE"}:
            return GateDecision(
                action=result.action,
                reason="رفضت بوابة المناعة هذا الفعل.",
                findings=[finding.to_dict() for finding in result.findings],
            )
    elif FALLBACK_BLOCK.search(intent.command):
        return GateDecision("BLOCK", "رفض احتياطي: الأمر يطابق نمطاً خطراً.")

    if intent.tool != "shell":
        return GateDecision("REVIEW", "الأداة ليست shell ضمن هذه النسخة وتتطلب مراجعة.")
    return GateDecision("ALLOW", policy_reason)
