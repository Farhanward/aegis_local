from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_POLICY = Path("config") / "aegis_policy.json"


@dataclass(frozen=True)
class AllowedCommand:
    executable: str
    prefixes: tuple[tuple[str, ...], ...] = ()
    max_seconds: float = 10.0
    extra_args: str = "none"


@dataclass(frozen=True)
class GatePolicy:
    allowed_commands: tuple[AllowedCommand, ...] = ()
    blocked_patterns: tuple[re.Pattern[str], ...] = ()
    allowed_cwd_roots: tuple[Path, ...] = ()
    max_output_chars: int = 12000
    almunaa_model_path: Path | None = None


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return []


def _default_blocked_patterns() -> tuple[re.Pattern[str], ...]:
    patterns = [
        r"rm\s+-rf\s+/",
        r"docker\s+rm\s+-f",
        r"docker\s+system\s+prune",
        r"format\s+[a-z]:",
        r"Remove-Item\b.+-Recurse",
        r"del\s+/s",
        r"/var/run/docker\.sock",
        r"\.env\b",
        r"id_rsa",
        r"private_key",
        r"vssadmin\s+delete\s+shadows",
    ]
    return tuple(re.compile(pattern, re.I) for pattern in patterns)


def default_policy() -> GatePolicy:
    return GatePolicy(
        allowed_commands=(
            AllowedCommand("python", (("--version",), ("-V",)), 5.0),
            AllowedCommand("git", (("status",), ("status", "--short")), 10.0),
            AllowedCommand("docker", (("ps",),), 10.0, "docker_ps_readonly"),
        ),
        blocked_patterns=_default_blocked_patterns(),
        allowed_cwd_roots=(Path("C:/Projects").resolve(strict=False),),
        max_output_chars=12000,
        almunaa_model_path=Path("C:/Projects/almunaa/models/almunaa_lexical_guard.json"),
    )


def load_policy(path: str | Path | None = None) -> GatePolicy:
    if path is None:
        path = DEFAULT_POLICY
    policy_path = Path(path)
    if not policy_path.exists():
        return default_policy()
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    allowed = []
    for item in data.get("allowed_commands", []):
        allowed.append(
            AllowedCommand(
                executable=str(item["executable"]),
                prefixes=tuple(tuple(str(part) for part in prefix) for prefix in item.get("prefixes", [])),
                max_seconds=float(item.get("max_seconds", 10.0)),
                extra_args=str(item.get("extra_args") or "none"),
            )
        )
    roots = tuple(Path(root).resolve(strict=False) for root in data.get("allowed_cwd_roots", ["C:/Projects"]))
    blocked = tuple(re.compile(str(pattern), re.I) for pattern in data.get("blocked_patterns", [])) or _default_blocked_patterns()
    model_path = data.get("almunaa_model_path")
    return GatePolicy(
        allowed_commands=tuple(allowed) or default_policy().allowed_commands,
        blocked_patterns=blocked,
        allowed_cwd_roots=roots,
        max_output_chars=int(data.get("max_output_chars", 12000)),
        almunaa_model_path=Path(model_path) if model_path else None,
    )


def command_allowed(command: str, policy: GatePolicy) -> tuple[bool, str, float]:
    for blocked in policy.blocked_patterns:
        if blocked.search(command):
            return False, f"يطابق نمط منع: {blocked.pattern}", 0.0
    if _has_shell_control(command):
        return False, "يرفض AEGIS رموز تحكم shell داخل الأمر.", 0.0
    argv = split_command(command)
    if not argv:
        return False, "تعذر تحليل الأمر بأمان.", 0.0
    executable = Path(argv[0]).name.lower()
    args = tuple(argv[1:])
    for allowed in policy.allowed_commands:
        if executable != allowed.executable.lower():
            continue
        if not allowed.prefixes:
            return True, "الأمر مسموح.", allowed.max_seconds
        for prefix in allowed.prefixes:
            if args == prefix:
                return True, "الأمر مسموح.", allowed.max_seconds
            if args[: len(prefix)] == prefix and _extra_args_allowed(executable, prefix, args[len(prefix):], allowed.extra_args):
                return True, "الأمر مسموح بوسائط قراءة مقيدة.", allowed.max_seconds
    return False, "الأمر خارج قائمة السماح.", 0.0


def _has_shell_control(command: str) -> bool:
    controls = ("\n", "\r", ";", "&&", "||", "`", "$(", "<(", "|", ">", "<")
    return any(token in command for token in controls)


def _extra_args_allowed(executable: str, prefix: tuple[str, ...], extras: tuple[str, ...], mode: str) -> bool:
    if not extras or mode == "none":
        return False
    if mode != "docker_ps_readonly" or executable != "docker" or prefix != ("ps",):
        return False
    no_value = {"-a", "--all", "-q", "--quiet", "--no-trunc", "--size"}
    value_options = {"--format", "--filter"}
    index = 0
    while index < len(extras):
        arg = extras[index]
        if _has_shell_control(arg):
            return False
        if arg in no_value:
            index += 1
            continue
        if any(arg.startswith(option + "=") for option in value_options):
            index += 1
            continue
        if arg in value_options:
            if index + 1 >= len(extras) or _has_shell_control(extras[index + 1]):
                return False
            index += 2
            continue
        return False
    return True


def cwd_allowed(cwd: str | Path, policy: GatePolicy) -> tuple[bool, Path]:
    target = Path(cwd).resolve(strict=False)
    for root in policy.allowed_cwd_roots:
        try:
            target.relative_to(root)
            return True, target
        except ValueError:
            continue
    return False, target


def write_default_policy(path: str | Path = DEFAULT_POLICY) -> Path:
    policy_path = Path(path)
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {
        "allowed_cwd_roots": ["C:/Projects"],
        "max_output_chars": 12000,
        "almunaa_model_path": "C:/Projects/almunaa/models/almunaa_lexical_guard.json",
        "allowed_commands": [
            {"executable": "python", "prefixes": [["--version"], ["-V"]], "max_seconds": 5},
            {"executable": "git", "prefixes": [["status"], ["status", "--short"]], "max_seconds": 10},
            {"executable": "docker", "prefixes": [["ps"]], "max_seconds": 10, "extra_args": "docker_ps_readonly"},
        ],
        "blocked_patterns": [pattern.pattern for pattern in _default_blocked_patterns()],
    }
    policy_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return policy_path
