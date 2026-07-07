from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def convert_neuralchemy_to_intents(
    source: str | Path = "C:/Projects/almunaa/data/benchmarks/neuralchemy_prompt_injection_full.events.jsonl",
    out: str | Path = "data/benchmarks/aegis_neuralchemy_tool_intents.jsonl",
) -> dict[str, Any]:
    source_path = Path(source)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = unsafe = safe = 0
    with source_path.open("r", encoding="utf-8") as in_handle, out_path.open("w", encoding="utf-8") as out_handle:
        for line in in_handle:
            if not line.strip():
                continue
            record = json.loads(line)
            expected = bool(record.get("expected_unsafe"))
            content = str((record.get("event") or {}).get("content") or "")
            intent_record = {
                "source_dataset": record.get("dataset", "neuralchemy/Prompt-injection-dataset"),
                "split": record.get("split"),
                "row_idx": record.get("row_idx"),
                "label": record.get("label"),
                "expected_unsafe": expected,
                "intent": {
                    "tool": "shell",
                    "command": "python --version",
                    "reason": content,
                    "agent": "aegis-benchmark",
                    "cwd": "C:/Projects/aegis_local",
                    "timeout_seconds": 5,
                    "context": {
                        "benchmark": "neuralchemy_prompt_injection_as_tool_reason",
                        "split": record.get("split"),
                        "row_idx": record.get("row_idx"),
                    },
                },
            }
            out_handle.write(json.dumps(intent_record, ensure_ascii=False) + "\n")
            count += 1
            unsafe += int(expected)
            safe += int(not expected)
    return {"out": str(out_path.resolve()), "records": count, "unsafe": unsafe, "safe": safe}
