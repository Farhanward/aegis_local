from __future__ import annotations

import json
import statistics
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .gate import decide
from .models import ToolIntent
from .policy import load_policy


UNSAFE_ACTIONS = {"REVIEW", "QUARANTINE", "BLOCK"}


def iter_jsonl(path: str | Path) -> Iterable[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def expected_unsafe(record: dict[str, Any]) -> bool | None:
    if "expected_unsafe" in record:
        return bool(record["expected_unsafe"])
    if "label" in record:
        label = record["label"]
        if isinstance(label, int):
            return label == 1
        if str(label).lower() in {"1", "true", "unsafe", "malicious"}:
            return True
        if str(label).lower() in {"0", "false", "safe", "benign"}:
            return False
    return None


def intent_from_record(record: dict[str, Any]) -> ToolIntent:
    if isinstance(record.get("intent"), dict):
        return ToolIntent.from_dict(record["intent"])
    return ToolIntent.from_dict(record)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100) * (len(ordered) - 1))))
    return ordered[index]


def evaluate_intents(path: str | Path, *, limit: int | None = None, repeat: int = 1, policy_path: str | Path | None = None) -> dict[str, Any]:
    records = list(iter_jsonl(path))
    if limit is not None:
        records = records[:limit]
    policy = load_policy(policy_path)
    tracemalloc.start()
    started = time.perf_counter()
    durations: list[float] = []
    actions: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    tp = tn = fp = fn = unlabeled = 0
    errors: list[dict[str, Any]] = []
    processed = 0
    for _round in range(max(1, repeat)):
        for idx, record in enumerate(records):
            processed += 1
            try:
                intent = intent_from_record(record)
                item_started = time.perf_counter()
                decision = decide(intent, policy=policy)
                durations.append((time.perf_counter() - item_started) * 1000)
                actions[decision.action] += 1
                reasons[decision.reason] += 1
                expected = expected_unsafe(record)
                predicted = decision.action in UNSAFE_ACTIONS
                if expected is None:
                    unlabeled += 1
                elif expected and predicted:
                    tp += 1
                elif expected and not predicted:
                    fn += 1
                elif not expected and predicted:
                    fp += 1
                else:
                    tn += 1
            except Exception as exc:
                errors.append({"row": idx, "error": repr(exc)})
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed = time.perf_counter() - started
    labeled = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    accuracy = (tp + tn) / labeled if labeled else 0.0
    p99 = percentile(durations, 99)
    return {
        "input": str(Path(path).resolve()),
        "records_loaded": len(records),
        "repeat": max(1, repeat),
        "processed": processed,
        "errors": len(errors),
        "error_samples": errors[:10],
        "elapsed_seconds": round(elapsed, 4),
        "throughput_per_second": round(processed / elapsed, 2) if elapsed else 0.0,
        "actions": dict(actions),
        "top_reasons": dict(reasons.most_common(12)),
        "labeled": labeled,
        "unlabeled": unlabeled,
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
        },
        "latency_ms": {
            "mean": round(statistics.fmean(durations), 4) if durations else 0.0,
            "p95": round(percentile(durations, 95), 4),
            "p99": round(p99, 4),
            "max": round(max(durations), 4) if durations else 0.0,
        },
        "memory": {"current_mb": round(current / (1024 * 1024), 3), "peak_mb": round(peak / (1024 * 1024), 3)},
        "collapse": {
            "status": "PASS" if not errors and p99 < 25 and peak < 128 * 1024 * 1024 else "DEGRADED",
            "no_exceptions": not errors,
            "p99_under_25ms": p99 < 25,
            "peak_memory_under_128mb": peak < 128 * 1024 * 1024,
        },
    }
