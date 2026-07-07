from __future__ import annotations

from typing import Any


def pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def batch_markdown(report: dict[str, Any]) -> str:
    metrics = report.get("metrics", {})
    latency = report.get("latency_ms", {})
    memory = report.get("memory", {})
    collapse = report.get("collapse", {})
    confusion = report.get("confusion", {})
    lines = [
        "# تقرير AEGIS",
        "",
        f"- الملف: `{report.get('input')}`",
        f"- السجلات: `{report.get('records_loaded')}`",
        f"- التكرار: `{report.get('repeat')}`",
        f"- الفحوص: `{report.get('processed')}`",
        f"- الأخطاء: `{report.get('errors')}`",
        f"- الإنتاجية: `{report.get('throughput_per_second')}` فحص/ثانية",
        "",
        "## الجودة",
        "",
        f"- Accuracy: `{pct(float(metrics.get('accuracy', 0)))}`",
        f"- Precision: `{pct(float(metrics.get('precision', 0)))}`",
        f"- Recall: `{pct(float(metrics.get('recall', 0)))}`",
        f"- Specificity: `{pct(float(metrics.get('specificity', 0)))}`",
        f"- F1: `{pct(float(metrics.get('f1', 0)))}`",
        f"- Confusion: `TP={confusion.get('tp', 0)} TN={confusion.get('tn', 0)} FP={confusion.get('fp', 0)} FN={confusion.get('fn', 0)}`",
        "",
        "## الضغط",
        "",
        f"- الحالة: `{collapse.get('status')}`",
        f"- بلا استثناءات: `{collapse.get('no_exceptions')}`",
        f"- P99 أقل من 25ms: `{collapse.get('p99_under_25ms')}`",
        f"- الذاكرة أقل من 128MB: `{collapse.get('peak_memory_under_128mb')}`",
        f"- Latency mean/p95/p99/max: `{latency.get('mean')} / {latency.get('p95')} / {latency.get('p99')} / {latency.get('max')}` ms",
        f"- Peak memory: `{memory.get('peak_mb')}` MB",
        "",
        "## القرارات",
        "",
    ]
    for action, count in (report.get("actions") or {}).items():
        lines.append(f"- `{action}`: `{count}`")
    lines.extend(["", "## أكثر الأسباب", ""])
    for reason, count in (report.get("top_reasons") or {}).items():
        lines.append(f"- `{reason}`: `{count}`")
    lines.append("")
    return "\n".join(lines)
