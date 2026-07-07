from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .crypto import sign_bytes, verify_bytes


DEFAULT_LEDGER = Path("ledger") / "aegis-ledger.jsonl"


def canonical(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def last_hash(path: str | Path = DEFAULT_LEDGER) -> tuple[int, str]:
    ledger = Path(path)
    if not ledger.exists():
        return 0, "GENESIS"
    last = None
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = json.loads(line)
    if last is None:
        return 0, "GENESIS"
    return int(last["index"]), str(last["record_hash"])


def append_record(payload: dict[str, Any], ledger_path: str | Path = DEFAULT_LEDGER) -> dict[str, Any]:
    ledger = Path(ledger_path)
    index, previous = last_hash(ledger)
    base = {
        "index": index + 1,
        "timestamp": datetime.now(UTC).isoformat(),
        "previous_hash": previous,
        "payload_hash": sha256_text(canonical(payload)),
    }
    record_hash = sha256_text(canonical(base))
    signature = sign_bytes(record_hash.encode("utf-8"))
    record = {**base, "record_hash": record_hash, "signature": signature, "payload": payload}
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(canonical(record) + "\n")
    return {key: record[key] for key in ("index", "timestamp", "previous_hash", "payload_hash", "record_hash", "signature")}


def verify_ledger(ledger_path: str | Path = DEFAULT_LEDGER) -> dict[str, Any]:
    ledger = Path(ledger_path)
    if not ledger.exists():
        return {"ok": True, "records": 0, "message": "ledger file does not exist yet"}
    previous = "GENESIS"
    count = 0
    for line_number, line in enumerate(ledger.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        base = {
            "index": record.get("index"),
            "timestamp": record.get("timestamp"),
            "previous_hash": record.get("previous_hash"),
            "payload_hash": record.get("payload_hash"),
        }
        if record.get("previous_hash") != previous:
            return {"ok": False, "line": line_number, "message": "broken hash chain"}
        if record.get("payload_hash") != sha256_text(canonical(record.get("payload"))):
            return {"ok": False, "line": line_number, "message": "payload hash mismatch"}
        expected_hash = sha256_text(canonical(base))
        if record.get("record_hash") != expected_hash:
            return {"ok": False, "line": line_number, "message": "record hash mismatch"}
        if not verify_bytes(str(record.get("record_hash")).encode("utf-8"), str(record.get("signature"))):
            return {"ok": False, "line": line_number, "message": "signature mismatch"}
        previous = str(record.get("record_hash"))
        count += 1
    return {"ok": True, "records": count, "message": "ledger verified"}
