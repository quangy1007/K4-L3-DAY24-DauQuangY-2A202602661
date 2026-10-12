"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_PREV_HASH = "0" * 64
REQUIRED_FIELDS = (
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
)


def _compute_hash(payload_without_hash: dict) -> str:
    canonical = json.dumps(payload_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = GENESIS_PREV_HASH
    if path.exists():
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            last_record = json.loads(lines[-1])
            prev_hash = str(last_record.get("hash", GENESIS_PREV_HASH))

    record = {k: v for k, v in entry.items() if k not in ("prev_hash", "hash")}
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return False

    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return False

    expected_prev_hash = GENESIS_PREV_HASH
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False

        if not isinstance(row, dict):
            return False

        for field in REQUIRED_FIELDS:
            if field not in row:
                return False

        reason = row.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return False

        if row.get("prev_hash") != expected_prev_hash:
            return False

        stored_hash = row.get("hash")
        if not isinstance(stored_hash, str) or not stored_hash:
            return False

        row_without_hash = {k: v for k, v in row.items() if k != "hash"}
        if _compute_hash(row_without_hash) != stored_hash:
            return False

        expected_prev_hash = stored_hash

    return True
