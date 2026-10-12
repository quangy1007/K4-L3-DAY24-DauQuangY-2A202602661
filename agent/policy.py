"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals(principals_file: Path | None = None) -> dict:
    path = principals_file or PRINCIPALS_FILE
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_iso_utc(ts: str) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    normalized = ts.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Rule tối thiểu bắt buộc: dữ liệu restricted đi kèm egress phải DENY tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return (
            False,
            f"Deny: classification='restricted' cannot be processed with egress_enabled=True "
            f"(owner={context.agent_owner}, tool={context.requested_tool or 'n/a'}).",
        )

    if not context.agent_owner or not context.request_purpose:
        return False, "Deny: missing agent_owner or request_purpose in PolicyContext."

    if context.delegation_depth < 0:
        return False, f"Deny: invalid negative delegation_depth={context.delegation_depth}."

    # 2. Kiểm tra Principal từ nguồn tin cậy data/principals.json
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return (
            False,
            f"Deny: unknown or unauthenticated principal_id={context.principal_id!r}.",
        )
    principal = principals[context.principal_id]

    # 3. Kiểm tra thời hạn uỷ quyền (TTL / expires_at)
    expires_dt = _parse_iso_utc(context.expires_at)
    if expires_dt is None:
        return False, f"Deny: missing or invalid expires_at={context.expires_at!r}."
    now_utc = datetime.now(timezone.utc)
    if expires_dt <= now_utc:
        return (
            False,
            f"Deny: session/token expired at {context.expires_at} (now={now_utc.isoformat()}).",
        )

    # 4. Kiểm tra mục đích xử lý (request_purpose) của principal
    allowed_purposes = set(principal.get("purposes", []))
    if context.request_purpose not in allowed_purposes:
        return (
            False,
            f"Deny: purpose={context.request_purpose!r} not allowed for principal "
            f"{context.principal_id!r} (allowed={sorted(allowed_purposes)}).",
        )

    # 5. Kiểm tra quyền hiệu lực OBO = principal.allowed_tools ∩ agent_scopes (∩ parent_scopes nếu depth > 0)
    if not context.requested_tool:
        return False, "Deny: requested_tool is empty."

    principal_tools = set(principal.get("allowed_tools", []))
    agent_scopes = set(context.agent_scopes)
    effective_scopes = principal_tools & agent_scopes
    if context.delegation_depth > 0:
        effective_scopes &= set(context.parent_scopes)

    if context.requested_tool not in effective_scopes:
        return (
            False,
            f"Deny: tool={context.requested_tool!r} is outside effective OBO scopes "
            f"{sorted(effective_scopes)} for principal={context.principal_id!r} "
            f"(depth={context.delegation_depth}).",
        )

    return (
        True,
        f"Allow: tool={context.requested_tool!r} permitted for principal={context.principal_id!r} "
        f"with purpose={context.request_purpose!r}, classification={context.data_classification!r}, "
        f"egress={context.egress_enabled}.",
    )
