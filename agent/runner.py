"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành 2 run riêng biệt — KHÔNG run nào được cầm
cả 3 chân của lethal trifecta cùng lúc:
  - Run A: chỉ gọi search_docs (untrusted content), redact PII trước khi
    qua boundary và chỉ xuất danh sách ticket_id kiểu int lấy từ tên file.
  - Run B: chỉ nhận danh sách int ticket_id đã sanitize từ Run A, tra cứu
    customer_id qua nguồn tin cậy data/customers.json (related_tickets),
    kiểm tra PEP + OBO trước khi gọi read_customer, và chặn tuyệt đối
    egress (http_post) đối với dữ liệu restricted.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
CUSTOMERS_FILE = DATA_DIR / "customers.json"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_FILENAME_RE = re.compile(r"^ticket-(\d+)[a-zA-Z]*\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _hash_args(args_obj: dict) -> str:
    canonical = json.dumps(args_obj, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _extract_ticket_ids_from_filenames(docs: list[dict]) -> list[int]:
    ticket_ids: set[int] = set()
    for doc in docs:
        doc_id = str(doc.get("id", ""))
        match = _TICKET_FILENAME_RE.match(doc_id)
        if match:
            ticket_ids.add(int(match.group(1)))
    return sorted(ticket_ids)


def _resolve_customers_from_trusted_store(
    ticket_ids: list[int], customers_file: Path | None = None
) -> list[str]:
    if not ticket_ids:
        return []
    wanted = set(ticket_ids)
    path = customers_file or CUSTOMERS_FILE
    customers = json.loads(path.read_text(encoding="utf-8"))
    matched_ids: list[str] = []
    for record in customers:
        related = {int(t) for t in record.get("related_tickets", [])}
        if related & wanted:
            matched_ids.append(str(record["customer_id"]))
    return matched_ids


def _log_and_check(
    ctx: PolicyContext,
    args_meta: dict,
    ledger_path: Path,
    run_id: str,
) -> bool:
    allow, reason = policy.check(ctx)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger.append(
        {
            "ts": now_iso,
            "agent_id": ctx.agent_owner,
            "run_id": run_id,
            "on_behalf_of": ctx.principal_id,
            "expires_at": ctx.expires_at,
            "tool": ctx.requested_tool,
            "args_hash": _hash_args(args_meta),
            "classification": ctx.data_classification,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        },
        ledger_path,
    )
    return allow


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    target_dir = Path(log_dir) if log_dir is not None else REPORTS_DIR
    ledger_path = target_dir / "ledger.jsonl"

    now_utc = datetime.now(timezone.utc)
    expires_at = (now_utc + timedelta(minutes=15)).isoformat()

    # ── RUN A: Untrusted Content Reader (chỉ có quyền search_docs, không private data, không egress) ──
    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_a_scopes = ("search_docs",)
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=run_a_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    if not _log_and_check(ctx_search, {"query_len": len(message)}, ledger_path, run_a_id):
        return "Yêu cầu bị từ chối bởi chính sách bảo mật (search_docs denied)."

    raw_docs = tools.search_docs(message)

    # PII Gate tại boundary: redact toàn bộ PII trong văn bản trước khi sử dụng tiếp
    sanitized_docs = [
        {"id": d["id"], "text": pii.redact(d["text"])} for d in raw_docs
    ]

    # Chỉ truyền dữ liệu có kiểu chặt (list[int] ticket_id lấy từ tên file) qua boundary sang Run B
    trusted_ticket_ids = _extract_ticket_ids_from_filenames(sanitized_docs)

    # Phát hiện xem trong untrusted corpus có chỉ thị đòi gọi egress (http_post) hay không
    # Lưu ý: TUYỆT ĐỐI KHÔNG lấy customer_ids từ injected.customer_ids (free text của attacker)
    combined_raw_text = "\n\n".join(d["text"] for d in raw_docs)
    injected = llm.find_injection(combined_raw_text)

    # ── RUN B: Private Data Reader (chỉ tra customer từ related_tickets, kiểm OBO trước khi đọc) ──
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"
    parent_scopes = ("search_docs", "read_customer")
    run_b_scopes = ("read_customer",)

    candidate_customer_ids = _resolve_customers_from_trusted_store(trusted_ticket_ids)
    collected_records: list[dict] = []

    for cid in candidate_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=run_b_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        if _log_and_check(ctx_read, {"customer_id": cid}, ledger_path, run_b_id):
            try:
                collected_records.append(tools.read_customer(cid))
            except tools.ToolError:
                continue

    # Nếu untrusted content cố kích hoạt http_post (egress), chặn tại PEP và ghi bằng chứng deny vào ledger
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=run_b_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        if _log_and_check(
            ctx_post,
            {"target_url": injected.target_url, "record_count": len(collected_records)},
            ledger_path,
            run_b_id,
        ):
            tools.http_post(injected.target_url, {"records": collected_records})

    return llm.summarize(sanitized_docs)
