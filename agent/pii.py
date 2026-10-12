"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).
"""
from __future__ import annotations

import re

# 1. Contextual bank account: đi kèm từ khoá STK / số tài khoản / bank_account
_BANK_CTX_RE = re.compile(
    r"(?i:\bstk\b|số\s+tài\s+khoản|so\s+tai\s+khoan|bank_account)\s*[:=-]?\s*(\d{8,16})\b"
)
# 2. Standalone bank account: 13-16 chữ số, hoặc 8-11 chữ số bắt đầu khác 0 (tránh trùng SĐT/CCCD)
_BANK_STANDALONE_RE = re.compile(r"\b(?:[1-9]\d{12,15}|[1-9]\d{7,10})\b")
# 3. CCCD Việt Nam: đúng 12 chữ số liên tiếp
_CCCD_RE = re.compile(r"\b\d{12}\b")
# 4. SĐT Việt Nam: bắt đầu bằng 0 (hoặc +84), tổng 10-11 chữ số, cho phép dấu cách hoặc gạch ngang đơn
_PHONE_RE = re.compile(r"(?<!\w)(?:\+84|0)\d(?:[\s-]?\d){8,9}\b")
# 5. Email chuẩn
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")


def _overlaps_any(start: int, end: int, spans: list[dict]) -> bool:
    return any(start < s["end"] and s["start"] < end for s in spans)


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    # Ưu tiên 1: STK có ngữ cảnh rõ ràng (kể cả STK 12 số không bị nhầm thành CCCD)
    for m in _BANK_CTX_RE.finditer(text):
        start, end = m.span(1)
        if not _overlaps_any(start, end, entities):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # Ưu tiên 2: Email
    for m in _EMAIL_RE.finditer(text):
        start, end = m.span(0)
        if not _overlaps_any(start, end, entities):
            entities.append({"type": "EMAIL", "start": start, "end": end})

    # Ưu tiên 3: CCCD 12 chữ số
    for m in _CCCD_RE.finditer(text):
        start, end = m.span(0)
        if not _overlaps_any(start, end, entities):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    # Ưu tiên 4: Số điện thoại Việt Nam
    for m in _PHONE_RE.finditer(text):
        start, end = m.span(0)
        digits_only = re.sub(r"[\s-]", "", m.group(0))
        if digits_only.startswith("+84"):
            digits_only = "0" + digits_only[3:]
        if len(digits_only) in (10, 11) and not _overlaps_any(start, end, entities):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})

    # Ưu tiên 5: STK đứng độc lập (8-11 hoặc 13-16 chữ số bắt đầu khác 0)
    for m in _BANK_STANDALONE_RE.finditer(text):
        start, end = m.span(0)
        if not _overlaps_any(start, end, entities):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    entities.sort(key=lambda e: (e["start"], e["end"]))
    return entities


def redact(text: str) -> str:
    entities = detect(text)
    if not entities:
        return text
    result = text
    for ent in sorted(entities, key=lambda e: (e["start"], e["end"]), reverse=True):
        result = result[: ent["start"]] + f"[REDACTED_{ent['type']}]" + result[ent["end"] :]
    return result
