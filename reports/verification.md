# Verification — điền trước khi nộp

- **OS / Python / Gitleaks version:**
  - OS: Windows 11 (`win32`, NT 10.0) / WSL2 Ubuntu sẵn sàng
  - Python: `Python 3.14.5` (`.venv`)
  - Gitleaks: `8.30.1` (`gitleaks version` -> `8.30.1`)
  - Pre-commit: `pre-commit 4.7.0` (hook `gitleaks-system` pin `rev: v8.30.1`)
- **`python -m pytest tests/ -q`:**
  - `33 passed` (100% test suite pass: `test_pii.py` đạt `precision=1.000, recall=1.000` trên 118 thực thể; `test_policy.py`, `test_obo.py`, `test_split.py`, `test_ledger.py`, `test_injection.py` (8/8 biến thể × principal), `test_supply_chain.py`, `test_check_lure_cli.py`, `test_scaffold_dispatch.py` đều PASS).
  - *Lưu ý:* `conftest.py` dùng fixture `clean_sink` tự xoá `reports/sink.log` sau mỗi test, vì vậy sau khi chạy `pytest` đã chạy lại bước Prove (`python sink/sink.py --reset` -> `python -m agent.loop --mock --as support_l1 ...` và `--as dpo ...`) để sinh `reports/attack-after.log` (`0 bytes`) và `reports/ledger.jsonl` thực tế.
- **`pre-commit run --all-files`:**
  - `Detect hardcoded secrets.................................................Passed` (exit code `0`).
  - Quét lịch sử Git bằng `gitleaks git --config .gitleaks.toml --redact --verbose .` phát hiện đúng 1 finding token giả (`RuleID: lab24-synthetic-token`, file `lab-fake-secret.txt`, commit `1bdd849`, exit code `1` như dự kiến).
  - Quét thư mục hiện tại bằng `gitleaks dir --config .gitleaks.toml .` báo `no leaks found` (exit code `0`).
- **Ledger verify:**
  - Lệnh: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (46 dòng log hợp lệ, đầy đủ `reason`, `on_behalf_of`, `run_id`, `expires_at`, chuỗi băm `prev_hash` -> `hash` liền mạch; có dòng `http_post` `deny` cho cả `support_l1` tại dòng 23 và `dpo` tại dòng 46).
- **Các lỗi còn lại:**
  - Không còn lỗi nào trong code, test hay pre-commit. (Trên Windows PowerShell mặc định mã hoá console `cp1252`, khi chạy `python -m agent.check_lure` in ký tự Unicode `─`/`✓` cần đặt `$env:PYTHONUTF8="1"`; khi bật UTF-8 báo `4/4 lure sẵn sàng`).
