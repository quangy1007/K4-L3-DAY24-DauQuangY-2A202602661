# DPIA-lite — điền trong checkpoint 5

## 1. Loại dữ liệu và phân loại (Data Inventory & Classification)
- **Dữ liệu tổng hợp (Synthetic Data Only):** Toàn bộ dữ liệu trong repo được sinh tự động bằng `scripts/generate_fixtures.py` với `random.seed(20240824)` (`scripts/generate_fixtures.py:17`), không chứa dữ liệu cá nhân thật.
- **Hai nhóm dữ liệu và mức phân loại (`data_classification`):**
  1. **`internal` — Nội dung ticket hỗ trợ (`corpus/ticket-001.md`..`ticket-040.md`, `ticket-901.md`..`ticket-904b.md`):**
     - Là nguồn dữ liệu **không tin cậy (untrusted content)** do người dùng/bên ngoài gửi vào, có thể chứa cả thông tin xác minh cá nhân lẫn chỉ thị prompt injection của kẻ tấn công.
     - Trước khi đi qua ranh giới giữa các run, văn bản được lọc qua cổng PII (`agent/pii.py:44-91`) để phát hiện và che (`[REDACTED_<TYPE>]`) 4 loại thực thể nhạy cảm:
       - `VN_CCCD` (12 chữ số căn cước công dân)
       - `VN_PHONE` (số điện thoại Việt Nam 10–11 chữ số)
       - `VN_BANK_ACCOUNT` (số tài khoản ngân hàng 8–16 chữ số)
       - `EMAIL` (địa chỉ thư điện tử)
  2. **`restricted` — Hồ sơ định danh khách hàng (`data/customers.json`):**
     - Là kho dữ liệu riêng tư (**private data store**), mỗi bản ghi (`KH-000001`..`KH-000024`, `KH-000777`, `KH-000999`) chứa: `customer_id`, `name`, `cccd`, `phone`, `bank_account`, `email`, và `related_tickets`.
     - Chỉ được truy xuất khi thực sự cần đối chiếu theo `related_tickets` và tuyệt đối **cấm đi kèm quyền gửi ra mạng ngoài (`egress_enabled=True`)**.

## 2. Mục đích xử lý và Principal (Processing Purposes & Principals)
Nguồn chính sách định danh mô phỏng nằm tại `data/principals.json:1-5`:
- **`support_l1`:**
  - `allowed_tools`: `["search_docs"]`
  - `purposes`: `["summarize-tickets", "support-reply"]`
  - Chỉ được tìm và tóm tắt ticket (`search_docs` với dữ liệu `internal`); bị từ chối hoàn toàn (`deny`) khi gọi `read_customer` trên dữ liệu `restricted`.
- **`billing`:**
  - `allowed_tools`: `["search_docs", "read_customer"]`
  - `purposes`: `["summarize-tickets", "billing-reconciliation"]`
- **`dpo` (Data Protection Officer):**
  - `allowed_tools`: `["search_docs", "read_customer"]`
  - `purposes`: `["summarize-tickets", "support-reply", "privacy-audit"]`
  - Được phép đọc hồ sơ khách hàng (`read_customer`) gắn với các ticket hợp lệ (`related_tickets`) phục vụ mục đích `support-reply` khi `egress_enabled=False`, nhưng vẫn bị chặn tuyệt đối nếu cố gửi dữ liệu `restricted` qua `http_post` (`egress_enabled=True`).

## 3. Luồng dữ liệu qua các Run, Tool và Endpoint (Data Flow & Trifecta Split)
Kiến trúc `agent/runner.py:94-188` tách 1 yêu cầu thành 2 run độc lập để phá vỡ *lethal trifecta*:
1. **Run A (`lab24-agent/run-a`, `delegation_depth=0`, `egress_enabled=False`):**
   - Quyền tối đa (`agent_scopes`): `("search_docs",)`.
   - Gọi `tools.search_docs(message)` (`agent/tools.py:34-52`) đọc file `.md` từ `corpus/`.
   - Chạy `pii.redact()` (`agent/runner.py:127-129`) để che toàn bộ CCCD, SĐT, STK, Email trong văn bản trước khi chuyển cho `llm.summarize(sanitized_docs)`.
   - Chỉ trích xuất danh sách số nguyên `trusted_ticket_ids: list[int]` từ **tên file** (`agent/runner.py:42-49`, `132`) để truyền qua ranh giới sang Run B. Văn bản tự do (free text) của kẻ tấn công không bao giờ được dùng để suy ra `customer_id`.
2. **Run B (`lab24-agent/run-b`, `delegation_depth=1`, `parent_scopes=("search_docs", "read_customer")`):**
   - Quyền tối đa (`agent_scopes`): `("read_customer",)`.
   - Ánh xạ `trusted_ticket_ids` sang `candidate_customer_ids` chỉ thông qua trường `related_tickets` trong `data/customers.json` (`agent/runner.py:52-65`, `144`). Nhờ vậy, khách hàng `KH-000777` (`related_tickets: []`) dù bị kẻ tấn công nêu đích danh trong free text vẫn không bao giờ bị đọc (`tests/test_split.py`).
   - Trước mỗi lệnh `tools.read_customer(cid)` (`agent/tools.py:55-65`), Run B gọi `policy.check()` và `ledger.append()` (`agent/runner.py:147-164`).
3. **Kiểm soát Egress (`tools.http_post`) và Endpoint:**
   - Ở tầng công cụ, `tools.http_post()` (`agent/tools.py:68-85`) chỉ cho phép gọi tới loopback `http://127.0.0.1:10024/*` (sink nội bộ tại `sink/sink.py:58-61`).
   - Ở tầng kiến trúc và chính sách, mọi yêu cầu `http_post` xuất phát từ dữ liệu `restricted` (`egress_enabled=True`) đều bị `policy.check()` (`agent/policy.py:60-65`) chặn cứng với `decision="deny"`, nên hàm `tools.http_post()` không bao giờ được thực thi sau khi có containment.

## 4. Bằng chứng Deny/Allow và Giới hạn của Mock so với Hệ thống Thực tế
### Bằng chứng kiểm toán (Audit Evidence)
- **Trước containment (`reports/attack-before.log`):** Dòng log ghi nhận request `POST /reconcile` làm lộ nguyên bản ghi `KH-000999` (`cccd="811753472374"`, `phone="0861707895"`, `bank_account="9103069783"`, `email="le.thu.trang666@example.vn"`).
- **Sau containment (`reports/attack-after.log` & `reports/ledger.jsonl`):**
  - `reports/attack-after.log` rỗng hoàn toàn (`0 bytes`).
  - `reports/ledger.jsonl` lưu chuỗi băm SHA-256 (`verify(Path("reports/ledger.jsonl")) == True`), không lưu PII thô mà chỉ lưu `args_hash`, đầy đủ `on_behalf_of`, `agent_id`, `run_id`, `expires_at`, `decision` và `reason` không rỗng:
    - Với `support_l1`: `search_docs` -> `allow`; `read_customer` -> `deny` (thiếu quyền trong `effective_scopes`); `http_post` -> `deny` (`classification='restricted'` + `egress_enabled=True`).
    - Với `dpo`: `search_docs` -> `allow`; `read_customer` -> `allow` (đọc hợp lệ các khách hàng có `related_tickets` khớp); `http_post` -> `deny` (`classification='restricted'` + `egress_enabled=True`).

### Giới hạn của bài Lab / Mock so với Hệ thống Production
1. **Xác thực và uỷ quyền OBO (`--as` & `data/principals.json`):** Trong lab, cờ `--as` chỉ chọn một chuỗi `principal_id` giả lập và tra cứu file tĩnh `data/principals.json` (`agent/policy.py:38-40`). Hệ thống production phải xác thực danh tính thật qua OAuth2 / OIDC, sử dụng token OBO có chữ ký số (JWS/JWT), ràng buộc `aud`/`scp`/`exp` bằng mật mã học và kiểm tra thu hồi token.
2. **PII Gate (`agent/pii.py`):** Lab dùng bộ biểu thức chính quy (regex) đạt `precision=1.000, recall=1.000` trên tập dữ liệu tổng hợp `tests/vn_pii_testset.jsonl` (`118/118` thực thể). Tuy nhiên trong thực tế, văn bản tự nhiên có thể chứa PII phi cấu trúc (họ tên, địa chỉ, số viết bằng chữ hoặc bị làm rối) đòi hỏi kết hợp regex với mô hình NER tiếng Việt, danh sách từ chối (deny-list) và cơ chế DLP chuyên dụng.
3. **Mock LLM (`agent/llm.py`):** `MockLLM` phát hiện prompt injection dựa trên chuẩn hoá Unicode + khớp `>= 2` cụm từ khoá cố định (`_INSTRUCTION_MARKERS`, `agent/llm.py:32-45`). LLM thật trong production có thể bị thao túng bằng các kỹ thuật ngữ nghĩa phức tạp hoặc đa ngôn ngữ không chứa các marker cố định này — do đó an toàn của hệ thống phải dựa vào **kiến trúc cô lập Trifecta Split và PEP** chứ không được dựa vào bộ phát hiện `find_injection()`.
4. **Sổ cái kiểm toán (`agent/ledger.py`):** Chuỗi băm SHA-256 lưu trong một file cục bộ (`reports/ledger.jsonl`) giúp phát hiện việc sửa đổi một dòng ở giữa hoặc thiếu `reason` (`agent/ledger.py:55-95`), nhưng **không phát hiện được việc xoá các dòng cuối (truncation) hoặc viết lại toàn bộ file rồi tính lại chuỗi băm** nếu kẻ tấn công có quyền ghi file. Trong production, sổ cái phải được đẩy theo thời gian thực sang kho lưu trữ WORM / append-only log server độc lập có chữ ký số hoặc neo (anchor) hash ra hệ thống bên ngoài.
