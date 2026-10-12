# Secret giả trong lịch sử Git — điền trong checkpoint 4

- **Scanner và phiên bản:** `gitleaks` version `8.30.1` (cấu hình `.gitleaks.toml`, pre-commit hook `gitleaks-system` pin tại `rev: v8.30.1`).
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, ngày `2026-10-09T16:22:06Z`, message: `chore: seed student lab with synthetic secret exercise`).
- **File, rule và kết quả quét lịch sử:**
  - Lệnh: `gitleaks git --config .gitleaks.toml --redact --verbose .`
  - Kết quả: Phát hiện **1 finding** (exit code `1` như dự kiến đối với bài tập):
    - **File:** `lab-fake-secret.txt` (dòng `1`)
    - **RuleID:** `lab24-synthetic-token` (khớp mẫu `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}` trong `.gitleaks.toml:6-10`)
    - **Fingerprint:** `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`
    - *Lưu ý:* Đây là token giả (synthetic, vô hiệu) được cài sẵn trong lịch sử Git phục vụ bài lab, không phải lỗi bảo mật hay credential thật.
- **Kết quả quét file hiện tại (HEAD working tree):**
  - Lệnh: `gitleaks dir --config .gitleaks.toml .` và `pre-commit run --all-files`
  - Kết quả: **`no leaks found` (exit code `0`)** — file `lab-fake-secret.txt` đã được xoá ở commit sau (`ece6ca4`), cây thư mục hiện tại hoàn toàn sạch.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi (revoke) và xoay vòng (rotate) ngay lập tức** khóa/token bị lộ tại hệ thống cấp phát (IAM / API provider).
  2. **Kiểm tra nhật ký truy cập (audit logs)** trong khoảng thời gian từ lúc commit được push tới lúc revoke để phát hiện truy cập trái phép.
  3. **Dọn lịch sử Git** (ví dụ dùng `git filter-repo`) nếu cần xoá dấu vết nhạy cảm trên kho lưu trữ chia sẻ, nhưng bước bắt buộc đầu tiên luôn là **revoke/rotate**.
- **Vì sao xoá file khỏi HEAD, cài pre-commit hook hoặc pin dependency vẫn chưa đủ (không thay thế bước rotate):**
  - **Xoá file ở commit sau (`git rm`) chỉ ẩn file khỏi `HEAD`**, trong khi toàn bộ nội dung blob của `lab-fake-secret.txt` vẫn nằm nguyên trong lịch sử `.git/objects` (như commit `1bdd849`) và bất kỳ ai clone/fetch repo đều đọc lại được; ngoài ra các bản clone hoặc hệ thống CI/CD đã kéo commit trước đó vẫn giữ bản sao của secret.
  - **Pre-commit hook (`gitleaks-system`)** chỉ là chốt chặn phòng ngừa ở phía client trước khi tạo commit mới (có thể bị bỏ qua nếu lập trình viên chạy `--no-verify` hoặc commit từ máy chưa cài hook), hoàn toàn không vô hiệu hoá được một credential đã bị lộ ra ngoài.
  - **Pin dependency và hash lock (`requirements.lock` với `--require-hashes`)** bảo vệ chuỗi cung ứng phần mềm (chống giả mạo gói tin / dependency confusion / tampering khi cài từ PyPI), nhưng không có tác dụng thu hồi quyền truy cập của một secret đã bị lộ trong mã nguồn. Vì vậy, khi secret đã lộ, **thu hồi và rotate** là biện pháp duy nhất làm mất hiệu lực thực tế của khoá đó.
