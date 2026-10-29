# TỔNG KẾT ĐỒ ÁN CUỐI KỲ: SECURESHARE
> **Học phần:** Bảo mật mạng máy tính và hệ thống  
> **Đề tài:** SecureShare — Hệ thống chia sẻ tài liệu an toàn với xác thực, phân quyền, mã hóa và kiểm tra tính toàn vẹn dữ liệu  
> **Trạng thái hệ thống:** Đã hoàn thiện toàn diện (Hoàn thành 36/36 Automated Test Cases - 100% PASS)

---

## I. TỔNG QUAN BÀI TOÁN & MỤC TIÊU AN NINH
- **Hướng tiếp cận:** Tập trung chuyên sâu vào **Bảo mật (Security)** và **Toàn vẹn dữ liệu (Data Integrity)**.
- **Vấn đề giải quyết:** Các hệ thống chia sẻ tệp truyền thống thường lưu file dạng plaintext, dễ bị đánh cắp khi lộ máy chủ (Data-at-rest theft), bị sửa đổi ngầm (Data Tampering), bị tấn công leo thang quyền/duyệt URL (IDOR), hoặc rò rỉ dữ liệu ra ngoài mà không biết nguồn tuồn (Data Leakage).
- **Tài sản cần bảo vệ:** Tài khoản & Phiên đăng nhập, Nội dung tệp tin, Chuỗi băm toàn vẹn SHA-256, Khóa mật mã, Nhật ký kiểm toán an ninh (Audit Logs).

---

## II. THIẾT KẾ DỮ LIỆU & CÁC DATA MODELS (QUAN TRỌNG)

Hệ thống có **5 Database Models** cốt lõi được xây dựng bằng SQLAlchemy ORM (`app/models.py`). Dưới đây là phân tích chi tiết, **đặc biệt lưu ý các Model và trường dữ liệu đóng vai trò quyết định an ninh**:

```text
+-------------------+       1:N       +-------------------+       1:N       +---------------------+
|       User        | <-------------> |    FileRecord     | <-------------> |   FilePermission    |
| (Auth & Defense)  |                 | (Lõi dữ liệu tệp) |                 |   (Chống IDOR)      |
+---------+---------+                 +---------+---------+                 +---------------------+
          |                                     |
          | 1:N                                 | 1:N
          v                                     v
+-------------------+                 +-------------------+
|     AuditLog      |                 |    SharedLink     |
| (SOC Monitoring)  |                 | (TTL & One-time)  |
+-------------------+                 +-------------------+
```

---

### 1. `FileRecord` — MODEL QUAN TRỌNG BẬC NHẤT (Core Security Model) ⭐⭐⭐⭐⭐
> Đây là **trái tim** của toàn bộ bài toán bảo vệ tệp tin và kiểm tra toàn vẹn.

| Tên trường (Field) | Kiểu dữ liệu | Ý nghĩa an ninh đặc biệt |
|---|---|---|
| `id` | Integer (PK) | Định danh tài liệu trong hệ thống. |
| `owner_id` | Integer (FK) | Liên kết với `User.id` để xác định chủ sở hữu hợp pháp (chống IDOR). |
| `original_name` | String(255) | Tên gốc của tệp khi người dùng tải lên (được sanitize sạch sẽ chống Path Traversal). |
| **`stored_name`** | String(255, Unique) | **RẤT QUAN TRỌNG:** Tên file lưu trên ổ cứng là một UUID ngẫu nhiên (ví dụ `a4f1...2c.enc`). Kẻ tấn công đọc ổ cứng không thể đoán được nội dung bên trong là gì. |
| **`sha256_hash`** | String(64, Index) | **CỰC KỲ QUAN TRỌNG:** Lưu mã băm SHA-256 nguyên bản lúc upload. Đây là "chân lý" duy nhất để hệ thống đối chiếu phát hiện tệp tin bị sửa đổi/giả mạo (Tampering). |
| **`integrity_status`**| String(32) | Ghi nhận trạng thái toàn vẹn: `VALID`, `TAMPERED`, `UNKNOWN`. Nếu trạng thái là `TAMPERED`, mọi yêu cầu tải về bị khóa tức thì. |
| **`is_honeypot`** | Boolean (Default False)| **TÍNH NĂNG NÂNG CAO (Active Defense):** Đánh dấu đây là file "mồi nhử". Người dùng thường/kẻ tấn công tò mò bấm vào sẽ lập tức bị khóa tài khoản ngay tại chỗ. |
| `file_size`, `mime_type`| Int, String | Quản lý hạn mức dung lượng (tối đa 10MB) và kiểm tra định dạng MIME thực tế. |

---

### 2. `FilePermission` — MODEL PHÂN QUYỀN TRUY CẬP (Chống IDOR) ⭐⭐⭐⭐⭐
> Đảm bảo nguyên tắc đặc quyền tối thiểu (Least Privilege) và triệt tiêu lỗ hổng IDOR.

| Tên trường (Field) | Kiểu dữ liệu | Ý nghĩa an ninh |
|---|---|---|
| `file_id` | Integer (FK) | Tài liệu được cấp quyền. |
| `user_id` | Integer (FK) | Người dùng được nhận quyền truy cập. |
| **`permission`** | String(20) | Mức độ quyền hạn chi tiết: `VIEW` (chỉ xem thông tin/metadata) hoặc `DOWNLOAD` (được phép giải mã và tải nội dung). |
| **`UniqueConstraint`**| `('file_id', 'user_id')` | Đảm bảo tính nhất quán dữ liệu, mỗi người chỉ có duy nhất 1 bản ghi quyền trên 1 tệp. |

*Lưu ý bảo mật:* Backend kiểm tra nghiêm ngặt: `if current_user.id != file.owner_id and not has_permission(file.id, current_user.id, 'DOWNLOAD')` $\rightarrow$ Trả về **HTTP 403 Forbidden** và ghi log `ACCESS_DENIED`.

---

### 3. `AuditLog` — MODEL TRÁCH NHIỆM & TRUY VẾT (Non-repudiation / SOC) ⭐⭐⭐⭐
> Phục vụ giám sát an ninh tập trung, điều tra sự cố (Digital Forensics) và phát hiện tấn công.

| Tên trường (Field) | Kiểu dữ liệu | Ý nghĩa an ninh |
|---|---|---|
| `user_id` | Integer (FK, Nullable) | ID người thực hiện (nếu là tấn công ẩn danh thì để Null). |
| `username_snapshot`| String(64) | Lưu tên tài khoản tại thời điểm xảy ra sự kiện (không sợ bị sai lệch khi user đổi tên). |
| **`action`** | String(64, Index) | Tên sự kiện an ninh: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `UPLOAD_FILE`, `DOWNLOAD_FILE`, `ACCESS_DENIED`, `FILE_INTEGRITY_FAILED`, `HONEYPOT_TRIGGERED`. |
| `target_type`, `target_id`| String | Đối tượng bị tác động (`FILE`, `USER`, `AUTH`, `HONEYPOT`). |
| **`ip_address`** | String(64) | Địa chỉ IP của máy khách gửi yêu cầu. |
| **`user_agent`** | String(255) | Chuỗi định danh thiết bị/trình duyệt của người gửi yêu cầu. |
| **`status`** | String(32) | Phân cấp độ an ninh: `SUCCESS`, `FAILED`, `WARNING`, `CRITICAL`. |
| `message` | Text | Mô tả chi tiết hành vi và nguyên nhân lỗi. |

---

### 4. `User` — MODEL XÁC THỰC & PHÒNG THỦ DÒ QUÉT (Authentication & Lockout) ⭐⭐⭐⭐
> Bảo vệ danh tính và ngăn chặn tấn công từ chối dịch vụ / dò mật khẩu tự động.

| Tên trường / Hàm | Ý nghĩa an ninh |
|---|---|
| `password_hash` | Chuỗi băm an toàn theo chuẩn **PBKDF2:SHA-256** kết hợp Salt ngẫu nhiên. Tuyệt đối không lưu mật khẩu rõ. |
| **`failed_login_attempts`** | Đếm số lần đăng nhập thất bại liên tiếp. Khi đạt mốc 5 lần $\rightarrow$ kích hoạt khóa tài khoản. |
| **`locked_until`** | Mốc thời gian khóa tài khoản tạm thời (5 phút). Dù kẻ tấn công nhập đúng mật khẩu ở lần thứ 6 cũng bị từ chối. |
| **`totp_secret`, `is_2fa_enabled`** | **NÂNG CAO:** Xác thực 2 yếu tố (2FA) theo chuẩn RFC 6238 tương thích Google Authenticator. |
| `role` | Phân cấp vai trò: `user` (người dùng thông thường) hoặc `admin` (quản trị viên SOC). |

---

### 5. `SharedLink` — MODEL CHIA SẺ LIÊN KẾT AN TOÀN (Token & TTL) ⭐⭐⭐
> Hỗ trợ chia sẻ tệp ra bên ngoài nhưng vẫn kiểm soát được thời gian và số lượt.

- `token`: Chuỗi ngẫu nhiên bảo mật cao (URL-safe crypto token) dài 64 ký tự.
- `expires_at`: Mốc thời gian tự hủy liên kết (Time-To-Live). Quá giờ này link sẽ vô hiệu hóa.
- `max_downloads` & `download_count`: Giới hạn số lượt tải (ví dụ: chỉ cho tải 1 lần - One-time secret).
- `passcode_hash`: Mật khẩu bảo vệ bổ sung khi mở link (được băm PBKDF2).

---

## III. CÁC QUYẾT ĐỊNH THIẾT KẾ BẢO MẬT QUAN TRỌNG

Hệ thống có **4 quyết định thiết kế then chốt** cần nhấn mạnh trong bài thuyết trình:

### 1. Chu trình bảo mật tệp khép kín (End-to-End File Pipeline)
- **Khi Upload:** File tải lên $\rightarrow$ Đổi tên UUID $\rightarrow$ Tính băm SHA-256 nội dung gốc lưu DB $\rightarrow$ Mã hóa toàn bộ dữ liệu bằng thuật toán đối xứng **Fernet (AES-128-CBC + HMAC-SHA256)** $\rightarrow$ Ghi file `.enc` ra thư mục `storage/`.
- **Khi Download:** Đọc file `.enc` từ đĩa $\rightarrow$ Giải mã bằng khóa bí mật `FERNET_KEY` $\rightarrow$ Tính lại mã băm SHA-256 $\rightarrow$ **So khớp với CSDL**:
  - *Nếu khớp 100%:* Đóng dấu bản quyền số DLP và gửi về cho người dùng.
  - *Nếu sai lệch dù chỉ 1 bit:* **CHẶN ĐỨNG NGAY LẬP TỨC**, đổi trạng thái file thành `TAMPERED`, bắn cảnh báo đỏ lên màn hình và ghi log an ninh `FILE_INTEGRITY_FAILED`.

### 2. Ngăn ngừa triệt để lỗ hổng duyệt quyền (IDOR Prevention)
- Mọi thao tác truy cập file qua URL (`/files/<id>`, `/files/<id>/download`) đều đi qua lớp xác thực ủy quyền tập trung (`app/security/permissions.py`).
- Chỉ cho phép nếu: `User là Owner` HOẶC `User có quyền VIEW / DOWNLOAD trong bảng FilePermission`. Mọi hành vi sửa tham số URL đều trả về mã lỗi **HTTP 403 Forbidden**.

### 3. Phòng thủ chủ động (Active Defense — Honeypot Decoys)
- Admin có thể cắm các tệp mồi nhử mang tên nhạy cảm (ví dụ `passwords_root.txt`).
- Nếu có kẻ tấn công hoặc nội gián cố tình duyệt tìm và bấm tải tệp này, hệ thống sẽ kích hoạt bẫy: **Khóa ngay tài khoản kẻ tấn công, thu hồi phiên làm việc và báo động đỏ trạng thái `CRITICAL` trên Admin SOC Dashboard**.

### 4. Đóng dấu số pháp y chống tuồn dữ liệu (Forensic DLP Watermark)
- Khi một tài liệu văn bản hoặc ảnh hợp lệ được tải xuống, hệ thống tự động nhúng chìm thông tin: `SECURESHARE FORENSIC DLP WATERMARK | User: <username> | IP: <client_ip> | Timestamp: <utc_time>` vào nội dung tải về.
- Giúp truy vết nguồn gốc (Non-repudiation) nếu tài liệu bị chụp màn hình hoặc rò rỉ ra ngoài.

---

## IV. BẢN ĐỒ ĐÁNH ĐỔI THIẾT KẾ (SECURITY TRADE-OFFS)
> *Yêu cầu bắt buộc của môn học: Phân tích sự đánh đổi.*

| Tiêu chí | Mô hình truyền thống (Static Streaming) | Mô hình SecureShare (Security First) |
|---|---|---|
| **Cơ chế tải file** | Nginx / Web server gửi trực tiếp file tĩnh từ ổ cứng qua đường dẫn URL. | Bắt buộc chạy qua 4 bước: *Kiểm tra phiên $\rightarrow$ Kiểm tra quyền $\rightarrow$ Giải mã Fernet $\rightarrow$ Thẩm định SHA-256 $\rightarrow$ Đóng watermark*. |
| **Tốc độ & Tài nguyên** | Nhanh, tốn rất ít CPU của máy chủ. | **Đánh đổi:** Tăng nhẹ độ trễ mili-giây (latency) và tiêu tốn CPU máy chủ khi giải mã/băm hash. |
| **Mức độ an toàn** | Dễ lộ tệp tĩnh, không phát hiện được nếu file bị nhiễm mã độc/bị sửa đổi ngầm trên đĩa. | **Lợi ích đạt được:** Bảo vệ tuyệt đối bí mật dữ liệu (Data-at-rest), loại bỏ 100% rủi ro dữ liệu bị giả mạo và có nhật ký kiểm toán minh bạch. |

---

## V. KẾT QUẢ KIỂM THỬ TỰ ĐỘNG (AUTOMATED TESTS)
Hệ thống tích hợp bộ kiểm thử tự động **36 Test Cases** độc lập sử dụng `pytest`, toàn bộ **PASS 100%**:

1. **TC01 - TC06 (Xác thực & Phòng thủ):** Đăng ký, đăng nhập, phát hiện trùng lặp, băm mật khẩu, đếm lần sai và kích hoạt khóa tài khoản 5 phút khi sai $\ge 5$ lần.
2. **TC07 - TC10 (Upload & Mã hóa đĩa):** Tải lên file hợp lệ, chặn file đuôi cấm (`.exe`), giới hạn kích thước 10MB, kiểm chứng file trên đĩa ở dạng ciphertext Fernet.
3. **TC11 - TC14 (Phân quyền & Chống IDOR):** Quyền Owner, cấp quyền Download, chặn người dùng lạ, thử đổi ID trên URL bị chặn lỗi 403.
4. **TC15 - TC16 (Toàn vẹn & Chống Giả mạo):** Thẩm định SHA-256 thành công và kịch bản can thiệp byte tệp bị chặn đứng với mã lỗi toàn vẹn.
5. **TC17 - TC18 (Quản trị Admin):** Chặn User thường vào `/admin`, tài khoản Admin duyệt bảng SOC Logs.
6. **TC19 - TC26 (Advanced Security):** Mật khẩu yếu bị từ chối, định dạng email sai, cờ bảo mật cookie `HttpOnly`, kiểm tra Magic Byte chặn file giả dạng PDF (`sample_malware_disguised.pdf`), khử khuẩn Path Traversal filename (`../../../etc/passwd`).
7. **TC27 - TC36 (Ultra Security):** Bẫy Honeypot khóa tài khoản xâm nhập, đóng dấu chìm DLP Watermark text/image, chia sẻ link có thời hạn tự hủy (TTL), xác thực 2 lớp TOTP.

---

## VI. BỘ KỊCH BẢN DEMO THUYẾT TRÌNH TRONG 5 PHÚT

### 1. Chuẩn bị trước khi lên bục (Không tốn thời gian nhập liệu):
1. Chạy lệnh nạp dữ liệu sạch: `python scripts/seed_demo.py`
2. Mở sẵn **3 Tab**:
   - Tab 1: Trình duyệt bình thường - Đã login tài khoản `khoi` (người nhận file).
   - Tab 2: Trình duyệt ẩn danh - Đã login tài khoản `admin` (mở sẵn trang SOC Audit Logs).
   - Tab 3: Cửa sổ PowerShell - Gõ sẵn lệnh: `python scripts\tamper_demo.py 1`

### 2. Kịch bản nói & thao tác (4 phút 30 giây):
- **Phút 0:00 - 1:30 (Slide):**
  - Giới thiệu bài toán: Chọn hướng **Security**, bảo vệ bí mật và toàn vẹn file.
  - Nêu 4 quyết định thiết kế và 2 model quan trọng nhất: `FileRecord` (lưu UUID, SHA-256, Fernet) và `FilePermission` (chống IDOR).
  - Nêu sự đánh đổi: Chấp nhận độ trễ tính toán mã hóa/băm để đổi lấy an toàn dữ liệu tuyệt đối.
- **Phút 1:30 - 2:30 (Demo Luồng Chuẩn):**
  - Chuyển sang Tab 1: Người dùng `khoi` xem danh sách file được `bin` chia sẻ $\rightarrow$ Bấm **Tải về** $\rightarrow$ File tải về thành công (minh họa giải mã on-the-fly và kiểm tra quyền).
- **Phút 2:30 - 4:00 (Demo Tình Huống Rủi Ro "Ăn Tiền" - Data Tampering):**
  - *Nói:* "Bây giờ giả sử hacker xâm nhập ổ cứng server và sửa trộm byte file."
  - Bật PowerShell gõ Enter: chạy `tamper_demo.py 1` (đảo bit dữ liệu tệp mã hóa trên đĩa).
  - Quay lại Tab 1, bấm **Tải về lại** tệp ID `1`.
  - **Kết quả:** Hệ thống lập tức nhảy **Trang cảnh báo đỏ: "PHÁT HIỆN TỆP TIN BỊ GIẢ MẠO!"**, từ chối cho tải.
  - Chuyển sang Tab 2 (Admin): F5 thấy sự kiện cảnh báo đỏ `FILE_INTEGRITY_FAILED`.
- **Phút 4:00 - 4:30 (Kết bài):**
  - Bật terminal chiếu kết quả chạy `pytest -q` (36 passed in 32s). Kết thúc bài thuyết trình đúng giờ quy định.

