# SecureShare — Hệ Thống Chia Sẻ Tài Liệu An Toàn

> **Học phần:** Bảo mật mạng máy tính và hệ thống  
> **Đồ án cuối kỳ:** Xây dựng hệ thống chia sẻ tài liệu an toàn với xác thực, phân quyền, mã hóa và kiểm tra tính toàn vẹn dữ liệu.

---

## 1. Giới thiệu dự án (Description)

**SecureShare** là một ứng dụng web hoàn chỉnh được thiết kế và triển khai nhằm giải quyết bài toán cốt lõi trong an toàn thông tin: **Chia sẻ tài liệu giữa các người dùng mà vẫn đảm bảo tính bí mật (Confidentiality), tính toàn vẹn (Integrity), tính sẵn sàng (Availability) và tính trách nhiệm (Non-repudiation / Auditability)**.

Hệ thống kết hợp các tiêu chuẩn bảo mật hiện đại:
- **Xác thực người dùng:** Băm mật khẩu PBKDF2:SHA-256 kết hợp cơ chế chống tấn công dò mật khẩu (Brute-force lockout & Rate limiting).
- **Phân quyền truy cập (Access Control):** Kiểm soát nghiêm ngặt quyền sở hữu (Owner) và quyền chia sẻ (VIEW, DOWNLOAD) tại backend, ngăn ngừa triệt để lỗ hổng IDOR.
- **Mã hóa lưu trữ (Encryption at Rest):** Toàn bộ tệp tin tải lên được mã hóa đối xứng Fernet (AES-128-CBC + HMAC-SHA256) và đổi tên thành UUID ngẫu nhiên trước khi ghi vào ổ đĩa máy chủ.
- **Kiểm định toàn vẹn (Integrity Verification):** Tính toán mã băm SHA-256 trên nội dung gốc khi tải lên và tự động giải mã, băm lại để thẩm định trước khi cho phép tải về. Nếu tệp tin bị giả mạo (Tampering), lượt tải sẽ bị chặn ngay lập tức.
- **Nhật ký an ninh (Security Audit Logs):** Ghi vết chi tiết mọi hành vi quan trọng phục vụ công tác giám sát SOC và điều tra sự cố.

---

## 2. Mục tiêu đồ án (Objectives)

1. Xây dựng prototype ứng dụng web chạy thực tế, ổn định trên môi trường local.
2. Giao diện trực quan, hiện đại, tối giản theo phong cách **Trắng + Xanh dương (White & Blue)**.
3. Hiện thực đầy đủ chu trình bảo mật: Xác thực & Quản lý phiên $\rightarrow$ Kiểm soát tải lên $\rightarrow$ Mã hóa dữ liệu $\rightarrow$ Phân quyền chi tiết $\rightarrow$ Kiểm tra toàn vẹn $\rightarrow$ Ghi nhận nhật ký kiểm toán.
4. Xây dựng bộ test tự động với pytest bao phủ các kịch bản kiểm thử luồng nghiệp vụ và luồng tấn công rủi ro.
5. Cung cấp bộ công cụ giả lập tấn công (Tamper demo tool) và dữ liệu mẫu (Seed script) để phục vụ trình diễn học thuật.

---

## 3. Bài toán bảo mật (Security Problem)

Trong các hệ thống chia sẻ tệp truyền thống hoặc các dịch vụ lưu trữ chưa chuẩn hóa, doanh nghiệp và người dùng thường đối mặt với các nguy cơ nghiêm trọng:
- **Lộ lọt dữ liệu khi máy chủ bị xâm nhập:** Nếu tệp tin được lưu trữ dạng plaintext trên ổ cứng máy chủ, kẻ tấn công hoặc quản trị viên bất chính có thể đọc trộm toàn bộ nội dung.
- **Giả mạo dữ liệu (Data Tampering):** Tệp tin lưu trữ có thể bị sửa đổi, chèn mã độc bởi phần mềm gián điệp mà người dùng không thể nhận biết khi tải về.
- **Leo thang đặc quyền & IDOR:** Người dùng thay đổi tham số `file_id` trên thanh địa chỉ URL để xem hoặc tải về tài liệu riêng tư của người khác.
- **Dò quét mật khẩu (Brute-force Attacks):** Kẻ tấn công tự động hóa việc thử hàng nghìn mật khẩu để chiếm đoạt tài khoản.
- **Thiếu khả năng truy vết (Lack of Auditability):** Khi xảy ra sự cố rò rỉ dữ liệu, hệ thống không có nhật ký chi tiết để xác định ai đã truy cập, vào lúc nào và từ địa chỉ IP nào.

---

## 4. Tài sản cần bảo vệ (Assets)

1. **Thông tin tài khoản:** Mật khẩu, danh tính người dùng và phiên đăng nhập (Session cookie).
2. **Tài liệu người dùng (Files):** Nội dung plaintext của tài liệu, báo cáo, hợp đồng, hình ảnh.
3. **Mã băm toàn vẹn (Integrity Hashes):** Giá trị SHA-256 lưu trữ trong cơ sở dữ liệu.
4. **Khóa mã hóa (Cryptographic Keys):** Khóa Fernet và Secret key của ứng dụng.
5. **Nhật ký kiểm toán (Audit Logs):** Bằng chứng pháp lý ghi vết các hành vi an ninh hệ thống.

---

## 5. Đối tượng người dùng (Users)

- **USER (Người dùng tiêu chuẩn):**
  - Đăng ký tài khoản, đăng nhập, đổi phiên làm việc an toàn.
  - Tải lên tài liệu cá nhân (tự động mã hóa và tính hash).
  - Quản lý tài liệu sở hữu: xem chi tiết, tải về, phân quyền chia sẻ (VIEW / DOWNLOAD), gỡ quyền.
  - Xem danh sách tài liệu được người khác chia sẻ với mình.
  - Theo dõi nhật ký hoạt động cá nhân.
- **ADMIN (Quản trị viên an ninh):**
  - Xem dashboard tổng quan an ninh (SOC Dashboard).
  - Thống kê các sự kiện: Đăng nhập sai, Tài khoản bị khóa, Truy cập trái phép (IDOR), Tệp tin bị giả mạo.
  - Xem danh sách tài khoản người dùng và trạng thái khóa.
  - Xem và lọc toàn bộ nhật ký hệ thống (Audit Logs) theo hành động, trạng thái và người dùng.
  - *Lưu ý an ninh:* Quản trị viên chỉ xem metadata và nhật ký, không được tự động đọc nội dung tài liệu riêng tư của người dùng nếu không được chia sẻ quyền.

---

## 6. Tác nhân đe dọa (Threat Actors)

- **Kẻ tấn công ngoài (External Attacker):** Dò quét mật khẩu người dùng, khai thác lỗ hổng IDOR qua tham số URL, gửi tệp thực thi độc hại (`.exe, .sh`).
- **Kẻ tấn công nội bộ (Insider Threat):** Người dùng có tài khoản hợp lệ cố tình truy cập tài liệu của phòng ban khác mà mình không được phân quyền.
- **Kẻ xâm nhập máy chủ lưu trữ (Storage Intruder):** Kẻ đã chiếm quyền truy cập hệ thống tệp đĩa cứng và sửa đổi trực tiếp các byte dữ liệu của tệp tin.

---

## 7. Bảng mô hình đe dọa (Threat Model Table)

| Mối đe dọa (Threat) | Tài sản mục tiêu (Asset) | Mức rủi ro | Cơ chế phòng thủ (Defense Control) |
|---|---|---|---|
| **Brute-force Login** | Tài khoản người dùng | Cao (High) | Khóa tài khoản tạm thời 5 phút sau 5 lần nhập sai + Rate limiting 10 req/phút. |
| **Stolen Session** | Phiên đăng nhập / Tệp tin | Cao (High) | Cookie `HttpOnly`, `SameSite=Lax`, Session timeout 30 phút, hủy session khi logout. |
| **IDOR / Bypassed Auth** | Tài liệu riêng tư | Cao (High) | Xác thực quyền sở hữu và bảng `FilePermission` chặt chẽ ở backend cho mọi route. |
| **File Tampering** | Tính toàn vẹn của tệp | Cao (High) | Tính SHA-256 gốc, kiểm định lại trước khi cho phép tải xuống; chặn tải nếu không khớp. |
| **File Theft on Disk** | Bí mật dữ liệu tệp | Cao (High) | Mã hóa đối xứng Fernet (AES-128-CBC + HMAC) toàn bộ tệp; lưu tên ngẫu nhiên UUID. |
| **Dangerous File Upload** | An toàn máy chủ | Trung bình | Kiểm tra whitelist đuôi tệp (`.pdf, .docx, .txt, .png, .jpg`), giới hạn kích thước 10 MB. |
| **Privilege Abuse** | Toàn bộ hệ thống | Cao (High) | Phân quyền vai trò RBAC (`@admin_required`), admin không tự tiện đọc nội dung tệp cá nhân. |
| **Hidden Attack Activity** | Khả năng truy vết | Trung bình | Ghi nhận chi tiết vào bảng `AuditLog` với IP, User-Agent, Action, Status, Message. |

---

## 8. Các biện pháp kiểm soát an ninh (Security Controls)

1. **Xác thực mạnh:** Mật khẩu bắt buộc tối thiểu 8 ký tự, có chữ hoa, chữ thường và chữ số.
2. **Bảo vệ biểu mẫu:** Tích hợp CSRF token cho toàn bộ các POST requests thông qua Flask-WTF.
3. **Mã hóa lưu trữ (At-rest Encryption):** Dùng thư viện `cryptography.fernet`. Khóa được nạp từ biến môi trường `.env`, không hard-code trong mã nguồn.
4. **Kiểm tra tính toàn vẹn (Integrity Verification):** Thuật toán `hashlib.sha256`. Chỉ gửi tệp tin cho người dùng khi mã băm tính toán lại khớp 100% với giá trị lưu trong cơ sở dữ liệu.
5. **Cách ly định danh lưu trữ:** Tệp tin lưu trữ với tên `<uuid4>.<ext>.enc` trong thư mục `storage/`, tách biệt hoàn toàn với tên hiển thị của người dùng.

---

## 9. Kiến trúc hệ thống (Architecture)

```text
+--------------------------------------------------------------+
|                    Trình duyệt (Browser)                    |
|             Giao diện Trắng - Xanh (Bootstrap 5)            |
+------------------------------+-------------------------------+
                               |
                               | HTTPS / HTTP + CSRF Token
                               v
+--------------------------------------------------------------+
|                     Flask Application Core                   |
+------------------------------+-------------------------------+
                               |
         +---------------------+---------------------+
         |                                           |
         v                                           v
+------------------+                       +-------------------+
| Module Xác thực  |                       | Module Phân quyền |
| - Flask-Login    |                       | - Owner Check     |
| - PBKDF2:SHA-256 |                       | - VIEW / DOWNLOAD |
| - Rate Limiter   |                       | - IDOR Prevention |
+--------+---------+                       +---------+---------+
         |                                           |
         +---------------------+---------------------+
                               |
                               v
+--------------------------------------------------------------+
|                    File Security Pipeline                    |
|                                                              |
|   [Upload]:   Plaintext -> SHA-256 -> Fernet Encrypt -> Disk |
|   [Download]: Disk -> Fernet Decrypt -> Check SHA-256        |
|               -> (Match: Cho phép tải / Mismatch: Chặn tải)  |
+------------------------------+-------------------------------+
                               |
         +---------------------+---------------------+
         |                                           |
         v                                           v
+------------------+                       +-------------------+
|  SQLite Database |                       |  Isolated Storage |
|  (secureshare.db)|                       |  (UUID.enc files) |
+--------+---------+                       +-------------------+
         |
         v
+------------------+
|    Audit Logs    |
| (Giám sát SOC)   |
+------------------+
```

---

## 10. Cấu trúc thư mục dự án (Folder Structure)

```text
CuoiKi_BMMTVHT/
│
├── run.py                          # Điểm khởi chạy ứng dụng Flask
├── requirements.txt                # Danh sách thư viện phụ thuộc Python
├── .env.example                    # Tệp mẫu cấu hình biến môi trường
├── .env                            # Tệp cấu hình bí mật cục bộ (không commit)
├── .gitignore                      # Danh sách loại trừ khỏi git
├── README.md                       # Tài liệu hướng dẫn đồ án chi tiết
│
├── app/                            # Mã nguồn ứng dụng chính (Application Factory)
│   ├── __init__.py                 # Tạo Flask app factory, đăng ký blueprints & error handlers
│   ├── config.py                   # Cấu hình hệ thống (Config, TestConfig)
│   ├── extensions.py               # Khởi tạo db, login_manager, csrf, limiter
│   ├── models.py                   # ORM Models: User, FileRecord, FilePermission, AuditLog
│   │
│   ├── auth/                       # Phân hệ Xác thực tài khoản
│   │   ├── __init__.py
│   │   ├── routes.py               # Routes: /register, /login, /logout
│   │   └── forms.py                # Biểu mẫu: RegisterForm, LoginForm
│   │
│   ├── files/                      # Phân hệ Quản lý tài liệu & Chia sẻ
│   │   ├── __init__.py
│   │   ├── routes.py               # Routes: /, /dashboard, /files, /upload, /share, /download
│   │   ├── forms.py                # Biểu mẫu: UploadForm, ShareForm
│   │   └── services.py             # Nghiệp vụ: mã hóa, giải mã, băm hash, kiểm tra toàn vẹn
│   │
│   ├── admin/                      # Phân hệ Quản trị an ninh
│   │   ├── __init__.py
│   │   └── routes.py               # Routes: /admin, /admin/users, /admin/logs
│   │
│   ├── audit/                      # Phân hệ Nhật ký kiểm toán
│   │   ├── __init__.py
│   │   └── services.py             # Dịch vụ ghi log an ninh: log_security_event()
│   │
│   ├── security/                   # Các module mật mã & phân quyền lõi
│   │   ├── __init__.py
│   │   ├── crypto.py               # Mã hóa & giải mã Fernet
│   │   ├── hashing.py              # Tính toán mã băm SHA-256
│   │   ├── permissions.py          # Kiểm tra quyền: Owner, View, Download
│   │   └── decorators.py           # Decorator phân quyền: @admin_required
│   │
│   ├── templates/                  # Giao diện Jinja2 (Tone màu Trắng + Xanh)
│   │   ├── base.html               # Layout khung, navbar, flash messages, footer
│   │   ├── home.html               # Trang chủ giới thiệu
│   │   ├── dashboard.html          # Bảng điều khiển người dùng
│   │   ├── activity.html           # Lịch sử hoạt động cá nhân
│   │   ├── auth/
│   │   │   ├── login.html          # Giao diện đăng nhập
│   │   │   └── register.html       # Giao diện đăng ký với kiểm tra mật khẩu
│   │   ├── files/
│   │   │   ├── index.html          # Danh sách tệp (My Files & Shared With Me)
│   │   │   ├── upload.html         # Tải lên tệp kéo thả an toàn
│   │   │   └── detail.html         # Chi tiết tệp, mã SHA-256 & phân quyền chia sẻ
│   │   ├── admin/
│   │   │   ├── dashboard.html      # Trung tâm giám sát SOC admin
│   │   │   ├── users.html          # Danh sách quản lý tài khoản
│   │   │   └── logs.html           # Bảng nhật ký kiểm toán với bộ lọc
│   │   └── errors/                 # Trang lỗi bảo mật
│   │       ├── 403.html            # Từ chối truy cập / IDOR blocked
│   │       ├── 404.html            # Không tìm thấy trang
│   │       ├── 413.html            # Dung lượng tệp quá lớn
│   │       ├── 429.html            # Vượt quá giới hạn tần suất (Rate limit)
│   │       ├── 500.html            # Lỗi máy chủ
│   │       └── tampered.html       # Cảnh báo tệp tin bị giả mạo toàn vẹn
│   │
│   └── static/                     # Tài sản tĩnh
│       ├── css/
│       │   └── app.css             # Định kiểu hiện đại Trắng - Xanh
│       └── js/
│           └── app.js              # Xử lý kéo thả, sao chép hash, kiểm tra mật khẩu
│
├── storage/                        # Thư mục lưu trữ tệp mã hóa (UUID.enc)
│   └── .gitkeep
│
├── instance/                       # Thư mục chứa CSDL SQLite cục bộ
│   └── .gitkeep
│
├── evidence/                       # Thư mục lưu hình ảnh minh chứng báo cáo
│   └── .gitkeep
│
├── scripts/                        # Tập lệnh tiện ích quản trị & thử nghiệm
│   ├── generate_key.py             # Sinh khóa Fernet và Secret key tự động vào .env
│   ├── seed_demo.py                # Khởi tạo CSDL, 4 tài khoản mẫu và các tệp mã hóa
│   └── tamper_demo.py              # Công cụ giả lập sửa đổi byte tệp để demo phát hiện giả mạo
│
└── tests/                          # Bộ kiểm thử tự động (Pytest)
    ├── conftest.py                 # Cấu hình fixtures, CSDL tạm, thư mục storage tạm
    ├── test_auth.py                # TC01 - TC06: Kiểm thử xác thực & chống dò quét
    ├── test_upload.py              # TC07 - TC10: Kiểm thử xác thực upload & mã hóa đĩa
    ├── test_permissions.py         # TC11 - TC14: Kiểm thử phân quyền & chống IDOR
    ├── test_integrity.py           # TC15 - TC16: Kiểm thử toàn vẹn dữ liệu & chặn giả mạo
    └── test_admin.py               # TC17 - TC18: Kiểm thử phân quyền quản trị admin
```

---

## 11. Thiết kế cơ sở dữ liệu (Database Schema)

### Bảng `users`
- `id` (INTEGER, Primary Key): Định danh duy nhất.
- `username` (VARCHAR(64), Unique, Indexed): Tên đăng nhập.
- `email` (VARCHAR(120), Unique, Indexed): Địa chỉ thư điện tử.
- `password_hash` (VARCHAR(256)): Chuỗi băm mật khẩu PBKDF2:SHA-256.
- `role` (VARCHAR(20)): Vai trò (`user` hoặc `admin`).
- `failed_login_attempts` (INTEGER): Số lần đăng nhập sai liên tiếp.
- `locked_until` (DATETIME, Nullable): Mốc thời gian khóa tài khoản tạm thời.
- `created_at` (DATETIME): Thời điểm đăng ký.
- `last_login_at` (DATETIME, Nullable): Lần đăng nhập gần nhất.

### Bảng `file_records`
- `id` (INTEGER, Primary Key): Định danh tệp.
- `owner_id` (INTEGER, Foreign Key $\rightarrow$ `users.id`): Chủ sở hữu tệp.
- `original_name` (VARCHAR(255)): Tên gốc của tệp khi tải lên.
- `stored_name` (VARCHAR(255), Unique): Tên tệp ngẫu nhiên UUID lưu trên đĩa.
- `mime_type` (VARCHAR(128)): Định dạng tệp MIME.
- `file_size` (INTEGER): Dung lượng tệp tính bằng byte.
- `sha256_hash` (VARCHAR(64), Indexed): Mã băm SHA-256 nguyên bản.
- `integrity_status` (VARCHAR(32)): Trạng thái toàn vẹn (`VALID`, `TAMPERED`, `UNKNOWN`).
- `created_at` (DATETIME): Ngày tải lên.
- `updated_at` (DATETIME): Ngày cập nhật.

### Bảng `file_permissions`
- `id` (INTEGER, Primary Key): Định danh quyền.
- `file_id` (INTEGER, Foreign Key $\rightarrow$ `file_records.id`): Tệp tin được cấp quyền.
- `user_id` (INTEGER, Foreign Key $\rightarrow$ `users.id`): Người dùng nhận quyền.
- `permission` (VARCHAR(20)): Quyền truy cập (`VIEW` hoặc `DOWNLOAD`).
- `created_at` (DATETIME): Ngày cấp quyền.
- *Ràng buộc:* `UniqueConstraint('file_id', 'user_id')` đảm bảo mỗi cặp tệp - người dùng có 1 mức quyền duy nhất.

### Bảng `audit_logs`
- `id` (INTEGER, Primary Key): Định danh log.
- `user_id` (INTEGER, Foreign Key $\rightarrow$ `users.id`, Nullable): ID người thực hiện.
- `username_snapshot` (VARCHAR(64)): Tên người dùng tại thời điểm ghi nhận.
- `action` (VARCHAR(64), Indexed): Tên hành động an ninh (LOGIN_SUCCESS, ACCESS_DENIED,...).
- `target_type` (VARCHAR(64)): Loại đối tượng bị tác động (`USER`, `FILE`, `AUTH`, `SYSTEM`).
- `target_id` (VARCHAR(128), Nullable): ID của đối tượng bị tác động.
- `ip_address` (VARCHAR(64)): Địa chỉ IP của yêu cầu.
- `user_agent` (VARCHAR(255)): Thông tin trình duyệt/ứng dụng gửi yêu cầu.
- `status` (VARCHAR(32)): Kết quả (`SUCCESS`, `FAILED`, `WARNING`).
- `message` (TEXT): Nội dung chi tiết của sự kiện.
- `created_at` (DATETIME, Indexed): Thời điểm phát sinh sự kiện.

---

## 12. Hướng dẫn cài đặt và chạy ứng dụng

### 12.1 Môi trường Windows PowerShell

```powershell
# 1. Tạo môi trường ảo Python
python -m venv .venv

# 2. Kích hoạt môi trường ảo
.venv\Scripts\Activate.ps1

# 3. Cài đặt các gói phụ thuộc
pip install -r requirements.txt

# 4. Sao chép tệp cấu hình mẫu
copy .env.example .env

# 5. Sinh khóa mã hóa bảo mật Fernet và Secret Key
python scripts\generate_key.py

# 6. Khởi tạo cơ sở dữ liệu và nạp dữ liệu demo
python scripts\seed_demo.py

# 7. Khởi chạy máy chủ ứng dụng
python run.py
```

### 12.2 Môi trường Linux / macOS (Bash / Zsh)

```bash
# 1. Tạo môi trường ảo Python
python3 -m venv .venv

# 2. Kích hoạt môi trường ảo
source .venv/bin/activate

# 3. Cài đặt các gói phụ thuộc
pip install -r requirements.txt

# 4. Sao chép tệp cấu hình mẫu
cp .env.example .env

# 5. Sinh khóa mã hóa bảo mật Fernet và Secret Key
python scripts/generate_key.py

# 6. Khởi tạo cơ sở dữ liệu và nạp dữ liệu demo
python scripts/seed_demo.py

# 7. Khởi chạy máy chủ ứng dụng
python run.py
```

Sau khi chạy thành công, truy cập ứng dụng tại:
👉 **`http://127.0.0.1:5000`**

---

## 13. Danh sách tài khoản thử nghiệm (Demo Accounts)

Hệ thống được khởi tạo sẵn với 4 tài khoản mẫu:

| Tên đăng nhập (Username) | Mật khẩu (Password) | Vai trò (Role) | Mục đích minh họa |
|---|---|---|---|
| **admin** | `Admin@123` | **admin** | Theo dõi trung tâm giám sát SOC, Audit Logs, các sự kiện an ninh. |
| **bin** | `Bin@12345` | **user** | Chủ sở hữu tệp `bao_cao_bin.txt` (được chia sẻ cho Khôi quyền DOWNLOAD). |
| **khoi** | `Khoi@12345` | **user** | Chủ sở hữu tệp `ke_hoach_khoi.txt` (được chia sẻ cho Chương quyền VIEW). |
| **chuong** | `Chuong@12345` | **user** | Người dùng kiểm thử truy cập trái phép (IDOR test target). |

---

## 14. Lệnh kiểm thử tự động (Test Command)

Hệ thống tích hợp bộ kiểm thử tự động 18 test cases bằng `pytest`. Để chạy toàn bộ test trong môi trường độc lập (CSDL và thư mục lưu trữ tạm thời trong bộ nhớ):

```bash
pytest -q
```

Kết quả mong đợi:
```text
..................                                                       [100%]
18 passed in 23.67s
```

### Chi tiết 18 Test Cases bắt buộc:
- **Authentication:**
  - `TC01`: Đăng ký tài khoản hợp lệ $\rightarrow$ Thành công, mật khẩu được băm an toàn, ghi nhận audit log `REGISTER`.
  - `TC02`: Đăng ký tài khoản với username đã tồn tại $\rightarrow$ Bị từ chối (Reject duplicate).
  - `TC03`: Đăng nhập với mật khẩu chính xác $\rightarrow$ Thành công, cấp phiên làm việc, ghi nhận `LOGIN_SUCCESS`.
  - `TC04`: Đăng nhập sai mật khẩu $\rightarrow$ Tăng biến đếm thất bại, ghi nhận `LOGIN_FAILED`.
  - `TC05`: Đăng nhập sai $\ge 5$ lần liên tiếp $\rightarrow$ Tài khoản bị khóa tạm thời 5 phút, ghi nhận `ACCOUNT_LOCKED`.
  - `TC06`: Người dùng chưa đăng nhập cố tình vào `/dashboard` $\rightarrow$ Chuyển hướng về `/login`.
- **Upload Validation & Storage Encryption:**
  - `TC07`: Tải lên tài liệu `.pdf` $\rightarrow$ Thành công, mã hóa lưu trữ và ghi nhận `UPLOAD_FILE`.
  - `TC08`: Tải lên tệp thực thi độc hại `.exe` $\rightarrow$ Bị từ chối (HTTP 400), ghi nhận `INVALID_UPLOAD`.
  - `TC09`: Tải lên tệp vượt quá giới hạn 10 MB $\rightarrow$ Bị từ chối (HTTP 400 / 413).
  - `TC10`: Kiểm tra tệp tin trên ổ đĩa vật lý $\rightarrow$ Dữ liệu trên đĩa không bằng plaintext ban đầu, bắt đầu bằng định dạng chuỗi mã hóa Fernet.
- **Authorization & IDOR Prevention:**
  - `TC11`: Chủ sở hữu truy cập xem chi tiết tệp của mình $\rightarrow$ Thành công (HTTP 200).
  - `TC12`: Người dùng được chia sẻ quyền `DOWNLOAD` tải về tệp $\rightarrow$ Thành công, nội dung chính xác.
  - `TC13`: Người dùng lạ không có quyền truy cập tệp $\rightarrow$ Bị chặn với mã lỗi HTTP 403.
  - `TC14`: Tấn công IDOR (thay đổi tham số `file_id` trên URL) $\rightarrow$ Trả về HTTP 403, ghi nhận `ACCESS_DENIED`.
- **Integrity Verification & Tampering Defense:**
  - `TC15`: Tệp tin hợp lệ $\rightarrow$ Kiểm định SHA-256 thành công, trạng thái `VALID`, cho phép tải về.
  - `TC16`: Tệp tin bị can thiệp byte trên đĩa $\rightarrow$ Phát hiện lỗi toàn vẹn, chặn tải về (HTTP 400), chuyển trạng thái `TAMPERED`, ghi nhận `FILE_INTEGRITY_FAILED`.
- **Role-Based Access Control (Admin):**
  - `TC17`: Người dùng thường cố tình truy cập vào `/admin` $\rightarrow$ Bị chặn với mã lỗi HTTP 403, ghi nhận `ACCESS_DENIED`.
  - `TC18`: Tài khoản Admin truy cập `/admin/logs` $\rightarrow$ Thành công (HTTP 200), hiển thị toàn bộ lịch sử kiểm toán.

---

## 15. Kịch bản trình diễn (Demo Scenarios)

### Kịch bản 1 — Luồng chia sẻ an toàn bình thường (Normal Flow)
1. Đăng nhập tài khoản **`bin`** (`Bin@12345`).
2. Tải lên một tệp văn bản mới hoặc xem tệp `bao_cao_bin.txt`.
3. Xem chuỗi băm **SHA-256** của tệp và chia sẻ tệp cho người dùng **`khoi`** với quyền **`DOWNLOAD`**.
4. Đăng xuất tài khoản `bin`.
5. Đăng nhập tài khoản **`khoi`** (`Khoi@12345`).
6. Vào mục **Tài liệu** $\rightarrow$ chọn tab **Được chia sẻ với tôi**.
7. Bấm nút **Tải về** $\rightarrow$ Tệp được giải mã và tải về thành công.

### Kịch bản 2 — Chống tấn công dò quét mật khẩu (Brute-Force Protection)
1. Vào trang đăng nhập `/login`.
2. Nhập username `bin` và nhập sai mật khẩu 5 lần liên tiếp.
3. Ở lần thử thứ 5 trở đi: Hệ thống thông báo **"Tài khoản của bạn đã bị khóa tạm thời 5 phút do nhập sai 5 lần liên tiếp."**
4. Kẻ tấn công dù nhập đúng mật khẩu ở lần thứ 6 cũng sẽ bị từ chối đăng nhập.
5. Đăng nhập bằng tài khoản `admin` $\rightarrow$ Vào **Quản trị Admin** $\rightarrow$ Thấy thông báo cảnh báo và bản ghi `ACCOUNT_LOCKED`.

### Kịch bản 3 — Chống tấn công duyệt quyền trực tiếp (IDOR Prevention)
1. Tài khoản `bin` sở hữu tệp tin có ID là `1`.
2. Đăng nhập bằng tài khoản **`chuong`** (`Chuong@12345`) — người chưa từng được cấp quyền đối với tệp ID `1`.
3. Nhập trực tiếp đường dẫn trên thanh trình duyệt: `http://127.0.0.1:5000/files/1` hoặc `http://127.0.0.1:5000/files/1/download`.
4. Kết quả: Hệ thống chặn ngay lập tức, trả về trang lỗi **403 — Truy cập bị từ chối**.
5. Trong nhật ký Admin lập tức xuất hiện bản ghi: `ACCESS_DENIED` đối với người dùng `chuong`.

### Kịch bản 4 — Phát hiện và ngăn chặn giả mạo dữ liệu (File Tampering Detection)
*(Đây là kịch bản trình diễn quan trọng nhất của đồ án)*
1. Quan sát tệp tin ID `1` (`bao_cao_bin.txt`) đang có trạng thái toàn vẹn là **HỢP LỆ (VALID)**.
2. Mở một cửa sổ dòng lệnh terminal và chạy script giả lập tấn công làm hỏng byte tệp:
   ```powershell
   python scripts\tamper_demo.py 1
   ```
3. Script sẽ đảo các bit dữ liệu trong tệp đã mã hóa lưu trên đĩa máy chủ `storage/`.
4. Quay lại trình duyệt, dùng tài khoản `bin` hoặc `khoi` bấm nút **Tải về máy** của tệp ID `1`.
5. Kết quả:
   - Hệ thống tiến hành giải mã, kiểm tra băm SHA-256 và phát hiện dữ liệu không còn nguyên vẹn.
   - Quá trình tải về bị **CHẶN HOÀN TOÀN** (hiển thị trang cảnh báo đỏ: **"PHÁT HIỆN TỆP TIN BỊ GIẢ MẠO!"**).
   - Trạng thái tệp tin chuyển thành **BỊ GIẢ MẠO (TAMPERED)**.
   - Đăng nhập `admin`: Thấy mục **CẢNH BÁO TỆP TIN BỊ GIẢ MẠO** xuất hiện trên đầu Admin Dashboard và sự kiện `FILE_INTEGRITY_FAILED` được ghi nhận.
6. Để phục hồi lại hệ thống nguyên vẹn sau khi thử nghiệm xong, chỉ cần chạy:
   ```powershell
   python scripts\seed_demo.py
   ```

---

## 16. Phân tích đánh đổi an ninh (Security Trade-offs)

### 16.1 Đánh đổi giữa An toàn và Tiện dụng (Security vs Convenience)
- **Cơ chế áp dụng:** Mỗi khi người dùng yêu cầu tải xuống một tệp tin, máy chủ không thể gửi trực tiếp tệp tĩnh (static file streaming) mà bắt buộc phải qua 4 bước:
  1. Kiểm tra session đăng nhập và token chống giả mạo.
  2. Truy vấn CSDL để đối soát quyền sở hữu hoặc quyền chia sẻ `DOWNLOAD`.
  3. Đọc dữ liệu mã hóa từ đĩa cứng và thực hiện giải mã bằng thuật toán Fernet.
  4. Tính toán hàm băm SHA-256 trên nội dung vừa giải mã và so khớp chuỗi hex với CSDL.
- **Chi phí phát sinh:** Gia tăng mức tiêu thụ CPU của máy chủ, tăng nhẹ thời gian phản hồi (Latency) đối với các tệp tin có dung lượng lớn.
- **Giá trị bảo mật đạt được:** Đổi lại, hệ thống loại bỏ hoàn toàn nguy cơ rò rỉ dữ liệu qua đường dẫn tĩnh (direct URL guessing), ngăn chặn tuyệt đối việc phát tán dữ liệu đã bị sửa đổi trái phép và tạo ra nhật ký kiểm toán minh bạch 100%.

### 16.2 Tác động ngắn hạn (Short-term Impacts)
- Mã nguồn phức tạp hơn so với mô hình upload file thông thường.
- Đòi hỏi quy trình quản lý khóa mật mã (`FERNET_KEY`) cẩn trọng (mất khóa đồng nghĩa với mất toàn bộ khả năng đọc dữ liệu).
- Cần viết nhiều ca kiểm thử tự động để bảo đảm tính ổn định của chu trình mã hóa/giải mã.

### 16.3 Giá trị dài hạn (Long-term Benefits)
- Đáp ứng các tiêu chuẩn bảo mật dữ liệu lưu trữ (Data at Rest) theo quy định an toàn thông tin.
- Dễ dàng mở rộng chính sách phân quyền cho các tổ chức lớn (RBAC / ABAC).
- Đơn giản hóa việc rà soát và điều tra sự cố an ninh mạng (Incident Forensics).

---

## 17. Giới hạn hiện tại (Limitations)

- Sử dụng cơ sở dữ liệu SQLite cục bộ phù hợp cho môi trường đồ án học tập và demo; nếu triển khai môi trường doanh nghiệp quy mô lớn cần chuyển sang PostgreSQL với connection pooling.
- Hệ thống áp dụng một khóa đối xứng máy chủ chung (`FERNET_KEY`) cho các tệp tin. Kịch bản nâng cao trong tương lai có thể sử dụng cơ chế mã hóa bất đối xứng Envelope Encryption (mỗi tệp có 1 Data Encryption Key riêng và được bọc bởi Key Encryption Key).
- Kích thước tệp tin đang được giới hạn tối đa ở mức 10 MB để tối ưu hiệu năng tính toán băm và mã hóa trong bộ nhớ.

---

## 18. Hướng phát triển tương lai (Future Work)

1. Tích hợp xác thực đa yếu tố (MFA / TOTP) bằng Google Authenticator cho người dùng và quản trị viên.
2. Áp dụng kỹ thuật mã hóa phong bì (Envelope Encryption) kết hợp dịch vụ quản lý khóa phần cứng (KMS / HSM).
3. Hỗ trợ chia sẻ tệp có thời hạn (Expiring download links) và mật khẩu bảo vệ riêng cho từng lượt tải.
4. Tích hợp chữ ký số bất đối xứng (RSA / ECDSA) để xác thực danh tính người đăng tải tài liệu thay cho mã băm đối xứng.

---

## 19. Danh mục ảnh minh chứng cần chuẩn bị (Evidence Checklist)

Thư mục `evidence/` được tạo sẵn để người dùng lưu ảnh chụp màn hình khi làm báo cáo thuyết minh đồ án:

- [ ] `evidence/01_login_page.png`: Giao diện trang Đăng nhập và gợi ý tài khoản mẫu.
- [ ] `evidence/02_user_dashboard.png`: Giao diện Bảng điều khiển người dùng với 4 thẻ thống kê và tệp gần đây.
- [ ] `evidence/03_upload_success.png`: Giao diện tải lên tệp tin và thông báo mã hóa thành công.
- [ ] `evidence/04_file_detail_sha256.png`: Trang chi tiết tệp hiển thị mã băm SHA-256 và nút sao chép.
- [ ] `evidence/05_share_file_form.png`: Thao tác cấp quyền chia sẻ tệp cho người dùng khác (Khoi).
- [ ] `evidence/06_shared_user_download.png`: Người dùng được chia sẻ (Khoi) tải tệp thành công.
- [ ] `evidence/07_idor_blocked_403.png`: Người dùng không có quyền (Chuong) bị chặn lỗi 403 khi đổi URL.
- [ ] `evidence/08_brute_force_lockout.png`: Thông báo khóa tài khoản tạm thời 5 phút khi nhập sai 5 lần.
- [ ] `evidence/09_tamper_detection_alert.png`: Giao diện cảnh báo đỏ chặn tải về khi tệp bị giả mạo.
- [ ] `evidence/10_admin_soc_audit_logs.png`: Trung tâm giám sát Admin Dashboard và bảng Audit Logs đầy đủ.
- [ ] `evidence/11_pytest_all_passed.png`: Kết quả chạy lệnh `pytest -q` đạt 18/18 PASS.
