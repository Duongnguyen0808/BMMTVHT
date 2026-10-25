# SECURESHARE — FULL PROJECT BUILD SPEC FOR CODEX

## 0. MỤC TIÊU

Hãy xây dựng hoàn chỉnh từ đầu đến cuối một đồ án cuối kỳ cho học phần **Bảo mật mạng máy tính và hệ thống** với tên:

**SecureShare — Hệ thống chia sẻ tài liệu an toàn với xác thực, phân quyền, mã hóa và kiểm tra tính toàn vẹn dữ liệu**

Yêu cầu chính:
- Có prototype web chạy được thật.
- Có giao diện hiện đại, màu chủ đạo **trắng + xanh dương**.
- Có authentication, authorization, file sharing, encryption, SHA-256 integrity verification, audit log, brute-force protection.
- Có test case cho luồng bình thường và luồng rủi ro.
- Có dữ liệu mẫu để demo.
- Có README hướng dẫn chạy.
- Có script seed database.
- Có test tự động.
- Có kịch bản demo cuối cùng.
- Không dùng AI/ML, không cần dataset ngoài.
- Không làm các chức năng thừa không phục vụ mục tiêu bảo mật.
- Mọi chức năng phải chạy local ổn định.

---

# 1. CÔNG NGHỆ BẮT BUỘC

## Backend
- Python 3.12+
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-Limiter
- Werkzeug
- cryptography
- python-dotenv
- pytest

## Database
- SQLite

## Frontend
- HTML5
- CSS3
- Bootstrap 5
- Bootstrap Icons
- Vanilla JavaScript

## Security
- Password hash: Werkzeug PBKDF2 hoặc bcrypt nếu cài ổn định
- Session authentication: Flask-Login
- CSRF: Flask-WTF
- File integrity: SHA-256
- File encryption: Fernet từ `cryptography`
- Authorization: ownership + permission table
- Brute-force protection: Flask-Limiter + failed login counter
- Audit log: database

---

# 2. PHẠM VI CHỨC NĂNG

Hệ thống có 2 role:

## USER
Có thể:
- Đăng ký
- Đăng nhập
- Đăng xuất
- Xem dashboard
- Upload file
- Xem danh sách file của mình
- Xem file được chia sẻ
- Chia sẻ file cho user khác
- Gỡ quyền chia sẻ
- Download file nếu có quyền
- Xem trạng thái integrity của file
- Xem lịch sử hoạt động cá nhân

## ADMIN
Có thể:
- Tất cả quyền user
- Xem danh sách user
- Xem toàn bộ audit logs
- Xem các sự kiện bảo mật
- Xem các file bị phát hiện tampering
- Không được tự động đọc file private nếu không có quyền; admin chỉ xem metadata và log

---

# 3. CÁC YÊU CẦU BẢO MẬT CỐT LÕI

## 3.1 Authentication
- Không lưu password plaintext
- Password tối thiểu 8 ký tự
- Có ít nhất:
  - chữ hoa
  - chữ thường
  - số
- Không cho email trùng
- Không cho username trùng

## 3.2 Login protection
- Tối đa 5 lần sai liên tiếp
- Sau 5 lần sai:
  - khóa tài khoản tạm thời 5 phút
- Đồng thời rate limit endpoint login
- Ghi audit log mỗi lần login success/fail/locked

## 3.3 Session security
- Session cookie HttpOnly
- SameSite=Lax
- SESSION_COOKIE_SECURE để false trong local, có chú thích bật true khi deploy HTTPS
- Session timeout 30 phút
- Logout phải xóa session

## 3.4 CSRF
- Tất cả POST form phải có CSRF token

## 3.5 Upload validation
Chỉ cho:
- .pdf
- .docx
- .txt
- .png
- .jpg
- .jpeg

Giới hạn:
- tối đa 10 MB

Từ chối:
- .exe
- .bat
- .cmd
- .ps1
- .sh
- file extension không cho phép

Tên file:
- dùng secure_filename
- tên lưu thật trên server phải random UUID, không dùng tên gốc

## 3.6 File encryption
- File phải được mã hóa trước khi lưu vào `storage/`
- Dùng Fernet
- Key lấy từ `.env`
- Không hard-code key
- Nếu chưa có key thì cung cấp script tạo key

## 3.7 File integrity
Khi upload:
1. đọc plaintext file
2. tính SHA-256
3. lưu hash vào DB
4. mã hóa
5. lưu encrypted file vào storage

Khi download:
1. xác thực quyền
2. đọc encrypted file
3. giải mã
4. tính lại SHA-256 plaintext
5. so sánh với hash DB
6. nếu trùng → cho download
7. nếu không trùng → block download + log `FILE_INTEGRITY_FAILED`

## 3.8 Authorization
Mỗi file có:
- owner_id

Quyền chia sẻ:
- VIEW
- DOWNLOAD

Quy tắc:
- Owner luôn có full access
- User khác chỉ truy cập nếu có record permission
- Không tin file_id từ URL
- Mọi route file phải kiểm tra quyền ở backend
- Nếu user đổi ID URL để truy cập file không thuộc quyền:
  - trả 403
  - ghi audit log `ACCESS_DENIED`

## 3.9 Audit log
Log các action:
- REGISTER
- LOGIN_SUCCESS
- LOGIN_FAILED
- ACCOUNT_LOCKED
- LOGOUT
- UPLOAD_FILE
- DOWNLOAD_FILE
- SHARE_FILE
- REVOKE_SHARE
- ACCESS_DENIED
- FILE_INTEGRITY_OK
- FILE_INTEGRITY_FAILED
- INVALID_UPLOAD

Mỗi log gồm:
- id
- user_id nullable
- username_snapshot
- action
- target_type
- target_id
- ip_address
- user_agent
- status
- message
- created_at

---

# 4. DATABASE DESIGN

Tạo các model sau.

## User
Fields:
- id
- username
- email
- password_hash
- role
- failed_login_attempts
- locked_until
- created_at
- last_login_at

## FileRecord
Fields:
- id
- owner_id
- original_name
- stored_name
- mime_type
- file_size
- sha256_hash
- integrity_status
- created_at
- updated_at

integrity_status:
- UNKNOWN
- VALID
- TAMPERED

## FilePermission
Fields:
- id
- file_id
- user_id
- permission
- created_at

Unique:
- file_id + user_id

## AuditLog
Fields:
- id
- user_id nullable
- username_snapshot
- action
- target_type
- target_id nullable
- ip_address
- user_agent
- status
- message
- created_at

---

# 5. CẤU TRÚC THƯ MỤC

Tạo project:

```text
secureshare/
│
├── run.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
│
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── extensions.py
│   ├── models.py
│   │
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── forms.py
│   │
│   ├── files/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── forms.py
│   │   └── services.py
│   │
│   ├── admin/
│   │   ├── __init__.py
│   │   └── routes.py
│   │
│   ├── audit/
│   │   ├── __init__.py
│   │   └── services.py
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   ├── crypto.py
│   │   ├── hashing.py
│   │   ├── permissions.py
│   │   └── decorators.py
│   │
│   ├── templates/
│   │   ├── base.html
│   │   ├── home.html
│   │   ├── auth/
│   │   ├── files/
│   │   ├── admin/
│   │   └── errors/
│   │
│   └── static/
│       ├── css/
│       │   └── app.css
│       └── js/
│           └── app.js
│
├── storage/
│   └── .gitkeep
│
├── instance/
│   └── .gitkeep
│
├── scripts/
│   ├── generate_key.py
│   ├── seed_demo.py
│   └── tamper_demo.py
│
└── tests/
    ├── conftest.py
    ├── test_auth.py
    ├── test_upload.py
    ├── test_permissions.py
    ├── test_integrity.py
    └── test_admin.py
```

---

# 6. GIAO DIỆN — TRẮNG XANH

Thiết kế giao diện hiện đại nhưng không quá màu mè.

## Màu chủ đạo
- Background: `#F7FAFC`
- Card: `#FFFFFF`
- Primary blue: `#2563EB`
- Dark blue: `#1D4ED8`
- Light blue: `#DBEAFE`
- Text: `#0F172A`
- Muted: `#64748B`
- Border: `#E2E8F0`
- Danger: Bootstrap danger
- Success: Bootstrap success

## Style
- Navbar trắng
- Logo chữ SecureShare màu xanh
- Card bo góc 14px
- Shadow nhẹ
- Form input rõ ràng
- Button primary xanh
- Không dùng gradient quá mạnh
- Không dùng giao diện tối
- Responsive desktop + mobile
- Font ưu tiên Inter nếu load được, fallback system

## Các trang

### `/`
Landing page:
- Logo SecureShare
- slogan: `Secure document sharing with integrity verification`
- nút Login
- nút Register
- 3 card tính năng:
  - Secure Authentication
  - Encrypted Storage
  - Integrity Verification

### `/register`
- username
- email
- password
- confirm password

### `/login`
- username/email
- password
- trạng thái account lock

### `/dashboard`
Card thống kê:
- My Files
- Shared With Me
- Security Alerts
- Recent Activity

Table:
- recent files

### `/files`
Tabs:
- My Files
- Shared With Me

Columns:
- File name
- Owner
- Size
- Integrity
- Permission
- Created
- Actions

### `/files/upload`
Drag/drop area hoặc input file
- validate extension
- validate size
- display selected filename

### `/files/<id>`
File detail:
- metadata
- SHA-256 rút gọn
- integrity badge
- owner
- shared users
- actions share/download/revoke

### `/activity`
Audit logs cá nhân

### `/admin`
Admin dashboard:
- Total users
- Total files
- Failed logins
- Access denied
- Integrity failures

### `/admin/logs`
Table log có filter:
- action
- status
- username

### Error pages
- 403
- 404
- 429
- 500

---

# 7. ROUTES

## Public
- GET `/`
- GET/POST `/register`
- GET/POST `/login`
- POST `/logout`

## Authenticated
- GET `/dashboard`
- GET `/files`
- GET/POST `/files/upload`
- GET `/files/<int:file_id>`
- GET `/files/<int:file_id>/download`
- POST `/files/<int:file_id>/share`
- POST `/files/<int:file_id>/revoke/<int:user_id>`
- GET `/activity`

## Admin
- GET `/admin`
- GET `/admin/users`
- GET `/admin/logs`

---

# 8. FILE SERVICES

Trong `app/files/services.py`, viết function rõ ràng:

- `allowed_file(filename)`
- `validate_file_size(file_obj)`
- `generate_storage_name(original_name)`
- `calculate_sha256(data: bytes)`
- `encrypt_file_bytes(data: bytes)`
- `decrypt_file_bytes(data: bytes)`
- `save_encrypted_file(...)`
- `load_encrypted_file(...)`
- `verify_file_integrity(file_record)`
- `user_can_view_file(user, file_record)`
- `user_can_download_file(user, file_record)`

Không nhét toàn bộ logic vào route.

---

# 9. SECURITY SERVICES

## `crypto.py`
- load Fernet key from env
- encrypt bytes
- decrypt bytes
- fail safely nếu key thiếu

## `hashing.py`
- SHA-256 helper

## `permissions.py`
- ownership checks
- permission checks

## `decorators.py`
- `admin_required`

---

# 10. APP FACTORY

Dùng Flask app factory:

```python
create_app(config_name=None)
```

Khởi tạo:
- db
- login_manager
- csrf
- limiter

Register blueprints:
- auth
- files
- admin

Custom errors:
- 403
- 404
- 429
- 500

---

# 11. ENV

Tạo `.env.example`:

```env
FLASK_ENV=development
SECRET_KEY=change-me
FERNET_KEY=generate-me
DATABASE_URL=sqlite:///secureshare.db
MAX_CONTENT_LENGTH=10485760
SESSION_TIMEOUT_MINUTES=30
```

Không commit `.env`.

---

# 12. SEED DEMO DATA

Tạo `scripts/seed_demo.py`.

Tạo 4 account:

```text
admin
password: Admin@123

bin
password: Bin@12345

khoi
password: Khoi@12345

chuong
password: Chuong@12345
```

Admin role:
- admin

3 account còn lại:
- user

Tạo dữ liệu demo:
- ít nhất 3 FileRecord hợp lệ bằng cách upload thông qua service
- ít nhất 1 file của `bin`
- ít nhất 1 file của `khoi`
- ít nhất 1 file của `chuong`

Permissions:
- share 1 file Bin cho Khoi DOWNLOAD
- share 1 file Khoi cho Chuong VIEW

Không tạo plaintext password trong DB.

---

# 13. SCRIPT TAMPER DEMO

Tạo `scripts/tamper_demo.py`.

Mục đích:
- chỉ dùng local cho demo học tập
- chọn một file record
- sửa bytes encrypted file trong storage hoặc thay bằng dữ liệu khác
- làm file không thể vượt integrity/decryption check
- in ra file id bị tamper

Có hướng dẫn cách phục hồi bằng seed lại dữ liệu.

Không được dùng script này để can thiệp hệ thống bên ngoài.

---

# 14. TEST CASE BẮT BUỘC

Dùng pytest.

## Authentication
### TC01 Register hợp lệ
Expected: success

### TC02 Register username trùng
Expected: reject

### TC03 Login đúng
Expected: success

### TC04 Login sai password
Expected: failure log

### TC05 Login sai >=5 lần
Expected: account locked

### TC06 User chưa login truy cập `/dashboard`
Expected: redirect login

## Upload
### TC07 Upload `.pdf`
Expected: success

### TC08 Upload `.exe`
Expected: reject

### TC09 Upload >10MB
Expected: reject / 413

### TC10 Storage file
Expected: nội dung trên disk không bằng plaintext gốc

## Permission
### TC11 Owner xem file
Expected: success

### TC12 Shared DOWNLOAD user download
Expected: success

### TC13 User không có quyền
Expected: 403

### TC14 IDOR
User thay file_id URL sang file người khác
Expected: 403 + audit ACCESS_DENIED

## Integrity
### TC15 File hợp lệ
Expected:
- integrity VALID
- download success

### TC16 File bị tamper
Expected:
- download blocked
- integrity TAMPERED
- audit FILE_INTEGRITY_FAILED

## Admin
### TC17 User thường vào `/admin`
Expected: 403

### TC18 Admin vào `/admin/logs`
Expected: success

---

# 15. DEMO SCENARIOS

Chuẩn bị README section `Demo`.

## Demo 1 — Normal flow
1. login Bin
2. upload file `bao_cao.txt`
3. xem hash
4. share cho Khoi
5. logout
6. login Khoi
7. mở Shared With Me
8. download thành công

## Demo 2 — Brute Force Protection
1. nhập sai mật khẩu 5 lần
2. lần thứ 6
3. hệ thống báo temporarily locked
4. admin logs có ACCOUNT_LOCKED

## Demo 3 — IDOR / Unauthorized Access
1. Bin có file ID X
2. login Chương không được share
3. truy cập `/files/X`
4. trả 403
5. audit có ACCESS_DENIED

## Demo 4 — File Tampering
1. upload file bình thường
2. ghi nhận SHA-256
3. chạy tamper script
4. thử download
5. hệ thống block
6. hiện cảnh báo integrity failed
7. admin log có FILE_INTEGRITY_FAILED

Đây là demo quan trọng nhất.

---

# 16. TRADE-OFF PHẢI THỂ HIỆN TRONG README

Tạo mục:

## Security vs Convenience

Giải thích:
- Mỗi lần download cần:
  - session check
  - authorization check
  - decrypt
  - SHA-256 verification
- Điều này tăng CPU/time/complexity
- Đổi lại:
  - chống truy cập trái phép
  - phát hiện tampering
  - audit tốt hơn

## Short-term
- code phức tạp hơn
- cần quản lý encryption key
- cần test nhiều hơn

## Long-term
- giảm nguy cơ lộ dữ liệu
- dễ audit
- dễ mở rộng security policy

---

# 17. README PHẢI HOÀN CHỈNH

README cần có:

1. Project title
2. Description
3. Objectives
4. Security problem
5. Assets
6. Users
7. Threat actors
8. Threat table
9. Security controls
10. Architecture
11. Folder structure
12. Database schema
13. Installation
14. Environment setup
15. Generate Fernet key
16. Initialize database
17. Seed demo data
18. Run application
19. Demo accounts
20. Test commands
21. Demo scenarios
22. Security trade-off
23. Limitations
24. Future work

---

# 18. THREAT MODEL TABLE

README cần có bảng:

| Threat | Asset | Risk | Defense |
|---|---|---|---|
| Brute-force | Account | High | lock + rate limit |
| Stolen session | Account/File | High | secure session config |
| IDOR | File | High | backend authorization |
| File tampering | File | High | SHA-256 verification |
| File theft | File | High | Fernet encryption |
| Dangerous upload | Server | Medium | extension/size validation |
| Privilege abuse | System | High | RBAC |
| Hidden attack activity | Auditability | Medium | audit logs |

---

# 19. ARCHITECTURE

Trong README có ASCII architecture:

```text
+-------------------+
|      Browser      |
+---------+---------+
          |
          v
+-------------------+
|   Flask Web App   |
+----+---------+----+
     |         |
     v         v
+---------+ +--------------+
| Auth    | | Authorization|
+---------+ +--------------+
     |         |
     +----+----+
          |
          v
+-------------------+
| File Security     |
| - SHA-256         |
| - Fernet          |
+---------+---------+
          |
     +----+----+
     |         |
     v         v
+--------+ +---------+
| SQLite | | Storage |
+--------+ +---------+
     |
     v
+-------------------+
| Audit Log         |
+-------------------+
```

---

# 20. LỆNH CHẠY

README phải hướng dẫn Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python scripts\generate_key.py
python scripts\seed_demo.py
python run.py
```

Nếu generate_key.py cần tự ghi vào `.env`, phải xử lý cẩn thận và không xóa các biến khác.

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python scripts/generate_key.py
python scripts/seed_demo.py
python run.py
```

App mặc định:

```text
http://127.0.0.1:5000
```

---

# 21. TEST COMMAND

```bash
pytest -q
```

Phải đảm bảo:
- toàn bộ test pass
- không phụ thuộc DB production
- test dùng temporary SQLite database
- test dùng temporary storage directory

---

# 22. CHỤP ẢNH / BẰNG CHỨNG CẦN CÓ

Tạo thư mục gợi ý trong README:

```text
evidence/
```

Không cần tự chụp ảnh, nhưng ghi rõ người dùng phải chụp:

1. Trang login
2. Dashboard
3. Upload thành công
4. File detail có SHA-256
5. Share file
6. User được share download thành công
7. User không quyền bị 403
8. Login sai nhiều lần bị khóa
9. Tamper detection
10. Admin audit logs
11. pytest toàn bộ PASS

---

# 23. ACCEPTANCE CRITERIA

Không coi project hoàn thành nếu chưa đạt toàn bộ:

- [ ] App chạy được từ README
- [ ] Register chạy
- [ ] Login/logout chạy
- [ ] Password hashed
- [ ] Account lock chạy
- [ ] Session protection chạy
- [ ] CSRF chạy
- [ ] Upload validation chạy
- [ ] File được encryption trên disk
- [ ] SHA-256 lưu chính xác
- [ ] File owner download được
- [ ] File được share download được
- [ ] User không quyền bị 403
- [ ] IDOR bị chặn
- [ ] Tampered file bị block
- [ ] Audit log ghi đúng
- [ ] Admin dashboard chạy
- [ ] UI trắng xanh responsive
- [ ] Seed data chạy
- [ ] Tamper demo script chạy
- [ ] pytest pass
- [ ] README đầy đủ
- [ ] .env không bị commit
- [ ] storage user data không bị commit

---

# 24. CÁCH LÀM CỦA CODEX

Hãy thực hiện project theo thứ tự sau.

## PHASE 1 — Bootstrap
1. tạo folder structure
2. requirements
3. app factory
4. extensions
5. config
6. database models
7. migrations không bắt buộc; có thể dùng db.create_all cho đồ án

## PHASE 2 — Authentication
1. register
2. login
3. logout
4. session
5. lockout
6. audit login

## PHASE 3 — UI foundation
1. base layout
2. navbar
3. flash messages
4. login/register
5. dashboard
6. CSS trắng xanh

## PHASE 4 — File management
1. upload
2. metadata
3. encryption
4. hash
5. list
6. detail
7. download

## PHASE 5 — Sharing & Authorization
1. permissions table
2. share
3. revoke
4. owner check
5. DOWNLOAD permission
6. IDOR prevention

## PHASE 6 — Integrity
1. verify on download
2. status VALID/TAMPERED
3. block tampered files
4. audit logs

## PHASE 7 — Admin
1. admin dashboard
2. logs
3. user list
4. security statistics

## PHASE 8 — Demo Scripts
1. generate key
2. seed demo
3. tamper demo

## PHASE 9 — Tests
1. auth
2. upload
3. permission
4. integrity
5. admin

## PHASE 10 — Documentation
1. README
2. architecture
3. threat model
4. trade-off
5. demo script
6. screenshot checklist

---

# 25. QUY TẮC CODE

- Code rõ ràng, dễ đọc.
- Không viết toàn bộ trong `run.py`.
- Tách service khỏi route.
- Không hard-code secret.
- Không để TODO quan trọng.
- Không bỏ route trống.
- Không tạo fake UI mà backend không hoạt động.
- Nếu có lỗi dependency thì tự chọn bản tương thích.
- Không dùng package không cần thiết.
- Không dùng React/Vue.
- Không dùng Docker nếu không cần.
- Không dùng database online.
- Không dùng cloud.
- Chạy local là ưu tiên.
- Mọi lỗi user-facing phải hiển thị thông báo rõ ràng.
- Không leak stack trace trong production config.
- Không hiển thị Fernet key trên giao diện.
- Không log password.
- Không log plaintext file content.

---

# 26. ERROR HANDLING

Cần xử lý:
- file missing
- invalid extension
- file too large
- user not found
- permission denied
- corrupted encrypted file
- missing encryption key
- invalid CSRF
- rate limit
- 404
- 500

Error page vẫn theo giao diện trắng xanh.

---

# 27. DEMO DATA FILES

Trong seed script có thể tạo plaintext tạm trong memory rồi encryption, ví dụ:

```text
bao_cao_bin.txt
Noi dung bao cao cua Bin.

ke_hoach_khoi.txt
Ke hoach bao mat cua Khoi.

ghi_chu_chuong.txt
Ghi chu demo cua Chuong.
```

Sau khi seed:
- storage chỉ chứa encrypted bytes
- không lưu plaintext demo file trên disk nếu không cần

---

# 28. SECURITY ALERT UI

Dashboard hiển thị badge nếu:
- account vừa bị lock
- access denied xảy ra
- integrity fail

Admin dashboard có card:
- Failed Logins
- Access Denied
- Integrity Failures

---

# 29. FILE DETAIL

Trang chi tiết file phải hiển thị:

- Original name
- Owner
- Size
- MIME type
- Created at
- SHA-256 dạng:
  - full hash trong vùng copy được
- Integrity badge:
  - Valid
  - Tampered
  - Unknown
- Shared users
- Permission
- Download button nếu được phép
- Share form nếu là owner

---

# 30. AUDIT TABLE

Columns:
- Time
- Username
- Action
- Target
- IP
- Status
- Message

Có pagination cơ bản nếu dễ làm.

---

# 31. FORM VALIDATION

Dùng WTForms nếu thuận tiện:
- RegisterForm
- LoginForm
- UploadForm
- ShareForm

Messages bằng tiếng Việt hoặc tiếng Anh thống nhất.
Ưu tiên tiếng Việt cho UI.

Ví dụ:
- `Đăng nhập thành công.`
- `Tài khoản đã bị khóa tạm thời.`
- `Bạn không có quyền truy cập tài liệu này.`
- `Tệp có dấu hiệu bị chỉnh sửa. Tải xuống đã bị chặn.`

---

# 32. UI TEXT

Navbar:
- Trang chủ
- Dashboard
- Tài liệu
- Hoạt động
- Admin
- Đăng xuất

Dashboard:
- `Xin chào, <username>`
- `Tài liệu của tôi`
- `Được chia sẻ với tôi`
- `Cảnh báo bảo mật`
- `Hoạt động gần đây`

---

# 33. PROJECT COMPLETION OUTPUT

Khi hoàn tất, Codex phải:

1. đảm bảo toàn bộ file được tạo
2. chạy syntax check
3. chạy pytest
4. sửa lỗi cho tới khi test pass
5. kiểm tra app startup
6. cập nhật README theo đúng code thực tế
7. in ra cuối cùng:
   - cấu trúc project
   - lệnh cài
   - lệnh chạy
   - demo accounts
   - test result
   - các URL chính

Không dừng ở mức scaffold.
Không chỉ mô tả.
Phải tạo code thật đầy đủ.

---

# 34. FINAL EXPECTED DEMO

Người dùng cuối cùng phải có thể làm chính xác:

```text
1. python -m venv .venv
2. activate venv
3. pip install -r requirements.txt
4. copy .env.example .env
5. python scripts/generate_key.py
6. python scripts/seed_demo.py
7. python run.py
8. mở http://127.0.0.1:5000
9. login bằng bin / Bin@12345
10. upload file
11. share cho khoi
12. login khoi
13. download file thành công
14. login chuong
15. cố truy cập file không được share → 403
16. chạy tamper_demo.py
17. login owner
18. download file tampered → bị chặn
19. login admin
20. xem audit logs
21. chạy pytest -q → PASS
```

---

# 35. BẮT ĐẦU

Hãy bắt đầu xây dựng toàn bộ project SecureShare theo tài liệu này.

Ưu tiên:
1. chạy được
2. đúng security flow
3. test pass
4. giao diện trắng xanh đẹp, sạch
5. README đầy đủ
6. không bỏ sót acceptance criteria

Nếu phát hiện yêu cầu nào mâu thuẫn, ưu tiên tính đúng đắn bảo mật và khả năng chạy local ổn định.

Không hỏi lại nếu không thực sự bị chặn; tự đưa ra quyết định kỹ thuật hợp lý và tiếp tục cho tới khi hoàn thành project.
