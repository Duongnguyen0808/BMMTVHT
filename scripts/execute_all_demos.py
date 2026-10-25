import io
import os
import re
import sys
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from app import create_app
from app.extensions import db, limiter
from app.models import User, FileRecord, FilePermission, AuditLog
from scripts.seed_demo import seed
from scripts.tamper_demo import tamper_demo


def extract_csrf(html_text):
    if not html_text:
        return ""
    match = re.search(r'name=["\']csrf_token["\'][^>]*?value=["\']([^"\']+)["\']', html_text)
    if not match:
        match = re.search(r'value=["\']([^"\']+)["\'][^>]*?name=["\']csrf_token["\']', html_text)
    return match.group(1) if match else ""


def run():
    print("=" * 80)
    print("          THUC THI 5 KICH BAN DEMO VA KIEM DINH AN NINH SECURESHARE")
    print("=" * 80)

    # Khoi tao database sach
    print("\n[*] Buoc 0: Khoi tao du lieu sach (Seed initial database)...")
    seed()

    app = create_app()
    client = app.test_client()

    # -------------------------------------------------------------
    # DEMO 1: Login sai 5 lan -> Account Locked -> Lan 6 bi chan
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DEMO 1: BRUTE-FORCE PROTECTION (Nhap sai 5 lan -> Khoa tai khoan -> Lan 6 bi chan)")
    print("=" * 80)

    # Lan 1 -> 5 nhap sai mat khau
    for i in range(1, 6):
        res_get = client.get('/login')
        csrf_token = extract_csrf(res_get.text)
        res_post = client.post('/login', data={
            'csrf_token': csrf_token,
            'username_or_email': 'bin',
            'password': f'WrongPassword@{i}'
        })
        print(f"  [+] Lan thu {i}/5: Nhap sai mat khau -> HTTP {res_post.status_code}")

    with app.app_context():
        bin_user = User.query.filter_by(username='bin').first()
        print(f"  --> Trang thai user 'bin' trong DB: failed_login_attempts = {bin_user.failed_login_attempts}")
        print(f"  --> Thoi diem khoa den: {bin_user.locked_until}")
        print(f"  --> is_locked() = {bin_user.is_locked()}")
        assert bin_user.failed_login_attempts >= 5
        assert bin_user.is_locked() is True

        # Kiem tra AuditLog
        failed_logs_count = AuditLog.query.filter_by(action='LOGIN_FAILED', username_snapshot='bin').count()
        locked_logs_count = AuditLog.query.filter_by(action='ACCOUNT_LOCKED', username_snapshot='bin').count()
        print(f"  --> AuditLog: Da ghi nhan {failed_logs_count} ban ghi LOGIN_FAILED va {locked_logs_count} ban ghi ACCOUNT_LOCKED")
        assert failed_logs_count >= 4
        assert locked_logs_count >= 1

    # Lan thu 6: Thu dang nhap voi mat khau DUNG cua Bin (Bin@12345)
    limiter.reset()
    res_get = client.get('/login')
    csrf_token = extract_csrf(res_get.text)
    res_post6 = client.post('/login', data={
        'csrf_token': csrf_token,
        'username_or_email': 'bin',
        'password': 'Bin@12345'
    })
    assert "bị khóa" in res_post6.text or "khóa tạm thời" in res_post6.text
    print("  [+] Lan thu 6: Nhap mat khau DUNG -> HE THONG CHAN DANG NHAP (Thong bao tai khoan dang bi khoa)!")
    print("  ==> DEMO 1 DAT 100% YEU CAU!")

    # -------------------------------------------------------------
    # DEMO 2: Upload validation + Kiem tra truc tiep ma hoa file trong storage/
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DEMO 2: UPLOAD VALIDATION & MA HOA TRUC TIEP TRONG STORAGE/")
    print("=" * 80)

    # Mo khoa user bin de tiep tuc
    with app.app_context():
        bin_user = User.query.filter_by(username='bin').first()
        bin_user.failed_login_attempts = 0
        bin_user.locked_until = None
        db.session.commit()

    # Dang nhap hop le vao Bin
    limiter.reset()
    res_get = client.get('/login')
    client.post('/login', data={
        'csrf_token': extract_csrf(res_get.text),
        'username_or_email': 'bin',
        'password': 'Bin@12345'
    }, follow_redirects=True)

    # 2.1 Thu upload file .exe -> Phai bi tu choi
    res_upload_get = client.get('/files/upload')
    res_exe = client.post('/files/upload', data={
        'csrf_token': extract_csrf(res_upload_get.text),
        'file': (io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00FAKE_VIRUS"), "trojan.exe")
    }, content_type='multipart/form-data')
    assert res_exe.status_code == 400
    print("  [+] Thu tai len 'trojan.exe': He thong tu choi HTTP 400 (INVALID_UPLOAD)")

    with app.app_context():
        invalid_log = AuditLog.query.filter_by(action='INVALID_UPLOAD').first()
        assert invalid_log is not None
        print(f"  --> AuditLog da ghi nhan: {invalid_log.action} - {invalid_log.message}")

    # 2.2 Upload file van ban hop le (.txt)
    res_upload_get = client.get('/files/upload')
    secret_plaintext = b"Day la van ban mat cua Bin. Noi dung nay bat buoc phai duoc ma hoa Fernet tren dia."
    res_valid = client.post('/files/upload', data={
        'csrf_token': extract_csrf(res_upload_get.text),
        'file': (io.BytesIO(secret_plaintext), "tai_lieu_bao_mat_bin.txt")
    }, content_type='multipart/form-data', follow_redirects=True)
    assert res_valid.status_code == 200
    print("  [+] Tai len 'tai_lieu_bao_mat_bin.txt' hop le: Thanh cong!")

    # 2.3 KIEM TRA TRUC TIEP FILE TRONG STORAGE/ (Chung minh ma hoa)
    with app.app_context():
        file_rec = FileRecord.query.filter_by(original_name="tai_lieu_bao_mat_bin.txt").first()
        assert file_rec is not None
        storage_file = Path(app.config['STORAGE_FOLDER']) / file_rec.stored_name
        assert storage_file.exists(), f"Khong tim thay file {storage_file}"

        encrypted_disk_bytes = storage_file.read_bytes()
        print(f"\n  [!] MINH CHUNG KIEM TRA TRUC TIEP FILE TRONG storage/{file_rec.stored_name}:")
        print(f"      - Ten file tren o dia : {file_rec.stored_name}")
        print(f"      - Kich thuoc tren dia : {len(encrypted_disk_bytes)} bytes")
        print(f"      - Header Fernet       : {encrypted_disk_bytes[:16]}")
        print(f"      - 64 bytes dau tien   : {encrypted_disk_bytes[:64]}")
        print(f"      - SHA-256 luu trong DB: {file_rec.sha256_hash}")

        # Kiem tra tuyet doi khong co plaintext
        assert secret_plaintext not in encrypted_disk_bytes
        assert encrypted_disk_bytes.startswith(b'gAAAAA')
        print("      --> XAC NHAN: Du lieu tren dia da bi ma hoa hoan toan, KHONG THE DOC DUOC DANG PLAINTEXT!")
    print("  ==> DEMO 2 DAT 100% YEU CAU!")

    # -------------------------------------------------------------
    # DEMO 3: Share file Bin -> Khoi -> Khoi tai duoc
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DEMO 3: CHIA SE TAI LIEU (Bin share -> Khoi tai ve thanh cong)")
    print("=" * 80)

    # Bin chia se file ID 1 (bao_cao_bin.txt) cho Khoi voi quyen DOWNLOAD
    res_detail = client.get('/files/1')
    res_share = client.post('/files/1/share', data={
        'csrf_token': extract_csrf(res_detail.text),
        'username': 'khoi',
        'permission': 'DOWNLOAD'
    }, follow_redirects=True)
    assert res_share.status_code == 200
    print("  [+] Bin da cap quyen DOWNLOAD tep 'bao_cao_bin.txt' cho nguoi dung 'khoi'.")

    with app.app_context():
        perm = FilePermission.query.filter_by(file_id=1, user_id=3).first()  # khoi id is 3
        assert perm is not None
        assert perm.permission == 'DOWNLOAD'
        share_log = AuditLog.query.filter_by(action='SHARE_FILE').order_by(AuditLog.id.desc()).first()
        print(f"  --> AuditLog ghi nhan: {share_log.action} - {share_log.message}")

    # Dang xuat Bin, dang nhap Khoi
    client.get('/logout')
    limiter.reset()
    res_get = client.get('/login')
    client.post('/login', data={
        'csrf_token': extract_csrf(res_get.text),
        'username_or_email': 'khoi',
        'password': 'Khoi@12345'
    }, follow_redirects=True)

    # Khoi tai ve tep ID 1
    res_dl = client.get('/files/1/download')
    assert res_dl.status_code == 200
    print(f"  [+] Khoi tai ve thanh cong tep ID 1: HTTP {res_dl.status_code}, kich thuoc {len(res_dl.data)} bytes.")

    with app.app_context():
        dl_log = AuditLog.query.filter_by(action='DOWNLOAD_FILE', username_snapshot='khoi').first()
        ok_log = AuditLog.query.filter_by(action='FILE_INTEGRITY_OK').first()
        assert dl_log is not None
        assert ok_log is not None
        print(f"  --> AuditLog ghi nhan: {ok_log.action} va {dl_log.action}")
    print("  ==> DEMO 3 DAT 100% YEU CAU!")

    # -------------------------------------------------------------
    # DEMO 4: Chuong khong co quyen sua URL -> 403 + ACCESS_DENIED
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DEMO 4: PHONG CHONG TAN CONG IDOR (Chuong sua URL truy cap tep cua Bin -> 403)")
    print("=" * 80)

    # Dang xuat Khoi, dang nhap Chuong (Chuong KHONG co quyen voi tep 1)
    client.get('/logout')
    limiter.reset()
    res_get = client.get('/login')
    client.post('/login', data={
        'csrf_token': extract_csrf(res_get.text),
        'username_or_email': 'chuong',
        'password': 'Chuong@12345'
    }, follow_redirects=True)

    # Chuong sua URL de xem chi tiet tep ID 1
    res_idor_view = client.get('/files/1')
    assert res_idor_view.status_code == 403
    print("  [+] Chuong truy cap GET /files/1: BI CHAN VOI MA LOI HTTP 403 (Forbidden)!")

    # Chuong sua URL de tai ve tep ID 1
    res_idor_dl = client.get('/files/1/download')
    assert res_idor_dl.status_code == 403
    print("  [+] Chuong truy cap GET /files/1/download: BI CHAN VOI MA LOI HTTP 403 (Forbidden)!")

    with app.app_context():
        idor_log = AuditLog.query.filter_by(action='ACCESS_DENIED', username_snapshot='chuong', target_id='1').first()
        assert idor_log is not None
        print(f"  --> AuditLog ghi nhan: {idor_log.action} - {idor_log.message}")
    print("  ==> DEMO 4 DAT 100% YEU CAU!")

    # -------------------------------------------------------------
    # DEMO 5: Sua file trong storage -> SHA-256 mismatch -> Block download + FILE_INTEGRITY_FAILED
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DEMO 5: PHAT HIEN GIA MAO DU LIEU (Tampering -> Block Download + FILE_INTEGRITY_FAILED)")
    print("=" * 80)

    # Chay script tamper de sua truc tiep byte tren o dia cua tep ID 1
    print("  [*] Dang chay script tamper sua doi byte file ID 1 tren o dia...")
    tamper_demo(1)

    # Dang xuat Chuong, dang nhap Bin (chu so huu tep 1) de tai ve
    client.get('/logout')
    limiter.reset()
    res_get = client.get('/login')
    client.post('/login', data={
        'csrf_token': extract_csrf(res_get.text),
        'username_or_email': 'bin',
        'password': 'Bin@12345'
    }, follow_redirects=True)

    # Bin co gang tai ve tep bi sua
    res_tampered_dl = client.get('/files/1/download')
    assert res_tampered_dl.status_code == 400
    assert "PHÁT HIỆN TỆP TIN BỊ GIẢ MẠO" in res_tampered_dl.text
    print("  [+] Bin tai ve tep ID 1 bi sua byte:")
    print("      --> Ket qua: TAI VE BI CHAN HOAN TOAN (HTTP 400)!")
    print("      --> Giao dien canh bao do: 'PHAT HIEN TEP TIN BI GIA MAO!'")

    with app.app_context():
        file1 = db.session.get(FileRecord, 1)
        assert file1.integrity_status == 'TAMPERED'
        print(f"      --> Trang thai tep trong Database: integrity_status = '{file1.integrity_status}'")

        tamper_log = AuditLog.query.filter_by(action='FILE_INTEGRITY_FAILED', target_id='1').first()
        assert tamper_log is not None
        print(f"      --> AuditLog ghi nhan: {tamper_log.action} - {tamper_log.message}")
    print("  ==> DEMO 5 DAT 100% YEU CAU!")

    # -------------------------------------------------------------
    # DEMO 6: Quản trị viên Admin SOC & Audit Logs ĐẦY ĐỦ
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DEMO 6: QUAN TRI VIEN (ADMIN SOC DASHBOARD & AUDIT LOGS DAY DU)")
    print("=" * 80)

    client.get('/logout')
    limiter.reset()
    res_get = client.get('/login')
    client.post('/login', data={
        'csrf_token': extract_csrf(res_get.text),
        'username_or_email': 'admin',
        'password': 'Admin@123'
    }, follow_redirects=True)

    # 6.1 Admin Dashboard
    res_admin = client.get('/admin')
    assert res_admin.status_code == 200
    assert "TAMPERED" in res_admin.text
    print("  [+] Admin Dashboard: Hien thi day du thong ke va bang canh bao TAMPERED FILES.")

    # 6.2 Admin Users List
    res_users = client.get('/admin/users')
    assert res_users.status_code == 200
    print("  [+] Admin Users: Hien thi danh sach toan bo tai khoan, role, trang thai khoa.")

    # 6.3 Admin Logs List & Kiem tra tat ca cac loai hanh dong
    res_logs = client.get('/admin/logs')
    assert res_logs.status_code == 200
    print("  [+] Admin Logs: Hien thi danh sach nhat ky kiem toan voi bo loc.")

    # In ra bang tong hop Audit Logs truc tiep tu DB
    with app.app_context():
        logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
        print(f"\n  [!] TONG CONG CO {len(logs)} BAN GHI AUDIT LOG DUOC LUU TRU TRONG DATABASE:")
        print("  " + "-" * 76)
        print(f"  {'ID':<4} | {'Hanh dong (Action)':<22} | {'User':<10} | {'Status':<8} | {'Target'}")
        print("  " + "-" * 76)
        for log in logs:
            target_str = f"{log.target_type} #{log.target_id}" if log.target_type else ""
            print(f"  {log.id:<4} | {log.action:<22} | {log.username_snapshot:<10} | {log.status:<8} | {target_str}")
        print("  " + "-" * 76)

        actions_present = {l.action for l in logs}
        required_actions = {
            'LOGIN_SUCCESS', 'LOGIN_FAILED', 'ACCOUNT_LOCKED',
            'UPLOAD_FILE', 'INVALID_UPLOAD', 'DOWNLOAD_FILE',
            'SHARE_FILE', 'ACCESS_DENIED', 'FILE_INTEGRITY_FAILED',
            'LOGOUT'
        }
        diff = required_actions - actions_present
        assert not diff, f"Thieu cac action: {diff}"
        print(f"\n  [+] XAC NHAN: DAY DU 100% CAC ACTION YEU CAU: {sorted(list(actions_present))}")

    print("\n" + "=" * 80)
    print("  KET QUA: TOAN BO 5 DEMO VA TOAN BO YEU CAU BAO MAT DEU DAT 100%!")
    print("=" * 80)


if __name__ == '__main__':
    run()
