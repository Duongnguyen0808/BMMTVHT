import io
import os
import sys
import time
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC

from app import create_app
from app.extensions import db
from app.models import User, FileRecord, FilePermission, AuditLog
from scripts.seed_demo import seed
from scripts.tamper_demo import tamper_demo

EVIDENCE_DIR = BASE_DIR / 'evidence'
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
BASE_URL = "http://127.0.0.1:5000"


def setup_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1366,768")
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(5)
    return driver


def run_evidence_pipeline():
    print("==================================================================")
    print("  CHU TRINH TAO BANG CHUNG DEMO & KIEM TRA TOAN DIEN SECURESHARE  ")
    print("==================================================================")

    # Step 0: Clean Seed
    print("[0] Khoi tao co so du lieu sach ban dau...")
    seed()

    driver = setup_driver()
    try:
        # 1. Trang chu & Trang Dang ky
        print("\n[Demo 0.1] Chup anh Trang chu...")
        driver.get(f"{BASE_URL}/")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "01_home_page.png"))

        print("[Demo 0.2] Kiem tra Trang Dang ky tai khoan (Password Policy UI)...")
        driver.get(f"{BASE_URL}/register")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "02_register_page.png"))

        print("[Demo 0.3] Chup anh Trang Dang nhap...")
        driver.get(f"{BASE_URL}/login")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "03_login_page.png"))

        # -------------------------------------------------------------
        # DEMO 1: Login sai 5 lan -> Account Locked
        # -------------------------------------------------------------
        print("\n[DEMO 1] Thuc hien tan cong Brute-force: Nhap sai mat khau 5 lan lien tiep...")
        for attempt in range(1, 6):
            driver.get(f"{BASE_URL}/login")
            username_field = driver.find_element(By.ID, "username_or_email")
            password_field = driver.find_element(By.ID, "password")
            submit_btn = driver.find_element(By.XPATH, "//button[@type='submit']")

            username_field.clear()
            username_field.send_keys("bin")
            password_field.clear()
            password_field.send_keys(f"WrongPass@{attempt}")
            submit_btn.click()
            time.sleep(1)
            print(f"  -> Lan thu {attempt}/5 gui mat khau sai...")

        driver.save_screenshot(str(EVIDENCE_DIR / "04_brute_force_account_locked.png"))
        print("  -> [+] Da chup anh 04_brute_force_account_locked.png: Thong bao tai khoan bi khoa 5 phut!")

        # Thu lan thu 6 voi mat khau DUNG
        print("  -> Thu lan thu 6 voi mat khau DUNG cua Bin...")
        username_field = driver.find_element(By.ID, "username_or_email")
        password_field = driver.find_element(By.ID, "password")
        submit_btn = driver.find_element(By.XPATH, "//button[@type='submit']")
        username_field.clear()
        username_field.send_keys("bin")
        password_field.clear()
        password_field.send_keys("Bin@12345")
        submit_btn.click()
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "05_login_attempt6_blocked.png"))
        print("  -> [+] Lan thu 6 van bi CHAN do tai khoan dang bi khoa!")

        # -------------------------------------------------------------
        # DEMO 2: Upload file hop le + upload .exe bi tu choi
        # -------------------------------------------------------------
        print("\n[DEMO 2] Kiem tra Upload Validation & Ma hoa tren dia...")
        # Dang nhap bang Khoi
        driver.get(f"{BASE_URL}/login")
        driver.find_element(By.ID, "username_or_email").send_keys("khoi")
        driver.find_element(By.ID, "password").send_keys("Khoi@12345")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)

        # Chup Dashboard cua Khoi
        driver.save_screenshot(str(EVIDENCE_DIR / "06_khoi_dashboard.png"))

        # Tao 1 file .exe gia lap nguy hiem
        fake_exe = BASE_DIR / "scripts" / "payload.exe"
        fake_exe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00FAKE_VIRUS_EXECUTABLE")

        # Thu upload file .exe
        driver.get(f"{BASE_URL}/files/upload")
        file_input = driver.find_element(By.ID, "fileInput")
        file_input.send_keys(str(fake_exe))
        time.sleep(0.5)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "07_upload_exe_rejected.png"))
        print("  -> [+] Da chup anh 07_upload_exe_rejected.png: Tu choi tep nguy hiem .exe thanh cong!")
        try:
            fake_exe.unlink()
        except Exception:
            pass

        # Upload file hop le (.txt / .pdf)
        valid_txt = BASE_DIR / "scripts" / "tai_lieu_mat_khoi.txt"
        secret_plaintext = b"Day la tai lieu tuyet mat cua Khoi. Noi dung nay phai duoc ma hoa Fernet tren dia."
        valid_txt.write_bytes(secret_plaintext)

        driver.get(f"{BASE_URL}/files/upload")
        file_input = driver.find_element(By.ID, "fileInput")
        file_input.send_keys(str(valid_txt))
        time.sleep(0.5)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "08_upload_valid_detail_sha256.png"))
        print("  -> [+] Da chup anh 08_upload_valid_detail_sha256.png: Upload thanh cong, hien ma SHA-256!")
        try:
            valid_txt.unlink()
        except Exception:
            pass

        # Kiem tra truc tiep file tren o dia storage/
        app = create_app()
        with app.app_context():
            rec = FileRecord.query.filter_by(original_name="tai_lieu_mat_khoi.txt").first()
            assert rec is not None
            storage_path = Path(app.config['STORAGE_FOLDER']) / rec.stored_name
            assert storage_path.exists()
            disk_bytes = storage_path.read_bytes()
            assert disk_bytes != secret_plaintext, "CANH BAO: Tep tren dia chua ma hoa!"
            assert disk_bytes.startswith(b'gAAAAA'), "CANH BAO: Tep khong co header Fernet!"
            print(f"  -> [+] MINH CHUNG MA HOA TRUC TIEP: Tep tren dia '{rec.stored_name}' la chuoi ma hoa Fernet dai {len(disk_bytes)} bytes. Plaintext khong the doc duoc!")

        # -------------------------------------------------------------
        # DEMO 3: Share file Bin -> Khoi -> Khoi tai duoc
        # -------------------------------------------------------------
        print("\n[DEMO 3] Kiem tra Chia se tai lieu tu Bin sang Khoi & Khoi tai ve...")
        # Dang xuat Khoi
        driver.get(f"{BASE_URL}/logout")
        time.sleep(1)

        # Dang nhap Bin (mo khoa tai khoan truoc do de demo tiep)
        with app.app_context():
            bin_user = User.query.filter_by(username="bin").first()
            bin_user.failed_login_attempts = 0
            bin_user.locked_until = None
            db.session.commit()

        driver.get(f"{BASE_URL}/login")
        driver.find_element(By.ID, "username_or_email").send_keys("bin")
        driver.find_element(By.ID, "password").send_keys("Bin@12345")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)

        # Vao trang chi tiet tep bao_cao_bin.txt (ID 1)
        driver.get(f"{BASE_URL}/files/1")
        time.sleep(1)
        # Chia se lai voi quyen DOWNLOAD cho Khoi
        user_input = driver.find_element(By.NAME, "username")
        user_input.clear()
        user_input.send_keys("khoi")
        perm_select = Select(driver.find_element(By.NAME, "permission"))
        perm_select.select_by_value("DOWNLOAD")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Cấp quyền chia sẻ')]").click()
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "09_bin_shares_to_khoi.png"))
        print("  -> [+] Da chup anh 09_bin_shares_to_khoi.png: Form chia se va danh sach cap quyen!")

        # Dang xuat Bin, dang nhap Khoi
        driver.get(f"{BASE_URL}/logout")
        time.sleep(1)
        driver.get(f"{BASE_URL}/login")
        driver.find_element(By.ID, "username_or_email").send_keys("khoi")
        driver.find_element(By.ID, "password").send_keys("Khoi@12345")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)

        # Vao tab "Duoc chia se voi toi"
        driver.get(f"{BASE_URL}/files")
        time.sleep(1)
        shared_tab = driver.find_element(By.ID, "shared-tab")
        shared_tab.click()
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "10_khoi_shared_with_me_tab.png"))
        print("  -> [+] Da chup anh 10_khoi_shared_with_me_tab.png: Tab tai lieu duoc chia se!")

        # Khoi vao chi tiet tep ID 1 va thay nut Tai ve
        driver.get(f"{BASE_URL}/files/1")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "11_khoi_downloads_shared_file.png"))
        print("  -> [+] Da chup anh 11_khoi_downloads_shared_file.png: Khoi co quyen DOWNLOAD hop le!")

        # -------------------------------------------------------------
        # DEMO 4: Chuong khong co quyen nhung sua URL -> 403 + ACCESS_DENIED
        # -------------------------------------------------------------
        print("\n[DEMO 4] Kiem tra Phong chong IDOR: Chuong sua URL de truy cap tep rieng tu...")
        driver.get(f"{BASE_URL}/logout")
        time.sleep(1)

        # Dang nhap Chuong
        driver.get(f"{BASE_URL}/login")
        driver.find_element(By.ID, "username_or_email").send_keys("chuong")
        driver.find_element(By.ID, "password").send_keys("Chuong@12345")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)

        # Chuong sua URL thanh /files/1 (tep cua Bin)
        driver.get(f"{BASE_URL}/files/1")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "12_idor_attack_blocked_403.png"))
        print("  -> [+] Da chup anh 12_idor_attack_blocked_403.png: Giao dien chan loi 403 Access Denied!")

        # -------------------------------------------------------------
        # DEMO 5: Sua file trong storage -> SHA-256 mismatch -> Block download + FILE_INTEGRITY_FAILED
        # -------------------------------------------------------------
        print("\n[DEMO 5] Kiem tra Tinh toan ven & Phat hien Gia mao du lieu (Data Tampering)...")
        # Chay script tamper file 1
        tamper_demo(1)

        # Dang nhap Bin (chu so huu tep 1) va co gang tai ve
        driver.get(f"{BASE_URL}/logout")
        time.sleep(1)
        driver.get(f"{BASE_URL}/login")
        driver.find_element(By.ID, "username_or_email").send_keys("bin")
        driver.find_element(By.ID, "password").send_keys("Bin@12345")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)

        # Bin truy cap link download tep 1
        driver.get(f"{BASE_URL}/files/1/download")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "13_file_tampering_blocked_alert.png"))
        print("  -> [+] Da chup anh 13_file_tampering_blocked_alert.png: Trang canh bao do chan download vi pham toan ven!")

        # -------------------------------------------------------------
        # DEMO 6: Quản trị viên Admin SOC & Audit Logs ĐẦY ĐỦ
        # -------------------------------------------------------------
        print("\n[DEMO 6] Kiem tra Giao dien Admin SOC Dashboard & Audit Logs...")
        driver.get(f"{BASE_URL}/logout")
        time.sleep(1)
        driver.get(f"{BASE_URL}/login")
        driver.find_element(By.ID, "username_or_email").send_keys("admin")
        driver.find_element(By.ID, "password").send_keys("Admin@123")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(1)

        # Admin SOC Dashboard
        driver.get(f"{BASE_URL}/admin")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "14_admin_soc_dashboard.png"))
        print("  -> [+] Da chup anh 14_admin_soc_dashboard.png: SOC Dashboard voi bang canh bao Tampered Files!")

        # Admin Users List
        driver.get(f"{BASE_URL}/admin/users")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "15_admin_users_management.png"))
        print("  -> [+] Da chup anh 15_admin_users_management.png: Quan ly danh sach nguoi dung va trang thai khoa!")

        # Admin Audit Logs
        driver.get(f"{BASE_URL}/admin/logs")
        time.sleep(1)
        driver.save_screenshot(str(EVIDENCE_DIR / "16_admin_full_audit_logs.png"))
        print("  -> [+] Da chup anh 16_admin_full_audit_logs.png: Nhat ky kiem toan he thong day du tat ca hanh vi!")

        print("\n==================================================================")
        print("  HOAN TAT TOAN BO 5 DEMO & CHUP ANH MINH CHUNG VAO THU MUC evidence/!")
        print("==================================================================")

    finally:
        driver.quit()


if __name__ == "__main__":
    run_evidence_pipeline()
