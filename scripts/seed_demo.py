import io
import sys
from pathlib import Path
from werkzeug.datastructures import FileStorage

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.extensions import db
from app.models import User, FileRecord, FilePermission, AuditLog
from app.files.services import process_file_upload


def seed():
    app = create_app()
    with app.app_context():
        print("==================================================")
        print("          SECURESHARE DEMO DATA SEEDER            ")
        print("==================================================")

        # Clear existing data for clean seed
        print("[*] Cleaning existing tables...")
        FilePermission.query.delete()
        FileRecord.query.delete()
        AuditLog.query.delete()
        User.query.delete()
        db.session.commit()

        # Clean storage directory files
        storage_folder = Path(app.config.get('STORAGE_FOLDER'))
        for item in storage_folder.glob("*.enc"):
            try:
                item.unlink()
            except Exception:
                pass

        # 1. Create Users
        print("[*] Creating 4 demo user accounts...")
        users_data = [
            {'username': 'admin', 'email': 'admin@secureshare.local', 'password': 'Admin@123', 'role': 'admin'},
            {'username': 'bin', 'email': 'bin@secureshare.local', 'password': 'Bin@12345', 'role': 'user'},
            {'username': 'khoi', 'email': 'khoi@secureshare.local', 'password': 'Khoi@12345', 'role': 'user'},
            {'username': 'chuong', 'email': 'chuong@secureshare.local', 'password': 'Chuong@12345', 'role': 'user'}
        ]

        created_users = {}
        for u in users_data:
            user = User(
                username=u['username'],
                email=u['email'],
                role=u['role'],
                failed_login_attempts=0
            )
            user.set_password(u['password'])
            db.session.add(user)
            db.session.commit()
            created_users[u['username']] = user
            print(f"  [+] Created user: {u['username']} (role: {u['role']})")

        # 2. Upload Demo Files through service (encrypted & hashed)
        print("[*] Uploading and encrypting demo documents...")
        demo_files_info = [
            {
                'owner': created_users['bin'],
                'name': 'bao_cao_bin.txt',
                'content': b"Bao cao an ninh mang va bao mat thong tin he thong.\nTac gia: Sinh vien Bin.\nTrang thai: Bao mat cap cao (Confidential).\nSHA-256 va Fernet duoc ap dung."
            },
            {
                'owner': created_users['khoi'],
                'name': 'ke_hoach_khoi.txt',
                'content': b"Ke hoach danh gia rui ro va kiem thu xam nhap he thong SecureShare.\nTac gia: Sinh vien Khoi.\nNoi dung: Danh gia tan cong brute-force, IDOR va tampering."
            },
            {
                'owner': created_users['chuong'],
                'name': 'ghi_chu_chuong.txt',
                'content': b"Ghi chu he thong chia se tai lieu an toan.\nTac gia: Sinh vien Chuong.\nChu thich: Toan bo du lieu luu tru tren dia deu da duoc ma hoa Fernet."
            }
        ]

        created_records = {}
        for item in demo_files_info:
            stream = io.BytesIO(item['content'])
            storage_file = FileStorage(
                stream=stream,
                filename=item['name'],
                content_type='text/plain'
            )
            record = process_file_upload(storage_file, owner_id=item['owner'].id)
            created_records[item['name']] = record
            print(f"  [+] Uploaded & Encrypted: {record.original_name} (ID: {record.id}, Hash: {record.sha256_hash[:16]}...)")

        # 3. Setup Permissions
        print("[*] Configuring sharing permissions...")
        # Bin shares bao_cao_bin.txt to Khoi with DOWNLOAD permission
        p1 = FilePermission(
            file_id=created_records['bao_cao_bin.txt'].id,
            user_id=created_users['khoi'].id,
            permission='DOWNLOAD'
        )
        db.session.add(p1)

        # Khoi shares ke_hoach_khoi.txt to Chuong with VIEW permission
        p2 = FilePermission(
            file_id=created_records['ke_hoach_khoi.txt'].id,
            user_id=created_users['chuong'].id,
            permission='VIEW'
        )
        db.session.add(p2)
        db.session.commit()

        print(f"  [+] Shared '{created_records['bao_cao_bin.txt'].original_name}' -> 'khoi' [DOWNLOAD]")
        print(f"  [+] Shared '{created_records['ke_hoach_khoi.txt'].original_name}' -> 'chuong' [VIEW]")

        print("==================================================")
        print("[+] SEED DATA COMPLETED SUCCESSFULLY!")
        print("Demo Accounts:")
        print("  - admin  / Admin@123   (Admin)")
        print("  - bin    / Bin@12345   (User)")
        print("  - khoi   / Khoi@12345  (User)")
        print("  - chuong / Chuong@12345 (User)")
        print("==================================================")


if __name__ == '__main__':
    seed()
