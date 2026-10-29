"""
Script tạo tệp bẫy Honeypot an ninh (Honeytoken Trap)
Tạo tệp: mat_khau_server_backup.txt (is_honeypot=True)
Chia sẻ quyền cho tất cả user để giăng bẫy kiểm tra xâm nhập.
"""
import io
import sys
from pathlib import Path
from werkzeug.datastructures import FileStorage

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.extensions import db
from app.models import User, FileRecord, FilePermission
from app.files.services import process_file_upload

def seed_honeypot():
    app = create_app()
    with app.app_context():
        # Check if already exists
        existing = FileRecord.query.filter_by(original_name='mat_khau_server_backup.txt').first()
        if existing:
            existing.is_honeypot = True
            db.session.commit()
            print(f"[OK] Honeypot file already exists: ID {existing.id}")
            return existing.id

        admin = User.query.filter_by(role='admin').first()
        if not admin:
            print("[!] Admin not found, please run seed_demo first.")
            return None

        fake_content = b"[TOP SECRET] ROOT PASSWORDS BACKUP - DO NOT TOUCH!\nServer 1: root / P@ssw0rd2026!\nDatabase: postgres / SuperSecretDb#1\n"
        stream = io.BytesIO(fake_content)
        fs = FileStorage(stream=stream, filename='mat_khau_server_backup.txt', content_type='text/plain')

        record = process_file_upload(fs, owner_id=admin.id)
        record.is_honeypot = True
        db.session.commit()

        # Share to other users so it appears in their 'Shared with me' list as bait
        users = User.query.filter(User.role != 'admin').all()
        for u in users:
            perm = FilePermission(file_id=record.id, user_id=u.id, permission='DOWNLOAD')
            db.session.add(perm)
        db.session.commit()

        print(f"[OK] Honeypot file created: '{record.original_name}' (ID: {record.id}) - Bait shared to {len(users)} users.")
        return record.id

if __name__ == '__main__':
    seed_honeypot()
