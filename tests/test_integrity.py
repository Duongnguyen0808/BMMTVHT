import io
from pathlib import Path
from werkzeug.datastructures import FileStorage
from app.models import FileRecord, AuditLog
from app.files.services import process_file_upload


def test_tc15_file_integrity_valid(client, create_user, auth_client, app):
    """TC15: File hợp lệ -> expected integrity VALID + download success"""
    user = create_user(username='valid_file_user', email='vfu@example.com', password='Password@123')
    original_data = b"Clean untampered data contents for integrity verification."

    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(original_data), filename="clean.txt", content_type="text/plain")
        record = process_file_upload(fs, owner_id=user.id)
        record_id = record.id

    auth_client.login('valid_file_user', 'Password@123')
    res = client.get(f'/files/{record_id}/download')
    assert res.status_code == 200
    assert res.data == original_data

    # File integrity status must remain VALID
    with app.app_context():
        from app.extensions import db as test_db
        updated_rec = test_db.session.get(FileRecord, record_id)
        assert updated_rec.integrity_status == 'VALID'


def test_tc16_file_tampering_blocked(client, create_user, auth_client, app):
    """TC16: File bị tamper -> expected download blocked + integrity TAMPERED + audit FILE_INTEGRITY_FAILED"""
    user = create_user(username='tamper_target_user', email='ttu@example.com', password='Password@123')
    original_data = b"Critical financial record before being tampered."

    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(original_data), filename="financial.txt", content_type="text/plain")
        record = process_file_upload(fs, owner_id=user.id)
        record_id = record.id
        stored_filename = record.stored_name

    # Simulate attacker modifying encrypted bytes on disk
    storage_path = Path(app.config['STORAGE_FOLDER']) / stored_filename
    assert storage_path.exists()
    ciphertext = bytearray(storage_path.read_bytes())
    # Invert some bytes in ciphertext
    for i in range(12, min(24, len(ciphertext))):
        ciphertext[i] ^= 0xAA
    storage_path.write_bytes(bytes(ciphertext))

    # User attempts to download tampered file
    auth_client.login('tamper_target_user', 'Password@123')
    res = client.get(f'/files/{record_id}/download')

    # Download must be blocked (HTTP 400 with alert page)
    assert res.status_code == 400
    assert res.data != original_data

    # Database integrity_status must become TAMPERED
    with app.app_context():
        from app.extensions import db as test_db
        updated_rec = test_db.session.get(FileRecord, record_id)
        assert updated_rec.integrity_status == 'TAMPERED'

        # Audit log must contain FILE_INTEGRITY_FAILED
        log = AuditLog.query.filter_by(action='FILE_INTEGRITY_FAILED', target_id=str(record_id)).first()
        assert log is not None
        assert log.status == 'FAILED'
