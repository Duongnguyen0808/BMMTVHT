import io
from pathlib import Path
from app.models import FileRecord, AuditLog


def test_tc07_upload_pdf(client, create_user, auth_client, app):
    """TC07: Upload .pdf -> expected success"""
    user = create_user(username='uploader', email='uploader@example.com', password='Password@123')
    auth_client.login('uploader', 'Password@123')

    pdf_bytes = b"%PDF-1.4 sample pdf content for secure upload test"
    data = {
        'file': (io.BytesIO(pdf_bytes), 'document.pdf')
    }

    res = client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200

    record = FileRecord.query.filter_by(original_name='document.pdf', owner_id=user.id).first()
    assert record is not None
    assert record.file_size == len(pdf_bytes)
    assert record.integrity_status == 'VALID'


def test_tc08_upload_exe_rejected(client, create_user, auth_client):
    """TC08: Upload .exe -> expected reject"""
    create_user(username='malware_tester', email='mal@example.com', password='Password@123')
    auth_client.login('malware_tester', 'Password@123')

    exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00fake executable content"
    data = {
        'file': (io.BytesIO(exe_bytes), 'malware.exe')
    }

    res = client.post('/files/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 400

    # Ensure no FileRecord was created
    record = FileRecord.query.filter_by(original_name='malware.exe').first()
    assert record is None

    # Ensure INVALID_UPLOAD audit log was created
    log = AuditLog.query.filter_by(action='INVALID_UPLOAD').first()
    assert log is not None


def test_tc09_upload_too_large(client, create_user, auth_client, app):
    """TC09: Upload >10MB -> expected reject / 413"""
    create_user(username='bigfileuser', email='big@example.com', password='Password@123')
    auth_client.login('bigfileuser', 'Password@123')

    # Exceed MAX_CONTENT_LENGTH (10MB + 1024 bytes)
    big_bytes = b"A" * (10 * 1024 * 1024 + 1024)
    data = {
        'file': (io.BytesIO(big_bytes), 'large.pdf')
    }

    res = client.post('/files/upload', data=data, content_type='multipart/form-data')
    assert res.status_code in (400, 413)

    record = FileRecord.query.filter_by(original_name='large.pdf').first()
    assert record is None


def test_tc10_storage_file_is_encrypted(client, create_user, auth_client, app):
    """TC10: Storage file -> nội dung trên disk không bằng plaintext gốc (Fernet encrypted)"""
    user = create_user(username='encryptuser', email='encrypt@example.com', password='Password@123')
    auth_client.login('encryptuser', 'Password@123')

    raw_plaintext = b"This is a confidential secret text that must be encrypted on server disk."
    data = {
        'file': (io.BytesIO(raw_plaintext), 'confidential.txt')
    }

    res = client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200

    record = FileRecord.query.filter_by(original_name='confidential.txt', owner_id=user.id).first()
    assert record is not None

    storage_path = Path(app.config['STORAGE_FOLDER']) / record.stored_name
    assert storage_path.exists()

    on_disk_bytes = storage_path.read_bytes()
    # On disk bytes MUST NOT equal the raw plaintext
    assert on_disk_bytes != raw_plaintext
    assert raw_plaintext not in on_disk_bytes
    # Fernet ciphertext starts with 'gAAAAA' (base64)
    assert on_disk_bytes.startswith(b'gAAAAA')


def test_deep_inspection_magic_bytes_blocks_disguised_exe(client, create_user, auth_client):
    """Deep Inspection: Detect & block PE executable disguised as PDF."""
    create_user(username='spoof_tester', email='spoof@example.com', password='Password@123')
    auth_client.login('spoof_tester', 'Password@123')

    # Spoofed file: .pdf extension but binary header is 'MZ'
    fake_exe_bytes = b"MZ" + b"\x00" * 30 + b"BinaryPayload"
    data = {'file': (io.BytesIO(fake_exe_bytes), 'renamed_evil.pdf')}

    res = client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 400
    assert b"Magic Bytes" in res.data
    assert FileRecord.query.filter_by(original_name='renamed_evil.pdf').first() is None


def test_deep_inspection_magic_bytes_blocks_script_injection(client, create_user, auth_client):
    """Deep Inspection: Detect & block web script disguised as image."""
    create_user(username='script_attacker', email='attacker@example.com', password='Password@123')
    auth_client.login('script_attacker', 'Password@123')

    script_bytes = b"<?php echo 'malicious webshell'; ?>"
    data = {'file': (io.BytesIO(script_bytes), 'fake_avatar.png')}

    res = client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 400
    assert b"Magic Bytes" in res.data or b"nguy hi" in res.data
    assert FileRecord.query.filter_by(original_name='fake_avatar.png').first() is None

