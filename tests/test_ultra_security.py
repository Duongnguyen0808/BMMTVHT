import io
from datetime import datetime, timezone, timedelta
from werkzeug.datastructures import FileStorage
from app.models import User, FileRecord, FilePermission, SharedLink, AuditLog
from app.extensions import db
from app.files.services import process_file_upload
from app.security.watermark import apply_forensic_watermark


def test_honeypot_active_defense_trap(client, create_user, app):
    """Active Defense: Accessing a honeypot file immediately locks account and logs CRITICAL breach."""
    attacker = create_user('insider_attacker', 'insider@example.com', 'Password@123')
    admin = create_user('sec_admin', 'secadmin@example.com', 'Admin@123', role='admin')

    # Admin creates honeypot file
    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(b"Fake root credentials for trapping"), filename="honeypot_vault.txt", content_type="text/plain")
        trap_file = process_file_upload(fs, owner_id=admin.id)
        trap_file.is_honeypot = True
        db.session.commit()
        trap_id = trap_file.id

    # Insider attacker logs in and tries to access honeypot file
    client.post('/login', data={'username_or_email': 'insider_attacker', 'password': 'Password@123'})

    res = client.get(f'/files/{trap_id}')
    assert res.status_code == 403
    assert b"HONEYPOT" in res.data or b"B\xe1\xba\xa3y an ninh" in res.data or b"B\xe1\xba\xa2Y AN NINH" in res.data

    # Verify user account was locked
    locked_user = db.session.get(User, attacker.id)
    assert locked_user.is_locked() is True
    assert locked_user.failed_login_attempts >= 5

    # Verify CRITICAL audit log was created
    log = AuditLog.query.filter_by(action='HONEYPOT_TRIGGERED', target_type='HONEYPOT').first()
    assert log is not None
    assert log.status == 'CRITICAL'


def test_dynamic_forensic_watermark_text_and_image():
    """DLP: Dynamic watermarking injects recipient identity and forensic watermark."""
    # Test plaintext watermarking
    plain_text = b"Confidential business strategy document."
    watermarked_text = apply_forensic_watermark(plain_text, "report.txt", "analyst_bob", "192.168.1.100")
    assert b"SECURESHARE FORENSIC DLP WATERMARK" in watermarked_text
    assert b"analyst_bob" in watermarked_text
    assert b"192.168.1.100" in watermarked_text
    assert b"Confidential business strategy document." in watermarked_text

    # Test image watermarking (PNG)
    from PIL import Image
    img = Image.new("RGB", (100, 100), color="blue")
    img_bytes_io = io.BytesIO()
    img.save(img_bytes_io, format="PNG")
    raw_img_bytes = img_bytes_io.getvalue()

    watermarked_img = apply_forensic_watermark(raw_img_bytes, "avatar.png", "analyst_bob", "192.168.1.100")
    assert len(watermarked_img) > 0


def test_zero_trust_expiring_shared_link_lifecycle(client, create_user, app):
    """Zero-Trust: Expiring link with passcode self-destructs after max_downloads is reached."""
    owner = create_user('link_owner', 'linko@example.com', 'Password@123')

    # Upload test file
    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(b"Data for zero trust link testing"), filename="secret_doc.txt", content_type="text/plain")
        f = process_file_upload(fs, owner_id=owner.id)
        f_id = f.id

    client.post('/login', data={'username_or_email': 'link_owner', 'password': 'Password@123'})

    # Create link with 1 download limit and passcode 'Passcode@123'
    res_create = client.post(f'/files/{f_id}/create-link', data={
        'passcode': 'Passcode@123',
        'max_downloads': '1',
        'expire_minutes': '60'
    }, follow_redirects=True)
    assert res_create.status_code == 200

    link = SharedLink.query.filter_by(file_id=f_id).first()
    assert link is not None
    assert link.max_downloads == 1

    # Client logs out to act as guest recipient
    client.post('/logout')

    # 1. Access without entering passcode -> Returns page with form
    res_page = client.get(f'/share/link/{link.token}')
    assert res_page.status_code == 200
    assert b"passcode" in res_page.data.lower()

    # 2. Enter wrong passcode -> Rejected with error
    res_wrong = client.post(f'/share/link/{link.token}', data={'passcode': 'WrongPasscode'}, follow_redirects=True)
    assert res_wrong.status_code == 200
    assert b"kh\xc3\xb4ng ch\xc3\xadnh x\xc3\xa1c" in res_wrong.data
    assert link.download_count == 0

    # 3. Enter correct passcode -> Download succeeds (first download)
    res_ok = client.post(f'/share/link/{link.token}', data={'passcode': 'Passcode@123'})
    assert res_ok.status_code == 200
    assert res_ok.headers.get('Content-Disposition') is not None

    # Refresh link model
    db.session.refresh(link)
    assert link.download_count == 1
    assert link.is_exhausted() is True

    # 4. Attempt second download -> Link self-destructed / expired (HTTP 410)
    res_expired = client.get(f'/share/link/{link.token}')
    assert res_expired.status_code == 410
    assert b"t\xe1\xbb\xb1 h\xe1\xbb\xa7y" in res_expired.data or b"h\xe1\xba\xbft h\xe1\xba\xa1n" in res_expired.data
