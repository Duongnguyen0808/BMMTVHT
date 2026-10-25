import io
import pytest
from app.models import User, FileRecord, FilePermission, AuditLog
from app.security.crypto import encrypt_bytes, decrypt_bytes, CryptoError
from app.files.services import allowed_file, generate_storage_name, get_storage_path


def test_tc19_weak_password_rejected(client):
    """TC19: Weak passwords missing uppercase/numbers/length must be rejected."""
    # Test short password
    res1 = client.post('/register', data={
        'username': 'weakuser1',
        'email': 'weak1@example.com',
        'password': 'short',
        'confirm_password': 'short'
    })
    assert res1.status_code == 200
    assert User.query.filter_by(username='weakuser1').first() is None

    # Test password without uppercase
    res2 = client.post('/register', data={
        'username': 'weakuser2',
        'email': 'weak2@example.com',
        'password': 'password123',
        'confirm_password': 'password123'
    })
    assert res2.status_code == 200
    assert User.query.filter_by(username='weakuser2').first() is None


def test_tc20_invalid_email_format_rejected(client):
    """TC20: Invalid email formats must be rejected by validator."""
    res = client.post('/register', data={
        'username': 'bademailuser',
        'email': 'not-an-email',
        'password': 'StrongPassword@123',
        'confirm_password': 'StrongPassword@123'
    })
    assert res.status_code == 200
    assert User.query.filter_by(username='bademailuser').first() is None


def test_tc21_session_cookie_security_flags(client, create_user):
    """TC21: Authentication session cookies must have HttpOnly attribute."""
    create_user('cookieuser', 'cookie@example.com', 'Password@123')
    res = client.post('/login', data={
        'username_or_email': 'cookieuser',
        'password': 'Password@123'
    })
    cookies = res.headers.getlist('Set-Cookie')
    # Check that session cookie exists and has HttpOnly
    session_cookie = next((c for c in cookies if 'session=' in c), None)
    if session_cookie:
        assert 'HttpOnly' in session_cookie


def test_tc22_path_traversal_filename_sanitization(client, create_user):
    """TC22: Filename with path traversal characters (../) must be sanitized safely."""
    from werkzeug.utils import secure_filename
    malicious_filename = "../../../etc/passwd.txt"
    sanitized = secure_filename(malicious_filename)
    assert "../" not in sanitized
    assert "/" not in sanitized
    assert sanitized == "etc_passwd.txt"


def test_tc23_disallowed_and_double_extensions(app):
    """TC23: Executable scripts and dangerous extensions must be disallowed."""
    with app.app_context():
        assert allowed_file('virus.exe') is False
        assert allowed_file('script.sh') is False
        assert allowed_file('backdoor.bat') is False
        assert allowed_file('cmd.cmd') is False
        assert allowed_file('powershell.ps1') is False
        # Valid allowed files
        assert allowed_file('report.pdf') is True
        assert allowed_file('data.docx') is True
        assert allowed_file('image.png') is True


def test_tc24_zero_byte_empty_file_rejected(client, create_user):
    """TC24: 0-byte empty file upload must be rejected."""
    user = create_user('uploader', 'up@example.com', 'Password@123')
    client.post('/login', data={'username_or_email': 'uploader', 'password': 'Password@123'})

    empty_data = (io.BytesIO(b''), 'empty.txt')
    res = client.post('/files/upload', data={'file': empty_data}, content_type='multipart/form-data', follow_redirects=True)
    # Server returns 400 Bad Request or flashes error on 200
    assert res.status_code in [200, 400]
    assert FileRecord.query.filter_by(original_name='empty.txt').first() is None


def test_tc25_owner_cannot_self_share(client, create_user):
    """TC25: Owner cannot share file to themselves."""
    owner = create_user('owner1', 'owner1@example.com', 'Password@123')
    client.post('/login', data={'username_or_email': 'owner1', 'password': 'Password@123'})

    # Upload valid file
    file_data = (io.BytesIO(b'Test Content'), 'self_share.txt')
    client.post('/files/upload', data={'file': file_data}, content_type='multipart/form-data')
    f = FileRecord.query.filter_by(original_name='self_share.txt').first()

    res = client.post(f'/files/{f.id}/share', data={'username': 'owner1', 'permission': 'VIEW'}, follow_redirects=True)
    assert res.status_code == 200
    perm = FilePermission.query.filter_by(file_id=f.id, user_id=owner.id).first()
    assert perm is None


def test_tc26_revoke_permission_removes_access(client, create_user):
    """TC26: Revoking a user permission immediately blocks their access."""
    owner = create_user('rev_owner', 'rev_o@example.com', 'Password@123')
    collab = create_user('rev_collab', 'rev_c@example.com', 'Password@123')

    client.post('/login', data={'username_or_email': 'rev_owner', 'password': 'Password@123'})
    file_data = (io.BytesIO(b'Confidential Project'), 'project.txt')
    client.post('/files/upload', data={'file': file_data}, content_type='multipart/form-data')
    f = FileRecord.query.filter_by(original_name='project.txt').first()

    # Share with collab
    client.post(f'/files/{f.id}/share', data={'username': 'rev_collab', 'permission': 'DOWNLOAD'})
    assert FilePermission.query.filter_by(file_id=f.id, user_id=collab.id).first() is not None

    # Revoke
    client.post(f'/files/{f.id}/revoke/{collab.id}', follow_redirects=True)
    assert FilePermission.query.filter_by(file_id=f.id, user_id=collab.id).first() is None


def test_tc27_view_only_cannot_download_endpoint(client, create_user):
    """TC27: User with only VIEW permission receives 403 when hitting /download endpoint."""
    owner = create_user('v_owner', 'vo@example.com', 'Password@123')
    viewer = create_user('v_viewer', 'vv@example.com', 'Password@123')

    client.post('/login', data={'username_or_email': 'v_owner', 'password': 'Password@123'})
    file_data = (io.BytesIO(b'View Only Confidential Document'), 'view_only.txt')
    client.post('/files/upload', data={'file': file_data}, content_type='multipart/form-data')
    f = FileRecord.query.filter_by(original_name='view_only.txt').first()

    # Share with VIEW permission
    client.post(f'/files/{f.id}/share', data={'username': 'v_viewer', 'permission': 'VIEW'})
    client.post('/logout')

    # Login as viewer and attempt download
    client.post('/login', data={'username_or_email': 'v_viewer', 'password': 'Password@123'})
    res = client.get(f'/files/{f.id}/download')
    assert res.status_code == 403


def test_tc28_corrupt_ciphertext_fails_crypto(test_fernet_key):
    """TC28: Modified ciphertext causes Fernet to reject decryption due to HMAC failure."""
    original = b"Super Secret Financial Report"
    ciphertext = encrypt_bytes(original, test_fernet_key)

    # Tamper with the ciphertext by flipping bytes
    corrupt_bytes = bytearray(ciphertext)
    corrupt_bytes[-5] ^= 0xFF
    corrupt_ciphertext = bytes(corrupt_bytes)

    with pytest.raises(CryptoError):
        decrypt_bytes(corrupt_ciphertext, test_fernet_key)


def test_tc29_unauthenticated_admin_redirect(client):
    """TC29: Unauthenticated request to /admin redirects to login."""
    res = client.get('/admin')
    assert res.status_code in [302, 308]
    if res.status_code == 302:
        assert '/login' in res.headers.get('Location', '')


def test_tc30_non_admin_blocked_from_admin_logs(client, create_user):
    """TC30: Normal user is rejected with 403 Forbidden when accessing /admin/logs."""
    create_user('regular_user', 'regular@example.com', 'Password@123', role='user')
    client.post('/login', data={'username_or_email': 'regular_user', 'password': 'Password@123'})

    res = client.get('/admin/logs')
    assert res.status_code == 403
