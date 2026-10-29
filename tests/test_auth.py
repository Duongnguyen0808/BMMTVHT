import pytest
from app.models import User, AuditLog


def test_tc01_register_valid(client, db):
    """TC01: Register hợp lệ -> expected success"""
    res = client.post('/register', data={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'SecurePassword@123',
        'confirm_password': 'SecurePassword@123'
    }, follow_redirects=True)

    assert res.status_code == 200
    user = User.query.filter_by(username='newuser').first()
    assert user is not None
    assert user.email == 'newuser@example.com'
    assert user.password_hash != 'SecurePassword@123'
    assert user.check_password('SecurePassword@123') is True

    # Audit log check
    log = AuditLog.query.filter_by(action='REGISTER', username_snapshot='newuser').first()
    assert log is not None
    assert log.status == 'SUCCESS'


def test_tc02_register_duplicate_username(client, create_user):
    """TC02: Register username trùng -> expected reject"""
    create_user(username='existinguser', email='existing@example.com', password='Password@123')

    res = client.post('/register', data={
        'username': 'existinguser',
        'email': 'another@example.com',
        'password': 'SecurePassword@123',
        'confirm_password': 'SecurePassword@123'
    })

    assert res.status_code == 200
    # Username duplicate error shown
    assert b"T\xc3\xaan \xc4\x91\xc4\x83ng nh\xe1\xba\xadp n\xc3\xa0y \xc4\x91\xc3\xa3 \xc4\x91\xc9\x99c s\xe1\xbb\xad d\xe1\xbb\xa5ng." in res.data or b"\xc4\x91\xc3\xa3 \xc4\x91\xc6\xb0\xe1\xbb\xa3c s\xe1\xbb\xad d\xe1\xbb\xa5ng" in res.data
    # Ensure second user with different email but same username was not created
    users_count = User.query.filter_by(username='existinguser').count()
    assert users_count == 1


def test_tc03_login_valid(client, create_user):
    """TC03: Login đúng -> expected success"""
    create_user(username='validuser', email='valid@example.com', password='Password@123')

    res = client.post('/login', data={
        'username_or_email': 'validuser',
        'password': 'Password@123'
    }, follow_redirects=True)

    assert res.status_code == 200
    assert b"validuser" in res.data

    log = AuditLog.query.filter_by(action='LOGIN_SUCCESS', username_snapshot='validuser').first()
    assert log is not None
    assert log.status == 'SUCCESS'


def test_tc04_login_wrong_password(client, create_user):
    """TC04: Login sai password -> expected failure log"""
    create_user(username='wrongpwduser', email='wrongpwd@example.com', password='Password@123')

    res = client.post('/login', data={
        'username_or_email': 'wrongpwduser',
        'password': 'WrongPassword@999'
    }, follow_redirects=True)

    assert res.status_code == 200
    user = User.query.filter_by(username='wrongpwduser').first()
    assert user.failed_login_attempts == 1

    log = AuditLog.query.filter_by(action='LOGIN_FAILED', username_snapshot='wrongpwduser').first()
    assert log is not None
    assert log.status == 'FAILED'


def test_tc05_login_lockout_after_5_failures(client, create_user):
    """TC05: Login sai >=5 lần -> expected account locked"""
    create_user(username='lockuser', email='lock@example.com', password='Password@123')

    for i in range(5):
        client.post('/login', data={
            'username_or_email': 'lockuser',
            'password': 'WrongPassword@123'
        }, follow_redirects=True)

    user = User.query.filter_by(username='lockuser').first()
    assert user.failed_login_attempts >= 5
    assert user.is_locked() is True

    # 6th attempt should be blocked due to account locked
    res6 = client.post('/login', data={
        'username_or_email': 'lockuser',
        'password': 'Password@123'
    }, follow_redirects=True)

    assert res6.status_code == 200
    lock_log = AuditLog.query.filter_by(action='ACCOUNT_LOCKED', username_snapshot='lockuser').first()
    assert lock_log is not None


def test_tc06_unauthenticated_dashboard_redirect(client):
    """TC06: User chưa login truy cập /dashboard -> expected redirect login"""
    res = client.get('/dashboard')
    assert res.status_code == 302
    assert '/login' in res.headers['Location']


def test_2fa_totp_generation_and_login_flow(client, create_user):
    """2FA: Verify secret generation, login intercept, invalid OTP rejection, and successful login."""
    import pyotp
    from app.extensions import db

    user = create_user(username='totp_hero', email='totp@example.com', password='Password@123')
    secret = user.generate_totp_secret()
    user.is_2fa_enabled = True
    db.session.commit()

    # Verify secret is 32 base32 characters
    assert len(secret) == 32
    totp = pyotp.TOTP(secret)

    # 1. Login with password -> Redirects to /login/2fa
    res_step1 = client.post('/login', data={'username_or_email': 'totp_hero', 'password': 'Password@123'}, follow_redirects=False)
    assert res_step1.status_code == 302
    assert '/login/2fa' in res_step1.headers.get('Location', '')

    # 2. Wrong OTP -> Rejected
    res_step2 = client.post('/login/2fa', data={'otp_code': '000000'}, follow_redirects=True)
    assert res_step2.status_code == 200
    assert b"kh\xc3\xb4ng ch\xc3\xadnh x\xc3\xa1c" in res_step2.data

    # 3. Valid OTP -> Logged in successfully
    valid_code = totp.now()
    res_step3 = client.post('/login/2fa', data={'otp_code': valid_code}, follow_redirects=True)
    assert res_step3.status_code == 200
    assert b"totp_hero" in res_step3.data

