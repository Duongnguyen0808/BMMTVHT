import sys
import tempfile
import shutil
from pathlib import Path

# Add project root to sys.path for test execution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pytest
from cryptography.fernet import Fernet
from app import create_app
from app.config import TestConfig
from app.extensions import db as _db
from app.models import User, FileRecord, FilePermission, AuditLog


@pytest.fixture(scope='session')
def test_fernet_key():
    return Fernet.generate_key().decode('utf-8')


@pytest.fixture
def app(test_fernet_key):
    temp_dir = tempfile.mkdtemp()

    class CustomTestConfig(TestConfig):
        STORAGE_FOLDER = Path(temp_dir)
        FERNET_KEY = test_fernet_key
        SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False

    app = create_app(CustomTestConfig)

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    return _db


@pytest.fixture
def create_user(db):
    def _create_user(username, email, password, role='user'):
        user = User(
            username=username,
            email=email,
            role=role,
            failed_login_attempts=0
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user
    return _create_user


@pytest.fixture
def auth_client(client, create_user):
    class AuthActions:
        def __init__(self, client):
            self._client = client

        def login(self, username='testuser', password='Password@123'):
            return self._client.post('/login', data={
                'username_or_email': username,
                'password': password
            }, follow_redirects=True)

        def logout(self):
            return self._client.post('/logout', follow_redirects=True)

    return AuthActions(client)
