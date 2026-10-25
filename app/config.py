import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file
load_dotenv(BASE_DIR / '.env')


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-secret-key-change-in-production')
    FERNET_KEY = os.environ.get('FERNET_KEY', None)

    # Database
    db_url = os.environ.get('DATABASE_URL', f"sqlite:///{BASE_DIR / 'instance' / 'secureshare.db'}")
    if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite:////") and not ":" in db_url[10:]:
        # relative path resolution if needed
        rel_path = db_url.replace("sqlite:///", "")
        if not Path(rel_path).is_absolute():
            db_url = f"sqlite:///{BASE_DIR / rel_path}"
    SQLALCHEMY_DATABASE_URI = db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Uploads & Storage
    STORAGE_FOLDER = BASE_DIR / 'storage'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))  # 10 MB default
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg'}
    DISALLOWED_EXTENSIONS = {'exe', 'bat', 'cmd', 'ps1', 'sh'}

    # Session security
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT_MINUTES', 30)))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('true', '1')

    # Brute-force & Lockout
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 5

    # Rate Limiter
    RATELIMIT_DEFAULT = "200 per day; 50 per hour"
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    RATELIMIT_ENABLED = False
