from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # 2FA / TOTP (RFC 6238)
    totp_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    owned_files = db.relationship('FileRecord', back_populates='owner', cascade='all, delete-orphan')
    permissions = db.relationship('FilePermission', back_populates='user', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', back_populates='user')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def generate_totp_secret(self) -> str:
        import pyotp
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self) -> str:
        import pyotp
        if not self.totp_secret:
            self.generate_totp_secret()
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=self.email, issuer_name="SecureShare")

    def verify_totp(self, token: str) -> bool:
        import pyotp
        if not self.totp_secret or not token:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return bool(totp.verify(str(token).strip().replace(" ", ""), valid_window=1))

    def is_locked(self) -> bool:
        if self.locked_until:
            now = datetime.now(timezone.utc)
            if self.locked_until.tzinfo is None:
                return datetime.now(timezone.utc).replace(tzinfo=None) < self.locked_until
            return now < self.locked_until
        return False

    def is_admin(self) -> bool:
        return self.role == 'admin'

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"


class FileRecord(db.Model):
    __tablename__ = 'file_records'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False, unique=True)
    mime_type = db.Column(db.String(128), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # size in bytes
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    integrity_status = db.Column(db.String(32), default='VALID', nullable=False)
    is_honeypot = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    owner = db.relationship('User', back_populates='owned_files')
    permissions = db.relationship('FilePermission', back_populates='file', cascade='all, delete-orphan')
    shared_links = db.relationship('SharedLink', back_populates='file', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<FileRecord id={self.id} name='{self.original_name}' owner={self.owner_id} status='{self.integrity_status}'>"


class SharedLink(db.Model):
    __tablename__ = 'shared_links'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file_records.id'), nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    passcode_hash = db.Column(db.String(256), nullable=True)  # Optional passcode
    max_downloads = db.Column(db.Integer, default=1, nullable=False)
    download_count = db.Column(db.Integer, default=0, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    file = db.relationship('FileRecord', back_populates='shared_links')
    creator = db.relationship('User')

    def set_passcode(self, passcode: str):
        if passcode:
            self.passcode_hash = generate_password_hash(passcode, method='pbkdf2:sha256')
        else:
            self.passcode_hash = None

    def check_passcode(self, passcode: str) -> bool:
        if not self.passcode_hash:
            return True
        return check_password_hash(self.passcode_hash, passcode)

    def is_expired(self) -> bool:
        if self.expires_at:
            now = datetime.now(timezone.utc)
            if self.expires_at.tzinfo is None:
                return datetime.now(timezone.utc).replace(tzinfo=None) > self.expires_at
            return now > self.expires_at
        return False

    def is_exhausted(self) -> bool:
        return self.download_count >= self.max_downloads

    def is_valid(self) -> bool:
        return not self.is_expired() and not self.is_exhausted()


class FilePermission(db.Model):
    __tablename__ = 'file_permissions'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file_records.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    permission = db.Column(db.String(20), nullable=False)  # 'VIEW', 'DOWNLOAD'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('file_id', 'user_id', name='uq_file_user_permission'),
    )

    # Relationships
    file = db.relationship('FileRecord', back_populates='permissions')
    user = db.relationship('User', back_populates='permissions')

    def __repr__(self):
        return f"<FilePermission file_id={self.file_id} user_id={self.user_id} perm='{self.permission}'>"


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    username_snapshot = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    target_type = db.Column(db.String(64), nullable=True)
    target_id = db.Column(db.String(128), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(32), nullable=False)  # 'SUCCESS', 'FAILED', 'WARNING'
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    user = db.relationship('User', back_populates='audit_logs')

    def __repr__(self):
        return f"<AuditLog id={self.id} action='{self.action}' user='{self.username_snapshot}' status='{self.status}'>"
