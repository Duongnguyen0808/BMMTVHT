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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    owner = db.relationship('User', back_populates='owned_files')
    permissions = db.relationship('FilePermission', back_populates='file', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<FileRecord id={self.id} name='{self.original_name}' owner={self.owner_id} status='{self.integrity_status}'>"


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
