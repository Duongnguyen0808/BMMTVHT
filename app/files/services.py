import os
import uuid
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import current_app
from app.extensions import db
from app.models import FileRecord, FilePermission, User
from app.security.crypto import encrypt_bytes, decrypt_bytes, CryptoError
from app.security.hashing import calculate_sha256
from app.security.permissions import user_can_view_file, user_can_download_file, user_can_manage_file
from app.audit.services import log_security_event


class FileValidationError(Exception):
    pass


class IntegrityError(Exception):
    pass


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed and not disallowed."""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    disallowed = current_app.config.get('DISALLOWED_EXTENSIONS', {'exe', 'bat', 'cmd', 'ps1', 'sh'})
    if ext in disallowed:
        return False
    allowed = current_app.config.get('ALLOWED_EXTENSIONS', {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg'})
    return ext in allowed


def validate_file_size(size_bytes: int) -> bool:
    """Validate that file size does not exceed maximum content length."""
    max_size = current_app.config.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024)
    return 0 < size_bytes <= max_size


def generate_storage_name(original_name: str) -> str:
    """Generate a random UUID-based storage filename to prevent collisions and path attacks."""
    ext = original_name.rsplit('.', 1)[1].lower() if '.' in original_name else 'bin'
    return f"{uuid.uuid4().hex}.{ext}.enc"


def get_storage_path(stored_name: str) -> Path:
    """Get absolute path to stored file in configured storage folder."""
    storage_folder = Path(current_app.config.get('STORAGE_FOLDER'))
    storage_folder.mkdir(parents=True, exist_ok=True)
    return storage_folder / stored_name


def save_encrypted_file(stored_name: str, encrypted_bytes: bytes) -> Path:
    """Save encrypted bytes to storage directory."""
    target_path = get_storage_path(stored_name)
    with open(target_path, 'wb') as f:
        f.write(encrypted_bytes)
    return target_path


def load_encrypted_file(stored_name: str) -> bytes:
    """Load encrypted bytes from storage directory."""
    target_path = get_storage_path(stored_name)
    if not target_path.exists():
        raise FileNotFoundError(f"Tệp lưu trữ {stored_name} không tồn tại trên hệ thống đĩa.")
    with open(target_path, 'rb') as f:
        return f.read()


def process_file_upload(file_storage, owner_id: int) -> FileRecord:
    """Process an uploaded file: validate, hash, encrypt, save to disk and database."""
    original_filename = secure_filename(file_storage.filename or '')
    if not original_filename:
        raise FileValidationError("Tên tệp không hợp lệ.")

    if not allowed_file(original_filename):
        raise FileValidationError(f"Định dạng tệp '{original_filename}' không được phép tải lên hệ thống.")

    raw_bytes = file_storage.read()
    file_size = len(raw_bytes)

    if not validate_file_size(file_size):
        raise FileValidationError("Kích thước tệp vượt quá giới hạn cho phép (tối đa 10 MB) hoặc tệp rỗng.")

    # 1. Calculate SHA-256 hash on original plaintext bytes
    sha256_hash = calculate_sha256(raw_bytes)

    # 2. Encrypt bytes using Fernet
    try:
        encrypted_bytes = encrypt_bytes(raw_bytes)
    except Exception as e:
        raise CryptoError(f"Lỗi mã hóa tệp tin: {e}")

    # 3. Store encrypted file with UUID-based name
    stored_name = generate_storage_name(original_filename)
    save_encrypted_file(stored_name, encrypted_bytes)

    # 4. Save record in database
    mime_type = file_storage.content_type or 'application/octet-stream'
    file_record = FileRecord(
        owner_id=owner_id,
        original_name=original_filename,
        stored_name=stored_name,
        mime_type=mime_type,
        file_size=file_size,
        sha256_hash=sha256_hash,
        integrity_status='VALID'
    )
    db.session.add(file_record)
    db.session.commit()

    log_security_event(
        action='UPLOAD_FILE',
        status='SUCCESS',
        message=f"Đã tải lên và mã hóa tệp '{original_filename}' (SHA-256: {sha256_hash[:16]}...)",
        target_type='FILE',
        target_id=file_record.id
    )

    return file_record


def verify_file_integrity(file_record: FileRecord) -> tuple[bool, bytes | None]:
    """
    Verify integrity of file_record by loading, decrypting, and re-calculating SHA-256.
    Returns (is_valid, decrypted_bytes_or_None).
    """
    try:
        encrypted_bytes = load_encrypted_file(file_record.stored_name)
        decrypted_bytes = decrypt_bytes(encrypted_bytes)
        recalculated_hash = calculate_sha256(decrypted_bytes)

        if recalculated_hash.lower() == file_record.sha256_hash.lower():
            if file_record.integrity_status != 'VALID':
                file_record.integrity_status = 'VALID'
                db.session.commit()
            return True, decrypted_bytes
        else:
            # Tampering detected (hash mismatch)
            file_record.integrity_status = 'TAMPERED'
            db.session.commit()
            log_security_event(
                action='FILE_INTEGRITY_FAILED',
                status='FAILED',
                message=f"Phát hiện giả mạo tệp '{file_record.original_name}' (ID: {file_record.id}). Hash kỳ vọng: {file_record.sha256_hash[:16]}..., Hash thực tế: {recalculated_hash[:16]}...",
                target_type='FILE',
                target_id=file_record.id
            )
            return False, None
    except Exception as e:
        # Decryption failure or corrupted token also means tampering / corruption
        file_record.integrity_status = 'TAMPERED'
        db.session.commit()
        log_security_event(
            action='FILE_INTEGRITY_FAILED',
            status='FAILED',
            message=f"Lỗi giải mã/giả mạo tệp '{file_record.original_name}' (ID: {file_record.id}): {e}",
            target_type='FILE',
            target_id=file_record.id
        )
        return False, None
