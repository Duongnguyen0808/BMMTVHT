import os
from flask import current_app
from cryptography.fernet import Fernet, InvalidToken


class CryptoError(Exception):
    pass


def get_fernet_key(override_key: str | bytes = None) -> bytes:
    """Retrieve Fernet encryption key from arguments, Flask config, or environment."""
    if override_key:
        key = override_key
    elif current_app:
        key = current_app.config.get('FERNET_KEY') or os.environ.get('FERNET_KEY')
    else:
        key = os.environ.get('FERNET_KEY')

    if not key or key == 'generate-me' or key == 'generate-me-using-scripts/generate_key.py':
        raise CryptoError("Khóa mã hóa FERNET_KEY chưa được cấu hình. Vui lòng chạy scripts/generate_key.py.")

    if isinstance(key, str):
        key = key.strip().encode('utf-8')

    return key


def get_fernet_cipher(key: str | bytes = None) -> Fernet:
    """Get Fernet instance or raise CryptoError."""
    fernet_key = get_fernet_key(key)
    try:
        return Fernet(fernet_key)
    except Exception as e:
        raise CryptoError(f"Khóa Fernet không hợp lệ: {e}")


def encrypt_bytes(data: bytes, key: str | bytes = None) -> bytes:
    """Encrypt raw bytes using Fernet symmetric encryption."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Dữ liệu cần mã hóa phải là bytes.")
    cipher = get_fernet_cipher(key)
    return cipher.encrypt(bytes(data))


def decrypt_bytes(data: bytes, key: str | bytes = None) -> bytes:
    """Decrypt Fernet encrypted bytes. Raises CryptoError on failure/tampering."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Dữ liệu cần giải mã phải là bytes.")
    cipher = get_fernet_cipher(key)
    try:
        return cipher.decrypt(bytes(data))
    except InvalidToken:
        raise CryptoError("Giải mã thất bại: Dữ liệu bị giả mạo hoặc khóa không đúng (InvalidToken).")
    except Exception as e:
        raise CryptoError(f"Lỗi giải mã: {e}")
