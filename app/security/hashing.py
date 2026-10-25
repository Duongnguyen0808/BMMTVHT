import hashlib


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hex digest of given bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Dữ liệu băm phải là bytes.")
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest().lower()
