from app.models import User, FileRecord, FilePermission


def user_can_manage_file(user: User, file_record: FileRecord) -> bool:
    """Only the file owner can manage (share, revoke, delete) the file."""
    if not user or not user.is_authenticated or not file_record:
        return False
    return file_record.owner_id == user.id


def user_can_view_file(user: User, file_record: FileRecord) -> bool:
    """User can view file metadata/details if they are owner or have VIEW or DOWNLOAD permission."""
    if not user or not user.is_authenticated or not file_record:
        return False
    if file_record.owner_id == user.id:
        return True

    perm = FilePermission.query.filter_by(file_id=file_record.id, user_id=user.id).first()
    if perm and perm.permission in ('VIEW', 'DOWNLOAD'):
        return True

    return False


def user_can_download_file(user: User, file_record: FileRecord) -> bool:
    """User can download file if they are owner or have DOWNLOAD permission."""
    if not user or not user.is_authenticated or not file_record:
        return False
    if file_record.owner_id == user.id:
        return True

    perm = FilePermission.query.filter_by(file_id=file_record.id, user_id=user.id).first()
    if perm and perm.permission == 'DOWNLOAD':
        return True

    return False
