from functools import wraps
from flask import abort, request
from flask_login import current_user
from app.audit.services import log_security_event


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin():
            log_security_event(
                action='ACCESS_DENIED',
                status='FAILED',
                message=f"Người dùng '{current_user.username}' không có quyền quản trị để truy cập {request.path}",
                user=current_user,
                target_type='SYSTEM',
                target_id=request.path
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
