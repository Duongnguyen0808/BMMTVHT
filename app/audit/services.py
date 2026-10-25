from datetime import datetime, timezone
from flask import request, has_request_context
from flask_login import current_user
from app.extensions import db
from app.models import AuditLog, User


def log_security_event(
    action: str,
    status: str,
    message: str,
    user: User = None,
    username_snapshot: str = None,
    target_type: str = None,
    target_id: str = None,
    ip_address: str = None,
    user_agent: str = None
) -> AuditLog:
    """Record a security audit log event into the database."""
    try:
        user_id = None
        if user and hasattr(user, 'id'):
            user_id = user.id
            if not username_snapshot and hasattr(user, 'username'):
                username_snapshot = user.username
        elif has_request_context() and current_user and current_user.is_authenticated:
            user_id = current_user.id
            if not username_snapshot:
                username_snapshot = current_user.username

        if has_request_context():
            if not ip_address:
                # X-Forwarded-For check if reverse proxy, else remote_addr
                if request.headers.get('X-Forwarded-For'):
                    ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
                else:
                    ip_address = request.remote_addr or '127.0.0.1'
            if not user_agent:
                user_agent = request.user_agent.string[:250] if request.user_agent else 'Unknown'

        audit_entry = AuditLog(
            user_id=user_id,
            username_snapshot=username_snapshot or 'anonymous',
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            ip_address=ip_address or '127.0.0.1',
            user_agent=user_agent or 'Unknown',
            status=status,
            message=message,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(audit_entry)
        db.session.commit()
        return audit_entry
    except Exception as e:
        db.session.rollback()
        # Fallback print in server console for reliability
        print(f"[AUDIT LOG ERROR] Failed to record audit log: {e}")
        return None
