from flask import render_template, request
from flask_login import login_required
from app.admin import bp
from app.security.decorators import admin_required
from app.models import User, FileRecord, AuditLog


@bp.route('', methods=['GET'])
@bp.route('/', methods=['GET'])
@login_required
@admin_required
def dashboard():
    total_users = User.query.count()
    total_files = FileRecord.query.count()
    failed_logins = AuditLog.query.filter_by(action='LOGIN_FAILED').count()
    access_denied = AuditLog.query.filter_by(action='ACCESS_DENIED').count()
    integrity_failures = AuditLog.query.filter_by(action='FILE_INTEGRITY_FAILED').count()
    locked_accounts = User.query.filter(User.locked_until.isnot(None)).count()

    tampered_files = FileRecord.query.filter_by(integrity_status='TAMPERED').all()
    recent_security_logs = AuditLog.query.filter(
        AuditLog.action.in_(['FILE_INTEGRITY_FAILED', 'ACCESS_DENIED', 'ACCOUNT_LOCKED', 'LOGIN_FAILED'])
    ).order_by(AuditLog.created_at.desc()).limit(10).all()

    stats = {
        'total_users': total_users,
        'total_files': total_files,
        'failed_logins': failed_logins,
        'access_denied': access_denied,
        'integrity_failures': integrity_failures,
        'locked_accounts': locked_accounts
    }

    return render_template(
        'admin/dashboard.html',
        stats=stats,
        tampered_files=tampered_files,
        recent_security_logs=recent_security_logs
    )


@bp.route('/users')
@login_required
@admin_required
def users():
    users_list = User.query.order_by(User.id.asc()).all()
    return render_template('admin/users.html', users=users_list)


@bp.route('/logs')
@login_required
@admin_required
def logs():
    action_filter = request.args.get('action', '').strip()
    status_filter = request.args.get('status', '').strip()
    username_filter = request.args.get('username', '').strip()
    page = request.args.get('page', 1, type=int)

    query = AuditLog.query

    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if status_filter:
        query = query.filter(AuditLog.status == status_filter)
    if username_filter:
        query = query.filter(AuditLog.username_snapshot.ilike(f"%{username_filter}%"))

    query = query.order_by(AuditLog.created_at.desc())

    # Paginate (25 per page)
    pagination = query.paginate(page=page, per_page=25, error_out=False)
    logs_list = pagination.items

    distinct_actions = [row[0] for row in AuditLog.query.with_entities(AuditLog.action).distinct().all()]
    distinct_statuses = [row[0] for row in AuditLog.query.with_entities(AuditLog.status).distinct().all()]

    return render_template(
        'admin/logs.html',
        logs=logs_list,
        pagination=pagination,
        distinct_actions=distinct_actions,
        distinct_statuses=distinct_statuses,
        current_action=action_filter,
        current_status=status_filter,
        current_username=username_filter
    )
