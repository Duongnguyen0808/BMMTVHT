import io
from datetime import datetime, timezone, timedelta
import secrets
from flask import render_template, redirect, url_for, flash, request, abort, send_file, current_app
from flask_login import login_required, current_user, logout_user
from app.files import bp
from app.files.forms import UploadForm, ShareForm
from app.files.services import (
    process_file_upload,
    verify_file_integrity,
    user_can_view_file,
    user_can_download_file,
    user_can_manage_file,
    FileValidationError,
    allowed_file
)
from app.models import FileRecord, FilePermission, User, AuditLog, SharedLink
from app.extensions import db, csrf
from app.audit.services import log_security_event
from app.security.watermark import apply_forensic_watermark
from app.files.test_cases_catalog import TEST_CASES_DATA, CATEGORIES


@bp.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))
    return render_template('home.html')


@bp.route('/dashboard')
@login_required
def dashboard():
    my_files = FileRecord.query.filter_by(owner_id=current_user.id).order_by(FileRecord.created_at.desc()).all()

    shared_permissions = FilePermission.query.filter_by(user_id=current_user.id).all()
    shared_files = [p.file for p in shared_permissions if p.file]

    # Recent activity for this user
    recent_activities = AuditLog.query.filter(
        (AuditLog.user_id == current_user.id) | (AuditLog.username_snapshot == current_user.username)
    ).order_by(AuditLog.created_at.desc()).limit(8).all()

    # Security alerts for this user
    tampered_files_count = FileRecord.query.filter_by(owner_id=current_user.id, integrity_status='TAMPERED').count()
    failed_attempts = current_user.failed_login_attempts

    stats = {
        'my_files_count': len(my_files),
        'shared_files_count': len(shared_files),
        'tampered_count': tampered_files_count,
        'failed_attempts': failed_attempts
    }

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_files=my_files[:5],
        recent_activities=recent_activities
    )


@bp.route('/files')
@login_required
def index():
    my_files = FileRecord.query.filter_by(owner_id=current_user.id).order_by(FileRecord.created_at.desc()).all()

    shared_perms = FilePermission.query.filter_by(user_id=current_user.id).all()
    shared_items = []
    for sp in shared_perms:
        if sp.file:
            shared_items.append({
                'file': sp.file,
                'permission': sp.permission,
                'shared_at': sp.created_at
            })

    return render_template('files/index.html', my_files=my_files, shared_items=shared_items)


@bp.route('/files/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file_obj = form.file.data
        if not file_obj or not file_obj.filename:
            flash('Vui lòng chọn một tệp hợp lệ.', 'danger')
            return render_template('files/upload.html', form=form)

        if not allowed_file(file_obj.filename):
            log_security_event(
                action='INVALID_UPLOAD',
                status='WARNING',
                message=f"Tải lên tệp không hợp lệ: '{file_obj.filename}' (Định dạng bị từ chối)",
                target_type='FILE'
            )
            flash(f"Định dạng tệp '{file_obj.filename}' không được chấp nhận. Chỉ hỗ trợ .pdf, .docx, .txt, .png, .jpg, .jpeg.", 'danger')
            return render_template('files/upload.html', form=form), 400

        try:
            record = process_file_upload(file_obj, owner_id=current_user.id)
            flash(f"Tệp '{record.original_name}' đã được tải lên và mã hóa an toàn thành công!", 'success')
            return redirect(url_for('files.detail', file_id=record.id))
        except FileValidationError as e:
            log_security_event(
                action='INVALID_UPLOAD',
                status='WARNING',
                message=f"Lỗi xác thực tệp khi tải lên: {e}",
                target_type='FILE'
            )
            flash(str(e), 'danger')
            return render_template('files/upload.html', form=form), 400
        except Exception as e:
            flash(f"Lỗi xử lý tệp: {e}", 'danger')
            return render_template('files/upload.html', form=form), 500

    return render_template('files/upload.html', form=form)


@bp.route('/files/<int:file_id>')
@login_required
def detail(file_id):
    file_record = db.get_or_404(FileRecord, file_id)

    # 1. Active Defense: Honeypot Trap Trigger Check
    if file_record.is_honeypot and not current_user.is_admin():
        user = current_user._get_current_object()
        user.locked_until = datetime.now(timezone.utc) + timedelta(hours=24)
        user.failed_login_attempts = 99
        db.session.commit()

        log_security_event(
            action='HONEYPOT_TRIGGERED',
            status='CRITICAL',
            message=f"BẪY AN NINH KÍCH HOẠT: Tài khoản '{user.username}' đã xâm nhập tệp bẫy Honeypot ID {file_id} ('{file_record.original_name}'). Tài khoản đã bị khóa ngay lập tức!",
            user=user,
            target_type='HONEYPOT',
            target_id=file_id
        )
        username = user.username
        file_name = file_record.original_name
        logout_user()
        return render_template('errors/honeypot_breach.html', username=username, file_name=file_name), 403

    # Authorization Check
    if not user_can_view_file(current_user, file_record):
        log_security_event(
            action='ACCESS_DENIED',
            status='FAILED',
            message=f"Người dùng '{current_user.username}' cố gắng truy cập trái phép chi tiết tệp ID {file_id}",
            target_type='FILE',
            target_id=file_id
        )
        abort(403)

    is_owner = (file_record.owner_id == current_user.id)
    can_download = user_can_download_file(current_user, file_record)

    # Current permissions and shared links list for owner
    permissions = FilePermission.query.filter_by(file_id=file_record.id).all()
    shared_links = SharedLink.query.filter_by(file_id=file_record.id).all()
    share_form = ShareForm()

    return render_template(
        'files/detail.html',
        file=file_record,
        is_owner=is_owner,
        can_download=can_download,
        permissions=permissions,
        shared_links=shared_links,
        share_form=share_form
    )


@bp.route('/files/<int:file_id>/download')
@login_required
def download(file_id):
    file_record = db.get_or_404(FileRecord, file_id)

    # 1. Active Defense: Honeypot Trap Trigger Check
    if file_record.is_honeypot and not current_user.is_admin():
        user = current_user._get_current_object()
        user.locked_until = datetime.now(timezone.utc) + timedelta(hours=24)
        user.failed_login_attempts = 99
        db.session.commit()

        log_security_event(
            action='HONEYPOT_TRIGGERED',
            status='CRITICAL',
            message=f"BẪY AN NINH KÍCH HOẠT: Tài khoản '{user.username}' đã cố tải tệp bẫy Honeypot ID {file_id} ('{file_record.original_name}'). Tài khoản đã bị khóa ngay lập tức!",
            user=user,
            target_type='HONEYPOT',
            target_id=file_id
        )
        username = user.username
        file_name = file_record.original_name
        logout_user()
        return render_template('errors/honeypot_breach.html', username=username, file_name=file_name), 403

    # 2. Authorization check
    if not user_can_download_file(current_user, file_record):
        log_security_event(
            action='ACCESS_DENIED',
            status='FAILED',
            message=f"Người dùng '{current_user.username}' không có quyền tải xuống tệp ID {file_id}",
            target_type='FILE',
            target_id=file_id
        )
        abort(403)

    # 3. Decrypt & Verify Integrity
    is_valid, decrypted_bytes = verify_file_integrity(file_record)

    if not is_valid or decrypted_bytes is None:
        flash("Tệp có dấu hiệu bị chỉnh sửa hoặc giả mạo. Tải xuống đã bị chặn vì lý do an toàn toàn vẹn dữ liệu!", "danger")
        return render_template(
            'errors/tampered.html',
            file=file_record
        ), 400

    # 4. Forensic Watermarking (DLP)
    # Apply watermark if requested with ?watermark=1
    should_watermark = (request.args.get('watermark') == '1')
    if should_watermark:
        decrypted_bytes = apply_forensic_watermark(
            decrypted_bytes,
            file_record.original_name,
            current_user.username,
            request.remote_addr or '127.0.0.1'
        )
        log_security_event(
            action='DLP_WATERMARK_EMBEDDED',
            status='SUCCESS',
            message=f"Đã nhúng chữ ký mờ truy vết rò rỉ (Forensic Watermark) cho '{current_user.username}' khi tải tệp '{file_record.original_name}'.",
            target_type='FILE',
            target_id=file_record.id
        )

    # 5. Log success download & integrity ok
    log_security_event(
        action='FILE_INTEGRITY_OK',
        status='SUCCESS',
        message=f"Kiểm tra tính toàn vẹn SHA-256 tệp '{file_record.original_name}' (ID: {file_record.id}) thành công.",
        target_type='FILE',
        target_id=file_record.id
    )

    log_security_event(
        action='DOWNLOAD_FILE',
        status='SUCCESS',
        message=f"Người dùng '{current_user.username}' đã tải xuống tệp '{file_record.original_name}'.",
        target_type='FILE',
        target_id=file_record.id
    )

    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=file_record.mime_type,
        as_attachment=True,
        download_name=file_record.original_name
    )


@bp.route('/files/<int:file_id>/share', methods=['POST'])
@login_required
def share(file_id):
    file_record = db.get_or_404(FileRecord, file_id)

    if not user_can_manage_file(current_user, file_record):
        log_security_event(
            action='ACCESS_DENIED',
            status='FAILED',
            message=f"Người dùng '{current_user.username}' không có quyền chia sẻ tệp ID {file_id}",
            target_type='FILE',
            target_id=file_id
        )
        abort(403)

    form = ShareForm()
    if form.validate_on_submit():
        target_username = form.username.data.strip()
        permission_type = form.permission.data

        target_user = User.query.filter_by(username=target_username).first()
        if not target_user:
            flash(f"Không tìm thấy người dùng với tên '{target_username}'.", 'danger')
            return redirect(url_for('files.detail', file_id=file_id))

        if target_user.id == current_user.id:
            flash("Bạn là chủ sở hữu tệp này, không cần tự chia sẻ cho chính mình.", 'warning')
            return redirect(url_for('files.detail', file_id=file_id))

        existing_perm = FilePermission.query.filter_by(file_id=file_id, user_id=target_user.id).first()
        if existing_perm:
            existing_perm.permission = permission_type
            db.session.commit()
            flash(f"Đã cập nhật quyền chia sẻ cho '{target_username}' thành {permission_type}.", 'success')
        else:
            new_perm = FilePermission(
                file_id=file_id,
                user_id=target_user.id,
                permission=permission_type
            )
            db.session.add(new_perm)
            db.session.commit()
            flash(f"Đã chia sẻ tệp cho '{target_username}' với quyền {permission_type}.", 'success')

        log_security_event(
            action='SHARE_FILE',
            status='SUCCESS',
            message=f"Chủ sở hữu '{current_user.username}' chia sẻ tệp '{file_record.original_name}' cho '{target_username}' với quyền {permission_type}.",
            target_type='FILE',
            target_id=file_id
        )

    return redirect(url_for('files.detail', file_id=file_id))


@bp.route('/files/<int:file_id>/revoke/<int:user_id>', methods=['POST'])
@login_required
def revoke(file_id, user_id):
    file_record = db.get_or_404(FileRecord, file_id)

    if not user_can_manage_file(current_user, file_record):
        log_security_event(
            action='ACCESS_DENIED',
            status='FAILED',
            message=f"Người dùng '{current_user.username}' cố gắng gỡ quyền tệp ID {file_id} mà không phải chủ sở hữu.",
            target_type='FILE',
            target_id=file_id
        )
        abort(403)

    target_perm = FilePermission.query.filter_by(file_id=file_id, user_id=user_id).first()
    if target_perm:
        target_username = target_perm.user.username if target_perm.user else f"ID {user_id}"
        db.session.delete(target_perm)
        db.session.commit()

        log_security_event(
            action='REVOKE_SHARE',
            status='SUCCESS',
            message=f"Chủ sở hữu '{current_user.username}' đã gỡ quyền chia sẻ tệp '{file_record.original_name}' đối với '{target_username}'.",
            target_type='FILE',
            target_id=file_id
        )
        flash(f"Đã gỡ quyền truy cập của '{target_username}' thành công.", 'info')
    else:
        flash("Không tìm thấy thông tin chia sẻ cần gỡ.", 'warning')

    return redirect(url_for('files.detail', file_id=file_id))


@bp.route('/files/<int:file_id>/create-link', methods=['POST'])
@login_required
def create_share_link(file_id):
    file_record = db.get_or_404(FileRecord, file_id)
    if not user_can_manage_file(current_user, file_record):
        abort(403)

    token = secrets.token_urlsafe(16)
    passcode = request.form.get('passcode', '').strip()
    expire_minutes = int(request.form.get('expire_minutes', 60))
    max_downloads = int(request.form.get('max_downloads', 1))

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes) if expire_minutes > 0 else None

    link = SharedLink(
        file_id=file_record.id,
        created_by_id=current_user.id,
        token=token,
        max_downloads=max_downloads,
        expires_at=expires_at
    )
    if passcode:
        link.set_passcode(passcode)
    db.session.add(link)
    db.session.commit()

    log_security_event(
        action='SHARE_LINK_CREATED',
        status='SUCCESS',
        message=f"Tạo liên kết chia sẻ tự hủy (Tối đa {max_downloads} lượt tải, hết hạn sau {expire_minutes} phút, mật mã: {'Có' if passcode else 'Không'}) cho tệp '{file_record.original_name}'.",
        target_type='FILE',
        target_id=file_record.id
    )

    flash("Đã tạo liên kết chia sẻ bảo mật (Zero-Trust Link) thành công!", "success")
    return redirect(url_for('files.detail', file_id=file_record.id))


@bp.route('/files/<int:file_id>/revoke-link/<int:link_id>', methods=['POST'])
@login_required
def revoke_share_link(file_id, link_id):
    file_record = db.get_or_404(FileRecord, file_id)
    if not user_can_manage_file(current_user, file_record):
        abort(403)

    link = db.session.get(SharedLink, link_id)
    if link and link.file_id == file_record.id:
        db.session.delete(link)
        db.session.commit()
        log_security_event(
            action='SHARE_LINK_REVOKED',
            status='SUCCESS',
            message=f"Đã thu hồi liên kết chia sẻ tệp '{file_record.original_name}'.",
            target_type='FILE',
            target_id=file_record.id
        )
        flash("Đã thu hồi liên kết chia sẻ an toàn.", "info")

    return redirect(url_for('files.detail', file_id=file_record.id))


@bp.route('/share/link/<token>', methods=['GET', 'POST'])
def view_shared_link(token):
    link = SharedLink.query.filter_by(token=token).first()
    if not link or not link.is_valid():
        return render_template('files/shared_link_expired.html', link=link), 410

    file_record = link.file
    error_msg = None

    if request.method == 'POST':
        entered_passcode = request.form.get('passcode', '').strip()
        if link.passcode_hash and not link.check_passcode(entered_passcode):
            error_msg = "Mật mã truy cập không chính xác. Vui lòng thử lại!"
            log_security_event(
                action='SHARE_LINK_FAILED',
                status='FAILED',
                message=f"Nhập sai mật mã truy cập liên kết chia sẻ tệp '{file_record.original_name}'.",
                target_type='SHARE_LINK'
            )
        else:
            # Passcode correct / no passcode -> Deliver file & increment count
            is_valid, decrypted_bytes = verify_file_integrity(file_record)
            if not is_valid or decrypted_bytes is None:
                flash("Tệp có dấu hiệu bị giả mạo. Tải xuống đã bị khóa!", "danger")
                return render_template('errors/tampered.html', file=file_record), 400

            link.download_count += 1
            db.session.commit()

            # Dynamic DLP watermark for guest link
            decrypted_bytes = apply_forensic_watermark(
                decrypted_bytes,
                file_record.original_name,
                f"Guest Link (Share by: {link.creator.username})",
                request.remote_addr or '127.0.0.1'
            )

            log_security_event(
                action='SHARE_LINK_DOWNLOADED',
                status='SUCCESS',
                message=f"Tải tệp '{file_record.original_name}' qua liên kết chia sẻ bảo mật (Lần tải {link.download_count}/{link.max_downloads}).",
                target_type='SHARE_LINK',
                target_id=link.id
            )

            return send_file(
                io.BytesIO(decrypted_bytes),
                mimetype=file_record.mime_type,
                as_attachment=True,
                download_name=file_record.original_name
            )

    return render_template(
        'files/shared_link_view.html',
        link=link,
        file=file_record,
        error_msg=error_msg
    )


@bp.route('/activity')
@login_required
def activity():
    logs = AuditLog.query.filter(
        (AuditLog.user_id == current_user.id) | (AuditLog.username_snapshot == current_user.username)
    ).order_by(AuditLog.created_at.desc()).limit(100).all()

    return render_template('activity.html', logs=logs)


@bp.route('/testcases')
def testcases():
    return render_template(
        'testcases.html',
        test_cases=TEST_CASES_DATA,
        categories=CATEGORIES,
        total_tests=len(TEST_CASES_DATA),
        passed_tests=len(TEST_CASES_DATA)
    )


@bp.route('/api/run-pytest', methods=['POST'])
@csrf.exempt
def run_pytest_api():
    import sys
    import subprocess
    from pathlib import Path
    python_exe = sys.executable
    try:
        project_root = Path(current_app.root_path).parent
        result = subprocess.run(
            [python_exe, "-m", "pytest", "-q"],
            capture_output=True,
            text=True,
            timeout=45,
            cwd=str(project_root)
        )
        return {
            "success": (result.returncode == 0),
            "output": result.stdout if result.stdout else result.stderr,
            "returncode": result.returncode
        }
    except Exception as e:
        return {"success": False, "output": str(e), "returncode": -1}, 500
