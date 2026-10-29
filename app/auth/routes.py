from datetime import datetime, timezone, timedelta
from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
from app.auth import bp
from app.auth.forms import RegisterForm, LoginForm, Verify2FAForm
from app.models import User
from app.extensions import db, limiter
from app.audit.services import log_security_event


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role='user'
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        log_security_event(
            action='REGISTER',
            status='SUCCESS',
            message=f"Người dùng mới '{user.username}' ({user.email}) đã đăng ký tài khoản thành công.",
            user=user,
            target_type='USER',
            target_id=user.id
        )

        flash('Đăng ký tài khoản thành công! Bạn có thể đăng nhập ngay.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        ident = form.username_or_email.data.strip()
        user = User.query.filter(
            (User.username == ident) | (User.email == ident.lower())
        ).first()

        max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
        lockout_minutes = current_app.config.get('LOCKOUT_DURATION_MINUTES', 5)

        if not user:
            log_security_event(
                action='LOGIN_FAILED',
                status='FAILED',
                message=f"Đăng nhập thất bại: Tài khoản không tồn tại '{ident}'",
                username_snapshot=ident,
                target_type='AUTH'
            )
            flash('Tên đăng nhập hoặc mật khẩu không chính xác.', 'danger')
            return render_template('auth/login.html', form=form)

        # Check account lock
        if user.is_locked():
            log_security_event(
                action='ACCOUNT_LOCKED',
                status='WARNING',
                message=f"Từ chối đăng nhập: Tài khoản '{user.username}' đang bị khóa tạm thời.",
                user=user,
                target_type='AUTH',
                target_id=user.id
            )
            flash('Tài khoản của bạn đã bị khóa tạm thời 5 phút do nhập sai quá 5 lần. Vui lòng thử lại sau.', 'danger')
            return render_template('auth/login.html', form=form)

        # Check password
        if not user.check_password(form.password.data):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= max_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
                db.session.commit()

                log_security_event(
                    action='ACCOUNT_LOCKED',
                    status='WARNING',
                    message=f"Tài khoản '{user.username}' đã bị khóa {lockout_minutes} phút do nhập sai {user.failed_login_attempts} lần liên tiếp.",
                    user=user,
                    target_type='AUTH',
                    target_id=user.id
                )
                flash(f'Tài khoản đã bị khóa tạm thời {lockout_minutes} phút do nhập sai {max_attempts} lần liên tiếp.', 'danger')
            else:
                db.session.commit()
                remaining = max_attempts - user.failed_login_attempts
                log_security_event(
                    action='LOGIN_FAILED',
                    status='FAILED',
                    message=f"Đăng nhập thất bại cho '{user.username}' (Lần sai {user.failed_login_attempts}/{max_attempts}).",
                    user=user,
                    target_type='AUTH',
                    target_id=user.id
                )
                flash(f'Tên đăng nhập hoặc mật khẩu không chính xác. Bạn còn {remaining} lần thử trước khi tài khoản bị khóa.', 'danger')
            return render_template('auth/login.html', form=form)

        # Check if user has 2FA enabled
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            session['2fa_remember'] = form.remember_me.data
            session['2fa_next'] = request.args.get('next')
            flash("Mật khẩu chính xác. Vui lòng nhập mã bảo mật 6 số từ Google Authenticator trên điện thoại.", "info")
            return redirect(url_for('auth.login_2fa'))

        # Login success (No 2FA)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)
        db.session.commit()

        login_user(user, remember=form.remember_me.data)
        session.permanent = True

        log_security_event(
            action='LOGIN_SUCCESS',
            status='SUCCESS',
            message=f"Người dùng '{user.username}' đã đăng nhập thành công vào hệ thống.",
            user=user,
            target_type='AUTH',
            target_id=user.id
        )

        flash(f'Chào mừng trở lại, {user.username}!', 'success')
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('files.dashboard')
        return redirect(next_page)

    return render_template('auth/login.html', form=form)


@bp.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if current_user.is_authenticated:
        return redirect(url_for('files.dashboard'))

    user_id = session.get('2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id)
    if not user:
        session.pop('2fa_user_id', None)
        return redirect(url_for('auth.login'))

    form = Verify2FAForm()
    if form.validate_on_submit():
        otp_code = form.otp_code.data.strip()
        if user.verify_totp(otp_code):
            # 2FA Success!
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login_at = datetime.now(timezone.utc)
            db.session.commit()

            remember = session.pop('2fa_remember', False)
            next_page = session.pop('2fa_next', None)
            session.pop('2fa_user_id', None)

            login_user(user, remember=remember)
            session.permanent = True

            log_security_event(
                action='LOGIN_2FA_SUCCESS',
                status='SUCCESS',
                message=f"Xác thực 2 bước (2FA/TOTP) thành công cho '{user.username}'.",
                user=user,
                target_type='AUTH',
                target_id=user.id
            )

            flash(f'Chào mừng trở lại, {user.username}! Xác thực 2 bước thành công.', 'success')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('files.dashboard')
            return redirect(next_page)
        else:
            log_security_event(
                action='LOGIN_2FA_FAILED',
                status='FAILED',
                message=f"Xác thực 2 bước (2FA/TOTP) thất bại: Mã 6 số không đúng cho '{user.username}'.",
                user=user,
                target_type='AUTH',
                target_id=user.id
            )
            flash("Mã 2FA (từ 2fa.live hoặc Google Authenticator) không chính xác hoặc đã hết hạn 30s. Vui lòng lấy mã mới và thử lại.", "danger")

    return render_template('auth/login_2fa.html', form=form, user=user)


@bp.route('/security/2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    import qrcode
    import io
    import base64

    user = current_user
    secret = user.generate_totp_secret()
    db.session.commit()

    # Generate QR Code as base64 image
    totp_uri = user.get_totp_uri()
    qr = qrcode.QRCode(
        version=1,
        box_size=6,
        border=2,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    form = Verify2FAForm()
    if form.validate_on_submit():
        otp_code = form.otp_code.data.strip()
        if user.verify_totp(otp_code):
            user.is_2fa_enabled = True
            db.session.commit()

            log_security_event(
                action='2FA_ENABLED',
                status='SUCCESS',
                message=f"Người dùng '{user.username}' đã kích hoạt thành công Xác thực 2 bước (2FA/TOTP).",
                user=user,
                target_type='AUTH',
                target_id=user.id
            )
            flash("Kích hoạt Xác thực 2 bước (2FA) thành công! Từ bây giờ tài khoản của bạn được bảo vệ bởi Google Authenticator.", "success")
            return redirect(url_for('auth.setup_2fa'))
        else:
            flash("Mã 2FA (từ 2fa.live hoặc Google Authenticator) không chính xác hoặc đã đổi mới sau 30s. Vui lòng lấy mã mới nhất và thử lại.", "danger")

    return render_template('auth/setup_2fa.html', form=form, qr_base64=qr_base64, secret=secret)


@bp.route('/security/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    user = current_user
    user.is_2fa_enabled = False
    user.totp_secret = None
    db.session.commit()

    log_security_event(
        action='2FA_DISABLED',
        status='WARNING',
        message=f"Người dùng '{user.username}' đã hủy kích hoạt Xác thực 2 bước (2FA).",
        user=user,
        target_type='AUTH',
        target_id=user.id
    )
    flash("Đã hủy kích hoạt Xác thực 2 bước (2FA). Tài khoản hiện chỉ bảo vệ bằng mật khẩu đơn.", "warning")
    return redirect(url_for('auth.setup_2fa'))


@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        username = current_user.username
        user_id = current_user.id
        user_obj = current_user._get_current_object()

        logout_user()

        log_security_event(
            action='LOGOUT',
            status='SUCCESS',
            message=f"Người dùng '{username}' đã đăng xuất.",
            user=user_obj,
            username_snapshot=username,
            target_type='AUTH',
            target_id=user_id
        )

    flash('Bạn đã đăng xuất an toàn khỏi hệ thống.', 'info')
    response = redirect(url_for('auth.login'))
    remember_cookie = current_app.config.get("REMEMBER_COOKIE_NAME", "remember_token")
    session_cookie = current_app.config.get("SESSION_COOKIE_NAME", "session")
    response.delete_cookie(remember_cookie)
    response.delete_cookie(session_cookie)
    return response
