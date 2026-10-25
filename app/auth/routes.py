from datetime import datetime, timezone, timedelta
from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
from app.auth import bp
from app.auth.forms import RegisterForm, LoginForm
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

        # Login success
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
