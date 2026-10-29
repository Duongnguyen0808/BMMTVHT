import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.models import User


def validate_password_strength(form, field):
    password = field.data or ''
    if len(password) < 8:
        raise ValidationError("Mật khẩu phải có ít nhất 8 ký tự.")
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Mật khẩu phải chứa ít nhất 1 chữ hoa (A-Z).")
    if not re.search(r'[a-z]', password):
        raise ValidationError("Mật khẩu phải chứa ít nhất 1 chữ thường (a-z).")
    if not re.search(r'[0-9]', password):
        raise ValidationError("Mật khẩu phải chứa ít nhất 1 chữ số (0-9).")


class RegisterForm(FlaskForm):
    username = StringField(
        'Tên đăng nhập',
        validators=[
            DataRequired(message="Vui lòng nhập tên đăng nhập."),
            Length(min=3, max=30, message="Tên đăng nhập từ 3 đến 30 ký tự.")
        ]
    )
    email = StringField(
        'Địa chỉ Email',
        validators=[
            DataRequired(message="Vui lòng nhập địa chỉ email."),
            Email(message="Địa chỉ email không hợp lệ.")
        ]
    )
    password = PasswordField(
        'Mật khẩu',
        validators=[
            DataRequired(message="Vui lòng nhập mật khẩu."),
            validate_password_strength
        ]
    )
    confirm_password = PasswordField(
        'Xác nhận mật khẩu',
        validators=[
            DataRequired(message="Vui lòng nhập lại mật khẩu."),
            EqualTo('password', message="Mật khẩu xác nhận không trùng khớp.")
        ]
    )
    submit = SubmitField('Đăng ký tài khoản')

    def validate_username(self, field):
        if not re.match(r'^[a-zA-Z0-9_.-]+$', field.data):
            raise ValidationError("Tên đăng nhập chỉ chứa chữ cái, số, dấu gạch dưới, gạch ngang và chấm.")
        user = User.query.filter(User.username.ilike(field.data)).first()
        if user:
            raise ValidationError("Tên đăng nhập này đã được sử dụng.")

    def validate_email(self, field):
        user = User.query.filter(User.email.ilike(field.data)).first()
        if user:
            raise ValidationError("Địa chỉ email này đã được sử dụng.")


class LoginForm(FlaskForm):
    username_or_email = StringField(
        'Tên đăng nhập hoặc Email',
        validators=[DataRequired(message="Vui lòng nhập tên đăng nhập hoặc email.")]
    )
    password = PasswordField(
        'Mật khẩu',
        validators=[DataRequired(message="Vui lòng nhập mật khẩu.")]
    )
    remember_me = BooleanField('Ghi nhớ đăng nhập')
    submit = SubmitField('Đăng nhập')


class Verify2FAForm(FlaskForm):
    otp_code = StringField(
        'Mã bảo mật 6 số',
        validators=[
            DataRequired(message="Vui lòng nhập mã bảo mật 6 số."),
            Length(min=6, max=6, message="Mã bảo mật gồm đúng 6 chữ số.")
        ]
    )
    submit = SubmitField('Xác nhận & Đăng nhập')

