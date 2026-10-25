from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired


class UploadForm(FlaskForm):
    file = FileField(
        'Chọn tài liệu',
        validators=[FileRequired(message="Vui lòng chọn tệp tin cần tải lên.")]
    )
    submit = SubmitField('Tải lên & Mã hóa')


class ShareForm(FlaskForm):
    username = StringField(
        'Tên người nhận (Username)',
        validators=[DataRequired(message="Vui lòng nhập tên người dùng cần chia sẻ.")]
    )
    permission = SelectField(
        'Quyền hạn',
        choices=[
            ('DOWNLOAD', 'DOWNLOAD (Cho phép tải xuống & xem chi tiết)'),
            ('VIEW', 'VIEW (Chỉ xem thông tin metadata)')
        ],
        default='DOWNLOAD',
        validators=[DataRequired()]
    )
    submit = SubmitField('Chia sẻ tài liệu')
