import io
from app.models import FileRecord, FilePermission, AuditLog
from app.files.services import process_file_upload
from werkzeug.datastructures import FileStorage


def test_tc11_owner_view_file(client, create_user, auth_client, app):
    """TC11: Owner xem file -> expected success"""
    owner = create_user(username='owner1', email='owner1@example.com', password='Password@123')

    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(b"Owner file content"), filename="owner_file.txt", content_type="text/plain")
        record = process_file_upload(fs, owner_id=owner.id)
        record_id = record.id

    auth_client.login('owner1', 'Password@123')
    res = client.get(f'/files/{record_id}')
    assert res.status_code == 200
    assert b"owner_file.txt" in res.data


def test_tc12_shared_download_permission(client, create_user, auth_client, app, db):
    """TC12: Shared DOWNLOAD user download -> expected success"""
    owner = create_user(username='owner2', email='owner2@example.com', password='Password@123')
    recipient = create_user(username='recipient2', email='recipient2@example.com', password='Password@123')

    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(b"Shared text data 12345"), filename="shared_doc.txt", content_type="text/plain")
        record = process_file_upload(fs, owner_id=owner.id)
        record_id = record.id

        # Grant DOWNLOAD permission
        perm = FilePermission(file_id=record_id, user_id=recipient.id, permission='DOWNLOAD')
        db.session.add(perm)
        db.session.commit()

    # Recipient logs in and downloads
    auth_client.login('recipient2', 'Password@123')
    res = client.get(f'/files/{record_id}/download')
    assert res.status_code == 200
    assert res.data == b"Shared text data 12345"


def test_tc13_unauthorized_user_blocked(client, create_user, auth_client, app):
    """TC13: User không có quyền -> expected 403"""
    owner = create_user(username='owner3', email='owner3@example.com', password='Password@123')
    stranger = create_user(username='stranger3', email='stranger3@example.com', password='Password@123')

    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(b"Secret owner content"), filename="private_doc.txt", content_type="text/plain")
        record = process_file_upload(fs, owner_id=owner.id)
        record_id = record.id

    auth_client.login('stranger3', 'Password@123')
    # Try viewing
    res_view = client.get(f'/files/{record_id}')
    assert res_view.status_code == 403

    # Try downloading
    res_dl = client.get(f'/files/{record_id}/download')
    assert res_dl.status_code == 403


def test_tc14_idor_url_manipulation(client, create_user, auth_client, app):
    """TC14: IDOR - User thay file_id URL sang file người khác -> expected 403 + audit ACCESS_DENIED"""
    alice = create_user(username='alice', email='alice@example.com', password='Password@123')
    bob = create_user(username='bob', email='bob@example.com', password='Password@123')

    with app.app_context():
        fs = FileStorage(stream=io.BytesIO(b"Alice confidential medical report"), filename="alice_medical.pdf", content_type="application/pdf")
        alice_record = process_file_upload(fs, owner_id=alice.id)
        alice_file_id = alice_record.id

    # Bob logs in and tampers URL parameter with Alice's file_id
    auth_client.login('bob', 'Password@123')
    res = client.get(f'/files/{alice_file_id}')
    assert res.status_code == 403

    # Verify audit log recorded ACCESS_DENIED
    log = AuditLog.query.filter_by(action='ACCESS_DENIED', username_snapshot='bob', target_id=str(alice_file_id)).first()
    assert log is not None
    assert log.status == 'FAILED'
