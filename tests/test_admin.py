from app.models import AuditLog


def test_tc17_regular_user_cannot_access_admin(client, create_user, auth_client):
    """TC17: User thường vào /admin -> expected 403"""
    create_user(username='regular_joe', email='joe@example.com', password='Password@123', role='user')
    auth_client.login('regular_joe', 'Password@123')

    res = client.get('/admin')
    assert res.status_code == 403

    res_users = client.get('/admin/users')
    assert res_users.status_code == 403

    res_logs = client.get('/admin/logs')
    assert res_logs.status_code == 403

    # Audit log check for access denial to admin
    log = AuditLog.query.filter_by(action='ACCESS_DENIED', username_snapshot='regular_joe').first()
    assert log is not None


def test_tc18_admin_can_access_admin_logs(client, create_user, auth_client):
    """TC18: Admin vào /admin/logs -> expected success"""
    create_user(username='admin_boss', email='boss@example.com', password='AdminPassword@123', role='admin')
    auth_client.login('admin_boss', 'AdminPassword@123')

    res_dash = client.get('/admin/')
    assert res_dash.status_code == 200

    res_logs = client.get('/admin/logs')
    assert res_logs.status_code == 200
    assert b"Audit Logs" in res_logs.data or b"Nh\xe1\xba\xadt k\xc3\xbd" in res_logs.data

    res_users = client.get('/admin/users')
    assert res_users.status_code == 200
    assert b"admin_boss" in res_users.data
