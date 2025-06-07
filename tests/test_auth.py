def test_login_success(client, test_user):
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    }, follow_redirects=True)
    assert response.status_code == 200
    response = client.get('/')  # Check if we can access the protected route
    assert response.status_code == 200
    assert b'Add URL' in response.data

def test_login_failure(client, app_context):
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'wrongpass'
    }, follow_redirects=True)
    assert b'Invalid username or password' in response.data

def test_logout(auth_client):
    response = auth_client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data

def test_protected_route_redirect(client):
    response = client.get('/', follow_redirects=True)
    assert b'Login' in response.data

def test_settings_update_username(auth_client):
    response = auth_client.post('/settings/username', data={
        'new_username': 'newuser',
        'current_password': 'testpass'
    }, follow_redirects=True)
    assert b'Username updated successfully' in response.data

def test_settings_update_password(auth_client):
    response = auth_client.post('/settings/password', data={
        'current_password': 'testpass',
        'new_password': 'newpass',
        'confirm_password': 'newpass'
    }, follow_redirects=True)
    assert b'Password updated successfully' in response.data

def test_settings_generate_token(auth_client):
    response = auth_client.post('/settings/token', follow_redirects=True)
    assert b'Token generated successfully' in response.data

def test_settings_delete_token(auth_client):
    # First generate a token
    auth_client.post('/settings/token', follow_redirects=True)
    # Then delete it
    response = auth_client.post('/settings/token/delete', follow_redirects=True)
    assert b'Token deleted successfully' in response.data