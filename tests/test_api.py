import json
from app import User, db, app

def get_auth_token(client, username='testuser', password='testpass'):
    """Helper to get an auth token for testing."""
    response = client.post('/api/token',
                        json={
                            'username': username,
                            'password': password
                        })
    assert response.status_code == 200, "Failed to get auth token"
    return json.loads(response.data)['access_token']

def get_auth_headers(token):
    """Helper to create auth headers for testing."""
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-API-Token': token  # Also include token as API token for dual auth
    }

def get_api_token_headers(token):
    """Helper to create API token headers for testing."""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-API-Token': token
    }

def test_get_jwt_token(client, test_user, app_context):
    response = client.post('/api/token',
                         json={
                             'username': 'testuser',
                             'password': 'testpass'
                         })
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert 'access_token' in json_data

def test_api_get_urls(client, test_user, sample_url, app_context):
    token = get_auth_token(client)
    response = client.get('/api/urls', headers=get_auth_headers(token))
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert len(json_data) > 0
    assert json_data[0]['url'] == 'http://example.com'

def test_api_add_url(client, test_user, app_context):
    token = get_auth_token(client)
    response = client.post('/api/urls',
                       headers=get_auth_headers(token),
                       json={
                           'url': 'http://api-test.com',
                           'summary': 'API Test Summary',
                           'notes': 'API Test Notes',
                           'tags': ['api-test']
                       })
    assert response.status_code == 201
    json_data = json.loads(response.data)
    assert json_data['url'] == 'http://api-test.com'

def test_api_get_single_url(client, test_user, sample_url, app_context):
    # Make sure the sample URL belongs to the test user
    assert sample_url.user_id == test_user.id
    token = get_auth_token(client)
    url_id = sample_url.id
    response = client.get(f'/api/urls/{url_id}',
                        headers=get_auth_headers(token))
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['url'] == 'http://example.com'

def test_api_update_url(client, test_user, sample_url, app_context):
    token = get_auth_token(client)
    url_id = sample_url.id
    response = client.put(f'/api/urls/{url_id}',
                        headers=get_auth_headers(token),
                        json={
                            'url': 'http://updated-api-test.com',
                            'summary': 'Updated API Test Summary',
                            'notes': 'Updated API Test Notes',
                            'tags': ['updated-api-test']
                        })
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['url'] == 'http://updated-api-test.com'

def test_api_delete_url(client, test_user, sample_url, app_context):
    token = get_auth_token(client)
    url_id = sample_url.id
    response = client.delete(f'/api/urls/{url_id}',
                           headers=get_auth_headers(token))
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_api_get_tags(client, test_user, sample_tag, app_context):
    token = get_auth_token(client)
    response = client.get('/api/tags',
                        headers=get_auth_headers(token))
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert len(json_data) > 0
    assert json_data[0]['name'] == 'test-tag'

def test_api_add_url_with_api_token(client, test_user, app_context):
    # Get the user's API token
    api_token = test_user.token
    assert api_token is not None, "User should have an API token"
    
    # Create headers with only API token
    headers = get_api_token_headers(api_token)
    
    response = client.post('/api/urls',
                       headers=headers,
                       json={
                           'url': 'http://api-token-test.com',
                           'summary': 'API Token Test Summary',
                           'notes': 'API Token Test Notes',
                           'tags': ['api-token-test']
                       })
    assert response.status_code == 201
    json_data = json.loads(response.data)
    assert json_data['url'] == 'http://api-token-test.com'