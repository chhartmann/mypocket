from io import BytesIO
import json
from app import db, app

def test_index_page(auth_client):
    response = auth_client.get('/')
    assert response.status_code == 200
    assert b'Add URL' in response.data

def test_add_url(auth_client):
    response = auth_client.post('/add', data={
        'url': 'http://example.com',
        'summary': 'Test summary',
        'notes': 'Test notes',
        'tags': 'test,example'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'http://example.com' in response.data

def test_edit_url(auth_client, sample_url):
    url_id = sample_url.id
    response = auth_client.post(f'/edit/{url_id}', data={
        'url': 'http://updated-example.com',
        'summary': 'Updated summary',
        'notes': 'Updated notes',
        'tags': 'updated,test'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'http://updated-example.com' in response.data

def test_delete_url(auth_client, sample_url):
    url_id = sample_url.id
    response = auth_client.get(f'/delete/{url_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'http://example.com' not in response.data

def test_import_csv(auth_client):
    csv_content = b'Title,URL,Created At,Tags\nTest Site,http://test.com,1622505600,test,example'
    data = {
        'csv_file': (BytesIO(csv_content), 'test.csv')
    }
    response = auth_client.post('/import', data=data, follow_redirects=True,
                              content_type='multipart/form-data')
    assert response.status_code == 200
    assert b'Successfully imported' in response.data

def test_search_urls(auth_client, sample_url):
    response = auth_client.get('/?search=Example')
    assert response.status_code == 200
    assert b'Example Website' in response.data

def test_filter_by_tags(auth_client, sample_url, sample_tag):
    # Add tag to sample URL using a fresh session
    with app.app_context():
        sample_url = db.session.merge(sample_url)
        sample_tag = db.session.merge(sample_tag)
        sample_url.tags.append(sample_tag)
        tag_id = sample_tag.id  # Store the ID before committing
        db.session.commit()

    response = auth_client.get(f'/?tags={tag_id}')
    assert response.status_code == 200
    assert b'Example Website' in response.data