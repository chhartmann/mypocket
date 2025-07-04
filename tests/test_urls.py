from io import BytesIO
import json
from app import db, app, Url

def test_index_page(auth_client, app_context):
    response = auth_client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Add URL' in response.data

def test_add_url(auth_client, app_context):
    response = auth_client.post('/add', data={
        'url': 'http://example.com',
        'summary': 'Test summary',
        'notes': 'Test notes',
        'tags': 'test,example'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'http://example.com' in response.data

def test_edit_url(auth_client, sample_url, app_context):
    url_id = sample_url.id
    new_title = 'Updated Title'
    response = auth_client.post(f'/edit/{url_id}', data={ 
        'url': 'http://updated-example.com',
        'title': new_title,
        'summary': 'Updated summary',
        'notes': 'Updated notes',
        'tags': 'updated,test'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'http://updated-example.com' in response.data
    assert new_title.encode() in response.data

def test_delete_url(auth_client, sample_url, app_context):
    url_id = sample_url.id
    response = auth_client.get(f'/delete/{url_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'http://example.com' not in response.data

def test_import_csv(auth_client, app_context):
    csv_content = b'Title,URL,Created At,Tags\nTest Site,http://test.com,1622505600,test,example'
    data = {
        'csv_file': (BytesIO(csv_content), 'test.csv')
    }
    response = auth_client.post('/import', data=data, follow_redirects=True,
                              content_type='multipart/form-data')
    assert response.status_code == 200
    assert b'Successfully imported' in response.data

def test_search_urls(auth_client, sample_url, app_context):
    response = auth_client.get('/?search=Example', follow_redirects=True)
    assert response.status_code == 200
    assert b'Example Website' in response.data

def test_filter_by_tags(auth_client, sample_url, sample_tag, app_context):
    # Add tag to sample URL
    sample_url.tags.append(sample_tag)
    db.session.commit()
    
    # Get fresh copy of URL with tags
    url = db.session.get(Url, sample_url.id)
    assert sample_tag in url.tags
    
    response = auth_client.get(f'/?tags={sample_tag.id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'Example Website' in response.data

def test_manage_urls_duplicates(auth_client, app_context, test_user):
    # Add two URLs with the same address for the test user
    url1 = Url(url='http://dupe.com', title='Dupe 1', user_id=test_user.id)
    url2 = Url(url='http://dupe.com', title='Dupe 2', user_id=test_user.id)
    db.session.add_all([url1, url2])
    db.session.commit()

    response = auth_client.get('/manage-urls?show_duplicates=1', follow_redirects=True)
    assert response.status_code == 200
    # Both titles should appear in the response
    assert b'Dupe 1' in response.data
    assert b'Dupe 2' in response.data
    # The duplicate group header should appear
    assert b'Duplicate URLs Found' in response.data
    assert b'http://dupe.com' in response.data