import json

def test_manage_tags_page(auth_client, app_context):
    response = auth_client.get('/tags', follow_redirects=True)
    assert response.status_code == 200
    assert b'Manage Tags' in response.data

def test_add_tag(auth_client, app_context):
    response = auth_client.post('/tags', data={
        'tag_name': 'newtag'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'newtag' in response.data

def test_update_tag(auth_client, sample_tag, app_context):
    response = auth_client.put(f'/tags/{sample_tag.id}', 
                             json={'name': 'updated-tag'},
                             follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_delete_tag(auth_client, sample_tag, app_context):
    response = auth_client.delete(f'/tags/{sample_tag.id}',
                                follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_add_tag_to_url(auth_client, sample_url, sample_tag, app_context):
    response = auth_client.post(f'/url/{sample_url.id}/tags',
                              json={'tag_id': sample_tag.id},
                              follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_remove_tag_from_url(auth_client, sample_url, sample_tag, app_context):
    # First add the tag
    auth_client.post(f'/url/{sample_url.id}/tags',
                    json={'tag_id': sample_tag.id},
                    follow_redirects=True)
    
    # Then remove it
    response = auth_client.delete(f'/url/{sample_url.id}/tags',
                                json={'tag_id': sample_tag.id},
                                follow_redirects=True)
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True