import json

def test_manage_tags_page(auth_client):
    response = auth_client.get('/tags')
    assert response.status_code == 200
    assert b'Manage Tags' in response.data

def test_add_tag(auth_client):
    response = auth_client.post('/tags', data={
        'tag_name': 'newtag'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'newtag' in response.data

def test_update_tag(auth_client, sample_tag):
    response = auth_client.put(f'/tags/{sample_tag.id}', 
                             data=json.dumps({'name': 'updated-tag'}),
                             content_type='application/json')
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_delete_tag(auth_client, sample_tag):
    response = auth_client.delete(f'/tags/{sample_tag.id}')
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_add_tag_to_url(auth_client, sample_url, sample_tag):
    response = auth_client.post(f'/url/{sample_url.id}/tags',
                              data=json.dumps({'tag_id': sample_tag.id}),
                              content_type='application/json')
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True

def test_remove_tag_from_url(auth_client, sample_url, sample_tag):
    # First add the tag
    auth_client.post(f'/url/{sample_url.id}/tags',
                    data=json.dumps({'tag_id': sample_tag.id}),
                    content_type='application/json')
    
    # Then remove it
    response = auth_client.delete(f'/url/{sample_url.id}/tags',
                                data=json.dumps({'tag_id': sample_tag.id}),
                                content_type='application/json')
    assert response.status_code == 200
    json_data = json.loads(response.data)
    assert json_data['success'] is True