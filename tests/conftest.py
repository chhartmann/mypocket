import os
import tempfile
import pytest
from app import app as flask_app, db, User, Tag, Url

def create_app():
    """Create and configure a new Flask application instance for testing."""
    app = flask_app
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'JWT_SECRET_KEY': 'test-secret-key',
        'JWT_TOKEN_LOCATION': ['headers'],
        'JWT_ACCESS_TOKEN_EXPIRES': False,  # Tokens don't expire in testing
        'RATELIMIT_ENABLED': False,  # Disable rate limiting during tests
        'RATELIMIT_STORAGE_URL': 'memory://'  # Use in-memory storage for rate limiting
    })
    return app

@pytest.fixture(scope='function')
def app():
    """Create and configure a new app instance for each test."""
    _app = create_app()
    return _app

@pytest.fixture(scope='function')
def client(app):
    """Create a test client for the app."""
    return app.test_client()

@pytest.fixture(scope='function')
def app_context(app):
    """Create an application context."""
    with app.app_context() as ctx:
        # Initialize database
        db.create_all()
        yield ctx
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='function')
def test_user(app_context):
    # Create test user
    user = User(username='testuser')
    user.set_password('testpass')
    # Generate a test API token
    user.token = 'test-api-token-123'
    db.session.add(user)
    db.session.commit()
    return db.session.get(User, user.id)  # Get fresh copy after commit

@pytest.fixture(scope='function')
def auth_client(client, test_user):
    """Create an authenticated client."""
    with client.session_transaction() as session:
        session['_user_id'] = str(test_user.id)
        session['_fresh'] = True
    return client

@pytest.fixture(scope='function')
def sample_url(app_context, test_user):
    """Create a sample URL for testing."""
    url = Url(
        url='http://example.com',
        title='Example Website',
        summary='Test summary',
        notes='Test notes',
        user_id=test_user.id
    )
    db.session.add(url)
    db.session.commit()
    return db.session.get(Url, url.id)  # Get fresh copy after commit

@pytest.fixture(scope='function')
def sample_tag(app_context):
    """Create a sample tag for testing."""
    tag = Tag(name='test-tag')
    db.session.add(tag)
    db.session.commit()
    return db.session.get(Tag, tag.id)  # Get fresh copy after commit