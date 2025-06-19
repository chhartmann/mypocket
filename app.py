from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
from sqlalchemy import event
from datetime import datetime, timedelta
import os
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import csv
import io
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure Flask application
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF token validity in seconds
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Disable CSRF by default for GET requests

# Add session configuration
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Configure SQLite database and JWT
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,  "database", 'urls.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/images')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-here')  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

# Configure security headers with Talisman
csp = {
    'default-src': "'self'",
    'img-src': ['*', 'data:', 'https:'],  # Allow images from all sources
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        "'unsafe-inline'",  # Required for inline scripts
        "'unsafe-eval'"  # Required for some Bootstrap functionality
    ],
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        "'unsafe-inline'"  # Required for inline styles
    ],
    'font-src': [
        "'self'",
        'https://fonts.gstatic.com',
        'https://cdn.jsdelivr.net'
    ],
    'connect-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com'
    ]
}

# Initialize Talisman with CSP
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    force_https=False,  # Set to True in production
    session_cookie_secure=False,  # Allow cookies over HTTP in development
    strict_transport_security=False  # Disable HSTS in development
)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
jwt = JWTManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], mode=0o755, exist_ok=True)

# URL-Tag association table
url_tags = db.Table('url_tags',
    db.Column('url_id', db.Integer, db.ForeignKey('url.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
    db.UniqueConstraint('url_id', 'tag_id', name='uix_url_tag')
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(64), unique=True)
    urls = db.relationship('Url', backref='user', lazy=True)

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    urls = db.relationship('Url', secondary=url_tags, backref=db.backref('tags', lazy=True))

class Url(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    title = db.Column(db.String(500))
    image = db.Column(db.String(100))  # stores image filename
    summary = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create database tables and enable foreign keys
with app.app_context():
    # Enable SQLite foreign key support
    @event.listens_for(db.engine, 'connect')
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    
    # Create tables
    db.create_all()
    
    # Create default user if no users exist
    if not User.query.first():
        default_user = User(username='user')
        default_user.set_password('password')
        db.session.add(default_user)
        db.session.commit()
        print("Created default user with username 'user' and password 'password'")

def fetch_webpage_title(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else None
        return title.strip() if title else url
    except Exception as e:
        print(f"Error fetching title for {url}: {str(e)}")
        return url

# Create argument parser
parser = argparse.ArgumentParser(description='Flask Web Application')
parser.add_argument('--port', type=int, help='Port number to run the server on')

def sanitize_input(input_str):
    """
    Sanitize user input to prevent SQL injection.
    Returns None if input contains potentially dangerous patterns.
    """
    if not input_str:
        return None
    
    # Check for SQL injection patterns
    dangerous_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL comment patterns
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL injection with = operator
        r"((\%27)|(\'))union",  # SQL UNION injection
        r"exec(\s|\+)+(s|x)p\w+",  # SQL stored procedure injection
    ]
    
    import re
    for pattern in dangerous_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return None
    
    return input_str

@app.route('/')
@login_required
def index():
    # Get selected tag IDs from query parameters
    selected_tag_ids = request.args.getlist('tags')
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 9  # Number of items per page for tile view
    
    # Sanitize search query
    search_query = sanitize_input(search_query)
    
    # Base query - only show URLs belonging to the current user
    query = Url.query.filter_by(user_id=current_user.id)
    
    # Apply search filter if search query exists
    if search_query:
        search_term = f'%{search_query}%'
        query = query.filter(
            db.or_(
                Url.url.ilike(search_term),
                Url.title.ilike(search_term),
                Url.notes.ilike(search_term),
                Url.summary.ilike(search_term)
            )
        )
    
    # Apply tag filter if tags are selected
    if selected_tag_ids:
        try:
            # Convert string IDs to integers and validate
            tag_ids = [int(tag_id) for tag_id in selected_tag_ids if tag_id.isdigit()]
            # Filter URLs that have ALL selected tags
            query = query.filter(Url.tags.any(Tag.id.in_(tag_ids)))
        except ValueError:
            # If any tag ID is invalid, ignore the tag filter
            pass
    
    # Order by creation date and paginate
    pagination = query.order_by(Url.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    urls = pagination.items
    view_type = request.args.get('view', 'tile')  # Default to tile view
    
    # Get all tags for the filter
    all_tags = Tag.query.order_by(Tag.name).all()
    
    return render_template('index.html', 
                         urls=urls, 
                         view_type=view_type,
                         all_tags=all_tags,
                         selected_tag_ids=selected_tag_ids,
                         search_query=search_query,
                         pagination=pagination)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_url():
    if request.method == 'POST':
        url = request.form.get('url')
        summary = request.form.get('summary')
        notes = request.form.get('notes')
        tags = request.form.get('tags', '')
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        # Fetch webpage title
        title = fetch_webpage_title(url)
        
        new_url = Url(
            url=url,
            title=title,
            image=image_filename,
            summary=summary,
            notes=notes,
            user_id=current_user.id
        )
        db.session.add(new_url)
        db.session.commit()

        # Handle tags
        if tags:
            tag_names = [tag.strip() for tag in tags.split(',') if tag.strip()]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                new_url.tags.append(tag)

        db.session.commit()
        return redirect(url_for('index'))
    
    # Get all tags to display in the form
    all_tags = Tag.query.order_by(Tag.name).all()
    return render_template('add.html', tags=all_tags)

@app.route('/delete/<int:id>')
@login_required
def delete_url(id):
    url = Url.query.get_or_404(id)
    # Check if the current user owns the URL
    if url.user_id != current_user.id:
        flash('You do not have permission to delete this URL', 'danger')
        return redirect(url_for('index'))
    if url.image:
        # Delete the image file if it exists
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], url.image)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(url)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_url(id):
    url = Url.query.get_or_404(id)
    # Check if the current user owns the URL
    if url.user_id != current_user.id:
        flash('You do not have permission to edit this URL', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        new_url = request.form.get('url')
        new_title = request.form.get('title')
        # Update title when URL changes, or if user provided a new title
        if new_title is not None and new_title.strip() != '':
            url.title = new_title.strip()
        else:
            url.title = fetch_webpage_title(new_url)
        url.url = new_url
        url.summary = request.form.get('summary')
        url.notes = request.form.get('notes')
        tags = request.form.get('tags', '')  # Get tags from the form
        
        # Handle image upload
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                # Delete old image if it exists
                if url.image:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], url.image)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                url.image = image_filename

        # Handle tags
        url.tags.clear()  # Clear existing tags
        if tags:
            tag_names = [tag.strip() for tag in tags.split(',') if tag.strip()]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                url.tags.append(tag)

        db.session.commit()
        return redirect(url_for('index'))
    
    all_tags = Tag.query.order_by(Tag.name).all()
    return render_template('edit.html', url=url, tags=all_tags)

@app.route('/tags', methods=['GET', 'POST'])
@login_required
def manage_tags():
    if request.method == 'POST':
        tag_name = request.form.get('tag_name').strip()
        if tag_name:
            existing_tag = Tag.query.filter_by(name=tag_name).first()
            if not existing_tag:
                new_tag = Tag(name=tag_name)
                db.session.add(new_tag)
                db.session.commit()
    tags = Tag.query.order_by(Tag.name).all()
    return render_template('tags.html', tags=tags)

@app.route('/tags/<int:id>', methods=['PUT', 'DELETE'])
@login_required
def update_tag(id):
    tag = Tag.query.get_or_404(id)
    if request.method == 'PUT':
        tag_name = request.json.get('name').strip()
        if tag_name and tag_name != tag.name:
            existing_tag = Tag.query.filter_by(name=tag_name).first()
            if not existing_tag:
                tag.name = tag_name
                db.session.commit()
                return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Tag name already exists or is invalid'})
    elif request.method == 'DELETE':
        db.session.delete(tag)
        db.session.commit()
        return jsonify({'success': True})

@app.route('/url/<int:url_id>/tags', methods=['POST', 'DELETE'])
@login_required
def manage_url_tags(url_id):
    try:
        url = Url.query.get_or_404(url_id)
        tag_id = request.json.get('tag_id')
        if not tag_id:
            return jsonify({'success': False, 'message': 'Tag ID is required'}), 400
            
        tag = Tag.query.get_or_404(tag_id)
        
        if request.method == 'POST':
            if tag not in url.tags:
                url.tags.append(tag)
                db.session.commit()
            return jsonify({'success': True})
        elif request.method == 'DELETE':
            if tag in url.tags:
                url.tags.remove(tag)
                db.session.commit()
            return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_csv():
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(request.url)
        
        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if not file.filename.endswith('.csv'):
            flash('Please upload a CSV file', 'danger')
            return redirect(request.url)

        # Read the CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        
        # Skip the header row
        try:
            headers = next(csv_input)
        except StopIteration:
            flash('CSV file is empty', 'danger')
            return redirect(request.url)

        # Hardcoded column indices (0-based)
        title_column = 0  # First column
        url_column = 1  # Second column
        created_at_column = 2  # Third column
        tags_column = 3  # Fourth column

        # Process the data
        imported_count = 0
        for row in csv_input:
            try:
                # Skip empty rows
                if not any(row):
                    continue

                # Ensure the row has enough columns
                if len(row) < 1:
                    continue

                url = row[url_column].strip()
                if not url:
                    continue

                # Create new URL entry
                new_url = Url(url=url, user_id=current_user.id)  # Associate with the logged-in user
                
                # Set title if provided, otherwise fetch from webpage
                if len(row) > title_column and row[title_column].strip():
                    new_url.title = row[title_column].strip()
                else:
                    new_url.title = fetch_webpage_title(url)

                # Set created_at if provided
                if len(row) > created_at_column and row[created_at_column].strip():
                    try:
                        created_at = datetime.fromtimestamp(int(row[created_at_column].strip()))
                        new_url.created_at = created_at
                    except ValueError:
                        pass

                # Add tags if provided
                if len(row) > tags_column and row[tags_column].strip():
                    tag_names = [t.strip() for t in row[tags_column].split(',')]
                    for tag_name in tag_names:
                        if tag_name:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            new_url.tags.append(tag)

                new_url.summary = ""
                new_url.notes = ""
                db.session.add(new_url)
                imported_count += 1

            except Exception as e:
                db.session.rollback()
                flash(f'Error importing row: {str(e)}', 'danger')
                return redirect(url_for('import_csv'))

        try:
            db.session.commit()
            flash(f'Successfully imported {imported_count} URLs', 'success')
            return redirect(url_for('import_csv'))  # Redirect to index after successful import
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving to database: {str(e)}', 'danger')
            return redirect(url_for('import_csv'))

    return render_template('import.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit to 5 attempts per minute
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)  # Enable remember me functionality
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
            return redirect(next_page)
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Profile settings routes
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/settings/username', methods=['POST'])
@login_required
def update_username():
    new_username = request.form.get('new_username')
    current_password = request.form.get('current_password')
    
    if not new_username or not current_password:
        flash('All fields are required', 'danger')
        return redirect(url_for('settings'))
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('settings'))
    
    # Check if username already exists
    if User.query.filter_by(username=new_username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('settings'))
    
    current_user.username = new_username
    db.session.commit()
    flash('Username updated successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('settings'))
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('settings'))
    
    current_user.set_password(new_password)
    db.session.commit()
    flash('Password updated successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/token', methods=['POST'])
@login_required
def generate_token():
    import secrets
    token = secrets.token_hex(32)
    current_user.token = token
    db.session.commit()
    flash('Token generated successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/token/delete', methods=['POST'])
@login_required
def delete_token():
    current_user.token = None
    db.session.commit()
    flash('Token deleted successfully', 'success')
    return redirect(url_for('settings'))

def dual_auth_required():
    """
    A decorator that allows both JWT and database token authentication.
    For JWT, looks for 'Authorization: Bearer <token>' header.
    For database token, looks for 'X-API-Token: <token>' header.
    """
    def decorator(fn):
        def wrapper(*args, **kwargs):
            # First try JWT authentication
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                try:
                    # Extract the token
                    token = auth_header.split(' ')[1]
                    from flask_jwt_extended import decode_token
                    # Verify JWT token and get user ID
                    decoded = decode_token(token)
                    current_user_id = decoded['sub']
                    # Check if user exists
                    user = User.query.get(current_user_id)
                    if not user:
                        raise ValueError("User not found")
                    return fn(current_user_id, *args, **kwargs)
                except Exception as e:
                    app.logger.error(f"JWT auth failed: {str(e)}")
                    return jsonify({"error": "Invalid JWT token"}), 401
            
            # If JWT fails, try database token authentication
            api_token = request.headers.get('X-API-Token')
            if api_token:
                user = User.query.filter_by(token=api_token).first()
                if user:
                    return fn(user.id, *args, **kwargs)
                return jsonify({"error": "Invalid API token"}), 401
            
            return jsonify({"error": "Missing authentication"}), 401
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

# API routes for token authentication
@app.route('/api/token', methods=['POST'])
def get_token():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    try:
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Create access token with user ID
            access_token = create_access_token(identity=str(user.id))
            # Also store token in user's database token for dual auth
            user.token = access_token
            db.session.commit()
            return jsonify(access_token=access_token)
        
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        app.logger.error(f"Token generation error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# API endpoints
@app.route('/api/urls', methods=['GET'])
@jwt_required()
def api_get_urls():
    try:
        current_user_id = get_jwt_identity()
        urls = Url.query.filter_by(user_id=current_user_id).order_by(Url.created_at.desc()).all()
        return jsonify([{
            'id': url.id,
            'url': url.url,
            'title': url.title,
            'summary': url.summary,
            'notes': url.notes,
            'created_at': url.created_at.isoformat(),
            'tags': [{'id': tag.id, 'name': tag.name} for tag in url.tags]
        } for url in urls])
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/urls', methods=['POST'])
@dual_auth_required()
def api_add_url(current_user_id):
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Sanitize input
        url = sanitize_input(data['url'])
        if not url:
            return jsonify({'error': 'Invalid URL format'}), 400
            
        summary = sanitize_input(data.get('summary', ''))
        notes = sanitize_input(data.get('notes', ''))
        
        title = fetch_webpage_title(url)
        
        new_url = Url(
            url=url,
            title=title,
            summary=summary or '',
            notes=notes or '',
            user_id=current_user_id
        )
        
        # Handle tags if provided
        if 'tags' in data and isinstance(data['tags'], list):
            for tag_name in data['tags']:
                sanitized_tag = sanitize_input(tag_name)
                if sanitized_tag:
                    tag = Tag.query.filter_by(name=sanitized_tag).first()
                    if not tag:
                        tag = Tag(name=sanitized_tag)
                        db.session.add(tag)
                    new_url.tags.append(tag)
        
        db.session.add(new_url)
        db.session.commit()
        
        return jsonify({
            'id': new_url.id,
            'url': new_url.url,
            'title': new_url.title,
            'summary': new_url.summary,
            'notes': new_url.notes,
            'created_at': new_url.created_at.isoformat(),
            'tags': [{'id': tag.id, 'name': tag.name} for tag in new_url.tags]
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/urls/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def api_url_operations(id):
    try:
        current_user_id = get_jwt_identity()
        url = Url.query.get_or_404(id)
        # Ensure current_user_id is int for comparison
        if url.user_id != int(current_user_id):
            return jsonify({'error': 'Unauthorized'}), 403
        
        if request.method == 'GET':
            return jsonify({
                'id': url.id,
                'url': url.url,
                'title': url.title,
                'summary': url.summary,
                'notes': url.notes,
                'created_at': url.created_at.isoformat(),
                'tags': [{'id': tag.id, 'name': tag.name} for tag in url.tags]
            })
        
        elif request.method == 'PUT':
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400

            data = request.get_json()
            
            if 'url' in data:
                sanitized_url = sanitize_input(data['url'])
                if not sanitized_url:
                    return jsonify({'error': 'Invalid URL format'}), 400
                url.url = sanitized_url
                # Update title if URL changes
                url.title = fetch_webpage_title(sanitized_url)
            
            if 'summary' in data:
                url.summary = sanitize_input(data['summary']) or ''
            if 'notes' in data:
                url.notes = sanitize_input(data['notes']) or ''
            
            # Update tags if provided
            if 'tags' in data and isinstance(data['tags'], list):
                url.tags.clear()
                for tag_name in data['tags']:
                    sanitized_tag = sanitize_input(tag_name)
                    if sanitized_tag:
                        tag = Tag.query.filter_by(name=sanitized_tag).first()
                        if not tag:
                            tag = Tag(name=sanitized_tag)
                            db.session.add(tag)
                        url.tags.append(tag)
            
            db.session.commit()
            return jsonify({
                'id': url.id,
                'url': url.url,
                'title': url.title,
                'summary': url.summary,
                'notes': url.notes,
                'created_at': url.created_at.isoformat(),
                'tags': [{'id': tag.id, 'name': tag.name} for tag in url.tags]
            })
        
        elif request.method == 'DELETE':
            if url.image:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], url.image)
                if os.path.exists(image_path):
                    os.remove(image_path)
            db.session.delete(url)
            db.session.commit()
            return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/tags', methods=['GET'])
@jwt_required()
def api_get_tags():
    try:
        tags = Tag.query.order_by(Tag.name).all()
        return jsonify([{
            'id': tag.id,
            'name': tag.name
        } for tag in tags])
    except Exception as e:
        return jsonify({'error': str(e)}), 400
