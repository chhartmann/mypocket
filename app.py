from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from datetime import datetime
import os
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import csv
import io
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configure SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'urls.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/images')

# Ensure upload folder exists with proper permissions
os.makedirs(app.config['UPLOAD_FOLDER'], mode=0o755, exist_ok=True)

db = SQLAlchemy(app)

# URL-Tag association table
url_tags = db.Table('url_tags',
    db.Column('url_id', db.Integer, db.ForeignKey('url.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
    db.UniqueConstraint('url_id', 'tag_id', name='uix_url_tag')
)

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

# Create database tables and enable foreign keys
with app.app_context():
    # Enable SQLite foreign key support
    @event.listens_for(db.engine, 'connect')
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    
    db.create_all()

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
parser.add_argument('--port', type=int, default=5000, help='Port number to run the server on')

@app.route('/')
def index():
    # Get selected tag IDs from query parameters
    selected_tag_ids = request.args.getlist('tags')
    search_query = request.args.get('search', '').strip()
    
    # Base query
    query = Url.query
    
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
        # Convert string IDs to integers
        tag_ids = [int(tag_id) for tag_id in selected_tag_ids]
        # Filter URLs that have ALL selected tags
        query = query.filter(Url.tags.any(Tag.id.in_(tag_ids)))
    
    # Order by creation date
    urls = query.order_by(Url.created_at.desc()).all()
    view_type = request.args.get('view', 'tile')  # Default to tile view
    
    # Get all tags for the filter
    all_tags = Tag.query.order_by(Tag.name).all()
    
    return render_template('index.html', 
                         urls=urls, 
                         view_type=view_type,
                         all_tags=all_tags,
                         selected_tag_ids=selected_tag_ids,
                         search_query=search_query)

@app.route('/add', methods=['GET', 'POST'])
def add_url():
    if request.method == 'POST':
        url = request.form.get('url')
        summary = request.form.get('summary')
        notes = request.form.get('notes')
        tags = request.form.get('tags')  # Get tags from the form
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                # Secure the filename and save the file
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        # Fetch webpage title
        title = fetch_webpage_title(url)
        
        new_url = Url(
            url=url,
            title=title,
            image=image_filename,
            summary=summary,
            notes=notes
        )
        db.session.add(new_url)
        db.session.commit()

        # Handle tags
        if tags:
            tag_names = [tag.strip() for tag in tags.split(',')]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                new_url.tags.append(tag)

        db.session.commit()
        return redirect(url_for('index'))
    
    return render_template('add.html')

@app.route('/delete/<int:id>')
def delete_url(id):
    url = Url.query.get_or_404(id)
    if url.image:
        # Delete the image file if it exists
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], url.image)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(url)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_url(id):
    url = Url.query.get_or_404(id)
    if request.method == 'POST':
        new_url = request.form.get('url')
        # Update title when URL changes
        if new_url != url.url:
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
        
        # Get headers from the first row
        try:
            headers = next(csv_input)
        except StopIteration:
            flash('CSV file is empty', 'danger')
            return redirect(request.url)

        # If this is the first step (uploading file), show the column mapping form
        if 'url_column' not in request.form:
            return render_template('import.html', headers=headers)

        # Get the column mappings from the form
        url_column = headers.index(request.form['url_column'])
        title_column = headers.index(request.form['title_column']) if request.form.get('title_column') else None
        created_at_column = headers.index(request.form['created_at_column']) if request.form.get('created_at_column') else None
        tags_column = headers.index(request.form['tags_column']) if request.form.get('tags_column') else None

        # Process the data
        imported_count = 0
        for row in csv_input:
            try:
                # Skip empty rows
                if not any(row):
                    continue

                url = row[url_column].strip()
                if not url:
                    continue

                # Create new URL entry
                new_url = Url(url=url)
                
                # Set title if provided, otherwise fetch from webpage
                if title_column is not None:
                    new_url.title = row[title_column].strip() or fetch_webpage_title(url)
                else:
                    new_url.title = fetch_webpage_title(url)

                # Set created_at if provided
                if created_at_column is not None:
                    try:
                        created_at = datetime.strptime(row[created_at_column].strip(), '%Y-%m-%d %H:%M:%S')
                        new_url.created_at = created_at
                    except ValueError:
                        pass

                # Add tags if provided
                if tags_column is not None and row[tags_column].strip():
                    tag_names = [t.strip() for t in row[tags_column].split(',')]
                    for tag_name in tag_names:
                        if tag_name:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            new_url.tags.append(tag)

                db.session.add(new_url)
                imported_count += 1

            except Exception as e:
                db.session.rollback()
                flash(f'Error importing row: {str(e)}', 'danger')
                return redirect(url_for('import_csv'))

        try:
            db.session.commit()
            flash(f'Successfully imported {imported_count} URLs', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving to database: {str(e)}', 'danger')
            return redirect(url_for('import_csv'))

    return render_template('import.html', headers=None)

if __name__ == '__main__':
    args = parser.parse_args()
    app.run(debug=True, port=args.port)
