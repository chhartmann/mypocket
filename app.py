from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from datetime import datetime
import os
import argparse

# Create argument parser
parser = argparse.ArgumentParser(description='Flask Web Application')
parser.add_argument('--port', type=int, default=5000, help='Port number to run the server on')

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

@app.route('/')
def index():
    urls = Url.query.order_by(Url.created_at.desc()).all()
    view_type = request.args.get('view', 'tile')  # Default to tile view
    return render_template('index.html', urls=urls, view_type=view_type)

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
                from werkzeug.utils import secure_filename
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_url = Url(
            url=url,
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
        url.url = request.form.get('url')
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
                from werkzeug.utils import secure_filename
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

if __name__ == '__main__':
    args = parser.parse_args()
    app.run(debug=True, port=args.port)
