import os
import re
import random
from datetime import datetime, UTC
from bson.objectid import ObjectId
from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    send_from_directory, abort, jsonify, make_response
)
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# ----------------------------
# CONFIGURATION
# ----------------------------
app = Flask(__name__)

# --- File upload settings ---
#Get the Render URL from environment or use the actual URL
app.config['BASE_URL'] = os.environ.get('BASE_URL', 'https://tusome-guhv.onrender.com')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {
    'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'mp4', 'zip'
}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- App secrets & database ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['MONGO_URI'] = os.environ.get(
    'MONGO_URI',
    'mongodb+srv://jnyamawi_db_user:PZQKm1mLWlsJHyng@trial.6pajnwb.mongodb.net/elearning_db?retryWrites=true&w=majority'
)

# --- Mail configuration (for password reset) ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'jnyamawi@kabarak.ac.ke')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'nphedmrdodfcnadi')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

# ----------------------------
# INITIALIZE EXTENSIONS
# ----------------------------
mongo = PyMongo(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ----------------------------
# USER MODEL
# ----------------------------
class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc.get('_id'))
        self.username = user_doc.get('username')
        self.email = user_doc.get('email')
        self.role = user_doc.get('role', 'learner')

@login_manager.user_loader
def load_user(user_id):
    user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_doc) if user_doc else None

# ----------------------------
# HELPERS
# ----------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def extract_youtube_id(url):
    """Extract YouTube video ID from URL"""
    if not url:
        return None
    
    # Handle various YouTube URL formats
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/)([^&]+)',
        r'youtube\.com\/embed\/([^?]+)',
        r'youtube\.com\/v\/([^?]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None

def generate_username_suggestions(username):
    """Generate smart username suggestions when username is taken"""
    suggestions = []
    base_username = re.sub(r'\s+', '', username).lower()
    
    # Generate variations
    current_year = datetime.now().year
    current_month = datetime.now().month
    
    variations = [
        f"{base_username}{random.randint(100, 999)}",
        f"{base_username}{current_year}",
        f"{base_username}{random.randint(1, 99)}",
        f"{base_username}_{random.randint(10, 99)}",
        f"learn_{base_username}",
        f"edu_{base_username}",
        f"{base_username}_student",
        f"{base_username}_learner",
        f"{base_username}{random.choice(['x', 'z', 'y'])}",
        f"{base_username}{current_month:02d}{random.randint(10, 99)}"
    ]
    
    # Remove duplicates and limit to 5 suggestions
    seen = set()
    for suggestion in variations:
        if suggestion not in seen:
            seen.add(suggestion)
            suggestions.append(suggestion)
        if len(suggestions) >= 5:
            break
    
    return suggestions

def validate_username(username):
    """Validate username against rules"""
    errors = []
    
    if len(username) < 3:
        errors.append("Username must be at least 3 characters long")
    if len(username) > 30:
        errors.append("Username cannot exceed 30 characters")
    
    # Check for allowed characters
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        errors.append("Username can only contain letters, numbers, dots, underscores, and hyphens")
    
    # Check for reserved usernames
    reserved = ['admin', 'root', 'system', 'administrator', 'moderator', 'superuser']
    if username.lower() in reserved:
        errors.append("This username is not allowed")
    
    # Check for offensive patterns (simplified)
    offensive_patterns = ['badword1', 'badword2']  # Add your own list
    if any(pattern in username.lower() for pattern in offensive_patterns):
        errors.append("Username contains inappropriate content")
    
    return errors

# ----------------------------
# ROUTES
# ----------------------------

# HOME
@app.route('/')
def index():
    contents = list(mongo.db.contents.find().sort('created_at', -1))
    return render_template('index.html', contents=contents)

# REGISTER (LEARNERS) - UPDATED WITH ENHANCED USERNAME CHECKING
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        # Validate username
        validation_errors = validate_username(username)
        if validation_errors:
            for error in validation_errors:
                flash(error, 'danger')
            return redirect(url_for('register'))
        
        # Check if username exists
        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            # Generate suggestions
            suggestions = generate_username_suggestions(username)
            
            # Return to registration page with suggestions
            return render_template('register.html',
                                   error="Username already exists. Try one of these:",
                                   suggestions=suggestions,
                                   original_username=username,
                                   email=email)
        
        # Check if email exists
        existing_email = mongo.db.users.find_one({'email': email})
        if existing_email:
            flash('Email already registered. Please login or use another email.', 'danger')
            return render_template('register.html')
        
        # Validate password
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html', username=username, email=email)
        
        # Create new user
        hashed = generate_password_hash(password)
        user_data = {
            'username': username,
            'email': email,
            'password': hashed,
            'role': 'learner',
            'created_at': datetime.now(UTC),
            'last_login': None,
            'profile_complete': False
        }
        
        # Insert into database
        mongo.db.users.insert_one(user_data)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# API endpoint for real-time username checking
@app.route('/api/check-username', methods=['GET'])
def check_username():
    """API endpoint for real-time username availability checking"""
    username = request.args.get('username', '').strip()
    
    if len(username) < 3:
        return jsonify({
            'available': False,
            'message': 'Username too short (minimum 3 characters)'
        })
    
    # Validate username
    validation_errors = validate_username(username)
    if validation_errors:
        return jsonify({
            'available': False,
            'message': validation_errors[0]
        })
    
    # Check if username exists
    existing_user = mongo.db.users.find_one({'username': username})
    
    if existing_user:
        suggestions = generate_username_suggestions(username)
        return jsonify({
            'available': False,
            'message': 'Username already taken',
            'suggestions': suggestions
        })
    
    return jsonify({
        'available': True,
        'message': 'Username is available!'
    })

# API endpoint for real-time email checking
@app.route('/api/check-email', methods=['GET'])
def check_email():
    """API endpoint for real-time email availability checking"""
    email = request.args.get('email', '').strip().lower()
    
    # Basic email validation
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({
            'available': False,
            'message': 'Invalid email format'
        })
    
    # Check if email exists
    existing_email = mongo.db.users.find_one({'email': email})
    
    if existing_email:
        return jsonify({
            'available': False,
            'message': 'Email already registered'
        })
    
    return jsonify({
        'available': True,
        'message': 'Email is available'
    })

# LOGIN (ADMIN + LEARNER)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_doc = mongo.db.users.find_one({'username': username})
        if user_doc and check_password_hash(user_doc['password'], password):
            user = User(user_doc)
            login_user(user)
            
            # Update last login
            mongo.db.users.update_one(
                {'_id': ObjectId(user_doc['_id'])},
                {'$set': {'last_login': datetime.now(UTC)}}
            )
            
            flash('Logged in successfully!', 'success')

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('learner_dashboard'))

        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# LEARNER DASHBOARD
@app.route('/learner')
@login_required
def learner_dashboard():
    # Only learners should access this
    if current_user.role != 'learner':
        abort(403)
    contents = list(mongo.db.contents.find().sort('created_at', -1))
    return render_template('learner_dashboard.html', contents=contents)

# ADMIN DASHBOARD
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    contents = list(mongo.db.contents.find().sort('created_at', -1))
    return render_template('admin_dashboard.html', contents=contents)

# ADMIN UPLOAD CONTENT
@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def upload_content():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        file = request.files.get('file')
        filename = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        mongo.db.contents.insert_one({
            'title': title,
            'description': description,
            'filename': filename,
            'created_at': datetime.now(UTC),
            'completed_by': []
        })
        flash('Content uploaded successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('upload_content.html')

# ADMIN EDIT CONTENT
@app.route('/admin/edit/<content_id>', methods=['GET', 'POST'])
@login_required
def edit_content(content_id):
    if current_user.role != 'admin':
        abort(403)
    content = mongo.db.contents.find_one({'_id': ObjectId(content_id)})
    if not content:
        abort(404)

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        mongo.db.contents.update_one({'_id': ObjectId(content_id)}, {'$set': {
            'title': title,
            'description': description
        }})
        flash('Content updated.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_content.html', content=content)

# ADMIN DELETE CONTENT
@app.route('/admin/delete/<content_id>', methods=['POST'])
@login_required
def delete_content(content_id):
    if current_user.role != 'admin':
        abort(403)
    content = mongo.db.contents.find_one({'_id': ObjectId(content_id)})
    if not content:
        abort(404)

    if content.get('filename'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], content['filename']))
        except FileNotFoundError:
            pass

    mongo.db.contents.delete_one({'_id': ObjectId(content_id)})
    flash('Content deleted.', 'info')
    return redirect(url_for('admin_dashboard'))

# FILE VIEWING (for inline display in browser)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# VIEW SINGLE CONTENT (PDFs open inline)
@app.route('/content/<content_id>')
@login_required
def view_content(content_id):
    content = mongo.db.contents.find_one({'_id': ObjectId(content_id)})
    if not content:
        abort(404)

    file_url = None
    if content.get('filename'):
        file_url = url_for('uploaded_file', filename=content['filename'])

    # Detect if it's a PDF
    is_pdf = content.get('filename', '').lower().endswith('.pdf')

    return render_template(
        'view_content.html',
        content=content,
        file_url=file_url,
        is_pdf=is_pdf
    )

# --- Mark content as completed ---
@app.route('/complete/<content_id>', methods=['POST'])
@login_required
def mark_completed(content_id):
    if current_user.role != 'learner':
        return jsonify({'error': 'Only learners can mark progress'}), 403

    mongo.db.contents.update_one(
        {'_id': ObjectId(content_id)},
        {'$addToSet': {'completed_by': current_user.id}}
    )
    return jsonify({'message': 'Progress saved!'})

# PASSWORD RESET REQUEST
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user_doc = mongo.db.users.find_one({'email': email})
        if user_doc:
            token = serializer.dumps(str(user_doc['_id']))
            link = url_for('reset_token', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the link to reset your password: {link}\nIf you did not request this, ignore.'
            mail.send(msg)
        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html')

# PASSWORD RESET TOKEN
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        user_id = serializer.loads(token, max_age=3600)
    except Exception:
        flash('Reset link invalid or expired.', 'danger')
        return redirect(url_for('reset_request'))

    user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user_doc:
        flash('Invalid user.', 'danger')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        password = request.form['password']
        hashed = generate_password_hash(password)
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed}})
        flash('Your password has been updated. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html')

# ADMIN CREATION HELPER
def create_admin(username, email, password):
    if mongo.db.users.find_one({'username': username}):
        print('Admin already exists')
        return
    hashed = generate_password_hash(password)
    mongo.db.users.insert_one({
        'username': username,
        'email': email,
        'password': hashed,
        'role': 'admin',
        'created_at': datetime.now(UTC)
    })
    print('Admin created successfully!')

# --- Translation dictionary ---
LANGUAGES = {
    'en': {
        'title': 'E-Learning for Kids (Ages 4–10)',
        'site_name': 'TUSOME.com',
        'welcome': 'Welcome to TUSOME.com!',
        'hero_desc': 'Learning Program for Early Years, Ages 4–10',
        'kids_learning_alt': 'Kids Learning',
        'login': 'Login',
        'logout': 'Logout',
        'my_dashboard': 'My Dashboard',
        'admin_dashboard': 'Admin Dashboard',
        'create_account': 'CREATE YOUR FREE ACCOUNT',
        'hi_user': 'Hi {username}!',
    },
    'sw': {
        'title': 'Elimu ya Mtandaoni kwa Watoto (Miaka 4–10)',
        'site_name': 'TUSOME.com',
        'welcome': 'Karibu kwenye TUSOME.com!',
        'hero_desc': 'Programu ya Elimu ya Miaka ya Mapema, Miaka 4–10',
        'kids_learning_alt': 'Watoto Wanajifunza',
        'login': 'Ingia',
        'logout': 'Toka',
        'my_dashboard': 'Dashibodi Yangu',
        'admin_dashboard': 'Dashibodi ya Msimamizi',
        'create_account': 'TENGUA AKAUTI YAKO BURE',
        'hi_user': 'Habari {username}!',
    }
}

# --- Helper ---
def get_locale():
    return request.cookies.get('lang', 'en')

@app.context_processor
def inject_translations():
    lang = get_locale()
    def translate(key, **kwargs):
        text = LANGUAGES.get(lang, LANGUAGES['en']).get(key, f'{{{key}}}')
        # Support simple placeholders like {username}
        try:
            return text.format(**kwargs)
        except:
            return text
    return dict(_=translate)

# --- Language switcher route ---
@app.route('/set_lang/<lang>')
def set_lang(lang):
    if lang not in ['en', 'sw']:
        lang = 'en'
    response = make_response(redirect(request.referrer or url_for('index')))
    response.set_cookie('lang', lang, max_age=60*60*24*30)  # 30 days
    return response

# CLASSROOM MATERIALS ROUTES
@app.route('/classroom')
@login_required
def classroom():
    """Classroom page for learners to view study materials"""
    # Get all classroom materials from database
    materials = list(mongo.db.classroom_materials.find().sort('uploaded_at', -1))
    return render_template('classroom.html', materials=materials)

@app.route('/admin/upload_classroom_material', methods=['GET', 'POST'])
@login_required
def upload_classroom_material():
    """Admin page to upload classroom study materials"""
    if current_user.role != 'admin':
        abort(403)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category', 'general')
        grade_level = request.form.get('grade_level', 'all')
        file = request.files.get('file')
        
        if not title or not file:
            flash('Title and file are required.', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to make filename unique
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{filename}"
            
            # Create upload directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Save to database
            material = {
                'title': title,
                'description': description,
                'category': category,
                'grade_level': grade_level,
                'filename': filename,
                'original_filename': file.filename,
                'file_path': file_path,
                'file_type': file.filename.rsplit('.', 1)[1].lower(),
                'file_size': os.path.getsize(file_path),
                'uploaded_by': current_user.id,
                'uploaded_at': datetime.now(UTC),
                'download_count': 0
            }
            
            mongo.db.classroom_materials.insert_one(material)
            flash('Classroom material uploaded successfully!', 'success')
            return redirect(url_for('admin_classroom_materials'))
        else:
            flash('Invalid file type. Allowed types: ' + ', '.join(app.config['ALLOWED_EXTENSIONS']), 'error')
    
    return render_template('upload_classroom_material.html')

@app.route('/admin/classroom_materials')
@login_required
def admin_classroom_materials():
    """Admin view of all classroom materials"""
    if current_user.role != 'admin':
        abort(403)
    
    materials = list(mongo.db.classroom_materials.find().sort('uploaded_at', -1))
    return render_template('admin_classroom_materials.html', materials=materials)

@app.route('/admin/delete_classroom_material/<material_id>', methods=['POST'])
@login_required
def delete_classroom_material(material_id):
    """Delete classroom material"""
    if current_user.role != 'admin':
        abort(403)
    
    material = mongo.db.classroom_materials.find_one({'_id': ObjectId(material_id)})
    if not material:
        abort(404)
    
    # Delete file from filesystem
    if material.get('filename'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], material['filename']))
        except FileNotFoundError:
            pass
    
    # Delete from database
    mongo.db.classroom_materials.delete_one({'_id': ObjectId(material_id)})
    flash('Classroom material deleted successfully!', 'success')
    return redirect(url_for('admin_classroom_materials'))

@app.route('/classroom/download/<material_id>')
@login_required
def download_classroom_material(material_id):
    """Download classroom material and track download count"""
    material = mongo.db.classroom_materials.find_one({'_id': ObjectId(material_id)})
    if not material:
        abort(404)
    
    # Increment download count
    mongo.db.classroom_materials.update_one(
        {'_id': ObjectId(material_id)},
        {'$inc': {'download_count': 1}}
    )
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        material['filename'],
        as_attachment=True,
        download_name=material['original_filename']
    )

@app.route('/classroom/view/<material_id>')
@login_required
def view_classroom_material(material_id):
    """View classroom material directly in browser"""
    material = mongo.db.classroom_materials.find_one({'_id': ObjectId(material_id)})
    if not material:
        abort(404)
    
    # For PDFs, images, and videos, we can display them directly
    file_extension = material.get('file_type', '').lower()
    
    # Check if file can be displayed in browser
    viewable_types = ['pdf', 'png', 'jpg', 'jpeg', 'mp4']
    
    if file_extension in viewable_types:
        file_url = url_for('uploaded_file', filename=material['filename'])
        return render_template('view_material.html', 
                             material=material, 
                             file_url=file_url,
                             file_type=file_extension)
    else:
        # For non-viewable files, redirect to download
        flash('This file type cannot be viewed directly. Please download it.', 'info')
        return redirect(url_for('download_classroom_material', material_id=material_id))

# PROFILE ROUTE
@app.route('/profile')
@login_required
def profile():
    """About Me page displaying current user details and learning activity"""
    # Get user's downloaded materials (materials with download count > 0)
    downloaded_materials = list(mongo.db.classroom_materials.find({
        'download_count': {'$gt': 0}
    }).sort('uploaded_at', -1).limit(6))

    # Get recently accessed materials (mock data - you can implement actual tracking)
    recent_materials = list(mongo.db.classroom_materials.find().sort('uploaded_at', -1).limit(4))

    # Calculate statistics
    total_materials = mongo.db.classroom_materials.count_documents({})
    downloaded_count = len(downloaded_materials)
    recent_count = len(recent_materials)
    completed_count = mongo.db.contents.count_documents({'completed_by': current_user.id})

    # Mock recent activities (you can implement actual activity tracking)
    recent_activities = [
        {
            'icon': 'download',
            'title': 'Downloaded Mathematics Worksheet',
            'description': 'Grade 2 - Addition and Subtraction',
            'time': '2 hours ago'
        },
        {
            'icon': 'book',
            'title': 'Completed Reading Module',
            'description': 'Language Arts - Phonics',
            'time': '1 day ago'
        },
        {
            'icon': 'star',
            'title': 'Achievement Unlocked',
            'description': 'Completed 5 learning modules',
            'time': '2 days ago'
        }
    ]

    return render_template('profile.html',
                         downloaded_materials=downloaded_materials,
                         recent_materials=recent_materials,
                         recent_activities=recent_activities,
                         downloaded_count=downloaded_count,
                         recent_count=recent_count,
                         completed_count=completed_count,
                         total_materials=total_materials,
                         progress_percentage=65,  # Mock progress
                         learning_hours=24,       # Mock learning hours
                         current_streak=7,        # Mock streak
                         certificates_count=3)    # Mock certificates

# MOVIE THEATER ROUTE (SINGLE DEFINITION)
@app.route('/movie_theater')
@login_required
def movie_theater():
    """Movie theater page for educational videos"""
    # Get only active videos from database
    videos = list(mongo.db.educational_videos.find({'is_active': True}).sort('created_at', -1))
    return render_template('movie_theater.html', videos=videos)

# VIDEO MANAGEMENT ROUTES
@app.route('/admin/video_management')
@login_required
def admin_video_management():
    """Admin video management dashboard"""
    if current_user.role != 'admin':
        abort(403)
    
    videos = list(mongo.db.educational_videos.find().sort('created_at', -1))
    return render_template('admin_video_management.html', videos=videos)

@app.route('/admin/add_video', methods=['GET', 'POST'])
@login_required
def add_video():
    """Admin page to add educational videos"""
    if current_user.role != 'admin':
        abort(403)

    if request.method == 'POST':
        video_data = {
            'title': request.form.get('title'),
            'description': request.form.get('description'),
            'youtube_url': request.form.get('youtube_url'),
            'youtube_id': extract_youtube_id(request.form.get('youtube_url')),
            'category': request.form.get('category'),
            'difficulty_level': request.form.get('difficulty_level'),
            'duration': request.form.get('duration'),
            'tags': [tag.strip() for tag in request.form.get('tags', '').split(',') if tag.strip()],
            'is_active': True,
            'created_at': datetime.now(UTC),
            'updated_at': datetime.now(UTC),
            'added_by': current_user.id,
            'view_count': 0,
            'thumbnail_url': f"https://img.youtube.com/vi/{extract_youtube_id(request.form.get('youtube_url'))}/hqdefault.jpg"
        }
        
        mongo.db.educational_videos.insert_one(video_data)
        flash('Educational video added successfully!', 'success')
        return redirect(url_for('admin_video_management'))

    return render_template('add_video.html')

@app.route('/admin/edit_video/<video_id>', methods=['GET', 'POST'])
@login_required
def edit_video(video_id):
    """Edit educational video"""
    if current_user.role != 'admin':
        abort(403)

    video = mongo.db.educational_videos.find_one({'_id': ObjectId(video_id)})
    if not video:
        abort(404)

    if request.method == 'POST':
        update_data = {
            'title': request.form.get('title'),
            'description': request.form.get('description'),
            'youtube_url': request.form.get('youtube_url'),
            'youtube_id': extract_youtube_id(request.form.get('youtube_url')),
            'category': request.form.get('category'),
            'difficulty_level': request.form.get('difficulty_level'),
            'duration': request.form.get('duration'),
            'tags': [tag.strip() for tag in request.form.get('tags', '').split(',') if tag.strip()],
            'updated_at': datetime.now(UTC),
            'thumbnail_url': f"https://img.youtube.com/vi/{extract_youtube_id(request.form.get('youtube_url'))}/hqdefault.jpg"
        }
        
        mongo.db.educational_videos.update_one(
            {'_id': ObjectId(video_id)},
            {'$set': update_data}
        )
        flash('Video updated successfully!', 'success')
        return redirect(url_for('admin_video_management'))

    return render_template('edit_video.html', video=video)

@app.route('/admin/toggle_video/<video_id>', methods=['POST'])
@login_required
def toggle_video(video_id):
    """Toggle video active status"""
    if current_user.role != 'admin':
        abort(403)

    video = mongo.db.educational_videos.find_one({'_id': ObjectId(video_id)})
    if not video:
        abort(404)

    new_status = not video.get('is_active', True)
    mongo.db.educational_videos.update_one(
        {'_id': ObjectId(video_id)},
        {'$set': {'is_active': new_status, 'updated_at': datetime.now(UTC)}}
    )
    
    status_text = "activated" if new_status else "deactivated"
    flash(f'Video {status_text} successfully!', 'success')
    return redirect(url_for('admin_video_management'))

@app.route('/admin/delete_video/<video_id>', methods=['POST'])
@login_required
def delete_video(video_id):
    """Delete educational video"""
    if current_user.role != 'admin':
        abort(403)

    video = mongo.db.educational_videos.find_one({'_id': ObjectId(video_id)})
    if not video:
        abort(404)

    mongo.db.educational_videos.delete_one({'_id': ObjectId(video_id)})
    flash('Video deleted successfully!', 'success')
    return redirect(url_for('admin_video_management'))

# RUN SERVER
if __name__ == '__main__':
    app.run(debug=True)