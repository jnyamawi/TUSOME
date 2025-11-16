import os
import re
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
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {
    'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'mp4', 'zip'
}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- App secrets & database ---
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']          # Must set in Render
app.config['MONGO_URI'] = os.environ['MONGO_URI']           # Must set in Render

# --- Mail configuration (for password reset) ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']    # Gmail username
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']    # Gmail app password
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

# ----------------------------
# ROUTES
# ----------------------------

@app.route('/')
def index():
    contents = list(mongo.db.contents.find().sort('created_at', -1))
    return render_template('index.html', contents=contents)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if mongo.db.users.find_one({'username': username}):
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        hashed = generate_password_hash(password)
        mongo.db.users.insert_one({
            'username': username,
            'email': email,
            'password': hashed,
            'role': 'learner',
            'created_at': datetime.now(UTC)
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_doc = mongo.db.users.find_one({'username': username})
        if user_doc and check_password_hash(user_doc['password'], password):
            user = User(user_doc)
            login_user(user)
            flash('Logged in successfully!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('learner_dashboard'))

        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

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

# ----------------------------
# PASSWORD RESET
# ----------------------------

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
            try:
                mail.send(msg)
            except Exception as e:
                flash(f'Error sending email: {e}', 'danger')
        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html')

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

# ----------------------------
# RUN SERVER
# ----------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
