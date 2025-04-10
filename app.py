import os
from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session
from flask_pymongo import PyMongo
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.json_util import dumps

# Flask App Initialization
app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/teacher_interface"
mongo = PyMongo(app)

# Secret key for session and flash messages
app.secret_key = 'your_secret_key'

# Image Upload Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# MongoDB Connection Setup
client = MongoClient("mongodb://localhost:27017/teacher_interface")
db = client['teacher_interface']

# MongoDB Collections
users_collection = db['users']
achievements_collection = db['achievements']
notifications_collection = db['notifications']
projects_collection = db['projects']
settings_collection = db['settings']
mark_absent_collection = db['mark_absent']

# Utility function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes for the application
# Route for the basic page (home page)
# Keep only one @app.route('/')
@app.route('/')
def home():
    return render_template('basic.html')

@app.route('/basic')
def basic():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    elif 'admin' in session:
        return redirect(url_for('admin_dashboard'))
    return render_template('basic.html')  # Use 'index.html' if it's your main page

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('registration'))

        if users_collection.find_one({'email': email}):
            flash('Email is already registered!', 'error')
            return redirect(url_for('registration'))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'name': name,
            'email': email,
            'phone': phone,
            'password': hashed_password,
            'profile_img': None
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('index'))

    return render_template('registration.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user = users_collection.find_one({'email': email})
    if user and check_password_hash(user['password'], password):
        session['user'] = {
            'name': user['name'],
            'email': user['email'],
            'phone': user['phone'],
            'profile_img': user.get('profile_img')
        }
        flash(f'Welcome, {user["name"]}!', 'success')
        return redirect(url_for('dashboard'))

    flash('Invalid email or password.', 'error')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('index'))
    return render_template('dashboard.html', user=session['user'])



@app.route('/admin_registration', methods=['GET', 'POST'])
def admin_registration():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('admin_registration'))

        if admin_collection.find_one({'email': email}):
            flash('Email is already registered!', 'error')
            return redirect(url_for('admin_registration'))

        hashed_password = generate_password_hash(password)
        admin_collection.insert_one({
            'name': name,
            'email': email,
            'phone': phone,
            'password': hashed_password,
            'profile_img': None
        })
        flash('Admin registration successful! Please log in.', 'success')
        return redirect(url_for('admin_login'))

    return render_template('registration2.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        admin = admin_collection.find_one({'email': email})
        if admin and check_password_hash(admin['password'], password):
            session['admin'] = {
                'name': admin['name'],
                'email': admin['email'],
                'phone': admin['phone'],
                'profile_img': admin.get('profile_img')
            }
            flash(f'Welcome, {admin["name"]}!', 'success')
            return redirect(url_for('admin_dashboard'))  # Redirect to dashboard2.html

        flash('Invalid email or password.', 'error')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        flash('Please log in to access the admin dashboard.', 'error')
        return redirect(url_for('admin_login'))
    
    return render_template('dashboard2.html', admin=session['admin'])  # Ensuring admin data is passed


@app.route('/profile')
def profile():
    if 'user' in session:
        return render_template('profile.html', user=session['user'])
    flash('You need to log in first.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('admin', None)  # Also logout admin if they are logged in
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        flash('You need to log in first.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('settings'))

        settings_data = {
            'user_email': session['user']['email'],
            'email': email,
            'password': generate_password_hash(password),
            'updated_at': datetime.utcnow()
        }

        settings_collection.update_one(
            {'user_email': session['user']['email']},
            {'$set': settings_data},
            upsert=True
        )

        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))

    user_settings = settings_collection.find_one({'user_email': session['user']['email']})
    return render_template('settings.html', user=session['user'], settings=user_settings)

@app.route('/timetable')
def timetable():
    if 'user' in session:
        return render_template('timetable.html', user=session['user'])
    flash('You need to log in first.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/project')
def project():
    if 'user' in session:
        return render_template('projects.html', user=session['user'])
    flash('You need to log in first.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/notifications')
def notifications():
    if 'user' in session:
        notifications = list(notifications_collection.find({"user_email": session['user']['email']}).sort('timestamp', -1))
        return render_template('notifications.html', notifications=notifications)
    flash('You need to log in first.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/clear_notifications', methods=['POST'])
def clear_user_notifications():
    if 'user' in session:
        notifications_collection.delete_many({"user_email": session['user']['email']})
        return jsonify({"success": True, "message": "Notifications cleared successfully."}), 200
    return jsonify({"success": False, "message": "Unauthorized access."}), 401

@app.route('/reports')
def reports():
    if 'user' in session:
        return render_template('reports.html', user=session['user'])
    flash('You need to log in first.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/add_achievement', methods=['POST'])
def add_achievement():
    if 'user' in session:
        data = request.json
        achievement_content = data.get("content")

        if not achievement_content:
            return jsonify({"success": False, "message": "Achievement content is required."}), 400

        achievement = {
            "teacher_id": session['user']['email'],
            "content": achievement_content,
            "timestamp": datetime.now()
        }
        achievements_collection.insert_one(achievement)

        notification = {
            "user_email": session['user']['email'],
            "message": f"New achievement shared by {session['user']['name']}: {achievement_content}",
            "status": "unread",
            "timestamp": datetime.now()
        }
        notifications_collection.insert_one(notification)

        return jsonify({"success": True, "message": "Achievement added successfully."}), 200

    return jsonify({"success": False, "message": "Unauthorized access."}), 401

@app.route('/add_project_idea', methods=['POST'])
def add_project_idea():
    if 'user' in session:
        data = request.json
        project_idea_content = data.get("content")

        if not project_idea_content:
            return jsonify({"success": False, "message": "Project idea content is required."}), 400

        project_idea = {
            "teacher_id": session['user']['email'],
            "content": project_idea_content,
            "timestamp": datetime.now()
        }
        projects_collection.insert_one(project_idea)

        notification = {
            "user_email": session['user']['email'],
            "message": f"New project idea shared by {session['user']['name']}: {project_idea_content}",
            "timestamp": datetime.now()
        }
        notifications_collection.insert_one(notification)

        return jsonify({"success": True, "message": "Project idea shared successfully!"})
    return jsonify({"success": False, "message": "Unauthorized access."}), 403

@app.route('/fetch_notifications', methods=['GET'])
def fetch_notifications():
    if 'user' in session:
        notifications = list(notifications_collection.find({"user_email": session['user']['email'], "status": "unread"}))
        return jsonify(notifications)
    return jsonify({"error": "Unauthorized access"}), 401

@app.route('/notifications/mark_read', methods=['POST'])
def mark_notification_read():
    if 'user' in session:
        notification_id = request.json.get("notification_id")
        notifications_collection.update_one({"_id": notification_id}, {"$set": {"status": "read"}})
        return jsonify({"success": True, "message": "Notification marked as read."}), 200
    return jsonify({"success": False, "message": "Unauthorized access."}), 403

# Main Block to Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
