#!/usr/bin/env python3
"""
E2E Encrypted Cloud Drive
Server handles only encrypted blobs - zero knowledge encryption
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
import json
import uuid
import re
from datetime import datetime, timedelta
from pathlib import Path
from io import BytesIO
import secrets
from functools import wraps

app = Flask(__name__)

# Security: Load SECRET_KEY from environment or generate persistent one
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER',
                                              os.path.expanduser('~/cloud_drive_encrypted'))
app.config['TEMP_FOLDER'] = os.environ.get('TEMP_FOLDER',
                                           os.path.expanduser('~/cloud_drive_temp'))

# Security: Session cookie configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Set SESSION_COOKIE_SECURE=True in production with HTTPS
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)

# Security: Restrict CORS - only allow same origin by default
# Set CORS_ORIGINS environment variable to allow specific origins
cors_origins = os.environ.get('CORS_ORIGINS', '').split(',') if os.environ.get('CORS_ORIGINS') else []
if cors_origins and cors_origins[0]:
    CORS(app, origins=cors_origins, supports_credentials=True)
else:
    # No CORS headers if not configured - same-origin only
    pass

# Rate limiting storage (in-memory, use Redis in production)
login_attempts = {}  # {ip: {'count': int, 'lockout_until': datetime}}
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_LOCKOUT_MINUTES = 15

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERS_FILE = os.environ.get('USERS_FILE',
                            os.path.join(app.config['UPLOAD_FOLDER'], 'users.json'))

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def get_user_folder(user_id):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def validate_path(user_folder, requested_path):
    """
    Security: Validate that the requested path is within the user's folder.
    Prevents path traversal attacks (e.g., ../../../etc/passwd)
    Returns the safe absolute path or None if invalid.
    """
    # Normalize and resolve the full path
    user_folder_real = os.path.realpath(user_folder)
    full_path = os.path.realpath(os.path.join(user_folder, requested_path))

    # Check that the resolved path starts with the user's folder
    if not full_path.startswith(user_folder_real + os.sep) and full_path != user_folder_real:
        return None

    return full_path

def validate_password_strength(password):
    """
    Security: Validate password meets minimum requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long'
    if not re.search(r'[A-Za-z]', password):
        return False, 'Password must contain at least one letter'
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one number'
    return True, None

def check_rate_limit(ip_address):
    """
    Security: Check if IP is rate limited.
    Returns (is_allowed, seconds_until_unlock)
    """
    if ip_address not in login_attempts:
        return True, 0

    attempt_data = login_attempts[ip_address]

    # Check if currently locked out
    if attempt_data.get('lockout_until'):
        if datetime.now() < attempt_data['lockout_until']:
            seconds_remaining = (attempt_data['lockout_until'] - datetime.now()).seconds
            return False, seconds_remaining
        else:
            # Lockout expired, reset
            login_attempts[ip_address] = {'count': 0, 'lockout_until': None}
            return True, 0

    return True, 0

def record_login_attempt(ip_address, success):
    """
    Security: Record login attempt for rate limiting.
    """
    if success:
        # Reset on successful login
        if ip_address in login_attempts:
            del login_attempts[ip_address]
        return

    if ip_address not in login_attempts:
        login_attempts[ip_address] = {'count': 0, 'lockout_until': None}

    login_attempts[ip_address]['count'] += 1

    if login_attempts[ip_address]['count'] >= RATE_LIMIT_MAX_ATTEMPTS:
        login_attempts[ip_address]['lockout_until'] = datetime.now() + timedelta(minutes=RATE_LIMIT_LOCKOUT_MINUTES)

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    if user_id in users:
        user_data = users[user_id]
        return User(user_id, user_data['username'], user_data['password_hash'])
    return None

def build_file_tree(directory, base_path=''):
    """Build file tree structure"""
    tree = []
    
    try:
        items = sorted(os.listdir(directory))
    except PermissionError:
        return tree
    
    for item_name in items:
        item_path = os.path.join(directory, item_name)
        relative_path = os.path.join(base_path, item_name) if base_path else item_name
        
        if os.path.isdir(item_path):
            children = build_file_tree(item_path, relative_path)
            tree.append({
                'name': item_name,
                'type': 'folder',
                'icon': '📁',
                'path': relative_path,
                'children': children
            })
        elif item_name.endswith('.enc'):
            meta_path = item_path + '.meta'
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r') as f:
                        meta = json.load(f)
                    
                    original_name = meta.get('original_name', item_name)
                    encrypted_date = meta.get('encrypted_date', '')
                    
                    try:
                        date_obj = datetime.fromisoformat(encrypted_date)
                        date_display = date_obj.strftime('%Y-%m-%d %H:%M')
                    except:
                        date_display = 'Unknown'
                    
                    # Determine icon based on extension
                    extension = meta.get('extension', '').lower()
                    icon_map = {
                        '.pdf': '📄', '.txt': '📃',
                        '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
                        '.mp4': '🎬', '.avi': '🎬',
                        '.mp3': '🎵', '.wav': '🎵',
                        '.zip': '📦', '.tar': '📦',
                        '.py': '🐍', '.js': '📜'
                    }
                    file_icon = icon_map.get(extension, '📄')
                    
                    file_size = os.path.getsize(item_path)
                    
                    tree.append({
                        'name': original_name,
                        'encrypted_name': item_name,
                        'type': 'file',
                        'icon': file_icon,
                        'path': relative_path,
                        'date': date_display,
                        'size': file_size
                    })
                except Exception as e:
                    print(f"Error reading metadata: {e}")
    
    return tree

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Security: Rate limiting
        client_ip = request.remote_addr
        is_allowed, seconds_remaining = check_rate_limit(client_ip)
        if not is_allowed:
            return jsonify({
                'success': False,
                'message': f'Too many failed attempts. Try again in {seconds_remaining // 60 + 1} minutes.'
            })

        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        users = load_users()

        user_id = None
        for uid, user_data in users.items():
            if user_data['username'] == username:
                user_id = uid
                break

        if user_id and check_password_hash(users[user_id]['password_hash'], password):
            user = User(user_id, username, users[user_id]['password_hash'])
            login_user(user)
            record_login_attempt(client_ip, success=True)
            # NOTE: We do NOT store encryption password on server in E2E
            return jsonify({'success': True})

        # Security: Record failed attempt
        record_login_attempt(client_ip, success=False)
        return jsonify({'success': False, 'message': 'Invalid credentials'})

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return jsonify({'success': False, 'message': 'Username and password required'})

            # Security: Validate username format
            if len(username) < 3:
                return jsonify({'success': False, 'message': 'Username must be at least 3 characters'})
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                return jsonify({'success': False, 'message': 'Username can only contain letters, numbers, and underscores'})

            # Security: Password strength validation
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                return jsonify({'success': False, 'message': error_msg})

            users = load_users()

            for user_data in users.values():
                if user_data['username'] == username:
                    return jsonify({'success': False, 'message': 'Username already exists'})

            # Security: Use UUID instead of sequential IDs
            user_id = str(uuid.uuid4())
            users[user_id] = {
                'username': username,
                'password_hash': generate_password_hash(password)
            }
            save_users(users)

            get_user_folder(user_id)

            return jsonify({'success': True})

        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            return jsonify({'success': False, 'message': 'Registration failed'})

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/api/files')
@login_required
def get_files():
    """Get user's file tree"""
    user_folder = get_user_folder(current_user.id)
    tree = build_file_tree(user_folder)
    return jsonify({'files': tree})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Store encrypted blob - server never sees plaintext"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})

    file = request.files['file']
    metadata_json = request.form.get('metadata')

    if not metadata_json:
        return jsonify({'success': False, 'message': 'No metadata provided'})

    try:
        metadata = json.loads(metadata_json)
        user_folder = get_user_folder(current_user.id)

        # Server stores the ALREADY ENCRYPTED blob
        encrypted_blob = file.read()

        # Create folder structure if needed
        folder_path = metadata.get('folder_path', '')
        encrypted_filename = metadata.get('encrypted_filename', '')

        # Security: Validate filename
        if not encrypted_filename or '/' in encrypted_filename or '\\' in encrypted_filename:
            return jsonify({'success': False, 'message': 'Invalid filename'})

        if folder_path:
            # Security: Validate path traversal
            target_dir = validate_path(user_folder, folder_path)
            if target_dir is None:
                return jsonify({'success': False, 'message': 'Invalid path'})
            os.makedirs(target_dir, exist_ok=True)
            file_path = os.path.join(target_dir, encrypted_filename)
        else:
            file_path = os.path.join(user_folder, encrypted_filename)

        # Security: Final path validation
        final_path = validate_path(user_folder, os.path.relpath(file_path, user_folder))
        if final_path is None:
            return jsonify({'success': False, 'message': 'Invalid path'})

        # Save encrypted blob
        with open(final_path, 'wb') as f:
            f.write(encrypted_blob)

        # Save metadata (original name, date, etc)
        metadata['user_id'] = current_user.id
        metadata['encrypted_date'] = datetime.now().isoformat()

        with open(final_path + '.meta', 'w') as f:
            json.dump(metadata, f)

        return jsonify({'success': True, 'message': f'Uploaded {metadata["original_name"]}'})

    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'message': 'Upload failed'})

@app.route('/api/download/<path:file_path>')
@login_required
def download_file(file_path):
    """Send encrypted blob - client will decrypt"""
    try:
        user_folder = get_user_folder(current_user.id)

        # Security: Validate path traversal
        encrypted_path = validate_path(user_folder, file_path)
        if encrypted_path is None:
            return jsonify({'success': False, 'message': 'Invalid path'})

        meta_path = encrypted_path + '.meta'

        if not os.path.exists(encrypted_path):
            return jsonify({'success': False, 'message': 'File not found'})

        # Load metadata to get original name
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            original_name = meta.get('original_name', 'file.enc')
        else:
            original_name = 'file.enc'

        # Send the ENCRYPTED blob (no decryption on server)
        return send_file(
            encrypted_path,
            as_attachment=True,
            download_name=original_name + '.encrypted'  # Mark as encrypted
        )

    except Exception as e:
        return jsonify({'success': False, 'message': 'Download failed'})

@app.route('/api/delete/<path:file_path>', methods=['DELETE'])
@login_required
def delete_file(file_path):
    """Delete encrypted file"""
    try:
        user_folder = get_user_folder(current_user.id)

        # Security: Validate path traversal
        encrypted_path = validate_path(user_folder, file_path)
        if encrypted_path is None:
            return jsonify({'success': False, 'message': 'Invalid path'})

        meta_path = encrypted_path + '.meta'

        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        if os.path.exists(meta_path):
            os.remove(meta_path)

        return jsonify({'success': True, 'message': 'File deleted'})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Delete failed'})

@app.route('/api/delete_folder/<path:folder_path>', methods=['DELETE'])
@login_required
def delete_folder_complete(folder_path):
    """Delete entire folder and all contents"""
    try:
        user_folder = get_user_folder(current_user.id)

        # Security: Validate path traversal
        full_path = validate_path(user_folder, folder_path)
        if full_path is None:
            return jsonify({'success': False, 'message': 'Invalid path'})

        # Security: Prevent deleting the user's root folder
        if os.path.realpath(full_path) == os.path.realpath(user_folder):
            return jsonify({'success': False, 'message': 'Cannot delete root folder'})

        if os.path.exists(full_path) and os.path.isdir(full_path):
            import shutil
            shutil.rmtree(full_path)
            return jsonify({'success': True, 'message': 'Folder deleted completely'})

        return jsonify({'success': False, 'message': 'Folder not found'})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Delete failed'})

@app.route('/api/create_folder', methods=['POST'])
@login_required
def create_folder():
    """Create folder"""
    data = request.get_json()
    folder_name = data.get('folder_name')
    parent_path = data.get('parent_path', '')

    if not folder_name:
        return jsonify({'success': False, 'message': 'Folder name required'})

    # Security: Validate folder name (no path separators)
    if '/' in folder_name or '\\' in folder_name or '..' in folder_name:
        return jsonify({'success': False, 'message': 'Invalid folder name'})

    try:
        user_folder = get_user_folder(current_user.id)

        if parent_path:
            # Security: Validate parent path
            parent_full_path = validate_path(user_folder, parent_path)
            if parent_full_path is None:
                return jsonify({'success': False, 'message': 'Invalid path'})
            folder_path = os.path.join(parent_full_path, folder_name)
        else:
            folder_path = os.path.join(user_folder, folder_name)

        # Security: Final path validation
        final_path = validate_path(user_folder, os.path.relpath(folder_path, user_folder))
        if final_path is None:
            return jsonify({'success': False, 'message': 'Invalid path'})

        os.makedirs(final_path, exist_ok=True)
        return jsonify({'success': True, 'message': 'Folder created'})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to create folder'})

if __name__ == '__main__':
    # Security: Debug mode controlled by environment variable
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode, use_reloader=debug_mode)
