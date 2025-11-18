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
from datetime import datetime
from pathlib import Path
from io import BytesIO
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 
                                              os.path.expanduser('~/cloud_drive_encrypted'))
app.config['TEMP_FOLDER'] = os.environ.get('TEMP_FOLDER',
                                           os.path.expanduser('~/cloud_drive_temp'))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)

CORS(app)

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
            # NOTE: We do NOT store encryption password on server in E2E
            return jsonify({'success': True})
        
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
            
            users = load_users()
            
            for user_data in users.values():
                if user_data['username'] == username:
                    return jsonify({'success': False, 'message': 'Username already exists'})
            
            user_id = str(len(users) + 1)
            users[user_id] = {
                'username': username,
                'password_hash': generate_password_hash(password)
            }
            save_users(users)
            
            get_user_folder(user_id)
            
            return jsonify({'success': True})
        
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'})
    
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
        if folder_path:
            target_dir = os.path.join(user_folder, folder_path)
            os.makedirs(target_dir, exist_ok=True)
            file_path = os.path.join(target_dir, metadata['encrypted_filename'])
        else:
            file_path = os.path.join(user_folder, metadata['encrypted_filename'])
        
        # Save encrypted blob
        with open(file_path, 'wb') as f:
            f.write(encrypted_blob)
        
        # Save metadata (original name, date, etc)
        metadata['user_id'] = current_user.id
        metadata['encrypted_date'] = datetime.now().isoformat()
        
        with open(file_path + '.meta', 'w') as f:
            json.dump(metadata, f)
        
        return jsonify({'success': True, 'message': f'Uploaded {metadata["original_name"]}'})
    
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'message': f'Upload failed: {str(e)}'})

@app.route('/api/download/<path:file_path>')
@login_required
def download_file(file_path):
    """Send encrypted blob - client will decrypt"""
    try:
        user_folder = get_user_folder(current_user.id)
        encrypted_path = os.path.join(user_folder, file_path)
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
        return jsonify({'success': False, 'message': f'Download failed: {str(e)}'})

@app.route('/api/delete/<path:file_path>', methods=['DELETE'])
@login_required
def delete_file(file_path):
    """Delete encrypted file"""
    try:
        user_folder = get_user_folder(current_user.id)
        encrypted_path = os.path.join(user_folder, file_path)
        meta_path = encrypted_path + '.meta'
        
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        
        if os.path.exists(meta_path):
            os.remove(meta_path)
        
        return jsonify({'success': True, 'message': 'File deleted'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Delete failed: {str(e)}'})

@app.route('/api/delete_folder/<path:folder_path>', methods=['DELETE'])
@login_required
def delete_folder_complete(folder_path):
    """Delete entire folder and all contents"""
    try:
        user_folder = get_user_folder(current_user.id)
        full_path = os.path.join(user_folder, folder_path)
        
        if os.path.exists(full_path) and os.path.isdir(full_path):
            import shutil
            shutil.rmtree(full_path)
            return jsonify({'success': True, 'message': 'Folder deleted completely'})
        
        return jsonify({'success': False, 'message': 'Folder not found'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Delete failed: {str(e)}'})

@app.route('/api/create_folder', methods=['POST'])
@login_required
def create_folder():
    """Create folder"""
    data = request.get_json()
    folder_name = data.get('folder_name')
    parent_path = data.get('parent_path', '')
    
    if not folder_name:
        return jsonify({'success': False, 'message': 'Folder name required'})
    
    try:
        user_folder = get_user_folder(current_user.id)
        
        if parent_path:
            folder_path = os.path.join(user_folder, parent_path, folder_name)
        else:
            folder_path = os.path.join(user_folder, folder_name)
        
        os.makedirs(folder_path, exist_ok=True)
        return jsonify({'success': True, 'message': 'Folder created'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed: {str(e)}'})

if __name__ == '__main__':
    # Enable auto-reload in development
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)
