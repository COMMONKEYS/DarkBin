from flask import Flask, request, jsonify
import psycopg2 
import psycopg2.extras
import os
import hashlib
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")

DATABASE_URL = os.environ.get("DATABASE_URL")


# -----------------------
# DATABASE
# -----------------------
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn, cursor


# -----------------------
# INIT TABLES
# -----------------------
def init_db():
    conn, cursor = get_db()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        bio TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        expires TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pasts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        paste_id INTEGER,
        user_id INTEGER,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS profile_comments (
        id SERIAL PRIMARY KEY,
        profile_user_id INTEGER,
        commenter_user_id INTEGER,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS follows (
        id SERIAL PRIMARY KEY,
        follower_id INTEGER,
        following_id INTEGER,
        UNIQUE(follower_id, following_id)
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()


# -----------------------
# HELPERS
# -----------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_session(user_id):
    token = secrets.token_hex(32)
    expires = datetime.utcnow() + timedelta(days=7)

    conn, cursor = get_db()
    cursor.execute(
        "INSERT INTO sessions (token, user_id, expires) VALUES (%s, %s, %s)",
        (token, user_id, expires)
    )
    conn.commit()
    conn.close()

    return token


def get_user(token):
    conn, cursor = get_db()

    cursor.execute(
        "SELECT * FROM sessions WHERE token = %s AND expires > NOW()",
        (token,)
    )
    session_data = cursor.fetchone()

    if not session_data:
        conn.close()
        return None

    cursor.execute("SELECT * FROM users WHERE id = %s", (session_data["user_id"],))
    user = cursor.fetchone()
    conn.close()

    return user


# -----------------------
# AUTH ROUTES
# -----------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    conn, cursor = get_db()

    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id",
            (data["username"], hash_password(data["password"]))
        )
        user_id = cursor.fetchone()["id"]
        conn.commit()
    except:
        conn.close()
        return jsonify({"error": "Username taken"}), 400

    token = create_session(user_id)
    return jsonify({"token": token})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn, cursor = get_db()

    cursor.execute("SELECT * FROM users WHERE username = %s", (data["username"],))
    user = cursor.fetchone()
    conn.close()

    if not user or user["password"] != hash_password(data["password"]):
        return jsonify({"error": "Invalid login"}), 401

    token = create_session(user["id"])
    return jsonify({"token": token})


# -----------------------
# PASTES
# -----------------------
@app.route("/paste", methods=["POST"])
def create_paste():
    token = request.headers.get("Authorization")
    user = get_user(token)

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json

    conn, cursor = get_db()
    cursor.execute(
        "INSERT INTO pasts (user_id, title, content) VALUES (%s, %s, %s)",
        (user["id"], data["title"], data["content"])
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/pastes")
def get_pastes():
    conn, cursor = get_db()
    cursor.execute("SELECT * FROM pasts ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()

    return jsonify(data)


# -----------------------
# COMMENTS
# -----------------------
@app.route("/comment", methods=["POST"])
def comment():
    token = request.headers.get("Authorization")
    user = get_user(token)

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json

    conn, cursor = get_db()
    cursor.execute(
        "INSERT INTO comments (paste_id, user_id, content) VALUES (%s, %s, %s)",
        (data["paste_id"], user["id"], data["content"])
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})


# -----------------------
# FOLLOW SYSTEM
# -----------------------
@app.route("/follow", methods=["POST"])
def follow():
    token = request.headers.get("Authorization")
    user = get_user(token)

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    target_id = request.json["user_id"]

    conn, cursor = get_db()
    try:
        cursor.execute(
            "INSERT INTO follows (follower_id, following_id) VALUES (%s, %s)",
            (user["id"], target_id)
        )
        conn.commit()
    except:
        pass

    conn.close()
    return jsonify({"success": True})


# -----------------------
# PROFILE
# -----------------------
@app.route("/user/<username>")
def get_profile(username):
    conn, cursor = get_db()

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    cursor.execute("SELECT * FROM pasts WHERE user_id = %s", (user["id"],))
    pasts = cursor.fetchall()

    conn.close()

    return jsonify({
        "user": user,
        "pastes": pasts
    })


# -----------------------
# START
# -----------------------
init_db()

if __name__ == "__main__":
    app.run(debug=True)
