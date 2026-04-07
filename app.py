from flask import Flask, request, jsonify, render_template, redirect, make_response
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
# INIT TABLES (SAFE)
# -----------------------
def init_db():
    try:
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
        CREATE TABLE IF NOT EXISTS follows (
            id SERIAL PRIMARY KEY,
            follower_id INTEGER,
            following_id INTEGER,
            UNIQUE(follower_id, following_id)
        );
        """)

        conn.commit()
        conn.close()
        print("DB initialized")

    except Exception as e:
        print("DB init failed:", e)


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


def get_user_from_cookie():
    token = request.cookies.get("auth_token")

    if not token:
        return None

    conn, cursor = get_db()
    cursor.execute(
        "SELECT * FROM sessions WHERE token = %s AND expires > NOW()",
        (token,)
    )
    session = cursor.fetchone()

    if not session:
        conn.close()
        return None

    cursor.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    conn.close()

    return user


# -----------------------
# ROUTES
# -----------------------

@app.route("/")
def index():
    user = get_user_from_cookie()

    conn, cursor = get_db()
    cursor.execute("SELECT * FROM pasts ORDER BY id DESC LIMIT 20")
    pastes = cursor.fetchall()
    conn.close()

    return render_template("index.html", user=user, pastes=pastes)


# -----------------------
# AUTH
# -----------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    conn, cursor = get_db()

    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id",
            (username, hash_password(password))
        )
        user_id = cursor.fetchone()["id"]
        conn.commit()
    except:
        conn.close()
        return render_template("register.html", error="Username taken")

    token = create_session(user_id)

    response = make_response(redirect("/"))
    response.set_cookie("auth_token", token)

    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    conn, cursor = get_db()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or user["password"] != hash_password(password):
        return render_template("login.html", error="Invalid login")

    token = create_session(user["id"])

    response = make_response(redirect("/"))
    response.set_cookie("auth_token", token)

    return response


@app.route("/logout")
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("auth_token")
    return response


# -----------------------
# PASTES
# -----------------------

@app.route("/paste", methods=["POST"])
def create_paste():
    user = get_user_from_cookie()

    if not user:
        return redirect("/login")

    title = request.form.get("title")
    content = request.form.get("content")

    conn, cursor = get_db()
    cursor.execute(
        "INSERT INTO pasts (user_id, title, content) VALUES (%s, %s, %s)",
        (user["id"], title, content)
    )
    conn.commit()
    conn.close()

    return redirect("/")


# -----------------------
# PROFILE
# -----------------------

@app.route("/user/<username>")
def profile(username):
    conn, cursor = get_db()

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        return "User not found", 404

    cursor.execute("SELECT * FROM pasts WHERE user_id = %s", (user["id"],))
    pastes = cursor.fetchall()

    conn.close()

    return render_template("profile.html", user=user, pastes=pastes)


# -----------------------
# STARTUP
# -----------------------

init_db()

if __name__ == "__main__":
    app.run(debug=True)
