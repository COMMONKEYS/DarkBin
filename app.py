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
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set")

    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
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


def get_user():
    token = request.cookies.get("session")

    if not token:
        return None

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
# ROUTES (HTML)
# -----------------------
@app.route("/")
def index():
    user = get_user()
    return render_template("index.html", user=user)


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
    except Exception:
        conn.close()
        return render_template("register.html", error="Username taken")

    token = create_session(user_id)

    response = make_response(redirect("/"))
    response.set_cookie("session", token, httponly=True)
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
    response.set_cookie("session", token, httponly=True)
    return response


@app.route("/logout")
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("session")
    return response


# -----------------------
# PASTES
# -----------------------
@app.route("/create", methods=["POST"])
def create_paste():
    user = get_user()
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


@app.route("/pastes")
def view_pastes():
    conn, cursor = get_db()
    cursor.execute("SELECT * FROM pasts ORDER BY id DESC")
    pastes = cursor.fetchall()
    conn.close()

    return render_template("pastes.html", pastes=pastes)


# -----------------------
# API ROUTES (JSON)
# -----------------------
@app.route("/api/pastes")
def api_pastes():
    conn, cursor = get_db()
    cursor.execute("SELECT * FROM pasts ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()

    return jsonify(data)


# -----------------------
# START
# -----------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
