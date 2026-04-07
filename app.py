from flask import Flask, request, jsonify, render_template, redirect, make_response
from flask_wtf import CSRFProtect
import psycopg2
import psycopg2.extras
import os
import hashlib
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# ✅ FIX CSRF
csrf = CSRFProtect(app)

# ✅ DATABASE
DATABASE_URL = os.environ.get("DATABASE_URL")

# -----------------------
# DATABASE CONNECTION
# -----------------------
def get_db():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL is missing")

    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn, cursor

# -----------------------
# INIT DATABASE
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
    CREATE TABLE IF NOT EXISTS follows (
        id SERIAL PRIMARY KEY,
        follower_id INTEGER,
        following_id INTEGER,
        UNIQUE(follower_id, following_id)
    );
    """)

    conn.commit()
    conn.close()

# -----------------------
# JINJA FIX (naturaltime)
# -----------------------
@app.template_filter('naturaltime')
def naturaltime(value):
    now = datetime.utcnow()
    diff = now - value

    if diff.days > 0:
        return f"{diff.days}d ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600}h ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60}m ago"
    return "just now"

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
def home():
    conn, cursor = get_db()
    cursor.execute("SELECT * FROM pasts ORDER BY id DESC LIMIT 20")
    pasts = cursor.fetchall()
    conn.close()

    return render_template("index.html", pasts=pasts, user=get_user())

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
    except Exception as e:
        conn.close()
        return render_template("register.html", error="Username already taken")

    token = create_session(user_id)

    resp = make_response(redirect("/"))
    resp.set_cookie("session", token)
    return resp

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

    resp = make_response(redirect("/"))
    resp.set_cookie("session", token)
    return resp

# -----------------------
# PASTE SYSTEM
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

@app.route("/paste/<int:id>")
def view_paste(id):
    conn, cursor = get_db()

    cursor.execute("SELECT * FROM pasts WHERE id = %s", (id,))
    paste = cursor.fetchone()

    cursor.execute("SELECT * FROM comments WHERE paste_id = %s", (id,))
    comments = cursor.fetchall()

    conn.close()

    return render_template("paste.html", paste=paste, comments=comments, user=get_user())

# -----------------------
# COMMENTS
# -----------------------
@app.route("/comment", methods=["POST"])
def comment():
    user = get_user()
    if not user:
        return redirect("/login")

    paste_id = request.form.get("paste_id")
    content = request.form.get("content")

    conn, cursor = get_db()
    cursor.execute(
        "INSERT INTO comments (paste_id, user_id, content) VALUES (%s, %s, %s)",
        (paste_id, user["id"], content)
    )
    conn.commit()
    conn.close()

    return redirect(f"/paste/{paste_id}")

# -----------------------
# ERROR HANDLER (VERY IMPORTANT)
# -----------------------
@app.errorhandler(Exception)
def handle_error(e):
    return f"""
    <h1>ERROR</h1>
    <pre>{str(e)}</pre>
    """, 500

# -----------------------
# STARTUP
# -----------------------
init_db()

if __name__ == "__main__":
    app.run(debug=True)
