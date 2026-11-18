import re
import os
import hmac
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "shahzain.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

if len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError("Set a random SECRET_KEY (at least 32 characters) before starting the app.")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        email TEXT
    )""")

    columns = {
        row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()
    }
    if "email" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT")

    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
        "ON users(email COLLATE NOCASE)"
    )
    db.commit()
    db.close()

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        saved = session.get("_csrf", "")
        if not sent or not saved or not hmac.compare_digest(sent, saved):
            abort(400, "Invalid form token. Refresh the page and try again.")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        user = get_db().execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3 or len(username) > 24 or not username.replace("_", "").isalnum():
            flash("Username must be 3-24 characters and contain only letters, numbers, or underscores.", "danger")
            return render_template("register.html")

        if not email or len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        if len(password) < 12:
            flash("Password must be at least 12 characters long.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        try:
            get_db().execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password))
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("This username or email is already registered.", "danger")
            return render_template("register.html")

        flash("Your account has been created successfully. Please sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["_csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        time.sleep(0.7)
        flash("Incorrect username or password.", "danger")
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out successfully.", "success")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute(
        "SELECT username, role, created_at FROM users WHERE id=?",
        (session["user_id"],)
    ).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)

@app.route("/admin")
@admin_required
def admin():
    users = get_db().execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id DESC"
    ).fetchall()
    return render_template("admin.html", users=users)

@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message="Your request could not be processed."), 400

@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The page you requested could not be found."), 404

if __name__ == "__main__":
    init_db()
    # Local-only development server. Do not expose this directly to the internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
