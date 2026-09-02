"""
Authentication blueprint: login, registration, logout, and password reset.
"""

import hashlib
import os
import time
from flask import Blueprint, request, session, redirect, url_for, render_template_string, g

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# ------------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------------

def _get_db():
    from app import get_db
    return get_db()


def _hash_password(pw: str) -> str:
    # VULN: MD5 is cryptographically broken and unsuitable for password storage.
    return hashlib.md5(pw.encode()).hexdigest()


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------

LOGIN_TEMPLATE = """
<!doctype html>
<title>Employee Portal — Login</title>
<h2>Employee Portal</h2>
<form method="post">
  <label>Username <input name="username"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Log in</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<p><a href="/auth/forgot">Forgot password?</a></p>
"""


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        hashed = _hash_password(password)

        db = _get_db()
        # VULN: SQL injection — username is interpolated directly into the query.
        # An attacker can supply  ' OR '1'='1  to bypass authentication entirely.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
        user = db.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("files.list_files"))
        else:
            error = "Invalid credentials."

    return render_template_string(LOGIN_TEMPLATE, error=error)


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------

REGISTER_TEMPLATE = """
<!doctype html>
<title>Register</title>
<h2>Create Account</h2>
<form method="post">
  <label>Username <input name="username"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <label>Email    <input name="email"></label><br>
  <button type="submit">Register</button>
</form>
{% if msg %}<p>{{ msg }}</p>{% endif %}
"""


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    msg = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        hashed = _hash_password(password)

        db = _get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed, email),
            )
            db.commit()
            msg = "Account created. <a href='/auth/login'>Log in</a>"
        except Exception as exc:
            msg = f"Error: {exc}"

    return render_template_string(REGISTER_TEMPLATE, msg=msg)


# ------------------------------------------------------------------
# Logout
# ------------------------------------------------------------------

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


# ------------------------------------------------------------------
# Forgot / reset password
# ------------------------------------------------------------------

FORGOT_TEMPLATE = """
<!doctype html>
<title>Forgot Password</title>
<h2>Password Reset</h2>
<form method="post">
  <label>Username <input name="username"></label><br>
  <button type="submit">Send reset token</button>
</form>
{% if token %}<p>Your reset token: <strong>{{ token }}</strong></p>{% endif %}
"""

RESET_TEMPLATE = """
<!doctype html>
<title>Reset Password</title>
<h2>Reset Password</h2>
<form method="post">
  <input type="hidden" name="token" value="{{ token }}">
  <label>New password <input name="password" type="password"></label><br>
  <button type="submit">Reset</button>
</form>
{% if msg %}<p>{{ msg }}</p>{% endif %}
"""


@auth_bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    token = None
    if request.method == "POST":
        username = request.form.get("username", "")
        db = _get_db()
        user = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user:
            # VULN: Predictable token — based solely on user ID and current timestamp
            # truncated to seconds, making it trivially brute-forceable within a short
            # window.
            raw = f"{user['id']}:{int(time.time())}"
            token = hashlib.md5(raw.encode()).hexdigest()
            db.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (token, user["id"]),
            )
            db.commit()

    return render_template_string(FORGOT_TEMPLATE, token=token)


@auth_bp.route("/reset", methods=["GET", "POST"])
def reset():
    token = request.args.get("token", request.form.get("token", ""))
    msg = None
    if request.method == "POST":
        new_pw = request.form.get("password", "")
        db = _get_db()
        user = db.execute(
            "SELECT id FROM users WHERE password = ?", (token,)
        ).fetchone()
        if user:
            db.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (_hash_password(new_pw), user["id"]),
            )
            db.commit()
            msg = "Password updated. <a href='/auth/login'>Log in</a>"
        else:
            msg = "Invalid or expired token."

    return render_template_string(RESET_TEMPLATE, token=token, msg=msg)
