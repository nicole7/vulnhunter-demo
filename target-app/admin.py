"""
Admin panel: user management, system diagnostics, and audit log viewer.
"""

import subprocess
import os
from flask import (
    Blueprint,
    request,
    session,
    render_template_string,
    abort,
    redirect,
    url_for,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _get_db():
    from app import get_db
    return get_db()


def _require_admin():
    # VULN: Missing authentication check — the function only checks that a role
    # key exists in the session, but any logged-in user can set role='admin' by
    # manipulating the client-side session cookie (the secret key is hardcoded
    # and publicly visible in app.py, so an attacker can forge it trivially).
    if session.get("role") != "admin":
        abort(403)


# ------------------------------------------------------------------
# User list
# ------------------------------------------------------------------

USERS_TEMPLATE = """
<!doctype html>
<title>Admin — Users</title>
<h2>User Management</h2>
<table border="1">
  <tr><th>ID</th><th>Username</th><th>Role</th><th>Email</th><th>Actions</th></tr>
  {% for u in users %}
  <tr>
    <td>{{ u['id'] }}</td>
    <td>{{ u['username'] }}</td>
    <td>{{ u['role'] }}</td>
    <td>{{ u['email'] }}</td>
    <td>
      <a href="/admin/delete/{{ u['id'] }}">Delete</a> |
      <a href="/admin/promote/{{ u['id'] }}">Promote</a>
    </td>
  </tr>
  {% endfor %}
</table>
<hr>
<h3>System Diagnostics</h3>
<form method="post" action="/admin/ping">
  Host: <input name="host" value="127.0.0.1">
  <button type="submit">Ping</button>
</form>
<p><a href="/admin/audit">Audit Log</a></p>
"""


@admin_bp.route("/")
def dashboard():
    _require_admin()
    db = _get_db()
    users = db.execute("SELECT id, username, role, email FROM users").fetchall()
    return render_template_string(USERS_TEMPLATE, users=users)


# ------------------------------------------------------------------
# Delete user — missing CSRF protection (bonus issue)
# ------------------------------------------------------------------

@admin_bp.route("/delete/<int:user_id>")
def delete_user(user_id: int):
    _require_admin()
    db = _get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return redirect(url_for("admin.dashboard"))


# ------------------------------------------------------------------
# Promote user to admin
# ------------------------------------------------------------------

@admin_bp.route("/promote/<int:user_id>")
def promote_user(user_id: int):
    _require_admin()
    db = _get_db()
    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    db.commit()
    return redirect(url_for("admin.dashboard"))


# ------------------------------------------------------------------
# Ping diagnostic — command injection
# ------------------------------------------------------------------

PING_TEMPLATE = """
<!doctype html>
<title>Admin — Ping</title>
<h2>Ping Result</h2>
<pre>{{ output }}</pre>
<p><a href="/admin/">Back</a></p>
"""


@admin_bp.route("/ping", methods=["POST"])
def ping():
    _require_admin()
    host = request.form.get("host", "127.0.0.1")

    # VULN: Command injection — the host parameter is interpolated directly into
    # a shell string. An attacker with admin access can supply:
    #   127.0.0.1; cat /etc/passwd
    # to execute arbitrary OS commands on the server.
    cmd = f"ping -c 2 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr

    return render_template_string(PING_TEMPLATE, output=output)


# ------------------------------------------------------------------
# Audit log — SSTI via search filter
# ------------------------------------------------------------------

AUDIT_TEMPLATE = """
<!doctype html>
<title>Admin — Audit Log</title>
<h2>Audit Log</h2>
<form method="get">
  Filter: <input name="q" value="{{ q }}"> <button type="submit">Search</button>
</form>
<table border="1">
  <tr><th>ID</th><th>User</th><th>Action</th><th>Detail</th><th>Time</th></tr>
  {% for row in rows %}
  <tr>
    <td>{{ row['id'] }}</td>
    <td>{{ row['user_id'] }}</td>
    <td>{{ row['action'] }}</td>
    <td>{{ row['detail'] }}</td>
    <td>{{ row['ts'] }}</td>
  </tr>
  {% endfor %}
</table>
"""


@admin_bp.route("/audit")
def audit_log():
    _require_admin()
    q = request.args.get("q", "")
    db = _get_db()

    if q:
        # VULN: SQL injection in audit log search — the filter term is
        # interpolated directly into the LIKE clause.
        rows = db.execute(
            f"SELECT * FROM audit_log WHERE action LIKE '%{q}%' OR detail LIKE '%{q}%'"
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM audit_log").fetchall()

    # VULN: Server-Side Template Injection — the user-supplied query string `q`
    # is passed into render_template_string as a raw variable and then reflected
    # inside the template without sanitization. If Jinja2 auto-escape is off (the
    # default for render_template_string), an attacker can inject:
    #   {{ config }}   or   {{ ''.__class__.__mro__[1].__subclasses__() }}
    # to read application config or gain full RCE via Python introspection.
    return render_template_string(AUDIT_TEMPLATE, rows=rows, q=q)
