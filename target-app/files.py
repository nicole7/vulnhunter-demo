"""
File upload and download endpoints.
"""

import os
import pickle
import base64
from flask import (
    Blueprint,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    send_file,
    abort,
)

files_bp = Blueprint("files", __name__, url_prefix="/files")

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _require_login():
    if "user_id" not in session:
        abort(401)


def _get_db():
    from app import get_db
    return get_db()


# ------------------------------------------------------------------
# File listing
# ------------------------------------------------------------------

LIST_TEMPLATE = """
<!doctype html>
<title>My Files</title>
<h2>My Documents</h2>
<ul>
{% for doc in docs %}
  <li><a href="/files/download/{{ doc['id'] }}">{{ doc['filename'] }}</a>
      &nbsp; <a href="/files/preview/{{ doc['id'] }}">preview</a></li>
{% endfor %}
</ul>
<hr>
<h3>Upload</h3>
<form method="post" enctype="multipart/form-data" action="/files/upload">
  <input type="file" name="file"><br>
  <button type="submit">Upload</button>
</form>
<p><a href="/auth/logout">Log out</a> | <a href="/reports/generate">Reports</a></p>
"""


@files_bp.route("/", methods=["GET"])
def list_files():
    _require_login()
    db = _get_db()
    docs = db.execute(
        "SELECT id, filename FROM documents WHERE owner_id = ?",
        (session["user_id"],),
    ).fetchall()
    return render_template_string(LIST_TEMPLATE, docs=docs)


# ------------------------------------------------------------------
# Upload
# ------------------------------------------------------------------

@files_bp.route("/upload", methods=["POST"])
def upload():
    _require_login()
    f = request.files.get("file")
    if not f or f.filename == "":
        return "No file selected", 400

    # VULN: No extension or MIME-type validation — an attacker can upload a .py
    # or .sh file. If the server ever executes files from this directory, that's
    # remote code execution.
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)

    db = _get_db()
    db.execute(
        "INSERT INTO documents (owner_id, filename, path) VALUES (?, ?, ?)",
        (session["user_id"], f.filename, dest),
    )
    db.commit()
    return redirect(url_for("files.list_files"))


# ------------------------------------------------------------------
# Download — path traversal
# ------------------------------------------------------------------

@files_bp.route("/download/<int:doc_id>")
def download(doc_id: int):
    _require_login()
    db = _get_db()

    # VULN: Broken object-level authorization — the query does NOT check that
    # owner_id matches the session user. Any authenticated user can download
    # any document by guessing its integer ID.
    doc = db.execute(
        "SELECT * FROM documents WHERE id = ?", (doc_id,)
    ).fetchone()
    if not doc:
        abort(404)

    return send_file(doc["path"], as_attachment=True)


# ------------------------------------------------------------------
# Preview — path traversal via query parameter
# ------------------------------------------------------------------

PREVIEW_TEMPLATE = """
<!doctype html>
<title>File Preview</title>
<h2>Preview: {{ filename }}</h2>
<pre>{{ content }}</pre>
<p><a href="/files/">Back</a></p>
"""


@files_bp.route("/preview/<int:doc_id>")
def preview(doc_id: int):
    _require_login()
    db = _get_db()
    doc = db.execute(
        "SELECT * FROM documents WHERE id = ?", (doc_id,)
    ).fetchone()
    if not doc:
        abort(404)

    # VULN: Path traversal — doc["path"] is stored verbatim from the upload.
    # If a prior upload stored a path like "../../etc/passwd", preview will
    # read and display that arbitrary file.
    with open(doc["path"], "r", errors="replace") as fh:
        content = fh.read(8192)

    return render_template_string(
        PREVIEW_TEMPLATE, filename=doc["filename"], content=content
    )


# ------------------------------------------------------------------
# Restore from clipboard — insecure deserialization
# ------------------------------------------------------------------

RESTORE_TEMPLATE = """
<!doctype html>
<title>Restore File</title>
<h2>Restore from Clipboard</h2>
<p>Paste the base64-encoded file data exported from another session.</p>
<form method="post">
  <textarea name="data" rows="6" cols="80"></textarea><br>
  <button type="submit">Restore</button>
</form>
{% if msg %}<p>{{ msg }}</p>{% endif %}
"""


@files_bp.route("/restore", methods=["GET", "POST"])
def restore():
    _require_login()
    msg = None
    if request.method == "POST":
        raw = request.form.get("data", "")
        try:
            # VULN: Insecure deserialization — user-supplied base64 data is decoded
            # and passed directly to pickle.loads. An attacker can craft a payload
            # that executes arbitrary OS commands when deserialized.
            blob = base64.b64decode(raw)
            obj = pickle.loads(blob)
            filename = obj.get("filename", "restored_file.dat")
            content = obj.get("content", b"")
            dest = os.path.join(UPLOAD_DIR, filename)
            with open(dest, "wb") as fh:
                fh.write(content if isinstance(content, bytes) else content.encode())
            db = _get_db()
            db.execute(
                "INSERT INTO documents (owner_id, filename, path) VALUES (?, ?, ?)",
                (session["user_id"], filename, dest),
            )
            db.commit()
            msg = f"Restored: {filename}"
        except Exception as exc:
            msg = f"Restore failed: {exc}"

    return render_template_string(RESTORE_TEMPLATE, msg=msg)
