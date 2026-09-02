"""
Target app entry point.

A simple internal employee portal: login, file sharing, report generation,
and an admin panel for managing users. Intentionally vulnerable for use as a
VulnHunter demo target.
"""

import os
from flask import Flask, g, session
import sqlite3

from auth import auth_bp
from files import files_bp
from admin import admin_bp
from reports import reports_bp

# VULN: Hardcoded secret key — anyone who reads this source can forge sessions.
app = Flask(__name__)
app.secret_key = "super-secret-dev-key-1234"

DATABASE = os.path.join(os.path.dirname(__file__), "portal.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'employee',
            email    TEXT
        );
        CREATE TABLE IF NOT EXISTS documents (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id  INTEGER NOT NULL,
            filename  TEXT NOT NULL,
            path      TEXT NOT NULL,
            created   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            action    TEXT,
            detail    TEXT,
            ts        TEXT DEFAULT (datetime('now'))
        );
        INSERT OR IGNORE INTO users (username, password, role, email)
        VALUES
            ('admin',   '21232f297a57a5a743894a0e4a801fc3', 'admin',    'admin@corp.internal'),
            ('alice',   '6384e2b2184bcbf58eccf10ca7a6563c', 'employee', 'alice@corp.internal'),
            ('bob',     'e99a18c428cb38d5f260853678922e03', 'employee', 'bob@corp.internal');
        """
    )
    db.commit()
    db.close()


app.register_blueprint(auth_bp)
app.register_blueprint(files_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(reports_bp)


@app.route("/")
def index():
    from flask import redirect, url_for
    return redirect(url_for("auth.login"))


if __name__ == "__main__":
    init_db()
    # Debug mode exposes the Werkzeug interactive debugger — do not use in prod.
    app.run(debug=True, port=5000)
