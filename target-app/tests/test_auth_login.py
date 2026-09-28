"""
Security tests for POST /auth/login.

VULN-001 (CWE-89): the username field must be treated as data, never as SQL.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as portal  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(portal, "DATABASE", str(tmp_path / "portal.db"))
    portal.init_db()
    portal.app.config["TESTING"] = True
    return portal.app.test_client()


def _session(client):
    with client.session_transaction() as s:
        return dict(s)


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT 1, 'admin', 'x', 'admin', 'x' --",
    ],
)
def test_login_rejects_sql_injection_in_username(client, payload):
    resp = client.post(
        "/auth/login", data={"username": payload, "password": "wrong-password"}
    )

    assert resp.status_code == 200
    assert b"Invalid credentials." in resp.data
    assert "user_id" not in _session(client)


def test_login_accepts_valid_credentials(client):
    resp = client.post("/auth/login", data={"username": "admin", "password": "admin"})

    assert resp.status_code == 302
    sess = _session(client)
    assert sess["username"] == "admin"
    assert sess["role"] == "admin"


def test_login_rejects_wrong_password(client):
    resp = client.post("/auth/login", data={"username": "admin", "password": "nope"})

    assert resp.status_code == 200
    assert "user_id" not in _session(client)
