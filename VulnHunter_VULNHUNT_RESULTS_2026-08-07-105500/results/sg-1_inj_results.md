# Partition SG-1 — INJ Class Results

Scope: `target-app/auth.py` (auth_bp, /auth/*). Attacker: unauthenticated.

## Disposition Summary

| # | Input | Disposition | Reason |
|---|-------|-------------|--------|
| 1 | username (login) | **CANDIDATE** (VULN-INJ-001) | SQLi f-string sink auth.py:55 |
| 2 | password (login) | SAFE | MD5-hashed (hex only) before query at :50/:55; no injection chars survive |
| 3 | username (register) | SAFE (INJ) | Parameterized INSERT `?` auth.py:98-101. Reflected via `{{msg}}` but Jinja autoescape neutralizes; msg is literal string not user echo |
| 4 | password (register) | SAFE | MD5-hashed then parameterized :94,:99 |
| 5 | email (register) | SAFE | Parameterized INSERT `?` auth.py:99-101 |
| 6 | username (forgot) | SAFE | Parameterized SELECT `?` auth.py:155 |
| 7 | token (reset) | SAFE (INJ) | Parameterized SELECT `?` auth.py:180; rendered via `{{token}}` autoescaped. CROSS-CLASS(LOG): predictable/forgeable token → account takeover (S13, out of INJ scope) |
| 8 | password (reset) | SAFE | MD5-hashed then parameterized :185 |
| 9 | logout (no input) | NO-MATCH | No INJ sink |

## SSTI Assessment (S8 — render_template_string :66,107,169,192)
SAFE. All four calls use **fixed constant templates** (LOGIN/REGISTER/FORGOT/RESET_TEMPLATE); user input passed only as **context data** (`error=`, `msg=`, `token=`), never as the template string. Jinja2 autoescape (default in Flask) escapes rendered values. Not SSTI, not XSS.

---

## [VULN-INJ-001] SQL Injection in login — authentication bypass
- **Input**: #1: HTTP form field `username`, POST /auth/login
- **Class**: CWE-89: SQL Injection
- **Severity**: High+ (unauthenticated, full auth bypass + DB read)
- **Location**: auth.py:55 (executed :56)
- **Gate 0 (intended?)**: No. Query construction is not a feature the caller is meant to control.
- **Gate 1 (reachable?)**: Yes. `/auth/login` is a registered production route, unauthenticated.
- **Gate 2a (attacker-controlled?)**: Yes. `username = request.form.get("username")` :48 → interpolated raw at :55.
- **Gate 2b (sanitization?)**: None. f-string `f"...username = '{username}'..."` — no escaping, no parameterization. `password` side is MD5 hex, but username is fully raw.
- **Gate 3 (new capability?)**: Yes. `' OR '1'='1' --` returns a user row → authenticated as arbitrary/first user (typically admin) with zero credentials. Also enables UNION-based DB exfiltration.
- **Entry Point**: POST /auth/login
- **Data Flow**: request.form["username"] (auth.py:48) → `query` f-string (auth.py:55) → `db.execute(query)` (auth.py:56)
- **Root Cause**: Username interpolated directly into SQL via f-string instead of a parameterized query.
- **Exploitability**: Trivial. `username=' OR '1'='1' -- ` with any password bypasses auth and logs in as the first matching row.

## Cross-class notes (for NAV/LOG partitions)
- CROSS-CLASS(LOG): #7 reset token predictable (md5(id:epoch), S13) → account takeover.
- CROSS-CLASS(LOG): MD5 password hashing (S12, auth.py:23) and hardcoded Flask secret_key (S14, app.py:19-20) → session forgery.
