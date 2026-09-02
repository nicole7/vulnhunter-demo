# VULN-002 — Hardcoded Flask secret_key → Session Forgery

- **CWE**: 798 / 330
- **Severity**: High+
- **Location**: `app.py:20`
- **Subsumes**: NAV auth-bypass dups (sg-2 VULN-201, sg-3 NAV-01, sg-4 VULN-401)

## Static Data Flow Trace

```
1. SOURCE: secret key is a literal constant in source
   -> app.py:20   app.secret_key = "super-secret-dev-key-1234"

2. USE: Flask signs EVERY session cookie with this key (itsdangerous HMAC).
   Session dict is stored client-side, integrity-protected only by this key.

3. ATTACK: Attacker reads the key from source (or guesses this common dev value),
   then mints a cookie with:
       {"user_id": 1, "username": "admin", "role": "admin"}
   using flask.sessions.SecureCookieSessionInterface with the known key.

4. IMPACT: Every _require_admin (admin.py:30) and _require_login (files.py:26,
   reports.py:27) check trusts session["role"]/session["user_id"]. Forged cookie
   grants admin access to /admin/*, and arbitrary identity to /files/*, /reports/*.
```

## Attacker gains
Forge an admin session with no credentials → full access to every authenticated and admin-only endpoint. Root enabler for the CMDi/IDOR findings behind forgeable sessions.

## Expected vs Actual
- Secure app: random per-deploy secret from env/secrets manager → attacker cannot sign a valid cookie.
- Vulnerable app: fixed known key → attacker signs any session payload.
