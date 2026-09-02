# VULN-001 — SQL Injection / Auth Bypass in Login (`username`)

- **CWE**: 89 (SQLi) → 290 (auth bypass)
- **Severity**: High+
- **Endpoint**: `POST /auth/login` (unauthenticated)
- **Sink**: `auth.py:55-56`

## Static Data Flow Trace

```
1. ENTRY: Attacker sends POST /auth/login
   body: username=' OR '1'='1' --  &  password=anything
   -> auth.py:48   username = request.form.get("username", "")

2. PROPAGATION: username interpolated into an f-string SQL query, no escaping/params
   -> auth.py:55   query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"

3. SINK: query executed directly
   -> auth.py:56   user = db.execute(query).fetchone()
   Concrete SQL produced:
     SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '<md5>'
   The `--` comments out the password check; `OR '1'='1'` matches the first row.

4. IMPACT: fetchone() returns the first user row (id=1 = 'admin').
   -> auth.py:59-61  session["user_id"]/username/role set to admin.
   Attacker is authenticated as admin WITHOUT valid credentials.
   UNION variants also allow reading arbitrary columns/tables (DB read).
```

## Attacker gains
Full authentication bypass; logs in as `admin` (role=admin) unauthenticated, plus arbitrary DB read via UNION.

## Expected vs Actual
- Secure app: parameterized query → the literal string is treated as a username, no match, login denied.
- Vulnerable app: injected boolean tautology matches admin row → session established.
