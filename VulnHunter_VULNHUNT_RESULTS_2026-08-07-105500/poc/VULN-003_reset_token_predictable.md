# VULN-003 — Predictable Password Reset Token (ATO)

- **CWE**: 330 / 340 / 640 / 639
- **Severity**: High+
- **Endpoints**: `POST /auth/forgot`, `GET/POST /auth/reset` (unauthenticated)
- **Sink**: `auth.py:161-162` (generation), `auth.py:180` (consumption)

## Static Data Flow Trace

```
1. ENTRY: Attacker POST /auth/forgot with username=admin
   -> auth.py:152  username from form
   -> auth.py:154  SELECT id FROM users WHERE username='admin'  -> id = 1

2. TOKEN GEN: token = md5("{id}:{int(time.time())}")
   -> auth.py:161  raw = f"{user['id']}:{int(time.time())}"
   -> auth.py:162  token = hashlib.md5(raw.encode()).hexdigest()
   Entropy = (small integer id) x (unix second). No secret, no expiry.

3. TOKEN STORED AS PASSWORD:
   -> auth.py:163-166  UPDATE users SET password = <token> WHERE id = 1

4. ATTACK: Attacker knows id=1 and approximate epoch (server time ~ now).
   Brute-force md5("1:<t>") for t in a few-thousand-second window (trivial, offline).
   Then POST /auth/reset?token=<guess> with password=NEW
   -> auth.py:180  SELECT id FROM users WHERE password = <token>
   -> auth.py:183-185  UPDATE password = md5(NEW) for admin

5. IMPACT: Attacker sets admin's password -> full account takeover of any user
   including admin, unauthenticated.
```

## Attacker gains
Unauthenticated account takeover of any user (including admin) by guessing the low-entropy reset token.

## Expected vs Actual
- Secure app: `secrets.token_urlsafe(32)`, stored hashed, with expiry, separate from password column.
- Vulnerable app: token = md5(id:epoch), brute-forceable, and IS the new password.
