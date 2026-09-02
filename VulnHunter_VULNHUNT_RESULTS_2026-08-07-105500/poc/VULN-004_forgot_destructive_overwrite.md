# VULN-004 — Unauthenticated Destructive Password Overwrite

- **CWE**: 620 / 640
- **Severity**: High
- **Endpoint**: `POST /auth/forgot` (unauthenticated)
- **Sink**: `auth.py:163-167`

## Static Data Flow Trace

```
1. ENTRY: Attacker POST /auth/forgot with username=admin (any valid username).
   No ownership proof, no email verification, no rate limit.
   -> auth.py:152  username from form
   -> auth.py:154-156  lookup user by username

2. SINK: the user's live password is OVERWRITTEN with the reset token immediately,
   before any confirmation step.
   -> auth.py:163-166  UPDATE users SET password = <token> WHERE id = <victim>
   -> auth.py:167      db.commit()

3. IMPACT: The victim's existing password no longer works (it was replaced by the
   token md5 digest). Victim is locked out. Repeat across all usernames = mass DoS.
   Combined with VULN-003 (predictable token) this is also an ATO primitive.
```

## Attacker gains
Unauthenticated denial-of-service: overwrite/lock out any or every user's password by username alone. Chains with VULN-003 for takeover.

## Expected vs Actual
- Secure app: reset request only emails a token out-of-band; the live password is never changed until the user proves possession of the token AND submits a new password.
- Vulnerable app: password column clobbered on the spot for any submitted username.
