# VULN-007 — No Rate Limiting / Lockout on Auth Endpoints

- **CWE**: 307
- **Severity**: Medium
- **Locations**: `auth.py:44` (login), `auth.py:148` (forgot), `auth.py:172` (reset)

## Static Verification Trace

```
1. There is NO counter, lockout, CAPTCHA, or delay in login/forgot/reset handlers.
   -> auth.py:44-66   login: unlimited POST attempts
   -> auth.py:148-169 forgot: unlimited
   -> auth.py:172-192 reset: unlimited token submissions

2. Full-tree grep confirms no Flask-Limiter / no rate-limit decorator wired.

3. IMPACT: Amplifies VULN-003 — the predictable reset token can be brute-forced
   online at unlimited request rate against /auth/reset. Also enables credential
   stuffing against /auth/login.
```

## Attacker gains
Unbounded online brute force — makes token/credential guessing practical.

## Expected vs Actual
- Secure app: Flask-Limiter (e.g. 5/min) + account lockout on the auth routes.
- Vulnerable app: no control present (config-provable absence).
