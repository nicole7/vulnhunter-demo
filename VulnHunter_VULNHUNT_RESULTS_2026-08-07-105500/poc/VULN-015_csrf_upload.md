# VULN-015 — CSRF on POST /files/upload

- **CWE**: 352
- **Severity**: Medium
- **Endpoint**: `POST /files/upload`

## Static Verification Trace

```
1. Handler is a state-changing POST (writes a file + DB row) with NO CSRF token.
   -> files.py:74-93  upload()
2. Full-tree grep: no CSRFProtect / flask-wtf / SameSite cookie config.
3. ATTACK: Attacker page with a multipart auto-submit form targeting /files/upload
   causes a logged-in victim to upload attacker-chosen content (filename
   attacker-controlled -> chains to VULN-008 traversal write).
4. IMPACT: Cross-origin forced upload as the victim.
```

## Attacker gains
Force a victim to upload attacker-controlled files (distinct handler from restore), enabling the traversal-write chain.

## Expected vs Actual
- Secure app: CSRF token required on the form; SameSite cookies.
- Vulnerable app: no token.
