# VULN-014 — CSRF on POST /files/restore

- **CWE**: 352
- **Severity**: Medium
- **Endpoint**: `POST /files/restore`

## Static Verification Trace

```
1. Handler is a state-changing POST with NO CSRF token check.
   -> files.py:168-195  restore(): reads request.form["data"], writes a file + DB row.
2. Full-tree grep: no flask-wtf / CSRFProtect / SameSite config.
3. ATTACK: Attacker hosts an auto-submitting form:
     <form action="http://target/files/restore" method="POST">
       <input name="data" value="<base64 pickle payload>">
     </form><script>document.forms[0].submit()</script>
   A logged-in victim visiting the page issues the POST with their cookie.
4. IMPACT: Victim's session triggers restore -> chains to VULN-010 pickle RCE.
```

## Attacker gains
Force a victim's browser to trigger the restore endpoint (and thus pickle deserialization) cross-origin.

## Expected vs Actual
- Secure app: CSRFProtect token required; SameSite=Lax/Strict cookies.
- Vulnerable app: no token — any cross-origin POST with the session cookie is honored.
