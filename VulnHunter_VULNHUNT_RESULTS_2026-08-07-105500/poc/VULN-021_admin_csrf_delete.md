# VULN-021 — CSRF / State Change over GET: Admin Delete User

- **CWE**: 352
- **Severity**: Medium
- **Endpoint**: `GET /admin/delete/<int:user_id>`
- **Sink**: `admin.py:79-85`

## Static Verification Trace

```
1. Destructive DELETE performed on a GET request with no CSRF token.
   -> admin.py:79   @admin_bp.route("/delete/<int:user_id>")   # GET
   -> admin.py:83   DELETE FROM users WHERE id = <user_id>

2. Because it is a GET with no token, any embedded resource triggers it:
     <img src="http://target/admin/delete/2">
   A logged-in admin viewing attacker content silently deletes user 2.

3. IMPACT: Cross-origin forced deletion of user accounts as the admin victim.
```

## Attacker gains
Delete arbitrary user accounts by luring an admin to load an `<img>`/link.

## Expected vs Actual
- Secure app: POST + CSRF token + SameSite cookies; no state change on GET.
- Vulnerable app: GET with no token.
