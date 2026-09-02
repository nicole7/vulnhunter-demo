# VULN-022 — CSRF / State Change over GET: Admin Promote to Admin

- **CWE**: 352
- **Severity**: High (persistent privilege escalation)
- **Endpoint**: `GET /admin/promote/<int:user_id>`
- **Sink**: `admin.py:92-98`

## Static Verification Trace

```
1. Privilege-granting UPDATE performed on a GET request with no CSRF token.
   -> admin.py:92   @admin_bp.route("/promote/<int:user_id>")   # GET
   -> admin.py:96   UPDATE users SET role = 'admin' WHERE id = <user_id>

2. ATTACK: attacker (holding a normal account id=2) lures an admin to load:
     <img src="http://target/admin/promote/2">
   The admin's browser sends the GET with the admin cookie; user 2 becomes admin.

3. IMPACT: Persistent privilege escalation — attacker's own account is elevated
   to admin (distinct, higher impact than the delete CSRF).
```

## Attacker gains
Permanently escalate an attacker-chosen account to admin via a forced admin GET.

## Expected vs Actual
- Secure app: POST + CSRF token + SameSite cookies.
- Vulnerable app: GET with no token performs the role change.
