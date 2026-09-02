# Partition SG-4 (admin) — NAV Class Results

Scope: `/Users/nicolegasperini/Documents/VulnHunter/target-app/admin.py`
Class group: NAV (CSRF, IDOR, auth bypass, CVB, identity spoofing, confused deputy, mass assignment, param pollution)

## Disposition Summary

| # | Variable | Entry Point | Disposition |
|---|----------|-------------|-------------|
| 17 | session[role] | all /admin/* | CANDIDATE (VULN-401 auth bypass, VULN-402 CVB) |
| 18 | user_id | GET /admin/delete/<id> | CANDIDATE (VULN-403 CSRF) |
| 19 | user_id | GET /admin/promote/<id> | CANDIDATE (VULN-404 CSRF) |
| 20 | host | POST /admin/ping | CROSS-CLASS (INJ) |
| 21 | q | GET /admin/audit | CROSS-CLASS (INJ) |
| 26 | N/A dashboard | GET /admin/ | DESIGN-INTENT (admin reads user list; auth flaw already captured by #17) |

---

## [VULN-401] Auth decision on forgeable session role (privilege escalation)
- **Input**: #17 session `role` cookie (admin.py:30)
- **Class**: CWE-290 (Identity/Auth Spoofing) / CWE-287
- **Severity**: High+ (any party escalates to admin; all /admin/* state changes)
- **Location**: admin.py:25-31 `_require_admin`; app.py:20 hardcoded `secret_key`
- **Gate 0**: NOT intended — a security check trusting an attacker-forgeable value. Not exempt.
- **Gate 1**: `_require_admin` called from every admin handler (lines 69,81,94,116,158). Production.
- **Gate 2a**: `session["role"]` is client-side cookie; `secret_key="super-secret-dev-key-1234"` is hardcoded/public (app.py:20), so any party forges a cookie with `role=admin`.
- **Gate 2b**: None. Only a string equality check; no server-side session store, no signature secret protection.
- **Gate 3**: Attacker with no/low privilege gains full admin: delete users, promote to admin, run commands (via #20), SQLi/SSTI (via #21).
- **Data Flow**: forged cookie -> Flask session (app.py:20) -> `session.get("role")` (admin.py:30) -> access granted to all admin handlers.
- **Root Cause**: Authorization derived from unauthenticated, client-controlled, forgeable cookie signed with a hardcoded secret.

## [VULN-402] Conditional Validation Bypass — absent role fails open? (verified fails closed)
- **Input**: #17 absent `role` key
- **Analysis**: If `role` absent, `session.get("role")` returns `None != "admin"` -> `abort(403)`. Fails CLOSED.
- **Disposition**: SAFE for CVB (absent-input path denies). The exploit is forging, not omitting — covered by VULN-401. Recorded per mandatory absent-input analysis.

## [VULN-403] CSRF — state-changing user deletion via GET
- **Input**: #18 `user_id` (admin.py:79)
- **Class**: CWE-352
- **Severity**: Medium (requires authenticated admin victim to visit attacker page)
- **Location**: admin.py:79-85
- **Gate 0**: Deleting users is intended, but doing it via unprotected GET with no CSRF token is not. Not exempt.
- **Gate 1**: Route registered on `admin_bp`, production.
- **Resource ID Gate (639)**: `user_id` is `<int>`-typed; deleting ANY user is the admin panel's design purpose (no per-resource ownership model for admin). IDOR not applicable — admin legitimately manages all users. CSRF is the live NAV finding.
- **Gate 2b**: No CSRF token; GET method is trivially forgeable (`<img src>`). Flask provides no automatic CSRF here.
- **Gate 3**: Attacker CSRFs a logged-in admin into deleting arbitrary users (destructive, single request).
- **Root Cause**: State-changing operation exposed over GET with no anti-CSRF token.

## [VULN-404] CSRF — privilege escalation via GET promote
- **Input**: #19 `user_id` (admin.py:92)
- **Class**: CWE-352
- **Severity**: High (grants admin role to attacker-chosen account, single GET)
- **Location**: admin.py:92-98
- **Gate 0/1**: As VULN-403; not exempt, production.
- **Resource ID Gate (639)**: Admin promoting any user is design-intent; no CSRF token or method guard is the flaw.
- **Gate 2b**: No CSRF token; GET-forgeable.
- **Gate 3**: CSRF forces admin browser to promote attacker's account to admin -> persistent privilege escalation.
- **Root Cause**: State-changing role escalation over unprotected GET.

---

## Cross-Class Referrals
- **CROSS-CLASS** (input #20, admin.py:123-124, suspected class: INJ) — `host` -> `subprocess.run(shell=True)` command injection.
- **CROSS-CLASS** (input #21, admin.py:166, suspected class: INJ) — `q` -> f-string SQL LIKE injection.
- **CROSS-CLASS** (input #21, admin.py:177, suspected class: INJ) — `q` -> `render_template_string` SSTI/RCE.

## Post-Trace Authorization Helper Coverage Audit
All five handlers (dashboard, delete_user, promote_user, ping, audit_log) DO invoke `_require_admin()`. No sibling handler omits the check -> no CWE-862 gap. The defect is that `_require_admin` itself is bypassable (VULN-401), not that it is absent.
