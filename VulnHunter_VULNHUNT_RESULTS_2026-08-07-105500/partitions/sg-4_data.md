# Partition SG-4 (admin)

**Scan scope root**: `/Users/nicolegasperini/Documents/VulnHunter/target-app`
**App-specific file**: `admin.py` (`admin_bp`, prefix `/admin`)
**Entry points**: GET /admin/ dashboard, GET /admin/delete/<id>, GET /admin/promote/<id>, POST /admin/ping, GET /admin/audit
**Reachability**: PRODUCTION. Attacker profile: any party who forges a session cookie with `role=admin` (hardcoded secret key).

## Assigned Inputs

| # | Source Type | Location | Variable | Entry Point | Trust Level |
|---|---|---|---|---|---|
| 17 | Session cookie | admin.py:30 | `session[role]` | all /admin/* | authed (forgeable → admin) |
| 18 | HTTP path param | admin.py:80 | `user_id` | GET /admin/delete/<id> | admin |
| 19 | HTTP path param | admin.py:93 | `user_id` | GET /admin/promote/<id> | admin |
| 20 | HTTP form field | admin.py:117 | `host` | POST /admin/ping | admin |
| 21 | HTTP query param | admin.py:159 | `q` | GET /admin/audit | admin |
| 26 | no-input endpoint | admin.py:67 | N/A | GET /admin/ (dashboard) | admin |

## Sinks in scope
- S2 SQLi (f-string LIKE) admin.py:166 `... action LIKE '%{q}%' OR detail LIKE '%{q}%'`
- S4 Command injection (shell=True) admin.py:123-124 `f"ping -c 2 {host}"`
- S7 SSTI render_template_string + user var admin.py:177 reflects `q`
- S8 SSTI candidate render_template_string admin.py:72,127

## Shared Infrastructure
- `get_db()` app.py:25
- `_require_admin()` admin.py:25 — `session.get("role") != "admin"`, trusts forgeable cookie (S14)
- Flask session / `secret_key` app.py:19-20 — hardcoded (S14)

## Threat model
`_require_admin` trusts a forgeable role cookie → privilege escalation to admin. `host` → shell (command injection). `q` → raw SQL (SQLi) and render_template_string (SSTI). `user_id` path params → SQL delete/promote.
