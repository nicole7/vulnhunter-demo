# Partition SG-1 (auth)

**Scan scope root**: `/Users/nicolegasperini/Documents/VulnHunter/target-app`
**App-specific file**: `auth.py` (`auth_bp`, prefix `/auth`)
**Entry points**: POST /auth/login, POST /auth/register, POST /auth/forgot, GET|POST /auth/reset, GET /auth/logout
**Reachability**: PRODUCTION. Attacker profile: fully unauthenticated.

## Assigned Inputs

| # | Source Type | Location | Variable | Entry Point | Trust Level |
|---|---|---|---|---|---|
| 1 | HTTP form field | auth.py:48 | `username` | POST /auth/login | unauth |
| 2 | HTTP form field | auth.py:49 | `password` | POST /auth/login | unauth |
| 3 | HTTP form field | auth.py:91 | `username` | POST /auth/register | unauth |
| 4 | HTTP form field | auth.py:92 | `password` | POST /auth/register | unauth |
| 5 | HTTP form field | auth.py:93 | `email` | POST /auth/register | unauth |
| 6 | HTTP form field | auth.py:152 | `username` | POST /auth/forgot | unauth |
| 7 | HTTP query/form | auth.py:174 | `token` | GET/POST /auth/reset | unauth |
| 8 | HTTP form field | auth.py:177 | `password` | POST /auth/reset | unauth |
| 9 | no-input endpoint | auth.py:114 | N/A | GET /auth/logout | unauth (session) |

## Sinks in scope
- S1 SQLi (f-string) auth.py:55 login query
- S8 SSTI candidate render_template_string auth.py:66,107,169,192 (error/msg/token)
- S12 Weak crypto MD5 auth.py:23,162 (password hash + reset token)
- S13 Predictable reset token auth.py:161-162 `md5(f"{id}:{int(time.time())}")`

## Shared Infrastructure
- `get_db()` app.py:25 — sqlite3 connection
- `_hash_password()` auth.py:21 — MD5
- Flask session / `secret_key` app.py:19-20 — hardcoded key `super-secret-dev-key-1234` (S14) → session forgery

## Threat model
No app-layer auth on /auth/*. No caller identity binding. Session values forgeable due to hardcoded secret key. SQLi at login enables auth bypass (`' OR '1'='1`). Reset token predictable → account takeover.
