# Partition SG-1 (auth) — NAV Class Results

**Scope**: `target-app/auth.py` (`auth_bp`, `/auth`). Attacker: fully unauthenticated.
**Threat model**: No app-layer auth on `/auth/*`; no caller identity binding; hardcoded secret key.

## Input Dispositions

| # | Input | Entry | Disposition | Notes |
|---|---|---|---|---|
| 1 | `username` | POST /auth/login | CANDIDATE (NAV auth bypass) + CROSS-CLASS(INJ) | See VULN-101; SQLi sink is INJ |
| 2 | `password` | POST /auth/login | SAFE | Hashed then constrained in SQL; no NAV sink. Hash is INJ/crypto concern |
| 3 | `username` | POST /auth/register | SAFE | Parameterized INSERT; self-service registration (Missing-Auth exempt: caller IS subject) |
| 4 | `password` | POST /auth/register | SAFE | Parameterized; weak-hash is LOG/crypto (CROSS-CLASS candidate for S12) |
| 5 | `email` | POST /auth/register | SAFE | Parameterized INSERT; no NAV sink |
| 6 | `username` | POST /auth/forgot | CANDIDATE (NAV account takeover) | See VULN-102 |
| 7 | `token` | GET/POST /auth/reset | CANDIDATE (NAV predictable-token ATO) | See VULN-103 |
| 8 | `password` | POST /auth/reset | SAFE | Only written after token match; gated by #7 |
| 9 | logout | GET /auth/logout | DESIGN-INTENT | Clears own session; no cross-principal effect |

CROSS-CLASS notes (not owned by NAV):
- CROSS-CLASS (#1, auth.py:55, INJ/SQLi f-string).
- CROSS-CLASS (#4, auth.py:23, LOG/weak-crypto MD5 password hash — S12).
- CROSS-CLASS (SSTI render_template_string auth.py:66,107,169,192 — INJ; inputs reflected).
- Session forgery via hardcoded `secret_key` (app.py:19-20, S14) is out of assigned file scope — note for LOG/config partition: enables identity spoofing of `session["role"]`/`user_id`.

---

## Candidates

### [VULN-101] Login SQL injection yields full authentication bypass
- **Input**: #1 `username` (POST /auth/login form field)
- **Class**: CWE-89 (sink, INJ) → CWE-306/290 outcome (NAV auth bypass)
- **Severity**: High+ (unauthenticated → any account / admin access)
- **Location**: auth.py:55-62
- **Gate 0**: Not intended — login is meant to authenticate, not to accept `' OR '1'='1`.
- **Gate 1**: Reachable — production route `/auth/login`, POST.
- **Gate 2a**: Attacker-controlled — raw form field, unauthenticated.
- **Gate 2b**: None — f-string interpolation, no escaping/parameterization.
- **Gate 3**: New capability — attacker logs in as first/any user (payload `' OR '1'='1' -- `), then `session["role"]`/`user_id` set from that row → authenticated + role-privileged access to `files.list_files`.
- **Entry Point**: POST /auth/login
- **Data Flow**: request.form `username` (48) → f-string `query` (55) → `db.execute` (56) → `user` truthy → `session[...]` set (59-61).
- **Root Cause**: Username interpolated into SQL; truthy row grants session.
- **Note**: SQLi sink itself is CROSS-CLASS(INJ). NAV owns the auth-bypass outcome.

### [VULN-102] Forgot-password overwrites victim password with reset token (unauth account takeover)
- **Input**: #6 `username` (POST /auth/forgot)
- **Class**: CWE-640 (weak password recovery) / CWE-306 (no auth, cross-principal state change)
- **Severity**: High+ (unauthenticated attacker takes over ANY account by username)
- **Location**: auth.py:152-167
- **Gate 0**: NOT exempt — this is a security-critical flow; overwriting the stored password of an arbitrary user on demand is not intended behavior. Missing-Auth: cross-principal state change (target selected by attacker-supplied username).
- **Gate 1**: Reachable — production `/auth/forgot` POST.
- **Gate 2a**: Attacker-controlled — arbitrary username, unauthenticated. No ownership/identity binding to the named account.
- **Gate 2b**: None — parameterized lookup validates the name exists but performs no authorization.
- **Gate 3**: New capability — attacker sets ANY user's stored `password` column to a predictable token (161-166), instantly invalidating the victim's login and enabling takeover via the returned/derivable token. No email/out-of-band delivery.
- **Entry Point**: POST /auth/forgot
- **Data Flow**: form `username` (152) → lookup id (154) → `raw = "{id}:{epoch}"` (161) → md5 token (162) → `UPDATE users SET password = token WHERE id` (163-166) → token rendered back (169).
- **Root Cause**: Reset flow mutates the target account's credential with no caller-to-account binding and returns the token to the requester.

### [VULN-103] Predictable reset token = single-value access control (account takeover)
- **Input**: #7 `token` (GET/POST /auth/reset)
- **Class**: CWE-640 / CWE-330 (predictable token) / CWE-639 (token as sole object reference)
- **Severity**: High+ (unauthenticated ATO; token brute-forceable within seconds window)
- **Location**: auth.py:161-162 (generation), auth.py:174-187 (consumption)
- **Gate 0**: Not intended.
- **Gate 1**: Reachable — production `/auth/reset`.
- **Gate 2a**: Attacker-controlled — token supplied via query/form; also independently derivable: `md5(f"{id}:{int(time.time())}")` over small id space × few seconds.
- **Gate 2b**: None — token is sole lookup key (`WHERE password = ?`, 180); no session binding, no expiry, no freshness/audience check. Fails open on presence: any matching token → password overwrite.
- **Gate 3**: New capability — attacker computes/guesses another user's token, sets `new_pw` (177,185), owns the account.
- **Entry Point**: GET/POST /auth/reset
- **Data Flow**: `token` (174) → `SELECT id WHERE password = token` (180) → match → `UPDATE password = hash(new_pw)` (183-186).
- **Root Cause**: Reset token derived from low-entropy `id:epoch_seconds` and used as the only access-control credential.

---

## Post-Trace Authorization Helper Coverage Audit
No authorization/session-validation helpers exist in `auth.py`. All state-changing
handlers (login, register, forgot, reset) lack ownership/identity binding — consistent
with all-NONE threat model; findings above capture the cross-principal cases.
`logout` (self-scoped) is exempt. No sibling handler invokes an authz helper, so no
relative-gap CWE-862 finding (structural absence is captured by VULN-102/103).
