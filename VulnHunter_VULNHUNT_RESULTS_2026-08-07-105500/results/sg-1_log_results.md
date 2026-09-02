# Partition SG-1 (auth) — LOG Class Results

Scope: `/Users/nicolegasperini/Documents/VulnHunter/target-app`, file `auth.py`, `app.py`.
Class group: LOG (race, cache isolation, credential scope, resource exhaustion, prototype pollution, crypto, integer overflow). Attacker: unauthenticated. Reachability: PRODUCTION.

## Per-input dispositions

| # | Var | Disposition | Notes |
|---|-----|-------------|-------|
| 1 | username (login) | CROSS-CLASS (INJ) | #1, auth.py:55, SQLi f-string. Not LOG. |
| 2 | password (login) | SAFE (LOG) | MD5-hashed then used in parameterized-position of same f-string query; weak-hash captured under VULN-001. No LOG sink beyond that. |
| 3 | username (register) | CROSS-CLASS (INJ) | #3, auth.py:107 render_template_string via `msg` on INSERT error (auth.py:105→107). SSTI = INJ. |
| 4 | password (register) | CANDIDATE (LOG) | #4 → MD5 hash sink auth.py:23. See VULN-001. |
| 5 | email (register) | NO-MATCH (LOG) | Parameterized INSERT auth.py:99; no LOG sink. INJ owns SSTI path. |
| 6 | username (forgot) | CANDIDATE (LOG) | #6 triggers predictable reset token (VULN-002) and destructive password overwrite (VULN-003). |
| 7 | token (reset) | CANDIDATE (LOG) | #7 → predictable-token account takeover, VULN-002. SSTI render (auth.py:192) = CROSS-CLASS (INJ). |
| 8 | password (reset) | CANDIDATE (LOG) | #8 → MD5 hash sink auth.py:23 (VULN-001). |
| 9 | logout / session | CANDIDATE (LOG) | Hardcoded secret key → session forgery, VULN-004 (S14). |

---

## [VULN-001] Passwords stored with unsalted MD5
- **Input**: #4 password (register), #8 password (reset), plus login verification path
- **Class**: CWE-916 / CWE-327 (weak password hash)
- **Severity**: High
- **Location**: auth.py:23 (`_hash_password`), called at auth.py:50, 94, 185
- **Gate 0**: Not intended — password storage is meant to be secure; MD5 defeats it.
- **Gate 1**: `_hash_password` used at auth.py:50,94,185 — production paths (login, register, reset). Reachable.
- **Gate 2a**: `password` is unauthenticated HTTP form input (auth.py:92,177).
- **Gate 2b**: No salt, no work factor; MD5 is fast + broken. Seed data (app.py:67-69) is raw unsalted MD5 (`admin`=21232f...=md5("admin")). Confirms scheme.
- **Gate 3**: New capability — offline recovery of all stored credentials (incl. admin) via rainbow tables / GPU cracking. DB read (via SQLi VULN in INJ scope, or backup) yields plaintext passwords.
- **Entry Point**: POST /auth/register, POST /auth/reset
- **Data Flow**: form `password` → `_hash_password` (auth.py:23 `hashlib.md5`) → users.password column.
- **Root Cause**: MD5 unsalted used as password KDF.
- **Exploitability**: High once hashes obtained; trivial for weak passwords.

## [VULN-002] Predictable password-reset token → account takeover
- **Input**: #6 username (forgot), #7 token (reset)
- **Class**: CWE-330 / CWE-340 (predictable / insufficiently random token)
- **Severity**: High+ (unauthenticated full account takeover, incl. admin)
- **Location**: auth.py:161-162 (token gen), auth.py:180 (token consumed)
- **Gate 0**: Not intended — reset tokens must be unguessable.
- **Gate 1**: /auth/forgot and /auth/reset are registered production routes.
- **Gate 2a**: Attacker triggers token issuance for ANY username (auth.py:152 param); user id is small autoincrement, timestamp is `int(time.time())` — both attacker-inferable.
- **Gate 2b**: None. `md5(f"{id}:{int(time.time())}")` — search space = (few ids) × (seconds window). Fully brute-forceable; no secret salt.
- **Gate 3**: New capability — attacker resets/logs in as arbitrary victim (admin id=1). Business-invariant: auth boundary crossed. Immune to self-only dismissal.
- **Entry Point**: POST /auth/forgot then GET/POST /auth/reset.
- **Data Flow**: username → SELECT id (auth.py:155) → raw=`id:epoch` → md5 (auth.py:162) → stored as password → reset matches token (auth.py:180) → password overwrite (auth.py:185).
- **Root Cause**: Token derived from low-entropy, attacker-knowable values with no server secret.
- **Exploitability**: High — target a known id, iterate ~a few seconds of timestamps.

## [VULN-003] Unauthenticated forced password reset (destructive overwrite / DoS)
- **Input**: #6 username (forgot)
- **Class**: CWE-620 (unverified password change) / CWE-640
- **Severity**: High
- **Location**: auth.py:163-167
- **Gate 0**: Not intended — forgot flow should not clobber the live password before verification.
- **Gate 1**: Production route.
- **Gate 2a**: username unauthenticated form input.
- **Gate 2b**: None. On any valid username, current password is immediately overwritten with the token (auth.py:164) with no ownership/verification.
- **Gate 3**: New capability — attacker locks any user (incl. admin) out on demand by naming them (account-lockout DoS); combined with VULN-002 yields takeover.
- **Data Flow**: username → SELECT id → UPDATE users SET password=token (auth.py:164).
- **Root Cause**: State-changing overwrite of live credential in the request-token step without out-of-band delivery.
- **Exploitability**: High, single unauthenticated request.

## [VULN-004] Hardcoded Flask secret_key → session forgery
- **Input**: #9 session cookie (no request body input); trust anchor for all session values
- **Class**: CWE-798 (hardcoded credential) / CWE-330 → session forgery
- **Severity**: High+ (forge admin session)
- **Location**: app.py:20 `app.secret_key = "super-secret-dev-key-1234"`
- **Gate 0**: Not intended — secret key must be secret.
- **Gate 1**: Used by Flask session signing for every authenticated route; production.
- **Gate 2a**: Key is public (in source); attacker uses it to sign arbitrary session cookies.
- **Gate 2b**: None.
- **Gate 3**: New capability — attacker mints a session with `role=admin`, `user_id=1` (auth.py:59-61 set these) without any credentials, bypassing login entirely.
- **Data Flow**: hardcoded key (app.py:20) → itsdangerous session signer → forged cookie accepted → session["role"] trusted downstream.
- **Root Cause**: Static, source-embedded signing key.
- **Exploitability**: High+ — offline cookie forgery, no interaction.

---

## CROSS-CLASS flags (for INJ/NAV agents)
- CROSS-CLASS (#1, auth.py:55, INJ) — SQLi f-string login.
- CROSS-CLASS (#3, auth.py:105→107, INJ) — SSTI via `msg` render_template_string on INSERT-error string.
- CROSS-CLASS (#7, auth.py:192, INJ) — SSTI via `token` reflected into render_template_string (also auth.py:169 forgot template `token`).
- Note: /auth/reset performs no rate limiting on token guessing, reinforcing VULN-002 (no counter present at all — nothing to scope-bypass).

## Non-findings
- No race conditions: sqlite operations are simple; no check-then-act on count-limited resource, no async dispatch.
- No unbounded allocation / ReDoS / prototype pollution / integer overflow in scope (Python, no user-controlled sizes/regex/merge).
- No cache/credential-scope artifacts generated in auth.py.
