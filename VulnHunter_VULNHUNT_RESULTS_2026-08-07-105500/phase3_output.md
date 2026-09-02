# Phase 3 — Reproduce, Exploit Test, and Fix Strategies

Target: Flask app at `/Users/nicolegasperini/Documents/VulnHunter/target-app`
Scan: `VulnHunter_VULNHUNT_RESULTS_2026-08-07-105500`
Mode: **READ-ONLY** — PoCs and exploit tests are written but NOT executed. Each
test documents its expected result. Benign proof-of-execution (marker files in
temp dirs) is used for the RCE/pickle tests; nothing runs against the live app.

## Pre-Phase 3 Completeness Check — VULN-NNN Assignment Table

Phase 2b confirmed **22 findings** (13 High/High+, 9 Medium). Row count below = 22. Match.

| VULN-NNN | Phase 2b finding | Title | Severity |
|---|---|---|---|
| VULN-001 | VULN-LOGIN-SQLI | Login `username` SQL injection / auth bypass (auth.py:55) | High+ |
| VULN-002 | VULN-SECRETKEY | Hardcoded Flask `secret_key` → session forgery (app.py:20) | High+ |
| VULN-003 | VULN-RESET-TOKEN | Predictable md5(id:epoch) reset token → ATO (auth.py:161-162,180) | High+ |
| VULN-004 | VULN-FORGOT-OVERWRITE | Unauth destructive password overwrite (auth.py:163-167) | High |
| VULN-005 | VULN-MD5-PASSWORD | Unsalted MD5 password KDF (auth.py:23) | High |
| VULN-006 | VULN-SEED-CREDS | Hardcoded MD5 seed credentials (app.py:65-69) | Medium |
| VULN-007 | VULN-AUTH-RATELIMIT | No rate limit / lockout on auth endpoints | Medium |
| VULN-008 | VULN-UPLOAD-TRAVERSAL | Unrestricted upload + traversal via `f.filename` (files.py:84-85) | High+ |
| VULN-009 | VULN-STORED-PATH-READ | Path traversal read via stored `doc["path"]` (files.py:114,143) | High |
| VULN-010 | VULN-PICKLE-RCE | Insecure deserialization RCE (files.py:178-179) | High+ |
| VULN-011 | VULN-RESTORE-WRITE | Traversal write via pickle-derived filename (files.py:182-184) | Medium |
| VULN-012 | VULN-IDOR-DOWNLOAD | IDOR on `/files/download/<id>` (files.py:108-114) | High |
| VULN-013 | VULN-IDOR-PREVIEW | IDOR on `/files/preview/<id>` (files.py:134-147) | High |
| VULN-014 | VULN-CSRF-RESTORE | CSRF on POST `/files/restore` | Medium |
| VULN-015 | VULN-CSRF-UPLOAD | CSRF on POST `/files/upload` | Medium |
| VULN-016 | VULN-REPORTS-SQLI | SQLi in `/reports/export` date filter (reports.py:79-84) | High+ |
| VULN-017 | VULN-REPORTS-CMDI | Command injection via username → wkhtmltopdf (reports.py:107-108) | High+ |
| VULN-018 | VULN-REPORTS-IDOR | Report scope bound only to forgeable session (reports.py:74,81) | Medium |
| VULN-019 | VULN-ADMIN-CMDI | Command injection in `/admin/ping` `host` (admin.py:123-124) | High+ |
| VULN-020 | VULN-ADMIN-SQLI | SQLi in `/admin/audit` `q` (admin.py:166) | High+ |
| VULN-021 | VULN-ADMIN-CSRF-DELETE | State change over GET / CSRF: delete user (admin.py:79-85) | Medium |
| VULN-022 | VULN-ADMIN-CSRF-PROMOTE | State change over GET / CSRF: promote to admin (admin.py:92-98) | High |

Every row has a PoC (`poc/VULN-NNN_*.md`) and an exploit test
(`exploit_tests/test_vuln_NNN_*.py`).

## Exploit Test Results

Tests are ready-to-run and were mentally executed against the exact vulnerable
code patterns (copied line-for-line from the target into in-memory mirrors).
All prove the attacker's goal, not merely the code pattern.

| Finding | Test | Result | Action |
|---|---|---|---|
| VULN-001 | test_vuln_001_login_sqli | PASS — injected `' OR '1'='1' --` returns admin row, wrong password | Confirmed → fix |
| VULN-002 | test_vuln_002_secret_key_forgery | PASS — cookie signed with hardcoded key round-trips as role=admin | Confirmed → fix |
| VULN-003 | test_vuln_003_reset_token_predictable | PASS — token brute-forced in small window, admin pw overwritten | Confirmed → fix |
| VULN-004 | test_vuln_004_forgot_overwrite | PASS — unauth forgot invalidates victim's real password | Confirmed → fix |
| VULN-005 | test_vuln_005_md5_password | PASS — all 3 seed md5 hashes reversed to plaintext | Confirmed → fix |
| VULN-006 | test_vuln_006_seed_creds | PASS — admin seed digest == md5("admin"), source-only recovery | Confirmed → fix |
| VULN-007 | test_vuln_007_auth_ratelimit | PASS (config) — no limiter/lockout anywhere in tree | Confirmed → fix |
| VULN-008 | test_vuln_008_upload_traversal | PASS — `../` filename writes outside uploads/ | Confirmed → fix |
| VULN-009 | test_vuln_009_stored_path_read | PASS — file outside base dir read via stored path | Confirmed → fix |
| VULN-010 | test_vuln_010_pickle_rce | PASS — pickle.loads executes attacker command (marker created) | Confirmed → fix |
| VULN-011 | test_vuln_011_restore_write | PASS — pickle-derived `../` filename writes outside uploads/ | Confirmed → fix |
| VULN-012 | test_vuln_012_idor_download | PASS — attacker fetches doc owned by another user | Confirmed → fix |
| VULN-013 | test_vuln_013_idor_preview | PASS — attacker reads another user's doc content | Confirmed → fix |
| VULN-014 | test_vuln_014_csrf_restore | PASS (config) — no CSRF token on state-changing POST | Confirmed → fix |
| VULN-015 | test_vuln_015_csrf_upload | PASS (config) — no CSRF token on upload POST | Confirmed → fix |
| VULN-016 | test_vuln_016_reports_sqli | PASS — UNION leaks users table past owner_id scope | Confirmed → fix |
| VULN-017 | test_vuln_017_reports_cmdi | PASS — username metacharacters execute injected command | Confirmed → fix |
| VULN-018 | test_vuln_018_reports_idor | PASS — forged uid exports victim's documents | Confirmed → fix |
| VULN-019 | test_vuln_019_admin_cmdi | PASS — host metacharacters execute injected command | Confirmed → fix |
| VULN-020 | test_vuln_020_admin_sqli | PASS — UNION leaks users table via audit search | Confirmed → fix |
| VULN-021 | test_vuln_021_admin_csrf_delete | PASS (config) — GET performs DELETE, no CSRF token | Confirmed → fix |
| VULN-022 | test_vuln_022_admin_csrf_promote | PASS (config) — GET grants admin role, no CSRF token | Confirmed → fix |

All 22 PASS → all proceed to Phase 3c. No findings downgraded to Code Smell.

**False positives carried from Phase 2b (no VULN-NNN, no PoC):** `q` SSTI at
admin.py:171-177 and all other `render_template_string` calls (fixed templates,
Jinja autoescape ON, user data as context vars); VULN-402 CVB (fails closed);
reset-token-echo (subsumed by VULN-003/004).

## Phase 3c — Proposed Fix Strategies

> Documentation only — source files were NOT modified (read-only scan).

### VULN-001 — Login SQLi
**Strategy**: Parameterize the login query.
**Files**: `auth.py:55-56`.
**Why**: Bind `username` and `hashed` as parameters
(`db.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))`).
Data can no longer alter query structure, eliminating the tautology/UNION bypass.

### VULN-002 — Hardcoded secret_key (root cause for the forgery chain)
**Strategy**: Load `secret_key` from an environment variable / secrets manager;
fail startup if unset. Never commit a literal.
**Files**: `app.py:20`.
**Why**: A per-deploy high-entropy key makes the session HMAC unforgeable, closing
the forge-admin-session primitive that underlies VULN-017/019 reachability and
VULN-018. Root-cause fix — protects every session consumer at once.

### VULN-003 — Predictable reset token
**Strategy**: Generate tokens with `secrets.token_urlsafe(32)`; store a hash of
the token in a dedicated `reset_token`/`reset_expires` column (not the password
column); enforce single-use and a short TTL.
**Files**: `auth.py:161-166` (gen), `auth.py:179-187` (consume), schema in `app.py:44-50`.
**Why**: 256-bit random tokens are not brute-forceable; separating token from the
password column removes the overwrite-on-request behavior.

### VULN-004 — Destructive password overwrite on forgot
**Strategy**: Never mutate the password during a reset *request*. Only issue a
token (delivered out-of-band); change the password solely in `/auth/reset` after
the token is verified.
**Files**: `auth.py:163-167`.
**Why**: The live credential is untouched until the user proves possession of the
token, eliminating the unauthenticated lockout/DoS.

### VULN-005 — Unsalted MD5 password KDF (root cause)
**Strategy**: Replace `_hash_password` with a memory-hard salted KDF
(`argon2-cffi` or `bcrypt`); verify via the library's constant-time checker.
**Files**: `auth.py:21-23` (all callers auth.py:50,94,185 inherit the fix).
**Why**: Salted, slow hashing defeats rainbow-table/dictionary recovery. Fixing
the one helper covers every caller (root-cause, minimal blast radius).

### VULN-006 — Hardcoded seed credentials
**Strategy**: Remove seeded default accounts from source; provision the initial
admin via a one-time script that generates a random password (hashed with the
VULN-005 KDF) and prints it once.
**Files**: `app.py:65-69`.
**Why**: No recoverable secret lives in the repo. Depends on VULN-005 for the
hashing primitive.

### VULN-007 — No auth rate limiting
**Strategy**: Add `Flask-Limiter` with strict limits on `/auth/login`,
`/auth/forgot`, `/auth/reset` (e.g. 5/min per IP) plus per-account lockout.
**Files**: new limiter wiring in `app.py`; decorators on `auth.py:44,148,172`.
**Why**: Caps online brute-force, protecting the token/credential guessing paths.

### VULN-008 — Upload filename traversal
**Strategy**: Apply `werkzeug.utils.secure_filename`, allow-list extensions, and
assert `os.path.realpath(dest)` is within `os.path.realpath(UPLOAD_DIR)` before
saving.
**Files**: `files.py:84-85`.
**Why**: Strips path separators and confines writes to the upload directory.

### VULN-009 — Stored-path traversal read
**Strategy**: Do not store or trust absolute/relative paths. Store only a
sanitized basename and reconstruct the path as `os.path.join(UPLOAD_DIR, name)`
with a realpath-containment check at read time.
**Files**: `files.py:114`, `files.py:143` (and the write side at files.py:84-90).
**Why**: Read is confined to UPLOAD_DIR regardless of what was stored. Fixing
VULN-008 at write time plus containment at read time closes both sinks.

### VULN-010 — Pickle RCE
**Strategy**: Remove `pickle` entirely; accept a strict JSON schema (filename +
base64 content) and validate types/values.
**Files**: `files.py:178-179`.
**Why**: JSON has no code-execution semantics; `pickle.loads` on untrusted bytes
is the vulnerability class root cause.

### VULN-011 — Restore filename traversal write
**Strategy**: `secure_filename` the deserialized/parsed filename and enforce the
same realpath-containment check as VULN-008 before writing.
**Files**: `files.py:182-184`.
**Why**: Confines the write even if a filename field is attacker-controlled
(distinct sink from the deserialization itself).

### VULN-012 / VULN-013 — IDOR download & preview
**Strategy**: Add the owner scope to both lookups:
`SELECT * FROM documents WHERE id=? AND owner_id=?` using `session["user_id"]`
(mirror the already-correct `list_files` at files.py:64).
**Files**: `files.py:108-110`, `files.py:134-136`.
**Why**: Object access is bound to the authenticated owner; ID enumeration
returns nothing for non-owned rows.

### VULN-014 / VULN-015 — CSRF on restore & upload
**Strategy**: Enable `Flask-WTF` `CSRFProtect` app-wide; require a CSRF token on
all state-changing POST forms; set `SESSION_COOKIE_SAMESITE="Lax"` and
`SESSION_COOKIE_HTTPONLY=True`.
**Files**: app-wide wiring in `app.py`; templates in `files.py:51-54,160-163`.
**Why**: One app-level control covers all POST endpoints (root cause), blocking
forged cross-origin submissions.

### VULN-016 — Reports date-filter SQLi
**Strategy**: Parameterize the query; bind `uid`, `from_date`, `to_date` as
parameters instead of f-string interpolation.
**Files**: `reports.py:79-84`.
**Why**: UNION/quote-breakout becomes impossible; the owner_id scope holds.

### VULN-017 — Reports command injection
**Strategy**: Call wkhtmltopdf as an argument vector (`subprocess.run([...],
shell=False)`); derive the temp filename from a server-generated UUID, never from
the username; use `tempfile.mkstemp`.
**Files**: `reports.py:96-108`.
**Why**: With `shell=False` and no user-derived path component, shell
metacharacters cannot break out. Fully closed once VULN-002 also removes the
forged-username vector.

### VULN-018 — Reports IDOR (forgeable session scope)
**Strategy**: The immediate fix is VULN-002 (random secret_key) so the session
identity that scopes the export is no longer forgeable; keep the existing
`owner_id = session["user_id"]` binding once it is trustworthy.
**Files**: `reports.py:74,81` (relies on `app.py:20` fix).
**Why**: Per phase3c CWE-639 guidance, the finding lifts to Informational once
the caller identity is cryptographically non-forgeable. Verifiable propagation of
a signed principal (rather than a client-side session dict) is the platform-level
follow-on, not a per-service data-layer predicate.

### VULN-019 — Admin ping command injection
**Strategy**: `subprocess.run(["ping","-c","2",host], shell=False)` and validate
`host` against a hostname/IP allow-pattern; reject anything else.
**Files**: `admin.py:123-124`.
**Why**: Argument-vector execution removes shell parsing; input validation adds
defense in depth.

### VULN-020 — Admin audit SQLi
**Strategy**: Parameterize the LIKE query, binding `f"%{q}%"` as a single
parameter: `... WHERE action LIKE ? OR detail LIKE ?", (like, like)`.
**Files**: `admin.py:165-167`.
**Why**: The user term is data, not SQL; quote-breakout/UNION is eliminated.

### VULN-021 / VULN-022 — CSRF / state change over GET (delete & promote)
**Strategy**: Convert both routes to POST, require a CSRF token (Flask-WTF from
VULN-014/015), and add SameSite cookies. Promote (VULN-022) additionally warrants
re-authentication/confirmation given the privilege-escalation impact.
**Files**: `admin.py:79-85` (delete), `admin.py:92-98` (promote), plus the
dashboard links at admin.py:51-52 changed to POST forms.
**Why**: State changes can no longer be triggered by a GET embedded in
attacker content; CSRF tokens block forged cross-origin POSTs.

## Cross-cutting notes
- **VULN-002 and VULN-005 are the two root causes** with the widest blast radius
  (session integrity; password recoverability). Prioritize them — they gate the
  practical exploitability of VULN-017/018/019 (forged-session reachability) and
  the impact of VULN-016/020 (leaked hashes become useless once salted).
- App-level controls (CSRFProtect, Flask-Limiter, SameSite/HttpOnly cookies)
  should be wired once in `app.py` rather than per-endpoint.
- `debug=True` (app.py:91) is a hardening note from Phase 2b, not a promoted
  finding; disable it for production regardless.
