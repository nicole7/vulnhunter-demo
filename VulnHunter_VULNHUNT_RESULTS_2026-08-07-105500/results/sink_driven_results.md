# Sink-Driven Audit Results

Scope: `/Users/nicolegasperini/Documents/VulnHunter/target-app` (app.py, auth.py, files.py, admin.py, reports.py)
Method: start at dangerous sink, trace backward to callers/reachability.
Date: 2026-08-07

---

## 1. ACTION-SCOPE AUDIT (wildcard permissions in cloud/auth SDK)

**N/A.** No cloud SDK (boto3/AWS IAM/GCP/Azure) or policy-document construction present. No wildcard permission constants (`"*"`, `Action: "*"`, `Resource: "*"`) in source. Stack is Flask + sqlite3 + subprocess + pickle only.

---

## 2. CREDENTIAL-ISSUING SINK AUDIT

### CANDIDATE — Password-reset token minting with no access-level / rate branch
- input#: forgot-username (POST `/auth/forgot`, `request.form["username"]`)
- sink: `auth.py:162` (`token = hashlib.md5(raw.encode()).hexdigest()`) → written to DB at `auth.py:163-167`
- vuln class: Insecure credential issuance / predictable reset token (CWE-640, CWE-330)
- gate results:
  - Reachable unauthenticated? YES — `/auth/forgot` has no `_require_login`.
  - Branches on request type / access level before issuing? NO — any submitted username that exists gets a fresh token minted, and the token *overwrites the password field* immediately (account takeover primitive: attacker resets victim's password to a value they can derive).
  - Caller verifies requester owns the account? NO — no email delivery, token is returned in the HTTP response body (`FORGOT_TEMPLATE`, `auth.py:132`) to whoever submits the username.
- Note: single caller of the minting sink; it fails the "branch on access level" requirement. Confirmed FLAG.

### `_hash_password` (session/credential-adjacent) — see Crypto Audit item 3.1.

No session-signing helper is called directly in first-party code (Flask signs the cookie internally using `app.secret_key`; see items 3.4 / 4.1).

---

## 3. CRYPTOGRAPHIC SINK AUDIT

### 3.1 CANDIDATE — MD5 for password hashing
- input#: N/A (attacker input not required per audit rules)
- sink: `auth.py:23` `hashlib.md5(pw.encode()).hexdigest()` (helper `_hash_password`)
- callers: `auth.py:50` (login), `auth.py:94` (register), `auth.py:185` (reset)
- vuln class: Use of broken/weak hash for password storage (CWE-327, CWE-916)
- gate results:
  - (a) weak algorithm? YES — MD5, unsalted, single-round.
  - (b) security-sensitive context? YES — password authentication / stored credentials.
  - (c) extractable keys serialized? Hashes stored in `users.password` (DB); seed hashes hardcoded in `app.py:67-69`.
  - (d) non-crypto PRNG entropy? No salt at all.
  - Weak crypto + security-sensitive = CANDIDATE. FLAG.

### 3.2 CANDIDATE — Predictable, time-based reset token
- input#: forgot-username (POST `/auth/forgot`)
- sink: `auth.py:161-162` `raw = f"{user['id']}:{int(time.time())}"` then `hashlib.md5(raw).hexdigest()`
- vuln class: Predictable/insufficiently-random token, weak hash (CWE-330, CWE-338, CWE-327)
- gate results:
  - (a) weak algorithm/mode? YES — MD5.
  - (b) security-sensitive? YES — the token IS the new account credential (search key at `auth.py:180`).
  - (c) serialized to storage? YES — stored in `users.password`.
  - (d) key-adjacent entropy from non-crypto source? YES — only entropy is `int(time.time())` (seconds) + known/enumerable user id. Fully brute-forceable within the reset window; no `secrets`/`os.urandom`.
  - CANDIDATE. FLAG.

### 3.3 CANDIDATE — MD5 admin seed hashes in source
- sink: `app.py:67-69` (`'21232f297a57a5a743894a0e4a801fc3'` = md5("admin"), etc.)
- vuln class: Weak hash + hardcoded credential (CWE-327 / CWE-798) — cross-refs item 4.
- gate: weak algorithm YES; security-sensitive (admin login) YES; extractable/serialized YES. FLAG.

### 3.4 CANDIDATE — Session cookie signed with hardcoded secret
- sink: implicit — Flask itsdangerous HMAC signing keyed on `app.secret_key` (`app.py:20`)
- vuln class: Predictable signing key / forgeable sessions (CWE-330 / CWE-798) — cross-refs item 4.
- gate: key extractable (hardcoded in source) YES; security-sensitive (session integrity, role='admin' auth) YES. Enables privilege escalation via forged cookie (admin.py `_require_admin` trusts `session["role"]`). FLAG.

No SHA1/DES/RC4/ECB or key-size sinks found beyond the above.

---

## 4. SENSITIVE DATA STORAGE AUDIT

### 4.1 CANDIDATE — Hardcoded Flask secret key
- sink: `app.py:20` `app.secret_key = "super-secret-dev-key-1234"`
- vuln class: Hardcoded credential / cleartext secret in source (CWE-798, CWE-312)
- gate results:
  - Hardcoded secret in first-party source? YES.
  - Security-sensitive? YES — signs all session cookies; disclosure lets an attacker forge any session including `role='admin'` (chains into admin.py command injection / SSTI). FLAG.

### 4.2 CANDIDATE — Hardcoded seeded credentials (password hashes)
- sink: `app.py:67-69` INSERT of md5 hashes for admin/alice/bob
- vuln class: Hardcoded credentials in source (CWE-798, CWE-312). FLAG.

### 4.3 LOW — PII/credential exposure via reflected reset token
- sink: `auth.py:132` reset token echoed into HTTP response body.
- vuln class: Sensitive info exposure (CWE-200). Noted; primary flag is item 2 / 3.2.

No logging of secrets found (no `logging`/`print` of keys). Usernames written to `/tmp` paths (`reports.py:96,100`) — filename-only, not secret; noted, not flagged here.

---

## 5. CONCURRENCY / RACE CONDITION AUDIT

**N/A.** No `ThreadPoolExecutor`, `asyncio`, `threading`, `create_task`, or background dispatch in first-party source. All handlers are synchronous. Flask dev server default is single-request; `g._database` is per-request. No TOCTOU pattern (check-then-use across async boundary) found. Note: `os.path.exists`→`open` in `reports.py:110-111` is same-thread, not a security race.

---

## 6. RATE-LIMIT / ATTEMPT-COUNTER AUDIT

### 6.1 CANDIDATE — No rate limiting / lockout on authentication endpoints
- endpoints: `/auth/login` (`auth.py:44`), `/auth/forgot` (`auth.py:148`), `/auth/reset` (`auth.py:172`)
- vuln class: Improper restriction of excessive auth attempts (CWE-307)
- gate results:
  - Any attempt-counter / lockout session-attribute writes? NONE FOUND — no counter to rotate around, the control is simply absent.
  - Unauthenticated & unthrottled? YES for all three. Combined with predictable reset token (item 3.2), the reset token space is brute-forceable with unlimited attempts against `/auth/reset` (`auth.py:180` matches token to any user).
  - FLAG (missing rate-limiting on auth endpoints).

No rotatable binding identifier resetting an existing counter exists because no counter exists; documented as absent-control per audit instructions.

---

## Summary of flagged candidates
| # | Sink (file:line) | Vuln class | CWE |
|---|---|---|---|
| 2 | auth.py:162-167 | Insecure reset-token issuance / no owner check | 640, 330 |
| 3.1 | auth.py:23 | MD5 password hashing (unsalted) | 327, 916 |
| 3.2 | auth.py:161-162 | Predictable time-based reset token | 330, 338, 327 |
| 3.3 | app.py:67-69 | Weak/hardcoded seed hashes | 327, 798 |
| 3.4 | app.py:20 (signing) | Forgeable session (hardcoded HMAC key) | 330, 798 |
| 4.1 | app.py:20 | Hardcoded Flask secret_key | 798, 312 |
| 4.2 | app.py:67-69 | Hardcoded credentials | 798, 312 |
| 6.1 | auth.py:44/148/172 | No rate limit/lockout on auth | 307 |

Audits 1 and 5: N/A (no cloud SDK; no concurrency primitives).
