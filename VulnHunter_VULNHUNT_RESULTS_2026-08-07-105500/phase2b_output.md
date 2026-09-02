# Phase 2b — Adversarial Verification

Target: Flask app at `/Users/nicolegasperini/Documents/VulnHunter/target-app`
Files: `app.py`, `auth.py`, `files.py`, `admin.py`, `reports.py`
Scan: `VulnHunter_VULNHUNT_RESULTS_2026-08-07-105500`

## Candidate Manifest (flat list from all result files)

Trace agents raised the same underlying defects under multiple class-specific IDs
(INJ/LOG/NAV/sink-driven). The manifest below lists every CANDIDATE entry emitted,
then the verdict table de-duplicates per the Anti-merge rule (distinct
parameter/route/impact = distinct finding; same defect re-labeled across classes = one finding).

| # | Source file | Candidate ID | CWE | Endpoint / Param |
|---|---|---|---|---|
| 1 | sg-1_inj | VULN-INJ-001 | 89 | POST /auth/login — `username` SQLi |
| 2 | sg-1_nav | VULN-101 | 89→290 | POST /auth/login — auth-bypass outcome |
| 3 | sg-1_log | VULN-001 | 327/916 | MD5 password hashing |
| 4 | sink | 3.1 | 327/916 | MD5 password hashing (dup) |
| 5 | sg-1_log | VULN-002 | 330/340 | /auth/forgot+/reset — predictable reset token |
| 6 | sg-1_nav | VULN-103 | 640/330/639 | GET/POST /auth/reset — predictable token ATO (dup) |
| 7 | sink | 2 / 3.2 | 640/330 | reset-token issuance (dup) |
| 8 | sg-1_log | VULN-003 | 620/640 | POST /auth/forgot — unauth destructive password overwrite |
| 9 | sg-1_nav | VULN-102 | 640/306 | POST /auth/forgot — overwrite/ATO (dup of 8) |
| 10 | sg-1_log | VULN-004 | 798/330 | app.py:20 — hardcoded secret_key → session forgery |
| 11 | sink | 3.4 / 4.1 | 798/312 | hardcoded secret_key (dup) |
| 12 | sink | 3.3 / 4.2 | 798/312 | app.py:67-69 hardcoded MD5 seed creds |
| 13 | sink | 4.3 | 200 | reset token echoed in response (LOW) |
| 14 | sink | 6.1 | 307 | no rate-limit on auth endpoints |
| 15 | sg-2_inj | VULN-201 | 434/22 | POST /files/upload — `f.filename` traversal/unrestricted upload |
| 16 | sg-2_inj | VULN-202 | 22 | /files/download,/preview — stored path traversal read |
| 17 | sg-2_inj | VULN-203 | 502 | POST /files/restore — pickle RCE |
| 18 | sg-2_log | VULN-201(log) | 502 | pickle RCE (dup of 17) |
| 19 | sg-2_inj | VULN-204 | 22/434 | /files/restore — pickle-derived filename arbitrary write |
| 20 | sg-2_nav | VULN-201(nav) | 306/290 | /files/* — forgeable-session auth bypass (dup of 10) |
| 21 | sg-2_nav | VULN-202 | 639 | GET /files/download/<id> — IDOR |
| 22 | sg-2_nav | VULN-203 | 639 | GET /files/preview/<id> — IDOR |
| 23 | sg-2_nav | VULN-204 | 352 | POST /files/restore — CSRF |
| 24 | sg-2_nav | VULN-205 | 352 | POST /files/upload — CSRF |
| 25 | sg-3_inj | VULN-301 | 89 | GET /reports/export — `from_date`/`to_date` SQLi |
| 26 | sg-3_inj | VULN-302 | 78 | GET /reports/export?fmt=pdf — `username` command injection |
| 27 | sg-3_nav | VULN-NAV-01 | 290/287 | forgeable session identity (dup of 10) |
| 28 | sg-3_nav | VULN-NAV-02 | 639 | GET /reports/export — IDOR via forgeable user_id |
| 29 | sg-4_inj | VULN-401 | 78 | POST /admin/ping — `host` command injection |
| 30 | sg-4_inj | VULN-402 | 89 | GET /admin/audit — `q` SQLi |
| 31 | sg-4_nav | VULN-401(nav) | 290/287 | /admin/* — forgeable role auth bypass (dup of 10) |
| 32 | sg-4_nav | VULN-402(nav) | — | CVB absent-role — fails closed (SAFE, recorded) |
| 33 | sg-4_nav | VULN-403 | 352 | GET /admin/delete/<id> — CSRF |
| 34 | sg-4_nav | VULN-404 | 352 | GET /admin/promote/<id> — CSRF |
| 35 | (SSTI raised) | q SSTI | 1336 | GET /admin/audit — `q` SSTI (asserted SAFE by sg-4_inj) |

Distinct verifiable candidates after de-dup: 22 rows below.

## §9 Universal Auth Gap rollup

- **A — AUTHN absent?** No. Auth code exists: `auth.py:56-61` validates credentials
  against the DB and sets the session; `files.py:25-27` / `reports.py:26-28`
  `_require_login`; `admin.py:25-31` `_require_admin`. Some handlers have valid auth →
  rollup A does NOT fire.
- **B — AUTHZ absent?** No. `list_files` (files.py:64) and `export` (reports.py:81)
  bind `session["user_id"]` (owner_id scope) to the operation. At least one handler
  binds a UID → rollup B does NOT fire.
- §9 does not fire. Findings surface individually.

## Verification Table

| Finding | Gates complete? | Production-reachable? | Defenses cover attack? | Severity correct? | All call sites checked? | Verdict |
|---|---|---|---|---|---|---|
| VULN-LOGIN-SQLI (login `username`, auth.py:55) | Yes | Yes — POST /auth/login unauth | No — f-string interpolation, no param/escape | Yes — **High+** (unauth full bypass + DB read) | 1/1 (single sink) | **CONFIRMED** |
| VULN-SECRETKEY (hardcoded secret_key, app.py:20) | Yes | Yes — signs every session cookie | No — key literal in source | Yes — **High+** (forge admin session) | signer used app-wide | **CONFIRMED** (subsumes NAV auth-bypass dups: sg-2 VULN-201, sg-3 NAV-01, sg-4 VULN-401) |
| VULN-RESET-TOKEN (predictable md5(id:epoch), auth.py:161-162,180) | Yes | Yes — /auth/forgot + /auth/reset unauth | No — entropy = small id × seconds; no secret/expiry | Yes — **High+** (unauth ATO incl. admin) | gen+consume both read | **CONFIRMED** |
| VULN-FORGOT-OVERWRITE (destructive pwd overwrite, auth.py:163-167) | Yes | Yes — POST /auth/forgot unauth | No — overwrites live pwd on any valid username, no ownership | Yes — **High** (unauth lockout DoS / ATO primitive) | 1/1 | **CONFIRMED** (distinct param-impact from token guess; own row per Anti-merge) |
| VULN-MD5-PASSWORD (unsalted MD5 KDF, auth.py:23) | Yes | Yes — login/register/reset (:50,:94,:185) | No — MD5 unsalted; seed hashes confirm (app.py:67-69) | Yes — **High** | 3/3 callers | **CONFIRMED** |
| VULN-SEED-CREDS (hardcoded MD5 seed creds, app.py:67-69) | Yes — Gate2a N/A (config seed) | Yes — inserted at init_db | No — plaintext-recoverable admin creds in source | Reduce to **Medium** (config/secret exposure, no attacker input) | N/A | **CONFIRMED (Medium)** |
| VULN-AUTH-RATELIMIT (no lockout, auth.py:44/148/172) | Gate2a N/A | Yes | No control present | **Medium** (amplifies token brute-force) | N/A | **CONFIRMED (Medium)** |
| VULN-UPLOAD-TRAVERSAL (`f.filename`, files.py:84-85) | Yes | Yes — POST /files/upload (auth, session forgeable) | No — Werkzeug does NOT auto-`secure_filename`; verbatim | Yes — **High+** (arbitrary write → RCE) | 1/1 | **CONFIRMED** |
| VULN-STORED-PATH-READ (`doc["path"]`, files.py:114,143) | Yes | Yes — /files/download,/preview | No — no base-dir containment on stored path | Yes — **High** | 2/2 sinks | **CONFIRMED** |
| VULN-PICKLE-RCE (`data`, files.py:178-179) | Yes | Yes — POST /files/restore | No — `pickle.loads` on untrusted bytes | Yes — **High+** (RCE) | 1/1 | **CONFIRMED** |
| VULN-RESTORE-WRITE (pickle-derived filename, files.py:182-184) | Yes | Yes — reached only after pickle.loads | No — unsanitized filename join, traversal/absolute | Reduce to **Medium** (requires already-RCE pickle step) | 1/1 | **CONFIRMED (Medium)** (distinct sink/fix from RCE) |
| VULN-IDOR-DOWNLOAD (`doc_id`, files.py:108-114) | Yes | Yes — GET /files/download/<id> | No — query lacks `owner_id`; sibling list_files scopes | Yes — **High** | verified vs list_files:64 | **CONFIRMED** |
| VULN-IDOR-PREVIEW (`doc_id`, files.py:134-147) | Yes | Yes — GET /files/preview/<id> | No — same missing owner_id, separate sink | Yes — **High** | separate from download | **CONFIRMED** (distinct route/sink per Anti-merge) |
| VULN-CSRF-RESTORE (POST /files/restore) | Yes | Yes | No — no CSRF token, no framework CSRF | **Medium** | grep: no flask-wtf/CSRFProtect in tree | **CONFIRMED (Medium)** |
| VULN-CSRF-UPLOAD (POST /files/upload) | Yes | Yes | No CSRF token | **Medium** | distinct handler | **CONFIRMED (Medium)** |
| VULN-REPORTS-SQLI (`from_date`/`to_date`, reports.py:79-84) | Yes | Yes — GET /reports/export (auth, forgeable) | No — f-string into SQL; owner_id scope UNION-escapable | Yes — **High+** (cross-table DB read) | 1/1 | **CONFIRMED** |
| VULN-REPORTS-CMDI (`username`→wkhtmltopdf, reports.py:107-108) | Yes | Yes — /reports/export?fmt=pdf | No — session username in `shell=True` string, no quote | Yes — **High+** (RCE via forged session) | 1/1 | **CONFIRMED** |
| VULN-REPORTS-IDOR (forgeable user_id scope, reports.py:81) | Yes | Yes | Scope binds only forgeable session (defeated by secret_key) | Reduce to **Medium** — no crypto caller-auth (§8: crypto ✗ path → Original stands, but impact = subset of secret_key forgery) | 1/1 | **CONFIRMED (Medium)** |
| VULN-ADMIN-CMDI (`host`, admin.py:123-124) | Yes | Yes — POST /admin/ping (admin, forgeable) | No — `f"ping -c 2 {host}"` `shell=True` | Yes — **High+** (RCE) | 1/1 | **CONFIRMED** |
| VULN-ADMIN-SQLI (`q`, admin.py:166) | Yes | Yes — GET /admin/audit | No — f-string LIKE, quote breakout | Yes — **High+** (UNION DB read) | 1/1 | **CONFIRMED** |
| VULN-ADMIN-CSRF-DELETE (GET /admin/delete/<id>, admin.py:79-85) | Yes | Yes | No — state change over GET, no token | **Medium** | — | **CONFIRMED (Medium)** |
| VULN-ADMIN-CSRF-PROMOTE (GET /admin/promote/<id>, admin.py:92-98) | Yes | Yes | No — priv-escalation over GET, no token | **High** (persistent priv-esc, distinct impact from delete) | — | **CONFIRMED (High)** |

## FALSE POSITIVES (dropped, with evidence)

| Candidate | Verdict | Evidence |
|---|---|---|
| `q` SSTI at admin.py:177 (CWE-1336) | **FALSE POSITIVE** | `q` is passed as a Jinja **context variable** (`render_template_string(AUDIT_TEMPLATE, ..., q=q)`, admin.py:177) and rendered via `{{ q }}` — value data, not template source. The inline comment claiming "auto-escape off / RCE" is prose (Comment-skepticism §7); `render_template_string` compiles only the fixed `AUDIT_TEMPLATE` literal, and Jinja auto-escape is ON for Flask. User input never becomes template source. The real defect on `q` is the SQLi (admin.py:166), captured above. |
| SSTI in all other `render_template_string` calls (auth.py:66,107,169,192; files.py:67,147,195; reports.py:59; admin.py:72,127) | **FALSE POSITIVE** | Every call passes a fixed module-constant template string; user values flow only as context data under Jinja auto-escape. No attacker-controlled template source. (Trace agents already dispositioned these SAFE; confirmed.) |
| VULN-402 CVB (admin.py absent-role) | **FALSE POSITIVE / SAFE** | admin.py:30 `session.get("role") != "admin"` → absent role returns `None != "admin"` = True → `abort(403)`. Fails closed. |
| reset token echoed in response (CWE-200, sink 4.3) | **Not a standalone finding** | Subsumed — the reset token is the credential itself; issue is fully captured by VULN-RESET-TOKEN + VULN-FORGOT-OVERWRITE. |

## Notes / Cross-subgraph reconciliation

- Full-codebase grep for shared defenses: no `secure_filename`, no `CSRFProtect`/`flask-wtf`,
  no ORM/parameterization wrapper, no auth middleware beyond the two presence-only helpers.
  No cross-subgraph defense was missed by trace agents.
- `debug=True` (app.py:91) exposes the Werkzeug interactive debugger — code-quality/hardening note
  (only under `__main__`; not a request-reachable input). Not promoted to a finding.
- Confirmed count proceeding to Phase 3: **22 findings** (13 High/High+, 9 Medium; seed-creds and
  rate-limit reduced to Medium). Duplicate class-labeled entries for the same defect were merged
  per the "same defect re-labeled across classes" clause, NOT across distinct params/routes.
