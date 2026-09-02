# SG-2 NAV Trace Results (partition SG-2 — files.py)

Class group: CSRF, IDOR, auth bypass, conditional validation bypass, identity
spoofing, confused deputy, security signal spoofing, mass assignment, parameter
pollution.

Scope root: `/Users/nicolegasperini/Documents/VulnHunter/target-app`
File: `files.py` (`files_bp`, prefix `/files`)

---

## Per-input dispositions

| # | Input | Disposition | Note |
|---|-------|-------------|------|
| 10 | `session["user_id"]` | CANDIDATE (auth bypass, VULN-201) | `_require_login` presence-only; hardcoded secret allows forged session |
| 11 | upload content bytes `f` | CROSS-CLASS(INJ) | reaches S8 SSTI / S11 upload — not NAV |
| 12 | `f.filename` | CROSS-CLASS(INJ) | reaches S11 upload / S9 traversal — not NAV |
| 13 | `doc_id` (download) | CANDIDATE (IDOR, VULN-202) | no owner check |
| 14 | `doc_id` (preview) | CANDIDATE (IDOR, VULN-203) | no owner check |
| 15 | `doc["path"]` 2nd-order | CROSS-CLASS(INJ) | path traversal / arb file read — not NAV |
| 16 | `data` base64→pickle | CROSS-CLASS(INJ, S6 RCE) + CANDIDATE (CSRF, VULN-204) | deserialization is INJ; CSRF on POST is NAV |

Additional structural NAV findings: CSRF absent on ALL state-changing POSTs
(upload, restore) — VULN-204/205.

---

## CANDIDATES

#### [VULN-201] Auth bypass — presence-only session check with forgeable session
- **Input**: #10 session `user_id` (files.py:26,64)
- **Class**: CWE-306 / CWE-290 (missing effective auth)
- **Severity**: High+
- **Location**: files.py:25-27 (`_require_login`); app.py:19-20 (hardcoded key)
- **Gate 0**: Not intended — login is meant to authenticate; a forgeable session defeats it.
- **Gate 1**: `_require_login` called on every route (files.py:61,76,102,132,170). Production.
- **Gate 2a**: Attacker-controlled — Flask session signed with hardcoded `secret_key = "super-secret-dev-key-1234"` (app.py:20). Any party can mint a cookie with arbitrary `user_id`.
- **Gate 2b**: `_require_login` only checks `"user_id" in session` — no crypto binding beyond the forgeable signature. No effective defense.
- **Gate 3**: New capability — unauthenticated attacker becomes any authenticated user, then reaches all file operations and cross-user data (compounds VULN-202/203).
- **Entry Point**: all `/files/*` routes.
- **Root Cause**: Hardcoded signing key + presence-only session gate.

#### [VULN-202] IDOR — download any document by ID
- **Input**: #13 `doc_id` path param (files.py:100)
- **Class**: CWE-639
- **Severity**: High
- **Location**: files.py:108-114
- **Resource ID Gate (a)**: No ownership check. Query is `SELECT * FROM documents WHERE id = ?` — no `owner_id = session["user_id"]`. Compare list_files (files.py:63-64) which DOES scope by owner_id — download does not.
- **Gate 0**: NAV exemption — passthrough/no-authz is a missing check, not design.
- **Gate 1**: Route registered, production (files.py:100).
- **Gate 2a**: Attacker-controlled integer path param.
- **Gate 2b**: `<int:doc_id>` is format validation only — does not satisfy ownership (Gate a).
- **Gate 3**: Any authed user downloads any other user's document by guessing sequential integer ID.
- **Entry Point**: GET /files/download/<id>.

#### [VULN-203] IDOR — preview any document by ID
- **Input**: #14 `doc_id` path param (files.py:130)
- **Class**: CWE-639
- **Severity**: High
- **Location**: files.py:134-147
- **Resource ID Gate (a)**: No ownership check — same missing `owner_id` filter as VULN-202. Separate sink (preview reads+renders content vs. download send_file); fixing one does not fix the other.
- **Gate 0**: NAV exemption.
- **Gate 1**: Production (files.py:130).
- **Gate 2a**: Attacker-controlled.
- **Gate 2b**: int format only.
- **Gate 3**: Any authed user reads/renders any other user's document contents.
- **Entry Point**: GET /files/preview/<id>.

#### [VULN-204] CSRF — restore endpoint (state-changing POST, no token)
- **Input**: #16 form field `data` / POST /files/restore (files.py:168-173)
- **Class**: CWE-352
- **Severity**: Medium
- **Location**: files.py:168-190
- **Gate 0**: Not intended — no CSRF protection wired anywhere; Flask provides none by default and none is enabled.
- **Gate 1**: Production POST route.
- **Gate 2a**: Cross-origin form POST; accepts `multipart`/form body (not JSON), no Content-Type gate.
- **Gate 2b**: No CSRF token validated; no framework CSRF (no flask-wtf/CSRFProtect in codebase).
- **Gate 3**: Attacker auto-submits a form causing a file write + DB insert under the victim's session (also delivers the pickle RCE payload cross-site).
- **Entry Point**: POST /files/restore.

#### [VULN-205] CSRF — upload endpoint (state-changing POST, no token)
- **Input**: #11/#12 POST /files/upload (files.py:74-92)
- **Class**: CWE-352
- **Severity**: Medium
- **Location**: files.py:74-92
- **Gate 0**: Not intended — no CSRF protection present.
- **Gate 1**: Production POST route.
- **Gate 2a**: Cross-origin multipart form POST; no Content-Type/token gate.
- **Gate 2b**: No CSRF token; no framework CSRF enabled.
- **Gate 3**: Attacker forces a victim to upload attacker-controlled file (traversal/unrestricted upload) under victim's session. Separate handler/fix from VULN-204.
- **Entry Point**: POST /files/upload.

---

## CROSS-CLASS (out of NAV scope — flagged for INJ)
- CROSS-CLASS (input #11, files.py:85 & 67/147/195, suspected class: INJ) — unrestricted upload S11 / SSTI S8.
- CROSS-CLASS (input #12, files.py:84-85, suspected class: INJ) — path traversal / unrestricted upload via filename (S11/S9/S10).
- CROSS-CLASS (input #15, files.py:114 send_file & 143 open, suspected class: INJ) — path traversal / arbitrary file read (S9).
- CROSS-CLASS (input #16, files.py:179 `pickle.loads`, suspected class: INJ) — insecure deserialization RCE (S6). NAV also raised VULN-204 (CSRF) on same endpoint.

## Mass Assignment note
The pickle `obj` (input #16) sets `filename`/`content` written to disk + DB
(files.py:180-189). This is deserialization-driven arbitrary write (INJ/S10),
not a body-DTO mass-assignment gate case (no structured DTO with role-restricted
fields). Recorded under CROSS-CLASS(INJ); no separate CWE-915 candidate.

## Post-Trace Authorization Helper Coverage Audit
Siblings `list_files` (files.py:63-64) scope by `owner_id`; `download`
(files.py:108) and `preview` (files.py:134) do NOT → covered by VULN-202/203.
No other auth-helper divergence.
