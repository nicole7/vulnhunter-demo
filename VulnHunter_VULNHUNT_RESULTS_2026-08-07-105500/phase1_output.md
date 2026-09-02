# Phase 1: Reconnaissance — Attack Surface Report

## Structural Overview

**Languages**: Python 3
**Frameworks**: Flask >=3.0,<4 (Blueprints, `render_template_string`/Jinja2), `sqlite3` (raw SQL, no ORM), `subprocess`, `pickle`
**Module structure**: single-package Flask app; 4 blueprints registered in `app.py`.

Production source files (scope: `/Users/nicolegasperini/Documents/VulnHunter/target-app`):
- `app.py` — entry point, DB init, `get_db()`, blueprint registration, `/` redirect
- `auth.py` — `auth_bp` (`/auth`): login, register, logout, forgot, reset
- `files.py` — `files_bp` (`/files`): list, upload, download, preview, restore
- `admin.py` — `admin_bp` (`/admin`): dashboard, delete, promote, ping, audit
- `reports.py` — `reports_bp` (`/reports`): generate, export

No test/vendor/generated directories present. No build-time code swapping (Step 4): N/A — no Makefile/Dockerfile/bundler; single production variant.

---

## Step 1a: Sink Inventory

| # | Sink Type | Location | Detail |
|---|---|---|---|
| S1 | SQL injection (f-string) | auth.py:55 | `SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'` |
| S2 | SQL injection (f-string LIKE) | admin.py:166 | `... action LIKE '%{q}%' OR detail LIKE '%{q}%'` |
| S3 | SQL injection (f-string) | reports.py:79-83 | `from_date`/`to_date`/`uid` interpolated into query |
| S4 | Command injection (`shell=True`) | admin.py:123-124 | `f"ping -c 2 {host}"` |
| S5 | Command injection (`shell=True`) | reports.py:107-108 | `f"wkhtmltopdf {tmp_path} {out_path}"` (username-derived paths) |
| S6 | Insecure deserialization | files.py:179 | `pickle.loads(base64.b64decode(raw))` |
| S7 | SSTI (`render_template_string` + user var) | admin.py:177 | reflects `q` |
| S8 | SSTI candidate (`render_template_string`) | auth.py:66,107,169,192; files.py:67,147,195; admin.py:72,127; reports.py:59 | user data into templates; `error`/`msg`/`token`/`filename`/`content` |
| S9 | Path traversal / arbitrary file read | files.py:143 (`open(doc["path"])`), files.py:114 (`send_file(doc["path"])`) | `path` stored verbatim from upload |
| S10 | Arbitrary file write | files.py:182-184 | `open(os.path.join(UPLOAD_DIR, filename),"wb")` from pickle `filename` |
| S11 | Unrestricted file upload | files.py:84-85 | `os.path.join(UPLOAD_DIR, f.filename)`; no ext/MIME check; traversal via filename |
| S12 | Weak crypto (MD5) | auth.py:23,162 | password hashing + reset token |
| S13 | Predictable reset token | auth.py:161-162 | `md5(f"{id}:{int(time.time())}")` |
| S14 | Hardcoded secret key | app.py:20 | `super-secret-dev-key-1234` → session forgery |
| S15 | Debug mode | app.py:91 | `app.run(debug=True)` → Werkzeug console |

**Per-module sink coverage**: app.py ✓(S14,S15) · auth.py ✓(S1,S8,S12,S13) · files.py ✓(S6,S9,S10,S11) · admin.py ✓(S2,S4,S7) · reports.py ✓(S3,S5). All modules covered. No HTTP-client URL-concat sinks (no outbound HTTP calls).

---

## Step 1b: Input Inventory

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
| 10 | Session cookie | files.py:26,64 | `session[user_id]` | GET /files/ | authed (forgeable, S14) |
| 11 | File upload (content) | files.py:77,85 | `f` (file bytes) | POST /files/upload | authed |
| 12 | File upload (filename) | files.py:77,84 | `f.filename` | POST /files/upload | authed |
| 13 | HTTP path param | files.py:100 | `doc_id` | GET /files/download/<id> | authed |
| 14 | HTTP path param | files.py:130 | `doc_id` | GET /files/preview/<id> | authed |
| 15 | Second-order DB read | files.py:114,143 | `doc["path"]` | download/preview | authed |
| 16 | HTTP form field | files.py:173 | `data` (base64→pickle) | POST /files/restore | authed |
| 17 | Session cookie | admin.py:30 | `session[role]` | all /admin/* | authed (forgeable → admin) |
| 18 | HTTP path param | admin.py:80 | `user_id` | GET /admin/delete/<id> | admin |
| 19 | HTTP path param | admin.py:93 | `user_id` | GET /admin/promote/<id> | admin |
| 20 | HTTP form field | admin.py:117 | `host` | POST /admin/ping | admin |
| 21 | HTTP query param | admin.py:159 | `q` | GET /admin/audit | admin |
| 22 | HTTP query param | reports.py:69 | `fmt` | GET /reports/export | authed |
| 23 | HTTP query param | reports.py:70 | `from_date` | GET /reports/export | authed |
| 24 | HTTP query param | reports.py:71 | `to_date` | GET /reports/export | authed |
| 25 | Session field | reports.py:95 | `session[username]` | GET /reports/export (pdf) | authed (forgeable, S14) |
| 26 | no-input endpoint | admin.py:67 | N/A | GET /admin/ (dashboard) | admin |
| 27 | no-input endpoint | reports.py:56 | N/A | GET /reports/generate | authed |

**Completeness**: every route in README (14) + delete/promote/reset/restore covered. Session values (10,17,25) are attacker-controlled because the secret key is hardcoded (S14) → CWE-306/384 across all "authed"/"admin" gates.

### Step 1c: Indirect Dispatch
None. No handler maps, factories, or callback registries. Blueprint registration is static.

### Step 1e: Authorization Gate Audit
- `_require_login()` (files.py:25, reports.py:26): checks `"user_id" in session` only — no crypto binding.
- `_require_admin()` (admin.py:25): `session.get("role") != "admin"` — trusts forgeable cookie (S14). Latent privilege escalation. No `.contains()`/substring gate anti-patterns found.

### Step 1f: Authentication Path Enumeration
- Login (auth.py:55): single branch, SQLi-bypassable (`' OR '1'='1`).
- Reset (auth.py:181): token = predictable MD5 (S13) → account takeover.
- All session-based gates accept a forged cookie (no signature verification beyond the compromised hardcoded key).

---

## Step 2: Threat Model

| Entry-point group | App-layer auth enforcement | Caller identity binding | Per-resource authorization |
|---|---|---|---|
| `/auth/*` (login, register, forgot, reset, logout) | NONE | NONE | NONE |
| `/files/*` (list, upload, download, preview, restore) | files.py:26 (`_require_login` → abort 401) | NONE (session key hardcoded, app.py:20) | NONE (download/preview: no owner check, files.py:108/134) |
| `/reports/*` (generate, export) | reports.py:27 (`_require_login`) | NONE | NONE |
| `/admin/*` (dashboard, delete, promote, ping, audit) | admin.py:30 (`_require_admin` → abort 403) | NONE (role from forgeable cookie) | NONE |

- **Attacker profile**: `/auth/*` — any party reaching the endpoint (fully unauth). `/files`,`/reports`,`/admin` — enforcement present but binding NONE (hardcoded secret), so any party who forges a cookie (trivially, incl. `role=admin`) reaches them.
- **Attacker controls**: inputs #1–#27, including forged `user_id`/`role`/`username` session fields.
- **Attacker does NOT control**: `portal.db` seed rows (except via SQLi write), server filesystem outside uploads/tmp (except via traversal/RCE sinks).
- **Existing attacker capabilities (Gate 3 baseline)**: `/auth/*` — reach endpoint only. Others — with a forged cookie, reach any file/report/admin route; but each sink operation still subject to CWE evaluation in Phase 2.

---

## Trust Boundaries

| Boundary | Location | Input Source | Validation |
|---|---|---|---|
| HTTP → SQL | auth.py:55, admin.py:166, reports.py:79 | form/query params | NONE (f-string interpolation) |
| HTTP/session → shell | admin.py:124, reports.py:108 | `host`, `session[username]` | NONE (`shell=True`) |
| HTTP → deserialization | files.py:179 | `data` base64 | NONE (`pickle.loads`) |
| HTTP → template | admin.py:177 (+S8 sites) | `q`, `msg`, etc. | NONE (autoescape on for HTML but SSTI via `render_template_string`) |
| DB/upload → filesystem | files.py:114,143,182 | `doc[path]`, pickle `filename` | NONE (no path normalization) |
| Client cookie → identity/role | files/reports/admin gates | session cookie | Signed with hardcoded key (app.py:20) — effectively none |
| Upload → filesystem | files.py:84 | `f.filename` | NONE (no ext/MIME/name sanitization) |

---

## Shared Infrastructure Catalog

| Module | Role | Files |
|---|---|---|
| `get_db()` | sqlite3 connection provider | app.py:25 |
| `_require_login()` | authn gate (session presence) | files.py:25, reports.py:26 |
| `_require_admin()` | authz gate (session role) | admin.py:25 |
| `_hash_password()` | password hashing (MD5) | auth.py:21 |
| Flask session / `secret_key` | identity/session signing (hardcoded key) | app.py:19-20 |

---

## Subgraph Partitions

| Partition | Inputs | Entry Points | App-Specific Files | Shared Nodes Used | Reachability |
|---|---|---|---|---|---|
| SG-1 (auth) | 1–9 | /auth/login, /register, /forgot, /reset, /logout | auth.py | get_db, _hash_password, session | PRODUCTION |
| SG-2 (files) | 10–16 | /files/ list,upload,download,preview,restore | files.py | get_db, _require_login, session | PRODUCTION |
| SG-3 (reports) | 22–25, 27 | /reports/generate, /export | reports.py | get_db, _require_login, session | PRODUCTION |
| SG-4 (admin) | 17–21, 26 | /admin/ dashboard,delete,promote,ping,audit | admin.py | get_db, _require_admin, session | PRODUCTION |

Partitions are disjoint (each blueprint self-contained; only shared-catalog modules cross-cut). No pathological/oversized/undersized partitions. No DEV-ONLY gates — `debug=True` (app.py:91) affects the whole app but does not gate any route. All 4 production modules covered ✓.

**Prioritization for Phase 2**: SG-1 (unauth) first, then SG-2/SG-3 (authed, cookie-forgeable), then SG-4 (admin, cookie-forgeable to admin).
