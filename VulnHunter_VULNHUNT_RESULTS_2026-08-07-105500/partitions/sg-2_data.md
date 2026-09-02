# Partition SG-2 (files)

**Scan scope root**: `/Users/nicolegasperini/Documents/VulnHunter/target-app`
**App-specific file**: `files.py` (`files_bp`, prefix `/files`)
**Entry points**: GET /files/, POST /files/upload, GET /files/download/<id>, GET /files/preview/<id>, POST /files/restore
**Reachability**: PRODUCTION. Attacker profile: any party who forges a session cookie (hardcoded secret key).

## Assigned Inputs

| # | Source Type | Location | Variable | Entry Point | Trust Level |
|---|---|---|---|---|---|
| 10 | Session cookie | files.py:26,64 | `session[user_id]` | GET /files/ | authed (forgeable, S14) |
| 11 | File upload (content) | files.py:77,85 | `f` (file bytes) | POST /files/upload | authed |
| 12 | File upload (filename) | files.py:77,84 | `f.filename` | POST /files/upload | authed |
| 13 | HTTP path param | files.py:100 | `doc_id` | GET /files/download/<id> | authed |
| 14 | HTTP path param | files.py:130 | `doc_id` | GET /files/preview/<id> | authed |
| 15 | Second-order DB read | files.py:114,143 | `doc["path"]` | download/preview | authed |
| 16 | HTTP form field | files.py:173 | `data` (base64→pickle) | POST /files/restore | authed |

## Sinks in scope
- S6 Insecure deserialization files.py:179 `pickle.loads(base64.b64decode(raw))`
- S8 SSTI candidate render_template_string files.py:67,147,195 (filename/content)
- S9 Path traversal / arbitrary file read files.py:143 `open(doc["path"])`, files.py:114 `send_file(doc["path"])`
- S10 Arbitrary file write files.py:182-184 from pickle `filename`
- S11 Unrestricted file upload files.py:84-85 `os.path.join(UPLOAD_DIR, f.filename)` — no ext/MIME check, traversal via filename

## Shared Infrastructure
- `get_db()` app.py:25
- `_require_login()` files.py:25 — checks `"user_id" in session` only, no crypto binding
- Flask session / `secret_key` app.py:19-20 — hardcoded (S14)

## Threat model
`_require_login` gates routes but session forgeable. No per-resource owner check on download/preview (files.py:108/134) → IDOR. Filename unsanitized → traversal/unrestricted upload. `pickle.loads` on user data → RCE.
