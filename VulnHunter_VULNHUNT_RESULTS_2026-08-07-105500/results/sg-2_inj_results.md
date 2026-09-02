# Partition SG-2 — INJ Trace Results

**Scope**: `target-app/files.py` (`files_bp`, `/files`). All routes PRODUCTION-reachable.
Attacker: any party forging a session cookie (hardcoded `secret_key` "super-secret-dev-key-1234", app.py:20). `_require_login()` only checks `"user_id" in session` — no crypto binding.

## Disposition Summary

| # | Input | Disposition |
|---|-------|-------------|
| 10 | `session[user_id]` | SAFE (SQL parameterized; template autoescaped) / CROSS-CLASS see note |
| 11 | file bytes `f` | SAFE-for-INJ (content not a sink alone; see #12/#16) |
| 12 | `f.filename` | CANDIDATE VULN-201 (traversal + unrestricted upload) |
| 13 | `doc_id` (download) | NO-MATCH for INJ / CROSS-CLASS(NAV, IDOR) |
| 14 | `doc_id` (preview) | NO-MATCH for INJ / CROSS-CLASS(NAV, IDOR) |
| 15 | `doc["path"]` | CANDIDATE VULN-202 (traversal read) — second-order from #12 |
| 16 | `data` base64→pickle | CANDIDATE VULN-203 (RCE) + VULN-204 (arbitrary file write) |

---

#### [VULN-201] Unrestricted file upload + path traversal via filename
- **Input**: #12 `f.filename` (multipart upload)
- **Class**: CWE-434 (Unrestricted Upload) / CWE-22 (Path Traversal)
- **Severity**: High+
- **Location**: files.py:84-85 `os.path.join(UPLOAD_DIR, f.filename)`; `f.save(dest)`
- **Gate 0**: Not intended — no extension/MIME allowlist, filename not sanitized. `os.path.join` with an absolute or `../` filename escapes UPLOAD_DIR.
- **Gate 1**: Route `POST /files/upload` registered (app.py:77), production.
- **Gate 2a**: Attacker-controlled — raw multipart filename header.
- **Gate 2b**: No sanitization. Werkzeug `request.files` does NOT apply `secure_filename` automatically; `f.filename` is verbatim. `os.path.join(base, "../../x")` → escapes; absolute filename replaces base entirely.
- **Gate 3**: New capability — write arbitrary file content to arbitrary server path (e.g. `.py`/`.sh`/cron/webroot) → potential RCE; also no ext check.
- **Data Flow**: multipart filename → files.py:84 join → :85 `f.save(dest)` (write); stored path → documents.path (feeds VULN-202).
- **Root Cause**: Unsanitized user filename used as destination path with no allowlist.

#### [VULN-202] Path traversal / arbitrary file read via stored path
- **Input**: #15 `doc["path"]` (second-order; written by #12 upload)
- **Class**: CWE-22
- **Severity**: High+
- **Location**: files.py:114 `send_file(doc["path"])`; files.py:143 `open(doc["path"])`
- **Gate 0**: Not intended — path read verbatim from DB, originally attacker-controlled filename.
- **Gate 1**: `GET /files/download/<id>`, `GET /files/preview/<id>` registered, production.
- **Gate 2a**: Attacker-controlled indirect: user filename (#12) → documents.path → read here. Store-write requires only authed upload.
- **Gate 2b**: None. No base-dir containment check on `doc["path"]`.
- **Gate 3**: Reads arbitrary server files (e.g. traversal path stored via VULN-201) and returns/displays contents → file disclosure (`/etc/passwd`, secrets).
- **Data Flow**: filename (#12) → :84 dest → :90 INSERT path → :108/:134 SELECT → :114 send_file / :143 open→read → response.
- **Root Cause**: Stored path trusted for filesystem read with no canonicalization/allowlist.

#### [VULN-203] Insecure deserialization (RCE)
- **Input**: #16 `data` (base64 → pickle)
- **Class**: CWE-502
- **Severity**: High+
- **Location**: files.py:178-179 `pickle.loads(base64.b64decode(raw))`
- **Gate 0**: Not intended — arbitrary object restore.
- **Gate 1**: `POST /files/restore` registered, production.
- **Gate 2a**: Attacker-controlled form field `data`.
- **Gate 2b**: None. `pickle.loads` on untrusted input; `__reduce__` → OS command execution.
- **Gate 3**: Arbitrary code/command execution on server.
- **Data Flow**: form `data` → :173 → :178 b64decode → :179 pickle.loads → deserialization gadget runs.
- **Root Cause**: Untrusted pickle deserialization.

#### [VULN-204] Arbitrary file write via pickle-derived filename
- **Input**: #16 → `obj["filename"]` / `obj["content"]`
- **Class**: CWE-22 / CWE-434
- **Severity**: High+ (separate from 203: fixing pickle differently than fixing path join; independent sink at :182-184)
- **Location**: files.py:182-184 `os.path.join(UPLOAD_DIR, filename)`; `open(dest,"wb").write(content)`
- **Gate 0**: Not intended.
- **Gate 2b**: No sanitization of `filename` from deserialized object; traversal/absolute path escapes UPLOAD_DIR.
- **Gate 3**: Write attacker content to arbitrary path (in addition to RCE via 203).
- **Data Flow**: pickle obj → :180 filename → :182 join → :183-184 write.
- **Root Cause**: Unsanitized filename used as write destination.

---

## Non-INJ / SAFE notes

- **#10 `session["user_id"]`**: Into SQL at :64/:89/:187 — all parameterized (`?`), SAFE. Into `render_template_string` (S8 :67,:147,:195): templates are constant string literals; user values (`doc['filename']`, `content`) passed as Jinja **data** with autoescaping ON (Flask default) → not SSTI, not XSS. SAFE for INJ. CROSS-CLASS(NAV, CWE-306/session-forgery via hardcoded key S14) — auth/session weakness, out of INJ scope.
- **S8 SSTI (files.py:67,147,195)**: NO-MATCH — no user input flows into the *template string* itself; only into render context as escaped data.
- **#13/#14 `doc_id`**: `<int:doc_id>` type-constrained, parameterized SQL → SAFE for INJ. Missing owner_id check (files.py:108,134) → **CROSS-CLASS(NAV, CWE-639 IDOR)**.
- **#11 file bytes**: content alone reaches no INJ sink except as written data (covered by VULN-201). SAFE-for-INJ.
