# SG-2 LOG Trace Results (partition sg-2 / files.py)

Class focus: Race conditions, cache isolation, credential scope, resource exhaustion, prototype pollution, crypto issues, integer overflow, deserialization.

## Input Dispositions

| # | Disposition | Notes |
|---|---|---|
| 10 | CROSS-CLASS(NAV, CWE-287/384) | Session cookie from hardcoded `secret_key` (app.py:20) — forgeable session. Auth/session forgery is NAV. Reported below as crypto-adjacent context. |
| 11 | CROSS-CLASS(INJ, files.py:85) | File content saved to disk; no LOG sink. Unrestricted upload = INJ. |
| 12 | CROSS-CLASS(NAV, files.py:84) | `f.filename` → path traversal in `os.path.join(UPLOAD_DIR, f.filename)` — path/traversal is NAV. |
| 13 | CROSS-CLASS(NAV, files.py:108) | `doc_id` reaches SELECT with no owner check → IDOR (CWE-639). NAV. |
| 14 | CROSS-CLASS(NAV, files.py:134) | Same IDOR pattern on preview. NAV. |
| 15 | CROSS-CLASS(NAV, files.py:114,143) | `doc["path"]` → `send_file`/`open` path traversal / arbitrary file read. NAV. |
| 16 | **CANDIDATE** | `pickle.loads` on user base64 form field → RCE. LOG (deserialization). See VULN-201. |

No race-condition, cache-isolation, credential-scope, prototype-pollution, ReDoS, or integer-overflow sinks present in scope.

---

## Candidates

#### [VULN-201] Insecure deserialization (pickle.loads) on user-supplied form data → RCE
- **Input**: #16: HTTP form field `data` (base64) at files.py:173
- **Class**: CWE-502 (Deserialization of Untrusted Data)
- **Severity**: High+ (authenticated, but session forgeable via hardcoded key → effectively unauthenticated; yields OS command / arbitrary code execution)
- **Location**: files.py:179 `pickle.loads(base64.b64decode(raw))`
- **Gate 0 (intended behavior?)**: No. "Restore from clipboard" is a feature, but executing attacker code during deserialization is not intended. Not exempt.
- **Gate 1 (reachable?)**: Reachable — route `/files/restore` registered via `files_bp` (app.py:77), POST branch executes on user request. Production.
- **Gate 2a (attacker-controlled?)**: Yes. `raw = request.form.get("data","")` (files.py:173) is directly attacker-supplied.
- **Gate 2b (sanitization?)**: None. `base64.b64decode` then `pickle.loads` directly; no allowlist, no safe loader, no HMAC/signature check.
- **Gate 3 (new capability?)**: Yes — arbitrary code execution via crafted pickle `__reduce__`. New outcome beyond any other endpoint.
- **Entry Point**: POST /files/restore
- **Data Flow**: request.form["data"] (files.py:173) → base64.b64decode (178) → pickle.loads (179) → RCE
- **Root Cause**: Untrusted bytes deserialized with pickle.
- **Exploitability**: Trivial; standard `__reduce__` payload. Session gate bypassable via forged cookie (hardcoded `secret_key`, app.py:20).

## Cross-class note (crypto context)
Hardcoded `app.secret_key = "super-secret-dev-key-1234"` (app.py:20) is a hardcoded-secret crypto weakness enabling session forgery. Primary auth-bypass impact is NAV; flagged here as CROSS-CLASS(NAV) since it gates every route above. It amplifies VULN-201 to unauthenticated RCE.
