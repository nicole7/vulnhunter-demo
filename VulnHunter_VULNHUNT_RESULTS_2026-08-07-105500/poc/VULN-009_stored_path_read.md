# VULN-009 — Path Traversal Read via Stored `doc["path"]`

- **CWE**: 22
- **Severity**: High
- **Endpoints**: `GET /files/download/<id>`, `GET /files/preview/<id>`
- **Sinks**: `files.py:114` (send_file), `files.py:143` (open)

## Static Data Flow Trace

```
1. SETUP: Via VULN-008, a document row is stored whose `path` column points
   outside uploads/, e.g. path = "/etc/passwd" or "../../etc/passwd".
   -> files.py:89-90  INSERT ... path = dest  (attacker-influenced)

2. ENTRY: GET /files/download/<id>  (or /files/preview/<id>)
   -> files.py:108-110 / 134-136   SELECT * FROM documents WHERE id=<id>

3. SINK: stored path used with NO base-directory containment check.
   -> files.py:114  send_file(doc["path"], as_attachment=True)   # returns /etc/passwd
   -> files.py:143  open(doc["path"], "r") -> content reflected at files.py:147

4. IMPACT: Server returns the contents of an arbitrary server file.
```

## Attacker gains
Read arbitrary files on the server (e.g. `/etc/passwd`, app config, DB file) through download/preview.

## Expected vs Actual
- Secure app: resolve path with `os.path.realpath` and assert it is within UPLOAD_DIR before serving.
- Vulnerable app: serves whatever path string is stored.
