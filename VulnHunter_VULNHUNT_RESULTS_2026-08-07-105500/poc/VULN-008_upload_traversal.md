# VULN-008 — Unrestricted Upload + Path Traversal via `f.filename`

- **CWE**: 434 / 22
- **Severity**: High+
- **Endpoint**: `POST /files/upload` (auth; session forgeable via VULN-002)
- **Sink**: `files.py:84-85`

## Static Data Flow Trace

```
1. ENTRY: Attacker POST /files/upload multipart, filename controlled by client.
   filename = "../../../../home/appuser/.ssh/authorized_keys"  (or "shell.py")
   -> files.py:77  f = request.files.get("file")

2. PROPAGATION: filename used verbatim — Werkzeug does NOT auto-apply
   secure_filename; no extension/MIME check.
   -> files.py:84  dest = os.path.join(UPLOAD_DIR, f.filename)
   Because the filename contains ../ (or is absolute), os.path.join escapes
   UPLOAD_DIR:  os.path.join(UPLOAD_DIR, "../../etc/x") -> resolves outside uploads/.

3. SINK: attacker bytes written to the traversed path.
   -> files.py:85  f.save(dest)

4. IMPACT: Arbitrary file write outside uploads/ (overwrite authorized_keys, drop
   a .py/.wsgi that the server may execute) -> RCE / persistence.
```

## Attacker gains
Arbitrary file write to an attacker-chosen path → code execution or credential/key overwrite.

## Expected vs Actual
- Secure app: `werkzeug.utils.secure_filename`, allow-list extensions, and verify the resolved path stays within UPLOAD_DIR.
- Vulnerable app: raw filename joined and saved.
