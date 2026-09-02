# VULN-011 — Path Traversal Write via Pickle-Derived Filename

- **CWE**: 22 / 434
- **Severity**: Medium (requires the already-RCE pickle step of VULN-010)
- **Endpoint**: `POST /files/restore`
- **Sink**: `files.py:182-184`

## Static Data Flow Trace

```
1. ENTRY: Attacker POST /files/restore with a pickle that deserializes to a dict
   {"filename": "../../../../home/appuser/.ssh/authorized_keys", "content": b"ssh-rsa ..."}
   -> files.py:179  obj = pickle.loads(blob)
   -> files.py:180  filename = obj.get("filename", ...)   # attacker-controlled str

2. PROPAGATION: filename joined without sanitization; absolute or ../ escapes dir.
   -> files.py:182  dest = os.path.join(UPLOAD_DIR, filename)

3. SINK: attacker content written to the traversed path.
   -> files.py:183-184  open(dest,"wb").write(content)

4. IMPACT: Arbitrary file write to an attacker-chosen path (distinct sink/fix from
   the pickle RCE itself — this is the write primitive even if a safer loader
   returned a plain dict).
```

## Attacker gains
Arbitrary file write outside uploads/ from the deserialized filename field.

## Expected vs Actual
- Secure app: `secure_filename(filename)` and containment check before writing.
- Vulnerable app: raw filename joined and written.
