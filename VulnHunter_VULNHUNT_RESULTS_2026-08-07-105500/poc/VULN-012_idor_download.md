# VULN-012 — IDOR on File Download

- **CWE**: 639
- **Severity**: High
- **Endpoint**: `GET /files/download/<int:doc_id>`
- **Sink**: `files.py:108-114`

## Static Data Flow Trace

```
1. ENTRY: Authenticated attacker (user_id=2) requests another user's doc:
   GET /files/download/1   (doc 1 owned by user_id=1)
   -> files.py:101  download(doc_id=1)

2. QUERY: lookup by id ONLY — no owner_id predicate.
   -> files.py:108  SELECT * FROM documents WHERE id = 1
   Contrast the sibling list_files (files.py:64) which DOES scope by owner_id,
   proving the omission is a defect not a design.

3. SINK: file returned regardless of ownership.
   -> files.py:114  send_file(doc["path"], as_attachment=True)

4. IMPACT: Attacker downloads any user's document by enumerating integer IDs.
```

## Attacker gains
Read any user's uploaded document by ID enumeration.

## Expected vs Actual
- Secure app: `WHERE id=? AND owner_id=?` with session user_id.
- Vulnerable app: id-only lookup.
