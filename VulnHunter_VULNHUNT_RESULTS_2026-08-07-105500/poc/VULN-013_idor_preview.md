# VULN-013 — IDOR on File Preview

- **CWE**: 639
- **Severity**: High
- **Endpoint**: `GET /files/preview/<int:doc_id>`
- **Sink**: `files.py:134-147`

## Static Data Flow Trace

```
1. ENTRY: Authenticated attacker (user_id=2) requests GET /files/preview/1
   -> files.py:131  preview(doc_id=1)

2. QUERY: id-only lookup, no owner_id scope (distinct route/sink from download).
   -> files.py:134  SELECT * FROM documents WHERE id = 1

3. SINK: file content read and reflected in the preview page.
   -> files.py:143  open(doc["path"]).read(8192)
   -> files.py:147  render_template_string(PREVIEW_TEMPLATE, content=content)

4. IMPACT: Attacker views the contents of any user's document by ID.
```

## Attacker gains
Read any user's document contents via preview, independent of the download route.

## Expected vs Actual
- Secure app: `WHERE id=? AND owner_id=?`.
- Vulnerable app: id-only lookup.
