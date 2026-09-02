# VULN-006 — Hardcoded MD5 Seed Credentials (recoverable admin password)

- **CWE**: 798 / 312
- **Severity**: Medium
- **Location**: `app.py:65-69`

## Static Data Flow Trace

```
1. SOURCE: init_db seeds accounts with hardcoded md5 password digests.
   -> app.py:67   ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', ...)
   -> app.py:68   ('alice', '6384e2b2184bcbf58eccf10ca7a6563c', ...)
   -> app.py:69   ('bob',   'e99a18c428cb38d5f260853678922e03', ...)

2. RECOVERY: Because hashing is unsalted MD5 (VULN-005), the digests are
   reversible directly from source without touching the DB:
     md5("admin") == 21232f297a57a5a743894a0e4a801fc3
   -> the admin password is literally "admin".

3. IMPACT: Anyone reading the repo learns the admin login (admin / admin) and
   can authenticate normally at /auth/login.
```

## Attacker gains
Working admin credentials (`admin`/`admin`) recovered from source alone — no exploitation of a running service required.

## Expected vs Actual
- Secure app: no seeded default credentials in source; provisioning generates a random password out of band.
- Vulnerable app: predictable seed digests that reverse to the account names.
