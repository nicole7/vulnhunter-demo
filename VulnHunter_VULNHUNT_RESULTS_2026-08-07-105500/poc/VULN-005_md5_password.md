# VULN-005 — Unsalted MD5 Password Hashing

- **CWE**: 327 / 916
- **Severity**: High
- **Function**: `_hash_password` `auth.py:21-23`
- **Callers**: login `auth.py:50`, register `auth.py:94`, reset `auth.py:185`
- **Corroboration**: seed hashes `app.py:67-69`

## Static Data Flow Trace

```
1. DEFINITION:
   -> auth.py:23   return hashlib.md5(pw.encode()).hexdigest()
   Unsalted, single-round MD5 — a fast, collision-broken hash.

2. USE: stored as the password column value for every account.
   -> auth.py:50/94/185

3. ATTACK: Attacker who obtains the users table (via VULN-001/VULN-014/VULN-016
   UNION SQLi) recovers plaintext by:
     - Direct rainbow-table / dictionary lookup of the unsalted md5.
   Proof against seed data (app.py:67-69):
     md5("admin")  = 21232f297a57a5a743894a0e4a801fc3  -> matches admin row
     md5("alice")  = 6384e2b2184bcbf58eccf10ca7a6563c  -> matches alice row
     md5("bob")    = e99a18c428cb38d5f260853678922e03  -> matches bob row

4. IMPACT: All stored password hashes are trivially reversible to plaintext.
```

## Attacker gains
Instant plaintext recovery of any leaked password hash (demonstrated on all three seeded accounts), enabling credential reuse and lateral movement.

## Expected vs Actual
- Secure app: `bcrypt`/`argon2`/`scrypt` with per-user salt and work factor.
- Vulnerable app: bare `hashlib.md5` — the exploit test recomputes the seed digests and matches them.
