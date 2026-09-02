# VULN-018 — Reports Scope Bound Only to Forgeable Session (IDOR)

- **CWE**: 639
- **Severity**: Medium
- **Endpoint**: `GET /reports/export`
- **Sink**: `reports.py:74,81`

## Static Data Flow Trace

```
1. The export owner scope is taken solely from the session user_id.
   -> reports.py:74  uid = session["user_id"]
   -> reports.py:81  WHERE owner_id = {uid}

2. There is NO cryptographic / server-side caller-identity check beyond the
   session cookie, whose integrity depends on the hardcoded secret_key (VULN-002).

3. ATTACK: Attacker forges a session with user_id = <victim> (VULN-002) and
   exports the victim's documents. (Also reachable via VULN-016 UNION.)

4. IMPACT: Access to another user's report data. Impact is a subset of the
   secret_key forgery root cause; recorded separately per Anti-merge (distinct
   sink/fix — add non-forgeable caller identity).
```

## Attacker gains
Export another user's documents by presenting a forged session identity.

## Expected vs Actual
- Secure app: derive caller identity from a non-forgeable, cryptographically bound principal (fixed via VULN-002 random secret; longer-term signed claims).
- Vulnerable app: trusts forgeable session user_id.
