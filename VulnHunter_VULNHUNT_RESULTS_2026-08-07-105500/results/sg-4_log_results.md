# SG-4 LOG-Class Results (Race/Cache/Cred-scope/Resource-exhaustion/Prototype-pollution/Crypto/Integer-overflow)

Partition: SG-4 (admin.py). No LOG-class sinks are present in scope. All assigned
inputs reach INJ or NAV sinks and are flagged CROSS-CLASS.

## Per-input dispositions

### Input #17 — `session["role"]` (admin.py:30, `_require_admin`)
- **CROSS-CLASS (input #17, admin.py:30, suspected class: NAV)** — CWE-287/302.
  Auth gate trusts a client-forgeable role cookie (hardcoded `secret_key`
  app.py:20). This is an authentication/authorization bypass (NAV), not a LOG
  logic-flaw. The crypto root cause (hardcoded key) is noted below as SAFE-for-LOG
  context but the exploit outcome is NAV.
- **Absent-input (CVB) check**: If `role` is absent, `session.get("role") != "admin"`
  is True → `abort(403)`. Fails CLOSED. No conditional-validation-bypass. Not a LOG finding.

### Input #18 — `user_id` path param (admin.py:80, /admin/delete/<int:user_id>)
- **SAFE (LOG)** — `<int:...>` converter type-constrains to integer; no integer-
  overflow risk (Python ints are arbitrary-precision, used only as SQL bind param,
  not allocation size/index/loop bound). Value is parameterized (`?`). No LOG sink.
- **CROSS-CLASS (input #18, admin.py:81, suspected class: NAV)** — no ownership/CSRF
  check; state-changing GET. NAV concern.

### Input #19 — `user_id` path param (admin.py:93, /admin/promote/<int:user_id>)
- **SAFE (LOG)** — same as #18: int-constrained, parameterized, no LOG sink.
- **CROSS-CLASS (input #19, admin.py:96, suspected class: NAV)** — privilege-
  escalation primitive (promote to admin) with no CSRF/ownership check. NAV.

### Input #20 — `host` form field (admin.py:117, POST /admin/ping)
- **CROSS-CLASS (input #20, admin.py:123-124, suspected class: INJ)** — CWE-78
  command injection via `shell=True` f-string. INJ sink, not LOG.
- **LOG check**: `timeout=10` bounds runtime; no unbounded allocation/ReDoS. No
  LOG finding.

### Input #21 — `q` query param (admin.py:159, GET /admin/audit)
- **CROSS-CLASS (input #21, admin.py:166, suspected class: INJ)** — CWE-89 SQLi
  (f-string LIKE).
- **CROSS-CLASS (input #21, admin.py:177, suspected class: INJ)** — CWE-1336 SSTI
  via render_template_string. Both INJ, not LOG.
- **LOG check**: no regex backtracking, no allocation sized by `q`. No LOG finding.

### Input #26 — no-input dashboard (admin.py:67, GET /admin/)
- **NO-MATCH (LOG)** — no user input; static query. Auth gate reachability is NAV
  (see #17). No LOG sink.

## Shared-infra crypto note (in-scope but not a standalone LOG candidate here)
- Hardcoded `secret_key = "super-secret-dev-key-1234"` (app.py:20). Crypto weakness
  (LOG territory) but its exploit surface is session forgery → routed as CROSS-CLASS(NAV)
  per input #17. Recorded here for completeness; the MD5 password hashing
  (auth.py:23) and predictable reset token (auth.py:161) are crypto/LOG findings but
  live in auth.py, OUTSIDE partition SG-4 scope — defer to the auth-partition LOG agent.

## Summary
- LOG CANDIDATES: 0
- CROSS-CLASS: #17→NAV, #18→NAV, #19→NAV, #20→INJ, #21→INJ(x2)
- SAFE(LOG): #18, #19 (int-constrained, no overflow)
- NO-MATCH(LOG): #26
- No race conditions, cache-isolation, cred-scope, resource-exhaustion,
  prototype-pollution, or integer-overflow sinks exist in admin.py.
