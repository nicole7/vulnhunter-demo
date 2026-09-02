# SG-3 LOG-class Trace Results (partition: reports.py)

Class group: Race conditions, cache isolation, credential scope, resource
exhaustion, prototype pollution, crypto, integer overflow.

Partition sinks in scope (S3 SQLi, S5 command injection, S8 SSTI) all belong to
INJ/NAV class groups — no LOG-class sinks are declared in this partition. Each
input is traced forward to LOG sinks; where it reaches a non-LOG sink it is
flagged CROSS-CLASS.

## Per-input dispositions

### Input #22 — `fmt` (query param, reports.py:69)
- **NO-MATCH (LOG)**. `fmt` is compared to the literal `"pdf"` (reports.py:86)
  to select CSV vs PDF branch. No LOG sink: no crypto, no deserialization, no
  arithmetic/allocation, no cache key, no regex, no merge. Pure equality branch
  selector. Not reaching any LOG-class sink.

### Input #23 — `from_date` (query param, reports.py:70)
- **NO-MATCH (LOG)** for my class.
- **CROSS-CLASS (#23, reports.py:79-83, suspected class: INJ)** — `from_date`
  is interpolated via f-string into raw SQL (`AND created >= '{from_date}'`),
  executed at reports.py:84. SQL injection (CWE-89). Not a LOG sink.

### Input #24 — `to_date` (query param, reports.py:71)
- **NO-MATCH (LOG)** for my class.
- **CROSS-CLASS (#24, reports.py:79-83, suspected class: INJ)** — `to_date`
  interpolated into the same raw SQL string, executed at reports.py:84. SQL
  injection (CWE-89). Not a LOG sink.

### Input #25 — `session["username"]` (session field, reports.py:95)
- **NO-MATCH (LOG)** for my class.
- **CROSS-CLASS (#25, reports.py:107-108, suspected class: INJ)** — username
  (forgeable via hardcoded secret key) is interpolated into `tmp_path`/`out_path`
  and then into `cmd = f"wkhtmltopdf {tmp_path} {out_path}"`, run with
  `shell=True` (reports.py:108). OS command injection (CWE-78). Not a LOG sink.
  Note: session forgeability itself derives from the hardcoded `secret_key`
  (app.py:20) — that hardcoded-secret crypto issue lives in shared infra
  (app.py), outside this partition's app-specific file; flagged for the app.py
  partition owner.

### Input #27 — GET /reports/generate (no-input endpoint, reports.py:56)
- **NO-MATCH (LOG)**. Handler renders a static constant `GENERATE_TEMPLATE` via
  `render_template_string` (reports.py:59). No user input flows into it, so no
  SSTI and no LOG sink. (S8 SSTI is INJ-class and requires no traceable input
  here — static template.)

## LOG-class findings in partition (reports.py): NONE

Checked for each LOG pattern within reports.py scope:
- Race conditions (check-then-act / read-modify-write / async / TOCTOU): none —
  handlers are single-shot reads, no counters/balances/state mutation.
- Cache/state isolation: no caching in reports.py.
- Credential/policy scope: no policy/token generation in reports.py.
- Resource exhaustion (ReDoS / unbounded alloc / recursive parse): no regex,
  no user-controlled size/count/limit; query has no user LIMIT/OFFSET.
- Prototype pollution: N/A (Python).
- Crypto: no cipher/hash/random in reports.py. (MD5 password/token hashing lives
  in auth.py:23,162 — outside this partition; noted for auth.py owner.)
- Integer overflow: no arithmetic on user-controlled values.
- Sensitive data in logs (CWE-532): no logging calls in reports.py.

## Summary
| Input | LOG disposition | Cross-class |
|-------|-----------------|-------------|
| #22 fmt | NO-MATCH | — |
| #23 from_date | NO-MATCH | INJ (SQLi, reports.py:79-84) |
| #24 to_date | NO-MATCH | INJ (SQLi, reports.py:79-84) |
| #25 session.username | NO-MATCH | INJ (cmd inj, reports.py:107-108) |
| #27 /generate | NO-MATCH | — |

No LOG-class CANDIDATEs in this partition.
