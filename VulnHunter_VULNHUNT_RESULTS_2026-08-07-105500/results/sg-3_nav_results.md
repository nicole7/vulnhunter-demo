# SG-3 NAV Trace Results (partition: reports.py)

Class group: CSRF, IDOR, auth bypass, CVB, identity spoofing, confused deputy,
security-signal spoofing, mass assignment, parameter pollution.

## Per-input dispositions

### #22 `fmt` (query param, reports.py:69)
- Not a resource ID, not a body, not an authz-scope selector (csv/pdf are output
  formats for the caller's OWN data — Gate 0 feature parameter).
- Flows to SQL branch (S3) and PDF/command branch (S5) — both INJ sinks.
- **NAV disposition: NO-MATCH.** CROSS-CLASS (#22, reports.py:86 branch → S5
  command inj / S3 SQLi, suspected class: INJ).

### #23 `from_date` (query param, reports.py:70)
- Interpolated into raw SQL f-string reports.py:79-83.
- No NAV sink (not an ID, not identity, not a security header).
- **NAV disposition: CROSS-CLASS** (#23, reports.py:79-83, suspected class: INJ / SQLi).

### #24 `to_date` (query param, reports.py:71)
- Interpolated into raw SQL f-string reports.py:79-83.
- **NAV disposition: CROSS-CLASS** (#24, reports.py:79-83, suspected class: INJ / SQLi).

### #25 `session["username"]` (reports.py:95)
- Value read from session, interpolated into shell command reports.py:107-108
  (`wkhtmltopdf {tmp_path} {out_path}` where paths embed username). That sink is
  command injection → INJ.
- **NAV angle (identity spoofing, CWE-290):** `username` is an identity claim.
  The Flask session is signed with a HARDCODED secret key (app.py:20,
  `super-secret-dev-key-1234`), so an attacker can forge a session and set
  `username` (and `user_id`) to any value. The session is trusted as an
  authenticated identity but its integrity is not protected. See CANDIDATE below.
- Command-inj sink disposition: CROSS-CLASS (#25, reports.py:107-108, INJ).

### #27 GET /reports/generate (no-input, reports.py:56)
- Renders a static constant template (`GENERATE_TEMPLATE`) via
  render_template_string. No user input reaches the template (S8 SSTI not fed by
  attacker input here — the string is a hardcoded literal).
- Self-service UI, no cross-principal read/write.
- **NAV disposition: SAFE** (no NAV sink; template input is a server-side constant).

---

## CANDIDATE

#### [VULN-NAV-01] Forgeable session identity via hardcoded secret key (auth bypass / identity spoofing)
- **Input**: #25 session identity (`session["user_id"]` @ reports.py:74,
  `session["username"]` @ reports.py:95) — session integrity depends on secret key.
- **Class**: CWE-290 (Authentication Bypass by Spoofing) / CWE-287; enables CWE-639
  (the `owner_id = {uid}` scope at reports.py:81 is bypassable).
- **Severity**: High+ (unauthenticated attacker can mint any identity; grants
  access to any user's documents and, combined with S3/S5, full DB read + RCE).
- **Location**: app.py:20 (hardcoded key); consumed reports.py:26-28, 74, 95.
- **Gate 0**: Not intended behavior — a signed session that anyone can forge is a
  broken security control, not a feature.
- **Gate 1 (reachable?)**: PRODUCTION. `_require_login` gates GET /reports/export
  and /generate; `app.secret_key` set at import (app.py:19-20), used for every
  request. Reachable.
- **Gate 2a (attacker-controlled?)**: Yes. Secret is a public constant in source;
  any party can compute a valid session cookie with arbitrary `user_id`/`username`.
- **Gate 2b (sanitization?)**: None. `_require_login` (reports.py:26) checks only
  presence of `user_id`, never validity/ownership. No re-authentication.
- **Gate 3 (new capability?)**: Attacker with no credentials gains an authenticated
  identity of their choosing — reads other principals' documents (owner_id scope
  bypass) and controls `username` flowing to the command sink. Concrete new outcome.
- **Entry Point**: GET /reports/export (and all session-gated routes).
- **Data Flow**: hardcoded secret app.py:20 -> Flask session signer -> forged
  cookie -> `_require_login` presence check reports.py:26-28 -> `uid`
  reports.py:74 (SQL scope) and `username` reports.py:95 (PDF path).
- **Root Cause**: Session authenticity relies on a hardcoded, source-visible secret;
  the login gate verifies only key presence, not a trustworthy identity.
- **Exploitability**: High — key is in the repo; standard Flask session forging tools apply.

#### [VULN-NAV-02] IDOR — document scope relies on forgeable `user_id` (CWE-639)
- **Input**: #25 `session["user_id"]` (reports.py:74) selecting `owner_id` in the
  documents query (reports.py:81).
- **Class**: CWE-639 (IDOR / broken object-level authz).
- **Severity**: High (cross-principal document read; downgrade candidate per
  Phase 2b Authorization Delegation Rule — but no crypto caller auth exists here).
- **Resource ID Gate**: (a) No ownership check independent of the session value;
  the only binding IS the forgeable session. (b) No downstream service credential
  — direct local DB. (c) Single ID. Ownership binding is defeated by VULN-NAV-01,
  so any owner_id's documents are reachable.
- **Gate 0**: NAV exemption applies — scoping by a forgeable identifier is a
  missing authz control, not a feature.
- **Gate 1**: Production (see VULN-NAV-01).
- **Gate 2a**: Attacker-controlled via forged session.
- **Gate 2b**: No re-check of ownership; presence-only login gate.
- **Gate 3**: Read of arbitrary users' `documents` rows.
- **Entry Point**: GET /reports/export.
- **Data Flow**: forged session -> `uid` reports.py:74 -> `owner_id = {uid}`
  reports.py:81 -> db.execute reports.py:84.
- **Root Cause**: Object scope derives solely from an unforgeable-assumed session
  that is in fact forgeable.

---

## Absent-input / CVB analysis
- `_require_login` (reports.py:27): if `user_id` absent -> `abort(401)`. **Fails
  closed.** No conditional-validation-bypass finding.
- No CSRF finding: all in-scope routes are GET / read-export (state-changing PDF
  write is to /tmp only; no cross-user state mutation). Note per project threat
  model these are GET endpoints.

## Cross-class summary (for INJ agent)
- #22 fmt: CROSS-CLASS(INJ) — reports.py:86 branch → S5 command inj / S3 SQLi.
- #23 from_date: CROSS-CLASS(INJ) — reports.py:79-83 SQLi.
- #24 to_date: CROSS-CLASS(INJ) — reports.py:79-83 SQLi.
- #25 username→shell: CROSS-CLASS(INJ) — reports.py:107-108 command injection.
- #27 SSTI S8: static template, not attacker-fed (INJ agent should confirm SAFE).
