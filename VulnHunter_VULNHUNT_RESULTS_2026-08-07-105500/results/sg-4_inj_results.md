# SG-4 INJ Trace Results

Scope: admin.py (`admin_bp`, prefix `/admin`). Reachability PRODUCTION (forgeable admin session cookie, hardcoded secret key).

## Input Dispositions

| # | Var | Disposition | Notes |
|---|-----|-------------|-------|
| 17 | `session[role]` | CROSS-CLASS (NAV/LOG) | Auth/authz via forgeable cookie (`_require_admin`, admin.py:25-31). Privilege escalation, not an INJ class. suspected class: LOG/NAV (CWE-287/862). |
| 18 | `user_id` (delete) | SAFE | `<int:user_id>` converter type-constrains to int; parameterized query admin.py:83 `DELETE ... WHERE id = ?`. No INJ sink. (Note: missing CSRF/IDOR → CROSS-CLASS NAV, out of INJ scope.) |
| 19 | `user_id` (promote) | SAFE | `<int:user_id>` int converter; parameterized admin.py:96 `UPDATE ... WHERE id = ?`. No INJ sink. |
| 20 | `host` | CANDIDATE | Command injection. See VULN-401. |
| 21 | `q` | CANDIDATE | SQL injection. See VULN-402. SSTI (S7/S8) = SAFE, see below. |
| 26 | dashboard (no input) | NO-MATCH | No user input; static SELECT admin.py:71, fixed template. |

## SSTI sinks S7/S8 — SAFE (false positive)
admin.py:72, 127, 177: `render_template_string(FIXED_TEMPLATE, var=user_value)`. User input is passed as a template **variable** (`q=q`, `output=output`), rendered via `{{ q }}`/`{{ output }}` = data, not compiled as template source. Jinja renders variable values as inert strings. No SSTI. Would only be SSTI if user input were the template string argument itself — it is not.

---

## Candidates

### [VULN-401] Command injection via `host` in ping diagnostic
- **Input**: #20: HTTP form field `host` (POST /admin/ping)
- **Class**: CWE-78: OS Command Injection
- **Severity**: High+ (RCE)
- **Location**: admin.py:123-124
- **Gate 0**: Not intended — pinging a host is the feature; arbitrary shell exec is not. Not proxy/design.
- **Gate 1**: Reachable — route `/admin/ping` registered admin.py:114, production partition.
- **Gate 2a**: Attacker-controlled — `request.form.get("host")` admin.py:117.
- **Gate 2b**: No sanitization. `f"ping -c 2 {host}"` → `subprocess.run(cmd, shell=True)`. Shell metacharacters (`;`, `|`, `` ` ``, `$()`) pass through.
- **Gate 3**: New capability — arbitrary OS command execution as the app process.
- **Entry Point**: POST /admin/ping
- **Data Flow**: request.form[host] (admin.py:117) → f-string cmd (admin.py:123) → subprocess.run(shell=True) (admin.py:124)
- **Root Cause**: Unsanitized user input interpolated into a shell command string with `shell=True`.
- **Exploitability**: `host=127.0.0.1; cat /etc/passwd`. Requires admin (forgeable per #17).

### [VULN-402] SQL injection via `q` in audit log search
- **Input**: #21: HTTP query param `q` (GET /admin/audit)
- **Class**: CWE-89: SQL Injection
- **Severity**: High+ (full DB read via UNION; no row restriction)
- **Location**: admin.py:166
- **Gate 0**: Not intended — search filter is the feature; arbitrary SQL is not.
- **Gate 1**: Reachable — route `/admin/audit` admin.py:156, production.
- **Gate 2a**: Attacker-controlled — `request.args.get("q")` admin.py:159.
- **Gate 2b**: None. f-string into `LIKE '%{q}%'`; single quote breaks out of the literal.
- **Gate 3**: New capability — read/exfiltrate arbitrary tables (e.g. users, credentials) via UNION.
- **Entry Point**: GET /admin/audit?q=
- **Data Flow**: request.args[q] (admin.py:159) → f-string SQL (admin.py:166) → db.execute (admin.py:167)
- **Root Cause**: User input concatenated into SQL via f-string instead of parameterized query.
- **Exploitability**: `q=%' UNION SELECT ... --`. Requires admin (forgeable per #17).

## CROSS-CLASS flags
- CROSS-CLASS (input #17, admin.py:25-31, suspected class: NAV — CWE-287/862 forgeable-cookie privilege escalation)
- CROSS-CLASS (input #18, admin.py:79-85, suspected class: NAV — CSRF/IDOR state-changing GET delete)
- CROSS-CLASS (input #19, admin.py:92-98, suspected class: NAV — CSRF/IDOR privilege-granting GET promote)
