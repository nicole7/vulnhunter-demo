# VULN-019 — Command Injection in Admin Ping (`host`)

- **CWE**: 78
- **Severity**: High+
- **Endpoint**: `POST /admin/ping` (admin; role forgeable via VULN-002)
- **Sink**: `admin.py:123-124`

## Static Data Flow Trace

```
1. ENTRY: POST /admin/ping with host = "127.0.0.1; cat /etc/passwd"
   -> admin.py:117  host = request.form.get("host", "127.0.0.1")

2. PROPAGATION: host interpolated into a shell command string.
   -> admin.py:123  cmd = f"ping -c 2 {host}"
   Resulting cmd:  ping -c 2 127.0.0.1; cat /etc/passwd

3. SINK: executed with shell=True; output reflected to the page.
   -> admin.py:124  subprocess.run(cmd, shell=True, capture_output=True, ...)
   -> admin.py:127  render_template_string(PING_TEMPLATE, output=output)

4. IMPACT: Arbitrary OS command execution; output returned in the response
   (e.g. contents of /etc/passwd).
```

## Attacker gains
Remote code execution with command output reflected back to the attacker.

## Expected vs Actual
- Secure app: `subprocess.run(["ping","-c","2",host], shell=False)` plus host format validation.
- Vulnerable app: `shell=True` on an f-string containing host.
