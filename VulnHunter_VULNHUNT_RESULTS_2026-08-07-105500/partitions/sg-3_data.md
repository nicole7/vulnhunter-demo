# Partition SG-3 (reports)

**Scan scope root**: `/Users/nicolegasperini/Documents/VulnHunter/target-app`
**App-specific file**: `reports.py` (`reports_bp`, prefix `/reports`)
**Entry points**: GET /reports/generate, GET /reports/export
**Reachability**: PRODUCTION. Attacker profile: any party who forges a session cookie (hardcoded secret key).

## Assigned Inputs

| # | Source Type | Location | Variable | Entry Point | Trust Level |
|---|---|---|---|---|---|
| 22 | HTTP query param | reports.py:69 | `fmt` | GET /reports/export | authed |
| 23 | HTTP query param | reports.py:70 | `from_date` | GET /reports/export | authed |
| 24 | HTTP query param | reports.py:71 | `to_date` | GET /reports/export | authed |
| 25 | Session field | reports.py:95 | `session[username]` | GET /reports/export (pdf) | authed (forgeable, S14) |
| 27 | no-input endpoint | reports.py:56 | N/A | GET /reports/generate | authed |

## Sinks in scope
- S3 SQLi (f-string) reports.py:79-83 `from_date`/`to_date`/`uid` interpolated
- S5 Command injection (shell=True) reports.py:107-108 `f"wkhtmltopdf {tmp_path} {out_path}"` (username-derived paths)
- S8 SSTI candidate render_template_string reports.py:59

## Shared Infrastructure
- `get_db()` app.py:25
- `_require_login()` reports.py:26 — session presence only
- Flask session / `secret_key` app.py:19-20 — hardcoded (S14)

## Threat model
`_require_login` gates routes; session forgeable. Query params flow into raw SQL (SQLi). `session[username]` (forgeable) flows into a shell command path (command injection via wkhtmltopdf paths).
