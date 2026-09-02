# Target App

A small internal employee portal — **intentionally vulnerable** — used as a VulnHunter demo target.

> Do not deploy this app to any public or production environment.

## Running Locally

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The app starts at `http://127.0.0.1:5000`.

### Seed credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin | admin |
| alice | password | employee |
| bob | abc123 | employee |

## Application Routes

| Route | Description |
|-------|-------------|
| `GET /auth/login` | Login form |
| `POST /auth/login` | Submit credentials |
| `GET /auth/register` | Register new account |
| `GET /auth/forgot` | Request password reset |
| `GET /files/` | List own documents |
| `POST /files/upload` | Upload a file |
| `GET /files/download/<id>` | Download a document |
| `GET /files/preview/<id>` | Preview a document |
| `POST /files/restore` | Restore from base64 clipboard data |
| `GET /reports/generate` | Report generation form |
| `GET /reports/export?fmt=csv&from_date=...&to_date=...` | Export data |
| `GET /admin/` | Admin dashboard (admin role required) |
| `POST /admin/ping` | Diagnostic ping |
| `GET /admin/audit` | Audit log viewer |

## Structure

```
target-app/
├── app.py          Entry point, DB init, blueprint registration
├── auth.py         Login, registration, password reset
├── files.py        Upload, download, preview, restore
├── admin.py        User management, ping diagnostic, audit log
├── reports.py      CSV / PDF export
├── requirements.txt
└── uploads/        Created at runtime; stores uploaded files
```
