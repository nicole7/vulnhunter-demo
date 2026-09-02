# VulnHunter Demo

This repository is a **demonstration target** for [VulnHunter](https://github.com/capitalone/VulnHunter) — Capital One's open-source agentic AI security scanner.

It contains `target-app/`: a small, intentionally vulnerable Python/Flask web application designed to showcase VulnHunter's three-phase closed loop:

```
Hunt  →  Fix  →  Verify
```

---

## What's Inside

| Path | Description |
|------|-------------|
| `target-app/` | Intentionally vulnerable Flask app (the scan target) |
| `target-app/app.py` | Entry point; wires routes together |
| `target-app/auth.py` | Login, registration, session management |
| `target-app/db.py` | Database layer |
| `target-app/files.py` | File upload and download endpoints |
| `target-app/admin.py` | Admin-only management routes |
| `target-app/reports.py` | Report generation (PDF/CSV export) |
| `expected-findings.md` | Spoiler: the vulnerabilities VulnHunter should find |

> **Warning:** `target-app` is deliberately insecure. Never deploy it to a public network.

---

## Quick Start

### 1. Run the target app (optional — for manual exploration)

```bash
cd target-app
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
# App starts on http://127.0.0.1:5000
```

### 2. Install VulnHunter skills

```bash
git clone https://github.com/capitalone/vulnhunter.git
cd vulnhunter
./install.sh
```

### 3. Run the scanner against this repo

```bash
# From this project root (VulnHunter/)
claude --model opus \
       --add-dir ~/.claude/skills/vulnhunt \
       --add-dir ~/.claude/skills/vulnhunt/phases

# Then inside the Claude Code session:
/vulnhunt
```

VulnHunter will write its results to a `*_VULNHUNT_RESULTS_*` directory. Check `expected-findings.md` to see how its findings compare to the known vulnerabilities.

### 4. Run the fixer on a confirmed finding

```bash
claude --model opus --add-dir ~/.claude/skills/vulnhunter-fix
/vulnhunter-fix
```

### 5. Verify the fix

```bash
# Pre-create the output directory
mkdir -p out/

claude --model opus \
       --add-dir ~/.claude/skills/vulnhunt-fix-verify \
       --add-dir ~/.claude/skills/vulnhunt-fix-verify/phases

/vulnhunt-fix-verify \
  repo=$(pwd)/target-app \
  report=$(pwd)/<VULNHUNT_RESULTS_DIR>/README.md \
  fixed=VULN-001 \
  out=$(pwd)/out/
```

---

## Vulnerability Classes Embedded

The app contains realistic examples across all three VulnHunter hunt classes:

| Class | Vulnerabilities |
|-------|----------------|
| **Injection** | SQL injection, command injection, Server-Side Template Injection (SSTI) |
| **Navigation & Access** | Path traversal, broken object-level authorization, unauthenticated admin routes |
| **Logic & Crypto** | Hardcoded secret key, insecure deserialization (pickle), weak password hashing (MD5), predictable token generation |

See `expected-findings.md` for the full spoiler with line references and exploit paths.

---

## Why This App?

Traditional SAST scanners would fire dozens of alerts on this codebase — many of them noise. VulnHunter's attacker-first forward analysis starts at the entry points above and reasons through to each sink, running a falsification pass that eliminates candidates it can't prove are exploitable. The findings it emits should all be actionable.
