"""
Report generator — exports findings as JSON or HTML.
"""

import json
from datetime import datetime


def generate_report(findings, account, region, fmt):
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")

    if fmt == "json":
        filename = f"report_{timestamp}.json"
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "account_id": account["account_id"],
            "region": region,
            "summary": {"total": len(findings), "high": high, "medium": medium},
            "findings": findings,
        }
        with open(filename, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\n  📄  JSON report saved: {filename}")

    elif fmt == "html":
        filename = f"report_{timestamp}.html"
        html = _build_html(findings, account, region, high, medium)
        with open(filename, "w") as f:
            f.write(html)
        print(f"\n  🌐  HTML report saved: {filename}")


def _build_html(findings, account, region, high, medium):
    rows = ""
    for f in findings:
        color = "#ff4d4d" if f["severity"] == "HIGH" else "#ffa500"
        badge = (
            f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:0.85em;">{f["severity"]}</span>'
        )
        detail = f["detail"] if f.get("detail") else "—"
        rows += f"""
        <tr>
          <td>{badge}</td>
          <td><code>{f['resource']}</code></td>
          <td>{f['issue']}</td>
          <td style="font-size:0.85em;color:#888;">{detail}</td>
        </tr>"""

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AWS Misconfiguration Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f1117; color: #e0e0e0; padding: 40px; }}
    h1 {{ color: #fff; margin-bottom: 4px; font-size: 1.6em; }}
    .meta {{ color: #888; font-size: 0.9em; margin-bottom: 32px; }}
    .summary {{ display: flex; gap: 16px; margin-bottom: 32px; }}
    .card {{ background: #1a1d27; border-radius: 8px; padding: 20px 28px;
             min-width: 140px; text-align: center; }}
    .card .num {{ font-size: 2.2em; font-weight: bold; }}
    .card .label {{ font-size: 0.8em; color: #888; margin-top: 4px; }}
    .high {{ color: #ff4d4d; }}
    .medium {{ color: #ffa500; }}
    .total {{ color: #fff; }}
    table {{ width: 100%; border-collapse: collapse; background: #1a1d27;
             border-radius: 8px; overflow: hidden; }}
    th {{ background: #22263a; color: #aaa; font-size: 0.8em; text-transform: uppercase;
          letter-spacing: 0.08em; padding: 12px 16px; text-align: left; }}
    td {{ padding: 12px 16px; border-top: 1px solid #2a2d3a; vertical-align: top; }}
    tr:hover td {{ background: #1f2235; }}
    code {{ background: #2a2d3a; padding: 2px 6px; border-radius: 4px;
            font-size: 0.85em; color: #7dd3fc; }}
    .empty {{ text-align: center; padding: 40px; color: #555; }}
  </style>
</head>
<body>
  <h1>🔍 AWS Misconfiguration Report</h1>
  <div class="meta">
    Account: <strong>{account['account_id']}</strong> &nbsp;|&nbsp;
    Region: <strong>{region}</strong> &nbsp;|&nbsp;
    Generated: <strong>{timestamp}</strong>
  </div>

  <div class="summary">
    <div class="card"><div class="num total">{len(findings)}</div>
      <div class="label">Total Findings</div></div>
    <div class="card"><div class="num high">{high}</div>
      <div class="label">High Severity</div></div>
    <div class="card"><div class="num medium">{medium}</div>
      <div class="label">Medium Severity</div></div>
  </div>

  {"<table><thead><tr><th>Severity</th><th>Resource</th><th>Issue</th><th>Detail</th></tr></thead><tbody>" + rows + "</tbody></table>"
   if findings else '<div class="empty">✅ No findings — account looks clean.</div>'}
</body>
</html>"""
