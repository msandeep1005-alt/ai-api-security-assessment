from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any


def build_report(
    *,
    target: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:

    confirmed = [
        finding
        for finding in findings
        if finding.get("confirmed") is True
    ]

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in confirmed:
        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "report_metadata": {
            "title": "AI-Assisted API Security Assessment",
            "generated_at": datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": target,
        },
        "executive_summary": {
            "total_tests_with_findings": len(confirmed),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "overall_status": (
                "VULNERABILITIES IDENTIFIED"
                if confirmed
                else "NO CONFIRMED VULNERABILITIES"
            ),
        },
        "findings": findings,
    }


def save_json_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:

    path = Path(output_path)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path


def render_html_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:

    metadata = report["report_metadata"]
    summary = report["executive_summary"]
    findings = report["findings"]

    finding_sections = []

    for finding in findings:

        evidence = finding.get(
            "evidence",
            {},
        )

        victim = evidence.get(
            "victim",
            {},
        )

        attacker = evidence.get(
            "attacker",
            {},
        )

        finding_sections.append(
            f"""
            <section class="finding">
                <h2>{escape(str(finding.get("title", "")))}</h2>

                <table>
                    <tr>
                        <th>Finding ID</th>
                        <td>{escape(str(finding.get("finding_id", "")))}</td>
                    </tr>

                    <tr>
                        <th>Category</th>
                        <td>{escape(str(finding.get("category", "")))}</td>
                    </tr>

                    <tr>
                        <th>Severity</th>
                        <td><strong>
                            {escape(str(finding.get("severity", "")))}
                        </strong></td>
                    </tr>

                    <tr>
                        <th>Endpoint</th>
                        <td>
                            {escape(str(finding.get("method", "")))}
                            {escape(str(finding.get("endpoint", "")))}
                        </td>
                    </tr>

                    <tr>
                        <th>Confirmed</th>
                        <td>{escape(str(finding.get("confirmed", "")))}</td>
                    </tr>
                </table>

                <h3>Description</h3>
                <p>{escape(str(finding.get("description", "")))}</p>

                <h3>Impact</h3>
                <p>{escape(str(finding.get("impact", "")))}</p>

                <h3>Evidence</h3>

                <h4>Victim Request</h4>
                <pre>{escape(json.dumps(victim, indent=2))}</pre>

                <h4>Cross-User Request</h4>
                <pre>{escape(json.dumps(attacker, indent=2))}</pre>

                <h3>Remediation</h3>
                <p>{escape(str(finding.get("remediation", "")))}</p>
            </section>
            """
        )

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">

<title>{escape(str(metadata["title"]))}</title>

<style>

body {{
    font-family: Arial, Helvetica, sans-serif;
    margin: 0;
    background: #f5f7fa;
    color: #1f2937;
}}

.container {{
    max-width: 1100px;
    margin: auto;
    padding: 40px;
}}

header {{
    background: #111827;
    color: white;
    padding: 35px;
    border-radius: 10px;
    margin-bottom: 30px;
}}

h1 {{
    margin-top: 0;
}}

.card {{
    background: white;
    padding: 25px;
    border-radius: 10px;
    margin-bottom: 25px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.finding {{
    background: white;
    padding: 30px;
    border-radius: 10px;
    margin-top: 25px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
}}

th, td {{
    border: 1px solid #d1d5db;
    padding: 12px;
    text-align: left;
}}

th {{
    width: 200px;
    background: #f3f4f6;
}}

pre {{
    background: #111827;
    color: #e5e7eb;
    padding: 18px;
    overflow-x: auto;
    border-radius: 6px;
}}

.status {{
    font-size: 20px;
    font-weight: bold;
}}

</style>
</head>

<body>

<div class="container">

<header>
    <h1>{escape(str(metadata["title"]))}</h1>
    <p>Target: {escape(str(metadata["target"]))}</p>
    <p>Generated: {escape(str(metadata["generated_at"]))}</p>
</header>

<div class="card">

<h2>Executive Summary</h2>

<p class="status">
{escape(str(summary["overall_status"]))}
</p>

<table>

<tr>
    <th>Total Findings</th>
    <td>{summary["total_findings"]}</td>
</tr>

<tr>
    <th>Confirmed Findings</th>
    <td>{summary["total_tests_with_findings"]}</td>
</tr>

<tr>
    <th>Critical</th>
    <td>{summary["severity_counts"]["CRITICAL"]}</td>
</tr>

<tr>
    <th>High</th>
    <td>{summary["severity_counts"]["HIGH"]}</td>
</tr>

<tr>
    <th>Medium</th>
    <td>{summary["severity_counts"]["MEDIUM"]}</td>
</tr>

<tr>
    <th>Low</th>
    <td>{summary["severity_counts"]["LOW"]}</td>
</tr>

</table>

</div>

<h2>Security Findings</h2>

{"".join(finding_sections)}

</div>

</body>
</html>
"""

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        html,
        encoding="utf-8",
    )

    return path
