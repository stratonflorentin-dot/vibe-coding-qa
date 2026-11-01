"""Report generators: Markdown, JSON, HTML."""

import json
from datetime import datetime, timezone
from pathlib import Path

from .. import ScanResult


def markdown_report(result: ScanResult, title: str = "Vibe Coding QA Production Readiness Report") -> str:
    lines = [
        f"# {title}",
        "",
        f"- **Repository:** `{result.repo}`",
        f"- **Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"- **Overall Score:** {result.overall_score}/100",
        f"- **Critical Findings:** {result.critical_count}",
        f"- **High Findings:** {result.high_count}",
        f"- **Release Gate:** {'BLOCKED' if result.release_blocked else 'OPEN'}",
        "",
        "## Module Summary",
        "",
        "| Module | Score | Status | Findings |",
        "|--------|-------|--------|----------|",
    ]
    for module in result.modules:
        lines.append(f"| {module.module} | {module.score} | {module.status.value} | {len(module.findings)} |")
    lines.append("")

    if result.tests:
        lines.append("## Test Results")
        lines.append("")
        lines.append(f"- Status: `{result.tests.get('status', 'unknown')}`")
        lines.append(f"- Command: `{result.tests.get('command', 'N/A')}`")
        if "summary" in result.tests:
            lines.append(f"- Summary: {result.tests['summary']}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
    else:
        for f in sorted(result.findings, key=lambda x: (x.severity.value, x.module, str(x.file), x.line)):
            lines.append(f"### [{f.severity.value.upper()}] {f.rule}")
            lines.append(f"- **File:** `{f.file}`:{f.line}")
            lines.append(f"- **Message:** {f.message}")
            lines.append(f"- **Suggestion:** {f.suggestion}")
            lines.append(f"- **Confidence:** {f.confidence}")
            if f.fixable:
                lines.append(f"- **Auto-fixable:** yes")
            lines.append("")
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def html_report(result: ScanResult, title: str = "Vibe Coding QA Production Readiness Report") -> str:
    rows = ""
    for f in sorted(result.findings, key=lambda x: (x.severity.value, x.module, str(x.file), x.line)):
        severity_class = f"severity-{f.severity.value}"
        rows += (
            f"<tr class='{severity_class}'>"
            f"<td>{f.severity.value.upper()}</td>"
            f"<td>{f.module}</td>"
            f"<td><code>{f.file}:{f.line}</code></td>"
            f"<td>{f.message}</td>"
            f"<td>{f.suggestion}</td>"
            f"<td>{'yes' if f.fixable else 'no'}</td>"
            f"</tr>"
        )
    module_rows = ""
    for m in result.modules:
        module_rows += f"<tr><td>{m.module}</td><td>{m.score}</td><td>{m.status.value}</td><td>{len(m.findings)}</td></tr>"
    status = "BLOCKED" if result.release_blocked else "OPEN"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
th {{ background: #f3f3f3; }}
.severity-critical {{ background: #ffcccc; }}
.severity-high {{ background: #ffe6cc; }}
.severity-medium {{ background: #ffffcc; }}
.severity-low {{ background: #e6f3ff; }}
.severity-info {{ background: #f0f0f0; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p><strong>Repository:</strong> <code>{result.repo}</code></p>
<p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
<p><strong>Overall Score:</strong> {result.overall_score}/100</p>
<p><strong>Release Gate:</strong> {status}</p>
<h2>Module Summary</h2>
<table>
<thead><tr><th>Module</th><th>Score</th><th>Status</th><th>Findings</th></tr></thead>
<tbody>{module_rows}</tbody>
</table>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Module</th><th>Location</th><th>Message</th><th>Suggestion</th><th>Auto-fix</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""


def write_reports(result: ScanResult, output_dir: Path, prefix: str = "vcqa-report") -> dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    md_path = output_dir / f"{prefix}.md"
    json_path = output_dir / f"{prefix}.json"
    html_path = output_dir / f"{prefix}.html"
    md_path.write_text(markdown_report(result), encoding="utf-8")
    json_path.write_text(json_report(result), encoding="utf-8")
    html_path.write_text(html_report(result), encoding="utf-8")
    paths["markdown"] = md_path
    paths["json"] = json_path
    paths["html"] = html_path
    return paths
