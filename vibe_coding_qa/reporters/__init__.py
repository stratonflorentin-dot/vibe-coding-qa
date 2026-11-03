"""Report generators: Markdown, JSON, HTML."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .. import ScanResult
from ..gates import coverage_gaps, release_decision, release_gate_label


def _h(text: str) -> str:
    return html.escape(str(text))


def _value(value):
    return getattr(value, "value", value)


def markdown_report(result: ScanResult, title: str = "Vibe Coding QA Production Readiness Report") -> str:
    lines = [
        f"# {title}",
        "",
        f"- **Repository:** `{result.repo}`",
        f"- **Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"- **Overall Score:** {result.overall_score}/100",
        f"- **Critical Findings:** {result.critical_count}",
        f"- **High Findings:** {result.high_count}",
        f"- **Release Gate:** {release_gate_label(result)}",
        f"- **Decision:** {release_decision(result)}",
        "",
        "## Module Summary",
        "",
        "| Module | Score | Status | Findings |",
        "|--------|-------|--------|----------|",
    ]
    for module in result.modules:
        lines.append(f"| {module.module} | {module.score} | {module.status.value} | {len(module.findings)} |")
    lines.append("")
    scanner_notes = [f"{module.module}: {note}" for module in result.modules for note in module.notes]
    if scanner_notes:
        lines.extend(["## Scanner Notes", "", *[f"- {note}" for note in scanner_notes], ""])

    arch = result.tests.get("architecture")
    if arch:
        lines.append("## Detected Technology Stack")
        lines.append("")
        lines.append(f"- **Languages:** {', '.join(f'{k} ({v})' for k, v in arch.get('languages', {}).items() if v)}")
        lines.append(f"- **Frameworks:** {', '.join(arch.get('frameworks', [])) or 'none'}")
        lines.append(f"- **Package manager:** {arch.get('package_manager', 'unknown')}")
        lines.append(f"- **Databases:** {', '.join(arch.get('databases', [])) or 'none'}")
        lines.append(f"- **Auth providers:** {', '.join(arch.get('auth_providers', [])) or 'none'}")
        lines.append(f"- **Test runners:** {', '.join(arch.get('test_runners', [])) or 'none'}")
        lines.append(f"- **Deployment:** {', '.join(arch.get('deployment', [])) or 'none'}")
        lines.append("")

    if result.tests:
        lines.append("## Test Results")
        lines.append("")
        lines.append(f"- Status: `{_value(result.tests.get('status', 'unknown'))}`")
        lines.append(f"- Command: `{result.tests.get('command', 'N/A')}`")
        if "duration_ms" in result.tests:
            lines.append(f"- Duration: {result.tests['duration_ms']} ms")
        if result.tests.get("skipped") is not None:
            lines.append(f"- Skipped: {result.tests['skipped']}")
        if "summary" in result.tests:
            lines.append(f"- Summary: {result.tests['summary']}")
        lines.append("")

    fixes = result.tests.get("fixes")
    if fixes:
        lines.append("## Fixes")
        lines.append("")
        lines.append(f"- Mode: {'preview' if fixes.get('dry_run') else 'applied'}")
        lines.append(f"- Applied: {len(fixes.get('applied', []))}")
        lines.append(f"- Skipped: {len(fixes.get('skipped', []))}")
        for a in fixes.get("applied", []):
            lines.append(f"- `{a['finding']['rule']}` at `{a['finding']['file']}:{a['finding']['line']}`")
            if a.get("diff"):
                lines.append("  ```diff")
                lines.extend(["  " + line for line in a["diff"].splitlines()])
                lines.append("  ```")
        lines.append("")

    gaps = coverage_gaps(result)
    if gaps:
        lines.append("## Coverage Gaps and Limitations")
        lines.append("")
        for gap in gaps:
            lines.append(f"- {gap}")
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
    data = result.to_dict()
    data["release_gate"] = release_gate_label(result)
    data["release_decision"] = release_decision(result)
    data["coverage_gaps"] = coverage_gaps(result)
    return json.dumps(data, indent=2)


def html_report(result: ScanResult, title: str = "Vibe Coding QA Production Readiness Report") -> str:
    rows = ""
    for f in sorted(result.findings, key=lambda x: (x.severity.value, x.module, str(x.file), x.line)):
        severity_class = f"severity-{f.severity.value}"
        rows += (
            f"<tr class='{_h(severity_class)}'>"
            f"<td>{_h(f.severity.value.upper())}</td>"
            f"<td>{_h(f.module)}</td>"
            f"<td><code>{_h(f.file)}:{f.line}</code></td>"
            f"<td>{_h(f.message)}</td>"
            f"<td>{_h(f.suggestion)}</td>"
            f"<td>{'yes' if f.fixable else 'no'}</td>"
            f"</tr>"
        )
    module_rows = ""
    for m in result.modules:
        module_rows += f"<tr><td>{_h(m.module)}</td><td>{m.score}</td><td>{_h(m.status.value)}</td><td>{len(m.findings)}</td></tr>"
    scanner_notes = [f"{m.module}: {note}" for m in result.modules for note in m.notes]
    notes_html = ""
    if scanner_notes:
        notes_html = "<h2>Scanner Notes</h2><ul>" + "".join(f"<li>{_h(note)}</li>" for note in scanner_notes) + "</ul>"
    status = release_gate_label(result)
    decision = _h(release_decision(result))
    arch = result.tests.get("architecture", {})
    arch_html = ""
    if arch:
        arch_html = (
            f"<h2>Detected Technology Stack</h2><ul>"
            f"<li>Languages: {_h(', '.join(f'{k} ({v})' for k, v in arch.get('languages', {}).items() if v))}</li>"
            f"<li>Frameworks: {_h(', '.join(arch.get('frameworks', [])))}</li>"
            f"<li>Package manager: {_h(arch.get('package_manager', 'unknown'))}</li>"
            f"<li>Databases: {_h(', '.join(arch.get('databases', [])))}</li>"
            f"<li>Auth providers: {_h(', '.join(arch.get('auth_providers', [])))}</li>"
            f"<li>Test runners: {_h(', '.join(arch.get('test_runners', [])))}</li>"
            f"</ul>"
        )
    test_html = ""
    if result.tests:
        test_html = (
            f"<h2>Test Results</h2><ul>"
            f"<li>Status: {_h(_value(result.tests.get('status', 'unknown')))}</li>"
            f"<li>Command: <code>{_h(result.tests.get('command', 'N/A'))}</code></li>"
            f"<li>Duration: {_h(result.tests.get('duration_ms', 'N/A'))} ms</li>"
            f"</ul>"
        )
    gaps = coverage_gaps(result)
    gaps_html = ""
    if gaps:
        gaps_html = "<h2>Coverage Gaps and Limitations</h2><ul>" + "".join(f"<li>{_h(g)}</li>" for g in gaps) + "</ul>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_h(title)}</title>
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
<h1>{_h(title)}</h1>
<p><strong>Repository:</strong> <code>{_h(result.repo)}</code></p>
<p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
<p><strong>Overall Score:</strong> {result.overall_score}/100</p>
<p><strong>Release Gate:</strong> {status}</p>
<p><strong>Decision:</strong> {decision}</p>
{arch_html}
<h2>Module Summary</h2>
<table>
<thead><tr><th>Module</th><th>Score</th><th>Status</th><th>Findings</th></tr></thead>
<tbody>{module_rows}</tbody>
</table>
{notes_html}
{test_html}
{gaps_html}
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
