"""Parse allow-listed tool outputs into :class:`security_worker.normalize.Finding`.

Tool output is untrusted data. These parsers are intentionally defensive: a
bad line is ignored (or recorded as bounded evidence) rather than interpreted,
executed, or allowed to crash the worker's job loop.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

from .normalize import Finding, normalize_confidence, normalize_severity


class MalformedToolOutput(ValueError):
    """Raised when a tool's complete output cannot be parsed safely."""


def parse_output(
    tool: str,
    raw: str,
    *,
    target: str,
    tool_version: str | None = None,
) -> list[Finding]:
    """Dispatch output parsing by allow-listed tool key."""
    parsers = {
        "nmap": _parse_nmap,
        "nuclei": _parse_nuclei,
        "zap": _parse_zap,
        "nikto": _parse_nikto,
        "whatweb": _parse_whatweb,
        "testssl": _parse_testssl,
    }
    parser = parsers.get(tool)
    if parser is None:
        raise MalformedToolOutput(f"No result adapter is registered for {tool!r}.")
    try:
        return parser(raw, target=target, tool_version=tool_version)
    except (ET.ParseError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise MalformedToolOutput(f"{tool} returned malformed output.") from exc


def _finding(
    *,
    tool: str,
    target: str,
    tool_version: str | None,
    title: str,
    severity: str = "info",
    endpoint: str | None = None,
    category: str | None = None,
    description: str | None = None,
    confidence: str = "medium",
    evidence: str | None = None,
    remediation: str | None = None,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        tool=tool,
        tool_version=tool_version,
        target=target,
        endpoint=endpoint,
        title=title,
        category=category,
        description=description,
        severity=normalize_severity(severity),
        confidence=normalize_confidence(confidence),
        evidence=evidence,
        remediation=remediation,
        references=references or [],
    )


def _endpoint_url(value: str | None, fallback: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return fallback
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return fallback
    return candidate[:500]


def _json_lines(raw: str) -> list[dict[str, Any]]:
    rows = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _parse_nuclei(raw: str, *, target: str, tool_version: str | None) -> list[Finding]:
    findings = []
    for row in _json_lines(raw):
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        name = str(info.get("name") or row.get("template-id") or "Nuclei detection")
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            references = []
        tags = info.get("tags") or []
        tags = tags if isinstance(tags, list) else [str(tags)]
        endpoint = _endpoint_url(
            row.get("matched-at") or row.get("url") or row.get("host"), target
        )
        findings.append(_finding(
            tool="nuclei",
            target=target,
            tool_version=tool_version,
            title=name,
            severity=str(info.get("severity") or "info"),
            endpoint=endpoint,
            category=",".join(str(tag)[:40] for tag in tags[:8]) or "vulnerability",
            description=str(info.get("description") or "")[:4000] or None,
            confidence=str(row.get("matcher-status") or "medium"),
            evidence=json.dumps(row, ensure_ascii=False)[:8000],
            remediation=str(info.get("remediation") or "")[:4000] or None,
            references=[str(ref) for ref in references[:25]],
        ))
    return findings


def _parse_zap(raw: str, *, target: str, tool_version: str | None) -> list[Finding]:
    value = json.loads(raw or "{}")
    if isinstance(value, dict) and isinstance(value.get("alerts"), list):
        sites = [{"alerts": value["alerts"]}]
    else:
        sites = value.get("site", []) if isinstance(value, dict) else []
    if isinstance(sites, dict):
        sites = [sites]
    findings = []
    for site in sites if isinstance(sites, list) else []:
        alerts = site.get("alerts", []) if isinstance(site, dict) else []
        for alert in alerts if isinstance(alerts, list) else []:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") or [{}]
            if isinstance(instances, dict):
                instances = [instances]
            for instance in instances if isinstance(instances, list) else [{}]:
                instance = instance if isinstance(instance, dict) else {}
                uri = _endpoint_url(instance.get("uri"), target)
                refs = alert.get("reference") or ""
                references = re.findall(r"(?:CVE|CWE)-\d{4,7}", str(refs), flags=re.I)
                findings.append(_finding(
                    tool="zap",
                    target=target,
                    tool_version=tool_version,
                    title=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                    severity=str(alert.get("riskdesc") or "info").split()[0],
                    endpoint=uri,
                    category=str(alert.get("confidence") or "web"),
                    description=str(alert.get("desc") or "")[:4000] or None,
                    confidence=str(alert.get("confidence") or "medium"),
                    evidence=str(instance.get("evidence") or instance.get("param") or "")[:8000] or None,
                    remediation=str(alert.get("solution") or "")[:4000] or None,
                    references=references,
                ))
    return findings


def _parse_nmap(raw: str, *, target: str, tool_version: str | None) -> list[Finding]:
    root = ET.fromstring(raw or "")
    findings = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        port = port_node.get("portid", "")
        protocol = port_node.get("protocol", "tcp")
        service_name = service.get("name", "unknown") if service is not None else "unknown"
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        detail = " ".join(part for part in (product, version) if part)
        findings.append(_finding(
            tool="nmap",
            target=target,
            tool_version=tool_version,
            title=f"Open {protocol}/{port} service: {service_name}",
            severity="info",
            endpoint=f"{target}:{port}/{protocol}",
            category="network-service",
            description=f"An open port was found. Service identification: {detail or 'not identified'}.",
            confidence="medium" if service_name != "unknown" else "low",
            evidence=ET.tostring(port_node, encoding="unicode")[:8000],
            remediation="Confirm this service is required and restrict access to intended network ranges.",
        ))
    return findings


def _parse_nikto(raw: str, *, target: str, tool_version: str | None) -> list[Finding]:
    value = json.loads(raw or "{}")
    rows = value.get("vulnerabilities", []) if isinstance(value, dict) else []
    if isinstance(rows, dict):
        rows = [rows]
    findings = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        msg = str(row.get("msg") or row.get("message") or row.get("description") or "Nikto observation")
        uri = row.get("url") or row.get("uri")
        references = re.findall(r"(?:CVE|CWE)-\d{4,7}", msg, flags=re.I)
        findings.append(_finding(
            tool="nikto",
            target=target,
            tool_version=tool_version,
            title=msg[:300],
            severity=str(row.get("severity") or ("medium" if references else "info")),
            endpoint=_endpoint_url(uri, target),
            category="web-server",
            description=msg[:4000],
            confidence="medium" if references else "low",
            evidence=json.dumps(row, ensure_ascii=False)[:8000],
            references=references,
        ))
    return findings


def _parse_whatweb(raw: str, *, target: str, tool_version: str | None) -> list[Finding]:
    text = (raw or "").strip()
    if not text:
        return []
    value = json.loads(text)
    rows = value if isinstance(value, list) else [value]
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        plugins = row.get("plugins") if isinstance(row.get("plugins"), dict) else {}
        technologies = []
        for name, detail in list(plugins.items())[:100]:
            version = ""
            if isinstance(detail, dict):
                versions = detail.get("version") or []
                version = ", ".join(str(item) for item in versions[:3]) if isinstance(versions, list) else str(versions)
            technologies.append(f"{name} {version}".strip())
        if technologies:
            findings.append(_finding(
                tool="whatweb",
                target=target,
                tool_version=tool_version,
                title="Technology fingerprint",
                severity="info",
                endpoint=_endpoint_url(row.get("target"), target),
                category="technology",
                description="Technologies observed: " + ", ".join(technologies[:50]),
                confidence="medium",
                evidence=json.dumps(plugins, ensure_ascii=False)[:8000],
            ))
    return findings


def _parse_testssl(raw: str, *, target: str, tool_version: str | None) -> list[Finding]:
    value = json.loads(raw or "[]")
    rows = value if isinstance(value, list) else value.get("scanResult", []) if isinstance(value, dict) else []
    findings = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        severity = str(row.get("severity") or "info").lower()
        if severity in ("ok", "info", "informational", "not ok"):
            if severity in ("ok", "info", "informational"):
                continue
            severity = "medium"
        title = str(row.get("id") or row.get("finding") or row.get("ip") or "TLS configuration")
        findings.append(_finding(
            tool="testssl",
            target=target,
            tool_version=tool_version,
            title=title,
            severity=severity,
            endpoint=target,
            category="tls",
            description=str(row.get("finding") or row.get("severity_local") or "")[:4000] or None,
            confidence="high",
            evidence=json.dumps(row, ensure_ascii=False)[:8000],
            remediation="Use current TLS protocols and strong cipher suites; disable deprecated protocol versions.",
            references=re.findall(r"(?:CVE|CWE)-\d{4,7}", json.dumps(row), flags=re.I),
        ))
    return findings


__all__ = ["MalformedToolOutput", "parse_output"]
