"""Overview and activity aggregation.

Everything here is derived from persisted scans and findings — there are no
placeholder values. When a repository has never been scanned the API reports
``has_data = false`` and empty series instead of inventing numbers.
"""

from ..config import Settings
from ..persistence.store import Store


class DashboardService:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings

    # -------------------------------------------------------------- overview
    def overview(self, repository_id: int | None = None) -> dict:
        scans = self.store.latest_completed_scans()
        if repository_id is not None:
            scans = [s for s in scans if s["repository_id"] == repository_id]

        latest = scans[0] if scans else None

        severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        categories: dict[str, int] = {}
        for scan in scans:
            for key, value in self.store.severity_counts(scan_id=scan["id"]).items():
                severity[key] = severity.get(key, 0) + value
            for module, value in self.store.module_counts(scan_id=scan["id"]).items():
                categories[module] = categories.get(module, 0) + value

        history_scans = self.store.recent_scans(limit=20)
        if repository_id is not None:
            history_scans = [s for s in history_scans if s["repository_id"] == repository_id]
        history_scans = list(reversed(history_scans))

        score_history = []
        findings_trend = []
        test_history = []
        for scan in history_scans:
            counts = self.store.severity_counts(scan_id=scan["id"])
            at = scan.get("completed_at") or scan.get("created_at")
            label = scan.get("repository_name") or f"repository {scan['repository_id']}"
            score_history.append({
                "scan_id": scan["id"],
                "repository_id": scan["repository_id"],
                "repository": label,
                "at": at,
                "score": scan.get("overall_score"),
                "gate": scan.get("gate"),
                "critical": scan.get("critical_count") or 0,
                "high": scan.get("high_count") or 0,
            })
            findings_trend.append({
                "scan_id": scan["id"],
                "repository_id": scan["repository_id"],
                "at": at,
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
            })
            test_history.append({
                "scan_id": scan["id"],
                "repository_id": scan["repository_id"],
                "at": at,
                "executed": scan.get("tests_executed"),
                "passed": scan.get("tests_passed"),
                "failed": scan.get("tests_failed"),
                "skipped": scan.get("tests_skipped"),
                "status": scan.get("test_status"),
            })

        repositories = self.store.list_repositories()
        if repository_id is not None:
            repositories = [r for r in repositories if r["id"] == repository_id]
        repository_health = []
        for repo in repositories:
            latest_scan = repo.get("latest_scan") or {}
            repository_health.append({
                "repository_id": repo["id"],
                "name": repo["name"],
                "source_type": repo["source_type"],
                "main_language": repo.get("main_language"),
                "framework_count": len(repo.get("frameworks") or []),
                "score": latest_scan.get("overall_score"),
                "gate": latest_scan.get("gate"),
                "critical": latest_scan.get("critical_count") or 0,
                "high": latest_scan.get("high_count") or 0,
                "open_findings": self.store.open_finding_count(repo["id"]),
                "last_scan_at": latest_scan.get("completed_at"),
            })

        summary = {
            "overall_score": latest.get("overall_score") if latest else None,
            "critical": (latest.get("critical_count") or 0) if latest else 0,
            "high": (latest.get("high_count") or 0) if latest else 0,
            "total_open": self.store.open_finding_count(repository_id),
            "tests_executed": latest.get("tests_executed") if latest else None,
            "tests_passed": latest.get("tests_passed") if latest else None,
            "gate": latest.get("gate") if latest else None,
            "repository_count": len(repositories),
            "latest_scan_duration_ms": latest.get("duration_ms") if latest else None,
        }

        return {
            "summary": summary,
            "severity_breakdown": severity,
            "category_breakdown": categories,
            "score_history": score_history,
            "findings_trend": findings_trend,
            "test_history": test_history,
            "repository_health": repository_health,
            "has_data": bool(scans),
        }

    # -------------------------------------------------------------- activity
    def activity(self, limit: int = 30) -> dict:
        items: list[dict] = []

        for scan in self.store.recent_scans(limit=limit):
            items.append({
                "kind": "scan",
                "title": f"Scan {scan['status']} · {scan.get('repository_name', '')}".strip(),
                "detail": _scan_detail(scan),
                "at": scan.get("completed_at") or scan.get("created_at"),
                "repository_id": scan["repository_id"],
                "scan_id": scan["id"],
                "severity": None,
            })

        findings, _ = self.store.list_findings(limit=limit)
        for finding in findings:
            items.append({
                "kind": "finding",
                "title": f"{finding['severity'].upper()} · {finding['rule']}",
                "detail": f"{finding['file']}:{finding['line']} — {finding.get('message') or ''}".strip(),
                "at": finding.get("created_at"),
                "repository_id": finding["repository_id"],
                "scan_id": finding["scan_id"],
                "finding_id": finding["id"],
                "severity": finding["severity"],
            })

        for proposal in self.store.list_proposals()[:limit]:
            items.append({
                "kind": "remediation",
                "title": f"Remediation {proposal['status']}",
                "detail": f"{proposal.get('file') or ''} — {proposal.get('rationale') or ''}".strip(),
                "at": proposal.get("updated_at") or proposal.get("created_at"),
                "repository_id": proposal.get("repository_id"),
                "scan_id": None,
                "finding_id": proposal.get("finding_id"),
                "severity": None,
            })

        items.sort(key=lambda item: item.get("at") or "", reverse=True)
        return {"items": items[:limit]}


def _scan_detail(scan: dict) -> str:
    parts = []
    if scan.get("overall_score") is not None:
        parts.append(f"score {scan['overall_score']}")
    if scan.get("gate"):
        parts.append(f"gate {scan['gate']}")
    parts.append(f"critical {scan.get('critical_count') or 0}")
    parts.append(f"high {scan.get('high_count') or 0}")
    if scan.get("total_findings") is not None:
        parts.append(f"findings {scan['total_findings']}")
    return " · ".join(parts)
