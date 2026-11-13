"""Prepares the minimum relevant, redacted context for an intelligence task.

Vibe Intelligence never ships a whole project to a model. This engine assembles
only what the caller permits (metadata, the scan report, findings, optionally
architecture/dependencies), redacts secrets from every block, caps the total
size, and records a validated evidence reference for each source — pointing at
real repositories, scans, findings and files, never invented paths.

v1 is deterministic (store + existing static analysis). The interface leaves
room for vector search / deeper retrieval later without changing callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vibe_coding_qa.scanners import redact_secrets

from ..persistence.store import Store
from ..services.intel import build_architecture, build_dependencies
from .contracts import ContextOptions, EvidenceKind, EvidenceRef, IntelligenceRequest


@dataclass
class PreparedContext:
    blocks: list[str] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    char_count: int = 0

    @property
    def text(self) -> str:
        return "\n\n".join(self.blocks)


class ContextEngine:
    def __init__(self, store: Store):
        self.store = store

    def resolve_scan(self, request: IntelligenceRequest, repository: dict) -> dict | None:
        if request.scan_id is not None:
            scan = self.store.get_scan(request.scan_id)
            if scan and scan.get("repository_id") == repository["id"]:
                return scan
            return None
        return self.store.latest_completed_scan(repository["id"])

    def prepare(self, request: IntelligenceRequest, repository: dict) -> PreparedContext:
        ctx = PreparedContext()
        opt: ContextOptions = request.context
        budget = {"left": opt.max_chars}

        def add(block: str, evidence: EvidenceRef | None = None) -> None:
            text = redact_secrets(block).strip()
            if not text:
                return
            if len(text) > budget["left"]:
                text = text[: max(0, budget["left"])].rstrip() + "\n…[context truncated to fit budget]"
                if "Context was truncated to fit the size budget." not in ctx.limitations:
                    ctx.limitations.append("Context was truncated to fit the size budget.")
            budget["left"] -= len(text)
            ctx.blocks.append(text)
            ctx.char_count += len(text)
            if evidence is not None:
                ctx.evidence.append(evidence)

        if opt.repository_metadata:
            langs = repository.get("main_language") or "unknown language"
            frameworks = ", ".join(repository.get("frameworks") or []) or "none detected"
            add(
                f"# Project\nName: {repository['name']}\nKind: {repository['source_type']}\n"
                f"Primary language: {langs}\nFrameworks: {frameworks}\n"
                f"Package manager: {repository.get('package_manager') or 'unknown'}",
                EvidenceRef(kind=EvidenceKind.ARCHITECTURE, ref=f"repository:{repository['id']}"),
            )

        scan = self.resolve_scan(request, repository)
        if scan is None:
            ctx.limitations.append("No completed scan is available for this project yet.")

        if scan is not None and opt.scan_report and budget["left"] > 0:
            add(
                f"# Latest scan (#{scan['id']})\nStatus: {scan.get('status')}\n"
                f"Gate: {scan.get('gate')}\nScore: {scan.get('overall_score')}\n"
                f"Critical: {scan.get('critical_count')} · High: {scan.get('high_count')} · "
                f"Total findings: {scan.get('total_findings')}\n"
                f"Tests: {scan.get('test_status') or 'not reported'}",
                EvidenceRef(kind=EvidenceKind.SCAN, ref=str(scan["id"])),
            )

        if scan is not None and opt.findings and budget["left"] > 0:
            findings, _total = self.store.list_findings(scan_id=scan["id"], limit=200)
            seen: set[tuple] = set()
            unique: list[dict] = []
            for finding in findings:
                key = (finding["rule"], finding["message"])
                if key in seen:
                    continue
                seen.add(key)
                unique.append(finding)
                if len(unique) >= 25:
                    break
            if unique:
                lines = [
                    f"- [{f['severity']}] {f['rule']} — {f.get('message') or ''} "
                    f"({f['file']}:{f['line']})"
                    for f in unique
                ]
                add("# Findings (unique, de-duplicated)\n" + "\n".join(lines))
                for f in unique[:20]:
                    ctx.evidence.append(
                        EvidenceRef(kind=EvidenceKind.FINDING, ref=str(f["id"]), line=f.get("line"), detail=f["rule"])
                    )

        if opt.architecture and budget["left"] > 0:
            try:
                arch = build_architecture(self.store, repository)
                nodes = arch.get("nodes") or []
                edges = arch.get("edges") or []
                add(
                    f"# Architecture\nComponents: {len(nodes)} · relationships: {len(edges)}\n"
                    + "\n".join(f"- {n.get('label', n.get('id'))} ({n.get('kind')})" for n in nodes[:30]),
                    EvidenceRef(kind=EvidenceKind.ARCHITECTURE, ref=f"architecture:{repository['id']}"),
                )
            except Exception:  # noqa: BLE001 - never let context prep crash a task
                ctx.limitations.append("Architecture context could not be computed.")

        if opt.dependencies and budget["left"] > 0:
            try:
                deps = build_dependencies(self.store, repository, osv=False)
                items = deps.get("dependencies") or []
                add(
                    f"# Dependencies ({len(items)})\n"
                    + "\n".join(f"- {d.get('name')}@{d.get('version')}" for d in items[:40]),
                    EvidenceRef(kind=EvidenceKind.DEPENDENCY, ref=f"dependencies:{repository['id']}"),
                )
            except Exception:  # noqa: BLE001
                ctx.limitations.append("Dependency context could not be computed.")

        if opt.source_files:
            # v1 records the real files the in-scope findings point at as evidence
            # (validated paths), without shipping raw file contents. Full
            # content inclusion is a later enhancement behind this same flag.
            files: list[tuple[str, int]] = []
            if scan is not None:
                findings, _ = self.store.list_findings(scan_id=scan["id"], limit=200)
                for f in findings:
                    pair = (f["file"], f.get("line") or 0)
                    if pair not in files:
                        files.append(pair)
                    if len(files) >= opt.max_files:
                        break
            for path, line in files:
                ctx.evidence.append(EvidenceRef(kind=EvidenceKind.FILE, ref=path, line=line or None))
            ctx.limitations.append(
                "Source-file evidence lists affected paths; raw file contents are not yet shared."
            )

        return ctx


__all__ = ["ContextEngine", "PreparedContext"]
