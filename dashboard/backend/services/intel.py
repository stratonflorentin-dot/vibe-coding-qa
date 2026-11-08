"""Architecture graph and dependency intelligence.

Both are derived from static evidence: the repository profile, the resolved
lockfiles, and the persisted findings of the latest scan. Nothing here is
invented — when the data is missing the response says so.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from vibe_coding_qa.profile import analyze_repo
from vibe_coding_qa.scanners.dependencies import osv_lookup, resolved_dependencies

from ..persistence.store import Store
from .paths import repository_dir

_OSV_MAX_LOOKUPS = 40


def _source_node_for(file: str, module: str) -> str:
    """Map a finding's file to a node in the architecture graph."""
    lowered = file.lower()
    if lowered.endswith((".sql", ".prisma", ".graphql")):
        return "database"
    if "/migrations/" in f"/{lowered}" or lowered.startswith("migrations/"):
        return "database"
    if ".github/workflows" in lowered or lowered.endswith((".tf", "vercel.json", "netlify.toml", "dockerfile")):
        return "deployment"
    if lowered.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")) or lowered.startswith("tests/"):
        return "tests"
    if module == "database":
        return "database"
    if module == "infrastructure" or module == "dependencies":
        return "deployment"
    return "app"


def build_architecture(store: Store, repository: dict) -> dict:
    root = repository_dir(repository)
    notes: list[str] = [
        "The graph is derived from static file inspection and the latest scan; it is not a runtime "
        "call graph.",
    ]
    nodes: list[dict] = []
    edges: list[dict] = []

    def add_node(node_id: str, kind: str, label: str, **extra) -> None:
        if any(node["id"] == node_id for node in nodes):
            return
        nodes.append({"id": node_id, "kind": kind, "label": label,
                      "files": extra.pop("files", []), "confidence": "static", "details": extra})

    add_node("app", "application", repository["name"],
             source=repository["source"], source_type=repository["source_type"])

    architecture: dict = {}
    if root is not None:
        try:
            profile = analyze_repo(root)
            architecture = profile.to_dict()
        except Exception:  # noqa: BLE001
            notes.append("The repository could not be profiled; only persisted data is shown.")

    if root is None and repository["source_type"] != "local":
        notes.append("This remote repository has not been scanned yet, so no working tree is available.")

    for framework in repository.get("frameworks") or architecture.get("frameworks") or []:
        node_id = f"framework:{framework}"
        add_node(node_id, "framework", framework)
        edges.append({"source": "app", "target": node_id, "kind": "uses"})

    for database in repository.get("database_tech") or architecture.get("databases") or []:
        node_id = f"database:{database}"
        add_node(node_id, "database", database)
        edges.append({"source": "app", "target": node_id, "kind": "stores-data"})

    for provider in repository.get("auth_tech") or architecture.get("auth_providers") or []:
        node_id = f"auth:{provider}"
        add_node(node_id, "auth", provider)
        edges.append({"source": "app", "target": node_id, "kind": "authenticates"})

    for target in repository.get("deployment") or architecture.get("deployment") or []:
        node_id = f"deployment:{target}"
        add_node(node_id, "deployment", target)
        edges.append({"source": "app", "target": node_id, "kind": "deployed-via"})

    for runner in architecture.get("test_runners") or []:
        node_id = "tests"
        add_node(node_id, "tests", "Automated tests", runners=architecture.get("test_runners") or [])
        edges.append({"source": "app", "target": node_id, "kind": "verified-by"})

    for endpoint in (architecture.get("endpoints") or [])[:25]:
        node_id = f"endpoint:{endpoint.get('file')}:{endpoint.get('line')}"
        add_node(node_id, "endpoint", str(endpoint.get("path"))[:80], files=[endpoint.get("file")])
        edges.append({"source": "app", "target": node_id, "kind": "exposes"})

    # Attach the latest scan's findings to graph nodes by file.
    findings_by_node: dict[str, list[dict]] = {}
    latest = store.latest_completed_scan(repository["id"])
    if latest:
        findings, _ = store.list_findings(scan_id=latest["id"], limit=500)
        for finding in findings:
            node_id = _source_node_for(finding["file"], finding["module"])
            if node_id != "app" and not any(node["id"] == node_id for node in nodes):
                node_id = "app"
            findings_by_node.setdefault(node_id, []).append({
                "id": finding["id"],
                "rule": finding["rule"],
                "severity": finding["severity"],
                "file": finding["file"],
                "line": finding["line"],
                "message": finding.get("message"),
            })
    else:
        notes.append("No completed scan exists yet, so findings are not mapped onto the graph.")

    return {
        "repository_id": repository["id"],
        "nodes": nodes,
        "edges": edges,
        "findings_by_node": findings_by_node,
        "notes": notes,
    }


def _ecosystem_for(name: str, package_manager: str | None) -> str:
    if package_manager in ("pip", "poetry", "pipenv"):
        return "PyPI"
    return "npm"


def build_dependencies(store: Store, repository: dict, *, osv: bool) -> dict:
    root = repository_dir(repository)
    notes: list[str] = []
    if root is None:
        return {
            "repository_id": repository["id"],
            "package_manager": repository.get("package_manager"),
            "lockfiles": [],
            "dependencies": [],
            "notes": ["No working tree is available for this repository on this host; scan it first."],
            "osv_checked": False,
        }

    try:
        profile = analyze_repo(root)
    except Exception:  # noqa: BLE001
        profile = None

    direct: dict[str, str | None] = {}
    if profile is not None:
        for name, version in profile.dependencies.items():
            direct[name] = None if version in ("*", "") else version

    lockfiles = list(profile.lockfiles) if profile else []
    package_manager = profile.package_manager if profile else None

    resolved: dict[str, dict] = {}
    try:
        for ecosystem, name, version, lockfile in resolved_dependencies(root):
            entry = resolved.setdefault(name, {"ecosystem": ecosystem, "version": version,
                                               "lockfile": str(Path(lockfile).name)})
            entry["version"] = version
    except Exception:  # noqa: BLE001
        notes.append("Lockfiles could not be parsed for resolved versions.")

    names = sorted(set(direct) | set(resolved))
    if len(names) > 500:
        notes.append(f"Dependency list truncated to the first 500 of {len(names)} entries.")
        names = names[:500]

    advisories: dict[str, list[dict]] = {}
    osv_checked = False
    if osv and names:
        targets = []
        for name in names:
            entry = resolved.get(name)
            version = (entry or {}).get("version") or direct.get(name)
            if not version:
                continue
            ecosystem = (entry or {}).get("ecosystem") or _ecosystem_for(name, package_manager)
            targets.append((name, ecosystem, version))
            if len(targets) >= _OSV_MAX_LOOKUPS:
                notes.append(f"OSV lookups limited to the first {_OSV_MAX_LOOKUPS} dependencies.")
                break
        if targets:
            osv_checked = True
            failures = 0
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(osv_lookup, ecosystem, name, version): name
                           for name, ecosystem, version in targets}
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        advisories[name] = [_advisory(a) for a in future.result()]
                    except Exception:  # noqa: BLE001
                        failures += 1
                        advisories[name] = []
            if failures:
                notes.append(f"{failures} OSV lookup(s) could not be completed; results are partial.")
        else:
            notes.append("No pinned or resolved dependency versions were found to check against OSV.")

    dependencies = []
    for name in names:
        entry = resolved.get(name) or {}
        version = entry.get("version") or direct.get(name)
        found = advisories.get(name) or []
        if found:
            status = "advisory"
        elif not version:
            status = "unpinned"
        else:
            status = "ok"
        dependencies.append({
            "name": name,
            "version": version,
            "direct": name in direct,
            "license": None,
            "advisories": found,
            "status": status,
        })

    return {
        "repository_id": repository["id"],
        "package_manager": package_manager,
        "lockfiles": lockfiles,
        "dependencies": dependencies,
        "notes": notes,
        "osv_checked": osv_checked,
    }


def _advisory(raw: dict) -> dict:
    aliases = raw.get("aliases") or []
    severity = ((raw.get("database_specific") or {}).get("severity") or "").lower() or None
    return {
        "id": raw.get("id"),
        "aliases": aliases[:5],
        "severity": severity,
        "summary": (raw.get("summary") or "")[:300],
        "url": f"https://osv.dev/vulnerability/{raw.get('id', '')}",
        "modified": raw.get("modified"),
    }


def compare_scans(store: Store, base_id: int, head_id: int) -> dict:
    """Diff two scans of the same repository by finding fingerprint."""
    base = store.get_scan(base_id)
    head = store.get_scan(head_id)
    if base is None or head is None:
        raise KeyError("Both scans must exist to compare them.")
    if base["repository_id"] != head["repository_id"]:
        raise KeyError("Only scans of the same repository can be compared.")

    base_findings, _ = store.list_findings(scan_id=base_id, limit=2000)
    head_findings, _ = store.list_findings(scan_id=head_id, limit=2000)
    base_map = {f["fingerprint"]: f for f in base_findings}
    head_map = {f["fingerprint"]: f for f in head_findings}

    added = [head_map[k] for k in head_map.keys() - base_map.keys()]
    resolved = [base_map[k] for k in base_map.keys() - head_map.keys()]

    def summarise(items: list[dict]) -> list[dict]:
        return [
            {"rule": i["rule"], "severity": i["severity"], "file": i["file"], "line": i["line"],
             "message": i.get("message")}
            for i in sorted(items, key=lambda x: (x["severity"], x["file"], x["line"]))
        ]

    return {
        "base_scan_id": base_id,
        "head_scan_id": head_id,
        "base_score": base.get("overall_score"),
        "head_score": head.get("overall_score"),
        "score_delta": (
            (head.get("overall_score") or 0) - (base.get("overall_score") or 0)
            if base.get("overall_score") is not None and head.get("overall_score") is not None else None
        ),
        "added": summarise(added),
        "resolved": summarise(resolved),
        "unchanged_count": len(base_map.keys() & head_map.keys()),
    }
