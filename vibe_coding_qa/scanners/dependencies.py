"""Dependency, lockfile, CI, and supply-chain scanner.

This scanner performs local checks and optional, explicit OSV lookups.
Findings are labeled as 'heuristic' or 'verified' based on available evidence.
"""

import contextvars
import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import BaseScanner, is_ignored, load_ignore_patterns
from vibe_coding_qa import Finding, Severity


_OSV_ENDPOINT = "https://api.osv.dev/v1/query"
# Process-level cache: (ecosystem, name, version) -> (expiry_monotonic, advisories).
_OSV_CACHE: dict[tuple[str, str, str], tuple[float, list[dict]]] = {}

# Per-context override of the OSV switch. The dashboard runs scans in worker
# threads; a ContextVar keeps each scan's decision isolated instead of mutating
# the global environment (which concurrent scans would race on).
_OSV_OVERRIDE: contextvars.ContextVar[bool | None] = contextvars.ContextVar("vcqa_osv_override", default=None)


def set_osv_enabled(enabled: bool | None) -> contextvars.Token:
    """Override the OSV switch for the current context; returns a reset token."""
    return _OSV_OVERRIDE.set(enabled)


def reset_osv_enabled(token: contextvars.Token) -> None:
    _OSV_OVERRIDE.reset(token)


def osv_enabled() -> bool:
    override = _OSV_OVERRIDE.get()
    if override is not None:
        return override
    return os.environ.get("VCQA_OSV_ENABLED", "0").lower() in ("1", "true", "yes")


def clear_osv_cache() -> None:
    """Clear the OSV response cache (used by tests and long-running callers)."""
    _OSV_CACHE.clear()


def resolved_dependencies(repo: Path) -> list[tuple[str, str, str, Path]]:
    """Public wrapper: the resolved (ecosystem, name, version, lockfile) list."""
    return DependencyScanner(Path(repo))._resolved_dependencies()


def osv_lookup(ecosystem: str, name: str, version: str, timeout: float = 8.0) -> list[dict]:
    """Public wrapper: query OSV for advisories affecting one resolved package."""
    scanner = DependencyScanner(Path("."))
    scanner._OSV_FETCH_TIMEOUT = timeout
    return scanner._osv_lookup(ecosystem, name, version)


class DependencyScanner(BaseScanner):
    module = "dependencies"

    def __init__(self, repo: Path):
        super().__init__(repo)
        self.notes: list[str] = []
        self._reported_vulns: set[tuple[str, str]] = set()

    _OSV_MAX_BATCH = 250
    _OSV_MAX_CONCURRENCY = 5
    _OSV_FETCH_TIMEOUT = 8.0
    _OSV_CACHE_TTL = 3600.0
    _OSV_DEFAULT_BUDGET = 30.0

    # Locally maintained affected ranges (heuristic, not live advisories).
    # Each entry is matched against an *exact resolved version*, never reported
    # merely because a package has a historical CVE. Confirm with OSV before
    # treating any of these as a confirmed current vulnerability.
    KNOWN_VULNERABLE_RANGES = {
        "lodash": {
            "ecosystem": "npm",
            "affected": "<4.17.21",
            "cve": "CVE-2021-23337",
            "description": "command injection via template in lodash",
        },
        "express": {
            "ecosystem": "npm",
            "affected": "<4.17.3",
            "cve": "CVE-2022-24999",
            "description": "open redirect via qs in Express",
        },
        "jquery": {
            "ecosystem": "npm",
            "affected": "<3.5.0",
            "cve": "CVE-2020-11023",
            "description": "XSS via HTML containing <option> elements",
        },
    }

    # Historically compromised packages (supply chain incidents)
    # These are packages that were compromised at some point in history.
    # Presence alone doesn't mean the current version is malicious.
    HISTORICALLY_COMPROMISED = {
        "event-stream": {
            "incident": "event-stream@3.3.6 contained malicious code targeting Copay wallet (Nov 2018)",
            "cve": "CVE-2018-19207",
        },
        "flatmap-stream": {
            "incident": "flatmap-stream@0.1.1 was a malicious dependency of event-stream",
            "cve": "CVE-2018-19207",
        },
        "left-pad": {
            "incident": "left-pad was unpublished in 2016 causing widespread breakage; not malicious but demonstrates supply chain fragility",
            "cve": None,
        },
    }

    def scan(self) -> list[Finding]:
        self._scan_package_json()
        self._scan_known_vulnerable_resolved()
        self._scan_python_deps()
        self._scan_lockfile_consistency()
        self._scan_ci_workflows()
        self._scan_dockerfile()
        self._scan_github_actions()
        self._scan_osv()
        return self.findings

    def _scan_osv(self) -> None:
        if not osv_enabled():
            self.notes.append("OSV lookups are disabled; dependency findings are based on local heuristics only.")
            return
        dependencies = self._resolved_dependencies()
        if not dependencies:
            self.notes.append("OSV lookup enabled, but no supported resolved dependencies were found in package-lock.json, yarn.lock, pnpm-lock.yaml, Poetry/uv lockfiles, Pipfile.lock, or pinned requirements.txt.")
            return
        if len(dependencies) > self._OSV_MAX_BATCH:
            self.notes.append(f"OSV query scope limited to the first {self._OSV_MAX_BATCH} of {len(dependencies)} resolved dependencies.")
            dependencies = dependencies[:self._OSV_MAX_BATCH]

        budget = self._osv_budget_seconds()
        deadline = time.monotonic() + budget
        advisories_by_index: dict[int, list[dict]] = {}
        failures: list[str] = []
        deferred = 0
        workers = max(1, min(self._OSV_MAX_CONCURRENCY, len(dependencies)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for index, (ecosystem, name, version, _lockfile) in enumerate(dependencies):
                if time.monotonic() >= deadline:
                    deferred = len(dependencies) - index
                    break
                futures[pool.submit(self._osv_lookup, ecosystem, name, version)] = index
            for future in as_completed(futures):
                index = futures[future]
                try:
                    advisories_by_index[index] = future.result()
                except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
                    name, version = dependencies[index][1], dependencies[index][2]
                    failures.append(f"{name}@{version} ({type(exc).__name__})")

        checked = 0
        for index, advisories in sorted(advisories_by_index.items()):
            _ecosystem, name, version, lockfile = dependencies[index]
            checked += 1
            for advisory in advisories:
                advisory_id = advisory.get("id", "OSV advisory")
                aliases = advisory.get("aliases", [])
                if aliases:
                    advisory_id = f"{advisory_id} ({', '.join(aliases[:3])})"
                database_severity = (advisory.get("database_specific") or {}).get("severity", "").lower()
                severity = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "moderate": Severity.MEDIUM,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }.get(database_severity, Severity.MEDIUM)
                self.add(
                    rule="osv-verified-vulnerability",
                    severity=severity,
                    file=lockfile,
                    line=self._dependency_line(lockfile, name, version),
                    message=f"OSV reports {name}@{version} as affected by {advisory_id}. Source: https://osv.dev/vulnerability/{advisory.get('id', '')}.",
                    suggestion="Review the advisory's affected range and upgrade to a version confirmed as patched.",
                    confidence="high",
                )
        note = f"OSV checked {checked} resolved dependencies; matches are advisory-backed and require review of affected ranges."
        if failures:
            note += f" {len(failures)} lookup(s) could not be verified: {', '.join(failures[:5])}."
        if deferred:
            note += f" {deferred} dependency(ies) were skipped after the {budget:.0f}s global time budget was exhausted."
        self.notes.append(note)

    @classmethod
    def _osv_budget_seconds(cls) -> float:
        raw = os.environ.get("VCQA_OSV_BUDGET_SECONDS", str(cls._OSV_DEFAULT_BUDGET))
        try:
            return max(1.0, float(raw))
        except ValueError:
            return cls._OSV_DEFAULT_BUDGET

    def _osv_lookup(self, ecosystem: str, name: str, version: str) -> list[dict]:
        key = (ecosystem, name, version)
        now = time.monotonic()
        cached = _OSV_CACHE.get(key)
        if cached and cached[0] > now:
            return cached[1]
        advisories = self._osv_request(ecosystem, name, version)
        _OSV_CACHE[key] = (now + self._OSV_CACHE_TTL, advisories)
        return advisories

    def _osv_request(self, ecosystem: str, name: str, version: str) -> list[dict]:
        payload = json.dumps({"package": {"name": name, "ecosystem": ecosystem}, "version": version}).encode("utf-8")
        request = urllib.request.Request(
            _OSV_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "vibe-coding-qa"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self._OSV_FETCH_TIMEOUT) as response:
            advisory_data = json.loads(response.read().decode("utf-8"))
        return advisory_data.get("vulns", [])

    def _resolved_dependencies(self) -> list[tuple[str, str, str, Path]]:
        found: list[tuple[str, str, str, Path]] = []
        lockfile = self.repo / "package-lock.json"
        if lockfile.is_file():
            try:
                lock_data = json.loads(lockfile.read_text(encoding="utf-8", errors="ignore"))
                for package_path, package in lock_data.get("packages", {}).items():
                    if not package_path.startswith("node_modules/"):
                        continue
                    name = package_path.rsplit("node_modules/", 1)[-1]
                    version = package.get("version")
                    if version:
                        found.append(("npm", name, str(version), lockfile))
                if not lock_data.get("packages"):
                    self._walk_npm_dependencies(lock_data.get("dependencies", {}), lockfile, found)
            except (OSError, json.JSONDecodeError):
                self.notes.append("Could not parse package-lock.json for OSV checks.")

        yarn_lock = self.repo / "yarn.lock"
        if yarn_lock.is_file():
            found.extend(self._parse_yarn_lock(yarn_lock))
        pnpm_lock = self.repo / "pnpm-lock.yaml"
        if pnpm_lock.is_file():
            found.extend(self._parse_pnpm_lock(pnpm_lock))

        for lock_name in ("requirements.txt",):
            requirements = self.repo / lock_name
            if requirements.is_file():
                for raw in requirements.read_text(encoding="utf-8", errors="ignore").splitlines():
                    match = re.match(r"\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)\s*(?:#.*)?$", raw)
                    if match:
                        found.append(("PyPI", match.group(1), match.group(2), requirements))

        for lock_name in ("poetry.lock", "uv.lock"):
            lockfile = self.repo / lock_name
            if lockfile.is_file():
                found.extend(self._parse_toml_lock(lockfile))

        pipfile_lock = self.repo / "Pipfile.lock"
        if pipfile_lock.is_file():
            try:
                lock_data = json.loads(pipfile_lock.read_text(encoding="utf-8", errors="ignore"))
                for section in ("default", "develop"):
                    for name, package in lock_data.get(section, {}).items():
                        version = package.get("version", "")
                        if version.startswith("=="):
                            found.append(("PyPI", name, version[2:], pipfile_lock))
            except (OSError, json.JSONDecodeError):
                self.notes.append("Could not parse Pipfile.lock for OSV checks.")

        return list(dict.fromkeys(found))

    @staticmethod
    def _parse_yarn_lock(lockfile: Path) -> list[tuple[str, str, str, Path]]:
        found: list[tuple[str, str, str, Path]] = []
        selectors: list[str] = []
        version: str | None = None

        def flush() -> None:
            if not version:
                return
            for selector in selectors:
                selector = selector.strip().strip(',').strip().strip('"\'')
                if selector.startswith("@"):
                    separator = selector.find("@", selector.find("/") + 1)
                else:
                    separator = selector.find("@")
                if separator > 0:
                    name = selector[:separator]
                    found.append(("npm", name, version, lockfile))

        for raw in lockfile.read_text(encoding="utf-8", errors="ignore").splitlines():
            if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
                flush()
                selectors = raw.rstrip()[:-1].split(",")
                version = None
            else:
                match = re.match(r"\s+version\s+[\"']?([^\"'\s]+)", raw)
                if match:
                    version = match.group(1)
        flush()
        return found

    @staticmethod
    def _parse_pnpm_lock(lockfile: Path) -> list[tuple[str, str, str, Path]]:
        found: list[tuple[str, str, str, Path]] = []
        in_packages = False
        for raw in lockfile.read_text(encoding="utf-8", errors="ignore").splitlines():
            if raw and not raw[0].isspace():
                in_packages = raw.rstrip().rstrip(":") == "packages"
                continue
            if not in_packages or len(raw) - len(raw.lstrip()) != 2 or not raw.strip().endswith(":"):
                continue
            selector = raw.strip()[:-1].strip().strip('"\'').lstrip("/")
            if selector.startswith("@"):
                separator = selector.rfind("@")
            else:
                separator = selector.rfind("@")
            if separator <= 0:
                continue
            name = selector[:separator]
            version = selector[separator + 1:].split("(", 1)[0]
            if name and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
                found.append(("npm", name, version, lockfile))
        return found

    @staticmethod
    def _parse_toml_lock(lockfile: Path) -> list[tuple[str, str, str, Path]]:
        found: list[tuple[str, str, str, Path]] = []
        name: str | None = None
        version: str | None = None

        def flush() -> None:
            if name and version:
                found.append(("PyPI", name, version, lockfile))

        for raw in lockfile.read_text(encoding="utf-8", errors="ignore").splitlines():
            if raw.strip() == "[[package]]":
                flush()
                name = None
                version = None
                continue
            name_match = re.match(r"\s*name\s*=\s*[\"']([^\"']+)", raw)
            version_match = re.match(r"\s*version\s*=\s*[\"']([^\"']+)", raw)
            if name_match:
                name = name_match.group(1)
            if version_match:
                version = version_match.group(1)
        flush()
        return found


    def _walk_npm_dependencies(self, dependencies: dict, lockfile: Path, found: list[tuple[str, str, str, Path]]) -> None:
        for name, package in dependencies.items():
            version = package.get("version")
            if version:
                found.append(("npm", name, str(version), lockfile))
            self._walk_npm_dependencies(package.get("dependencies", {}), lockfile, found)

    @staticmethod
    def _dependency_line(lockfile: Path, name: str, version: str) -> int:
        try:
            lines = lockfile.read_text(encoding="utf-8", errors="ignore").splitlines()
            markers = (f"node_modules/{name}", f"{name}@", f'name = "{name}"', f'"{name}":', f"{name}==")
            version_pattern = re.compile(r"(?<![A-Za-z0-9.+-])" + re.escape(version) + r"(?![A-Za-z0-9.+-])")
            for index, line in enumerate(lines):
                if any(marker in line for marker in markers):
                    nearby = "\n".join(lines[index:index + 8])
                    if version_pattern.search(nearby):
                        return index + 1
        except OSError:
            pass
        return 1

    def _scan_package_json(self) -> None:
        pkg = self.repo / "package.json"
        if not pkg.is_file():
            return
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, version in deps.items():
            cleaned = version.strip()
            pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+", cleaned))

            if pinned and name in self.KNOWN_VULNERABLE_RANGES:
                vuln_info = self.KNOWN_VULNERABLE_RANGES[name]
                if self._satisfies(cleaned, vuln_info["affected"]):
                    self._report_known_vulnerability(pkg, 1, name, cleaned, vuln_info)

            # Check for historically compromised packages
            if name in self.HISTORICALLY_COMPROMISED:
                incident = self.HISTORICALLY_COMPROMISED[name]
                self.add(
                    rule="historically-compromised-dependency",
                    severity=Severity.MEDIUM,  # Lower severity - historical incident, not current threat
                    file=pkg,
                    line=1,
                    message=f"Dependency '{name}' was involved in a historical supply-chain incident: {incident['incident']}.",
                    suggestion=f"Verify the current version is not affected. Check {incident['cve'] or 'supply chain advisories'} for details. This is a historical finding, not a confirmed current vulnerability.",
                    confidence="low",  # Historical incident, not current verification
                )

    def _scan_known_vulnerable_resolved(self) -> None:
        """Apply the locally maintained ranges to resolved (including transitive) npm deps."""
        for ecosystem, name, version, lockfile in self._resolved_dependencies():
            if ecosystem != "npm" or name not in self.KNOWN_VULNERABLE_RANGES:
                continue
            if (name, version) in self._reported_vulns:
                continue
            vuln_info = self.KNOWN_VULNERABLE_RANGES[name]
            if self._satisfies(version, vuln_info["affected"]):
                self._report_known_vulnerability(lockfile, self._dependency_line(lockfile, name, version), name, version, vuln_info)

    def _report_known_vulnerability(self, file: Path, line: int, name: str, version: str, vuln_info: dict) -> None:
        self._reported_vulns.add((name, version))
        self.add(
            rule="vulnerable-dependency",
            severity=Severity.MEDIUM,
            file=file,
            line=line,
            message=(
                f"Heuristic: {name}@{version} falls within the locally known affected range "
                f"'{vuln_info['affected']}' ({vuln_info['cve']}: {vuln_info['description']}). "
                f"Confirm this exact version against OSV or the vendor advisory."
            ),
            suggestion="Upgrade to a version the advisory marks as patched, then re-verify with OSV.",
            confidence="low",
        )

    def _scan_python_deps(self) -> None:
        req = self.repo / "requirements.txt"
        if not req.is_file():
            return
        for i, raw in enumerate(req.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "==" not in line:
                self.add(
                    rule="unpinned-python-dependency",
                    severity=Severity.LOW,
                    file=req,
                    line=i,
                    message="Python dependency is not pinned.",
                    suggestion="Pin versions and use a lockfile for reproducible, auditable builds.",
                    confidence="low",
                )

    def _scan_lockfile_consistency(self) -> None:
        pkg = self.repo / "package.json"
        has_lock = any((self.repo / name).is_file() for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"))
        if pkg.is_file() and not has_lock:
            self.add(
                rule="missing-lockfile",
                severity=Severity.MEDIUM,
                file=pkg,
                line=1,
                message="package.json exists without a lockfile.",
                suggestion="Commit a lockfile to ensure reproducible installs and supply-chain audits.",
                confidence="high",
            )

    def _scan_ci_workflows(self) -> None:
        workflows = self.repo / ".github" / "workflows"
        if not workflows.is_dir():
            return
        for path in workflows.glob("*.yml"):
            self._check_workflow(path)
        for path in workflows.glob("*.yaml"):
            self._check_workflow(path)

    def _check_workflow(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        lines = text.splitlines()
        for i, raw in enumerate(lines, 1):
            lowered = raw.lower()
            if "pull_request_target" in lowered:
                self.add(
                    rule="ci-pull-request-target",
                    severity=Severity.HIGH,
                    file=path,
                    line=i,
                    message="Workflow uses pull_request_target; review for cache/p checkout injection risks.",
                    suggestion="Prefer pull_request where possible, pin checkout ref to the merge commit, and avoid running untrusted code with secrets.",
                    confidence="medium",
                )
            if "actions/checkout@v1" in lowered or "actions/checkout@v2" in lowered:
                self.add(
                    rule="ci-outdated-checkout",
                    severity=Severity.LOW,
                    file=path,
                    line=i,
                    message="Workflow uses an old actions/checkout version.",
                    suggestion="Upgrade to actions/checkout@v4 and set persist-credentials: false when not needed.",
                    confidence="medium",
                )
            if re.search(r"secrets\.[a-z0-9_]+", raw, re.IGNORECASE) and ("pull_request" in text or "pull_request_target" in text):
                # Only flag if not in an environment context.
                if "environment:" not in raw and "environment:" not in "\n".join(lines[max(0, i - 5):i]):
                    self.add(
                        rule="ci-secret-in-pr-workflow",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message="Workflow may expose secrets to pull-request builds.",
                        suggestion="Scope secrets to protected environments and avoid using them in jobs triggered by forks.",
                        confidence="low",
                    )

    def _scan_dockerfile(self) -> None:
        ignore = load_ignore_patterns(self.repo)
        for path in self.repo.rglob("Dockerfile*"):
            if is_ignored(path, self.repo, ignore):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, raw in enumerate(text.splitlines(), 1):
                if re.search(r"^FROM\s+.*:latest", raw, re.IGNORECASE):
                    self.add(
                        rule="docker-latest-tag",
                        severity=Severity.LOW,
                        file=path,
                        line=i,
                        message="Docker base image uses the :latest tag.",
                        suggestion="Pin a specific digest or version tag for reproducible builds.",
                        confidence="medium",
                    )
                if re.search(r"^USER\s+root\s*$", raw, re.IGNORECASE):
                    self.add(
                        rule="docker-root-user",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message="Dockerfile explicitly runs as root.",
                        suggestion="Create and switch to a non-root user after installing dependencies.",
                        confidence="medium",
                    )
                if re.search(r"EXPOSE\s+\d+", raw, re.IGNORECASE) and "EXPOSE 443" not in raw.upper():
                    self.add(
                        rule="docker-exposed-port-review",
                        severity=Severity.INFO,
                        file=path,
                        line=i,
                        message="Dockerfile exposes a port; confirm TLS terminates at the edge.",
                        suggestion="Terminate TLS at the reverse proxy or load balancer; do not expose plain HTTP directly.",
                        confidence="low",
                    )

    def _scan_github_actions(self) -> None:
        # Additional high-level checks already covered in _scan_ci_workflows.
        pass

    @staticmethod
    def _version_tuple(version: str):
        return tuple(int(p) for p in re.split(r"[.-]", version) if p.isdigit())

    @classmethod
    def _satisfies(cls, version: str, constraint: str) -> bool:
        """Return True when a concrete version falls inside a comma-joined range.

        Supports ``<``, ``<=``, ``>``, ``>=`` and ``=`` against numeric dotted
        versions (e.g. ``"<3.5.0"`` or ``">=1.2.0,<1.5.0"``).
        """
        actual = cls._version_tuple(version)
        if not actual:
            return False
        for clause in constraint.split(","):
            match = re.fullmatch(r"(<=|>=|<|>|=)?\s*(\d+(?:\.\d+)*)", clause.strip())
            if not match:
                return False
            operator = match.group(1) or "="
            bound = tuple(int(p) for p in match.group(2).split("."))
            length = max(len(actual), len(bound))
            left = actual + (0,) * (length - len(actual))
            right = bound + (0,) * (length - len(bound))
            if operator == "<" and not left < right:
                return False
            if operator == "<=" and not left <= right:
                return False
            if operator == ">" and not left > right:
                return False
            if operator == ">=" and not left >= right:
                return False
            if operator == "=" and not left == right:
                return False
        return True