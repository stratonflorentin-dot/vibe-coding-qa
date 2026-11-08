"""Application architecture and technology profile."""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scanners import is_ignored, load_ignore_patterns


# Directories that only ever contain generated output, dependency caches, VCS
# metadata, or vendored code. They are pruned by the shared repository walker so
# architecture detection and test discovery never analyze them.
EXCLUDED_DIRS = frozenset({
    # Version control
    ".git", ".hg", ".svn",
    # Dependency / vendored trees (large; never first-party source)
    "node_modules", "bower_components", "vendor", "site-packages",
    # Python environments and caches
    ".venv", "venv", "virtualenv", ".tox", ".eggs", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache",
    # JS/TS build output and framework caches
    ".next", ".nuxt", ".svelte-kit", ".output", ".parcel-cache",
    "dist", "build", "out", "coverage", ".nyc_output",
    # Infrastructure / deployment caches
    ".terraform", ".serverless",
})


@dataclass
class AppProfile:
    path: Path
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    package_manager: str = "unknown"
    has_tests: bool = False
    test_runners: list[str] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    auth_providers: list[str] = field(default_factory=list)
    databases: list[str] = field(default_factory=list)
    env_files: list[str] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)
    lockfiles: list[str] = field(default_factory=list)
    ci_files: list[str] = field(default_factory=list)
    deployment: list[str] = field(default_factory=list)
    logging_hints: list[str] = field(default_factory=list)
    has_gitignore: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "languages": self.languages,
            "frameworks": self.frameworks,
            "package_manager": self.package_manager,
            "has_tests": self.has_tests,
            "test_runners": self.test_runners,
            "endpoints": self.endpoints,
            "auth_providers": self.auth_providers,
            "databases": self.databases,
            "env_files": self.env_files,
            "dependencies": self.dependencies,
            "lockfiles": self.lockfiles,
            "ci_files": self.ci_files,
            "deployment": self.deployment,
            "logging_hints": self.logging_hints,
            "has_gitignore": self.has_gitignore,
            "notes": self.notes,
        }


def iter_repo_files(
    repo: Path,
    extensions: tuple[str, ...] | None = None,
    *,
    pruned: set[str] | None = None,
) -> list[Path]:
    """Walk first-party repository files, skipping generated and vendored trees.

    This is the single source of truth for which files count as repository
    content across language detection, framework detection, and test discovery.
    It:

      * prunes :data:`EXCLUDED_DIRS` (``node_modules``, ``.venv``, ``dist``,
        ``coverage``, framework caches, ...) so generated code is never counted
        and huge dependency trees are never scanned;
      * honours ``.vcqaignore``;
      * never follows symlinks (neither directories nor files), so it cannot
        loop or read data outside the repository;
      * accepts only regular files strictly inside ``repo``.

    ``extensions`` filters by suffix (case-insensitive) when provided. When
    ``pruned`` is passed, the relative names of every skipped directory are
    recorded there so callers can report that completeness was affected.
    """
    repo = Path(repo)
    ignore = load_ignore_patterns(repo)
    results: list[Path] = []
    wanted = tuple(ext.lower() for ext in extensions) if extensions else None

    for current_root, dirs, files in os.walk(repo, followlinks=False):
        current = Path(current_root)
        kept_dirs: list[str] = []
        for name in dirs:
            child = current / name
            if name in EXCLUDED_DIRS:
                if pruned is not None:
                    pruned.add(str(child.relative_to(repo).as_posix()))
                continue
            if child.is_symlink():
                if pruned is not None:
                    pruned.add(str(child.relative_to(repo).as_posix()))
                continue
            if is_ignored(child, repo, ignore):
                if pruned is not None:
                    pruned.add(str(child.relative_to(repo).as_posix()))
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs

        for name in files:
            path = current / name
            if path.is_symlink():
                continue
            if wanted is not None and path.suffix.lower() not in wanted:
                continue
            results.append(path)

    return results


def _iter_source_files(repo: Path, extensions: tuple[str, ...]) -> list[Path]:
    return iter_repo_files(repo, extensions)


def _pruned_directories(repo: Path) -> list[str]:
    """Top-level excluded directories that actually exist (for completeness notes)."""
    found: list[str] = []
    for name in EXCLUDED_DIRS:
        if (repo / name).is_dir():
            found.append(name)
    return sorted(found)



def _detect_languages(repo: Path) -> dict[str, int]:
    extension_language = {
        ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".jsx": "javascript",
        ".py": "python", ".sql": "sql", ".html": "html",
        ".css": "css", ".md": "markdown", ".json": "json",
        ".yml": "yaml", ".yaml": "yaml", ".prisma": "prisma",
        ".vue": "vue", ".svelte": "svelte",
    }
    counts: dict[str, int] = {}
    # Deployment manifests and lockfiles are first-party content and are counted;
    # generated output and dependency trees are pruned by the walker.
    for path in iter_repo_files(repo, tuple(extension_language)):
        language = extension_language.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return counts


def _detect_frameworks(repo: Path) -> list[str]:
    hints: set[str] = set()
    files = {p.name: p for p in iter_repo_files(repo)}

    if any(name in files for name in ("next.config.js", "next.config.ts", "next.config.mjs")):
        hints.add("nextjs")
    if any(name in files for name in ("vite.config.ts", "vite.config.js", "vite.config.mjs")):
        hints.add("vite")
    if any(name in files for name in ("remix.config.js",)):
        hints.add("remix")
    if "nuxt.config.ts" in files or "nuxt.config.js" in files:
        hints.add("nuxt")
    if "angular.json" in files:
        hints.add("angular")
    if any((repo / name).is_dir() for name in ("supabase",)):
        hints.add("supabase")
    if (repo / "prisma").is_dir() or any(path.suffix.lower() == ".prisma" for path in files.values()):
        hints.add("prisma")
    if any(path.name == "firebase.rules" for path in files.values()):
        hints.add("firebase")
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name in deps:
                if name.startswith("react"):
                    hints.add("react")
                if name.startswith("vue"):
                    hints.add("vue")
                if name.startswith("svelte"):
                    hints.add("svelte")
                if name.startswith("express"):
                    hints.add("express")
                if name.startswith("fastify"):
                    hints.add("fastify")
                if name.startswith("@fastapi") or name == "fastapi":
                    hints.add("fastapi")
                if name == "django":
                    hints.add("django")
                if name.startswith("flask"):
                    hints.add("flask")
                if name in ("@clerk/clerk-react", "@clerk/nextjs"):
                    hints.add("clerk")
                if name in ("@auth0/auth0-react",):
                    hints.add("auth0")
                if name == "next-auth":
                    hints.add("nextauth")
        except Exception:
            pass
    return sorted(hints)


def _detect_package_manager(repo: Path) -> str:
    if (repo / "pnpm-lock.yaml").is_file():
        return "pnpm"
    if (repo / "yarn.lock").is_file():
        return "yarn"
    if (repo / "package-lock.json").is_file():
        return "npm"
    if (repo / "bun.lockb").is_file():
        return "bun"
    if (repo / "poetry.lock").is_file():
        return "poetry"
    if (repo / "Pipfile.lock").is_file():
        return "pipenv"
    if (repo / "requirements.txt").is_file():
        return "pip"
    if (repo / "pyproject.toml").is_file():
        return "pip"
    return "unknown"


def _detect_lockfiles(repo: Path) -> list[str]:
    names = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
             "poetry.lock", "Pipfile.lock", "requirements.txt"]
    return sorted([n for n in names if (repo / n).is_file()])


def _detect_ci(repo: Path) -> list[str]:
    ci: list[str] = []
    workflows = repo / ".github" / "workflows"
    if workflows.is_dir():
        ci.extend(str(p.relative_to(repo)) for p in workflows.glob("*.yml"))
        ci.extend(str(p.relative_to(repo)) for p in workflows.glob("*.yaml"))
    for name in (".gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml", "Jenkinsfile"):
        if (repo / name).is_file():
            ci.append(name)
    return sorted(ci)


def _detect_deployment(repo: Path) -> list[str]:
    deployment: list[str] = []
    names = [p.name for p in iter_repo_files(repo)]
    if any(name.startswith("Dockerfile") for name in names):
        deployment.append("docker")
    if any(name.startswith("docker-compose") and name.endswith((".yml", ".yaml")) for name in names):
        deployment.append("docker-compose")
    if (repo / "vercel.json").is_file() or (repo / ".vercel").is_dir():
        deployment.append("vercel")
    if (repo / "netlify.toml").is_file():
        deployment.append("netlify")
    if any(name.endswith(".tf") for name in names):
        deployment.append("terraform")
    if (repo / ".github" / "workflows").is_dir():
        deployment.append("github-actions")
    return sorted(set(deployment))


def _detect_databases(repo: Path, frameworks: list[str]) -> list[str]:
    dbs: set[str] = set()
    if (repo / "supabase").is_dir():
        dbs.add("supabase-postgres")
    if any(path.suffix.lower() == ".prisma" for path in iter_repo_files(repo)):
        dbs.add("prisma")
    if (repo / "firebase.rules").is_file() or "firebase" in frameworks:
        dbs.add("firebase")
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name in deps:
                if name in ("pg", "postgres"):
                    dbs.add("postgresql")
                if name in ("mysql2", "mysql"):
                    dbs.add("mysql")
                if name in ("mongoose",):
                    dbs.add("mongodb")
                if name in ("@supabase/supabase-js",):
                    dbs.add("supabase")
        except Exception:
            pass
    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
        if "django" in text:
            dbs.add("django-orm")
        if "sqlalchemy" in text:
            dbs.add("sqlalchemy")
    return sorted(dbs)


def _detect_auth_providers(repo: Path, frameworks: list[str]) -> list[str]:
    providers: set[str] = set()
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name in deps:
                if name in ("@clerk/clerk-react", "@clerk/nextjs"):
                    providers.add("clerk")
                if name in ("@auth0/auth0-react", "@auth0/nextjs-auth0"):
                    providers.add("auth0")
                if name == "next-auth":
                    providers.add("nextauth")
                if name in ("@supabase/supabase-js", "@supabase/auth-helpers-nextjs"):
                    providers.add("supabase-auth")
                if name == "firebase":
                    providers.add("firebase-auth")
        except Exception:
            pass
    for f in _iter_source_files(repo, (".ts", ".tsx", ".js", ".jsx", ".py")):
        text = f.read_text(encoding="utf-8", errors="ignore").lower()
        if "jwt" in text:
            providers.add("jwt")
        if "oauth" in text:
            providers.add("oauth")
        if "passport" in text:
            providers.add("passport")
    return sorted(providers)


def _detect_test_runners(repo: Path) -> list[str]:
    runners: set[str] = set()
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            scripts = data.get("scripts", {})
            if "test" in scripts:
                runners.add("npm-test")
            dev = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "jest" in dev:
                runners.add("jest")
            if "vitest" in dev:
                runners.add("vitest")
            if "mocha" in dev:
                runners.add("mocha")
            if "cypress" in dev:
                runners.add("cypress")
            if "playwright" in dev:
                runners.add("playwright")
        except Exception:
            pass
    files = iter_repo_files(repo)
    names = {path.name for path in files}
    if "pytest.ini" in names or "conftest.py" in names or (repo / "pyproject.toml").is_file():
        runners.add("pytest")
    unittest_files = [path for path in files if path.name.startswith("test") and path.suffix == ".py"]
    if any("unittest" in path.read_text(encoding="utf-8", errors="ignore") for path in unittest_files):
        runners.add("unittest")
    if any(path.suffix in (".ts", ".tsx") and (".test." in path.name or ".spec." in path.name) for path in files):
        runners.add("ts-js-tests")
    return sorted(runners)


def _extract_endpoints(repo: Path) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    patterns = [
        (r"(app|router|route)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", "express/fastify"),
        (r"@app\.(route|get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", "fastapi/flask"),
        (r"(path\s*=\s*['\"]([^'\"]+)['\"])", "django"),
        (r"export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(", "nextjs-app-router"),
        (r"api\/(\S+)", "heuristic"),
    ]
    seen: set[tuple[str, str, int]] = set()
    for path in _iter_source_files(repo, (".ts", ".tsx", ".js", ".jsx", ".py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            for pattern, framework in patterns:
                for match in re.finditer(pattern, raw, re.IGNORECASE):
                    key = (framework, match.group(0), i)
                    if key in seen:
                        continue
                    seen.add(key)
                    endpoints.append({
                        "method": "route",
                        "path": match.group(0),
                        "framework": framework,
                        "file": str(path.relative_to(repo)),
                        "line": i,
                    })
    return endpoints[:200]


def _detect_env_files(repo: Path) -> list[str]:
    return sorted(
        str(path.relative_to(repo))
        for path in iter_repo_files(repo)
        if path.name.startswith(".env")
    )


def _load_dependencies(repo: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps.update(data.get(section, {}))
        except Exception:
            pass
    req = repo / "requirements.txt"
    if req.is_file():
        for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, _, version = line.partition("==")
                deps[name.strip()] = version.strip()
            else:
                deps[line] = "*"
    return deps


def analyze_repo(repo: Path) -> AppProfile:
    # Single shared walk: every detection helper reads from the same pruned,
    # symlink-safe, .vcqaignore-aware file set so results stay consistent.
    files = iter_repo_files(repo)
    names = [path.name for path in files]

    profile = AppProfile(path=repo)
    profile.languages = _detect_languages(repo)
    profile.frameworks = _detect_frameworks(repo)
    profile.package_manager = _detect_package_manager(repo)
    profile.lockfiles = _detect_lockfiles(repo)
    profile.ci_files = _detect_ci(repo)
    profile.deployment = _detect_deployment(repo)
    profile.databases = _detect_databases(repo, profile.frameworks)
    profile.auth_providers = _detect_auth_providers(repo, profile.frameworks)
    profile.test_runners = _detect_test_runners(repo)
    profile.has_tests = bool(profile.test_runners)
    profile.env_files = _detect_env_files(repo)
    profile.dependencies = _load_dependencies(repo)
    profile.endpoints = _extract_endpoints(repo)
    profile.has_gitignore = (repo / ".gitignore").is_file()
    profile.logging_hints = []
    if any(name.startswith("sentry.") for name in names) or "@sentry" in " ".join(profile.dependencies):
        profile.logging_hints.append("sentry")
    if "winston" in profile.dependencies:
        profile.logging_hints.append("winston")
    if any(name.endswith(".log") for name in names):
        profile.logging_hints.append("log-files-present")
    profile.notes.append("Architecture profile is heuristic; verify manually against actual deployment.")
    pruned = _pruned_directories(repo)
    if pruned:
        profile.notes.append(
            "Generated and vendored directories were excluded from language, framework, and test "
            f"detection: {', '.join(pruned)}. Detection completeness is reduced accordingly."
        )
    return profile
