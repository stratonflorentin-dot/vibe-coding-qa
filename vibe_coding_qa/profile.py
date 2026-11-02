"""Application architecture and technology profile."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


def _iter_source_files(repo: Path, extensions: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for ext in extensions:
        files.extend(repo.rglob(f"*{ext}"))
    return [
        p for p in files
        if "node_modules" not in p.parts
        and ".git" not in p.parts
        and "__pycache__" not in p.parts
        and "vcqa-reports" not in str(p)
    ]


def _detect_languages(repo: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ext, lang in {
        ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".jsx": "javascript",
        ".py": "python", ".sql": "sql", ".html": "html",
        ".css": "css", ".md": "markdown", ".json": "json",
        ".yml": "yaml", ".yaml": "yaml", ".prisma": "prisma",
        ".vue": "vue", ".svelte": "svelte",
    }.items():
        counts[lang] = counts.get(lang, 0) + len(list(repo.rglob(f"*{ext}")))
    return counts


def _detect_frameworks(repo: Path) -> list[str]:
    hints: set[str] = set()
    files = {p.name: p for p in repo.rglob("*") if p.is_file()}
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
    if (repo / "prisma").is_dir() or any(repo.rglob("*.prisma")):
        hints.add("prisma")
    if any(repo.rglob("firebase.rules")):
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
    if any(repo.rglob("Dockerfile*")):
        deployment.append("docker")
    if any(repo.rglob("docker-compose*.yml")):
        deployment.append("docker-compose")
    if (repo / "vercel.json").is_file() or (repo / ".vercel").is_dir():
        deployment.append("vercel")
    if (repo / "netlify.toml").is_file():
        deployment.append("netlify")
    if (repo / "k8s").is_dir() or any(repo.rglob("*.yaml")) and "deployment" in " ".join(str(p) for p in repo.rglob("*.yaml")).lower():
        pass
    if any(repo.rglob("*.tf")):
        deployment.append("terraform")
    if (repo / ".github" / "workflows").is_dir():
        deployment.append("github-actions")
    return sorted(set(deployment))


def _detect_databases(repo: Path, frameworks: list[str]) -> list[str]:
    dbs: set[str] = set()
    if (repo / "supabase").is_dir():
        dbs.add("supabase-postgres")
    if any(repo.rglob("*.prisma")):
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
    if any(repo.rglob("pytest.ini")) or any(repo.rglob("conftest.py")) or (repo / "pyproject.toml").is_file():
        runners.add("pytest")
    if any(repo.rglob("*.test.ts")) or any(repo.rglob("*.test.tsx")) or any(repo.rglob("*.spec.ts")):
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
    return sorted([str(p.relative_to(repo)) for p in repo.rglob(".env*") if ".git" not in p.parts])


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
    if any(repo.rglob("sentry.*")) or "@sentry" in " ".join(profile.dependencies):
        profile.logging_hints.append("sentry")
    if "winston" in profile.dependencies:
        profile.logging_hints.append("winston")
    if any(repo.rglob("*.log")):
        profile.logging_hints.append("log-files-present")
    profile.notes.append("Architecture profile is heuristic; verify manually against actual deployment.")
    return profile
