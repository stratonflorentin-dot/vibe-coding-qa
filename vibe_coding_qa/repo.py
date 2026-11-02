"""Repository loader: local path or GitHub clone."""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import Finding, Severity, Status


def is_git_url(value: str) -> bool:
    return value.startswith(("http://", "https://", "git@")) or value.endswith(".git")


def _sanitize_url(url: str) -> str:
    """Remove credentials from a URL for safe logging."""
    return re.sub(r"https?://[^:]+:[^@]+@", "https://***:***@", url)


def clone_repo(github_ref: str, token: str | None = None, workdir: Path | None = None) -> Path:
    """Clone a GitHub repository into a temporary directory.

    Accepts:
      - owner/repo
      - https://github.com/owner/repo
      - git@github.com:owner/repo.git
    """
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="vcqa-repo-"))
    else:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)

    if "/" in github_ref and not github_ref.startswith("http") and not github_ref.startswith("git@"):
        url = f"https://github.com/{github_ref}.git"
    else:
        url = github_ref

    # Use git credential helper via environment variable to avoid token in URL
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    
    if token and url.startswith("https://"):
        # Use GIT_ASKPASS or credential helper via env to avoid token in command line
        # This is safer than embedding in URL
        env["GIT_ASKPASS"] = "echo"
        env["GIT_USERNAME"] = "token"
        env["GIT_PASSWORD"] = token
        cmd = ["git", "clone", "--depth", "1", "--single-branch", url, str(workdir)]
    else:
        cmd = ["git", "clone", "--depth", "1", "--single-branch", url, str(workdir)]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    
    if result.returncode != 0:
        # Sanitize any URLs in stderr before raising
        sanitized_stderr = _sanitize_url(result.stderr)
        raise RuntimeError(f"Failed to clone {_sanitize_url(url)}: {sanitized_stderr}")
    return workdir


def load_repository(source: str, token: str | None = None, workdir: Path | None = None) -> Path:
    if is_git_url(source) or ("/" in source and ".git" not in source and not Path(source).exists()):
        return clone_repo(source, token=token, workdir=workdir)
    path = Path(source).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Repository path not found: {path}")
    return path


def cleanup_repo(path: Path) -> None:
    """Remove a temporary cloned repository."""
    if "vcqa-repo-" in str(path):
        shutil.rmtree(path, ignore_errors=True)


def repo_metadata(repo: Path) -> dict:
    """Gather lightweight metadata about a repo."""
    metadata = {
        "path": str(repo),
        "languages": detect_languages(repo),
        "has_package_json": (repo / "package.json").is_file(),
        "has_requirements_txt": (repo / "requirements.txt").is_file(),
        "has_tests": bool(list(repo.rglob("*test*"))[:1]),
        "framework_hints": detect_frameworks(repo),
    }
    return metadata


def detect_languages(repo: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ext, lang in {
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".py": "python",
        ".sql": "sql",
        ".html": "html",
        ".css": "css",
        ".md": "markdown",
        ".json": "json",
        ".yml": "yaml",
        ".yaml": "yaml",
    }.items():
        counts[lang] = counts.get(lang, 0) + len(list(repo.rglob(f"*{ext}")))
    return counts


def detect_frameworks(repo: Path) -> list[str]:
    hints = []
    files = {p.name for p in repo.rglob("*") if p.is_file()}
    if "next.config.js" in files or "next.config.ts" in files or "next.config.mjs" in files:
        hints.append("nextjs")
    if "vite.config.ts" in files or "vite.config.js" in files:
        hints.append("vite")
    if any((repo / name).is_dir() for name in ("supabase", "prisma", "migrations")):
        hints.append("database")
    pkg = repo / "package.json"
    if pkg.is_file():
        text = pkg.read_text(encoding="utf-8", errors="ignore").lower()
        for name in ("react", "vue", "svelte", "angular", "express", "fastapi", "django", "flask"):
            if name in text:
                hints.append(name)
    return sorted(set(hints))


def read_text_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
