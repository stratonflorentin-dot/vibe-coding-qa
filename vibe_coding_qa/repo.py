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


def _create_git_config_with_credential_helper(token: str) -> tuple[str, str]:
    """Create a temporary Git credential store and config with restricted permissions."""
    import shlex
    from urllib.parse import quote

    credential_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".credentials", delete=False, prefix="vcqa-git-credentials-", encoding="utf-8"
    )
    credential_path = credential_file.name
    try:
        credential_file.write("https" + "://" + "x-access-token" + ":" + quote(token, safe="") + "@github.com\n")
    finally:
        credential_file.close()
    try:
        os.chmod(credential_path, 0o600)
    except OSError:
        pass
    config_content = "[credential]\n    helper = store --file=" + shlex.quote(credential_path) + "\n"
    config_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".gitconfig", delete=False, prefix="vcqa-git-config-", encoding="utf-8"
    )
    config_path = config_file.name
    try:
        config_file.write(config_content)
    finally:
        config_file.close()
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass
    return config_path, credential_path


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

    from urllib.parse import urlsplit
    parsed_url = urlsplit(url)
    if parsed_url.username is not None or parsed_url.password is not None:
        raise ValueError("Repository URLs must not contain embedded credentials; pass a GitHub token separately.")
    if token and parsed_url.hostname != "github.com":
        raise ValueError("GitHub tokens can only be used with github.com repositories.")

    allowed_environment = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
        "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
        "LANG", "LC_ALL", "LC_CTYPE", "SSH_AUTH_SOCK", "SSH_AGENT_PID",
    }
    env = {
        key: value for key, value in os.environ.items()
        if key.upper() in allowed_environment or key.upper().startswith("LC_")
    }
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"

    temporary_credentials: list[str] = []
    if token and url.startswith("https://"):
        config_path, credential_path = _create_git_config_with_credential_helper(token)
        temporary_credentials.extend((config_path, credential_path))
        env["GIT_CONFIG_GLOBAL"] = config_path
    cmd = ["git", "clone", "--depth", "1", "--single-branch", url, str(workdir)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    except OSError:
        raise RuntimeError("Unable to invoke Git while cloning the repository.") from None
    finally:
        for credential_path in temporary_credentials:
            try:
                os.unlink(credential_path)
            except OSError:
                pass

    if result.returncode != 0:
        sanitized_stderr = result.stderr.replace(token, "[REDACTED]") if token else result.stderr
        sanitized_stderr = _sanitize_url(sanitized_stderr)
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
