"""Repository registration and metadata refresh.

A repository is either a validated local directory or a validated git source.
Nothing is cloned at registration time: a remote repository is fetched with the
existing engine loader when it is first scanned, so registration stays cheap and
never performs a surprise network operation.
"""

from pathlib import Path

from vibe_coding_qa.profile import analyze_repo

from ..config import Settings
from ..persistence.store import Store
from ..security import ValidationError, resolve_repo_path, validate_git_source


def _derive_name(source: str, source_type: str) -> str:
    if source_type == "local":
        return Path(source).name or source
    cleaned = source.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    if cleaned.startswith("git@"):
        cleaned = cleaned.split(":", 1)[-1]
    parts = [p for p in cleaned.split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else source)


class RepositoryService:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings

    # ------------------------------------------------------------------ reads
    def list(self) -> list[dict]:
        return self.store.list_repositories()

    def get(self, repository_id: int) -> dict | None:
        return self.store.get_repository(repository_id)

    def require(self, repository_id: int) -> dict:
        repo = self.store.get_repository(repository_id)
        if repo is None:
            raise KeyError(f"Repository {repository_id} was not found.")
        return repo

    # ------------------------------------------------------------------ writes
    def register(self, *, source: str, source_type: str, name: str | None = None) -> dict:
        source_type = (source_type or "local").lower()
        if source_type == "local":
            resolved = resolve_repo_path(source, self.settings.allowed_repo_roots)
            normalized = str(resolved)
            metadata = self._detect(resolved)
        elif source_type == "github":
            normalized = validate_git_source(source)
            metadata = {}
        else:
            raise ValidationError(f"Unsupported repository source type: {source_type}")

        existing = self.store.get_repository_by_source(normalized)
        if existing:
            raise ValidationError(f"Repository is already registered: {normalized}")

        return self.store.create_repository(
            name=(name or "").strip() or _derive_name(normalized, source_type),
            source=normalized,
            source_type=source_type,
            **metadata,
        )

    def refresh(self, repository_id: int) -> dict:
        repo = self.require(repository_id)
        if repo["source_type"] != "local":
            raise ValidationError(
                "Metadata for remote repositories is captured when they are scanned."
            )
        resolved = resolve_repo_path(repo["source"], self.settings.allowed_repo_roots)
        metadata = self._detect(resolved)
        return self.store.update_repository(repository_id, **metadata) or repo

    def delete(self, repository_id: int) -> bool:
        return self.store.delete_repository(repository_id)

    # ------------------------------------------------------------- internals
    def _detect(self, path: Path) -> dict:
        """Detect the technology profile of a *local* repository."""
        try:
            profile = analyze_repo(path)
        except Exception:
            return {}
        languages = {k: v for k, v in profile.languages.items() if v}
        main_language = max(languages, key=languages.get) if languages else None
        return {
            "main_language": main_language,
            "frameworks": profile.frameworks,
            "package_manager": profile.package_manager,
            "database_tech": profile.databases,
            "auth_tech": profile.auth_providers,
            "deployment": profile.deployment,
        }

    def metadata_from_scan(self, repository_id: int, architecture: dict, share_source_context: bool) -> None:
        """Persist the richer metadata captured during a real scan.

        Repository paths are only stored/echoed when the operator opted in to
        sharing source context; otherwise the path stays on the server.
        """
        if not architecture:
            return
        languages = {k: v for k, v in (architecture.get("languages") or {}).items() if v}
        main_language = max(languages, key=languages.get) if languages else None
        self.store.update_repository(
            repository_id,
            main_language=main_language,
            frameworks=list(architecture.get("frameworks") or []),
            package_manager=architecture.get("package_manager"),
            database_tech=list(architecture.get("databases") or []),
            auth_tech=list(architecture.get("auth_providers") or []),
            deployment=list(architecture.get("deployment") or []),
        )
