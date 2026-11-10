"""Console entry point: run the local dashboard and open it in a browser.

Installed as the ``vibe-coding-qa`` command. It starts the FastAPI backend
(which also serves the prebuilt frontend) on a loopback address and opens the
browser at it. Everything stays on this machine: the database is a local SQLite
file under the user's home directory (``~/.vibe-coding-qa``) and nothing is sent
to any server.

Set ``VCQA_NO_BROWSER=1`` to skip opening the browser (useful for servers).
"""

from __future__ import annotations

import os
import threading
import time
import webbrowser


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def main() -> None:
    from .backend.config import get_settings
    from .backend.main import main as run_server

    settings = get_settings()
    url = f"http://{settings.host}:{settings.port}"

    if not _truthy(os.environ.get("VCQA_NO_BROWSER")):

        def _open() -> None:
            time.sleep(1.5)
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001 - opening a browser must never crash the server
                pass

        threading.Thread(target=_open, daemon=True).start()

    print(f"Vibe Coding QA is running at {url}  (press Ctrl+C to stop)")
    print(f"Your data stays on this machine: {settings.db_path}")
    run_server()


if __name__ == "__main__":
    main()
