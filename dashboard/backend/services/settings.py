"""Operator scan defaults.

These values are persisted in SQLite so the New Scan screen and the scan runner
share a single source of truth. Environment variables remain the fallback, so a
fresh install behaves exactly like the CLI until the operator changes something.
"""

from __future__ import annotations

from ..config import Settings
from ..persistence.store import Store
from ..profiles import PROFILES
from ..security import ValidationError

FIELDS = (
    "default_scan_profile",
    "allow_test_execution",
    "test_image",
    "test_timeout",
    "max_memory_mb",
    "max_cpu_seconds",
    "max_snapshot_mb",
    "max_write_mb",
    "osv_enabled",
)


def scan_settings(store: Store, settings: Settings) -> dict:
    """The effective scan defaults: persisted values, else environment values."""
    stored = store.all_settings().get("scan") or {}
    return {
        "default_scan_profile": str(stored.get("default_scan_profile") or settings.default_scan_profile),
        "allow_test_execution": bool(stored.get("allow_test_execution", settings.allow_test_execution)),
        "test_image": str(stored.get("test_image") or settings.default_test_image),
        "test_timeout": int(stored.get("test_timeout") or settings.default_test_timeout),
        "max_memory_mb": int(stored.get("max_memory_mb") or settings.default_max_memory_mb),
        "max_cpu_seconds": int(stored.get("max_cpu_seconds") or settings.default_max_cpu_seconds),
        "max_snapshot_mb": int(stored.get("max_snapshot_mb") or settings.default_max_snapshot_mb),
        "max_write_mb": int(stored.get("max_write_mb") or settings.default_max_write_mb),
        "osv_enabled": bool(stored.get("osv_enabled", settings.default_osv_enabled)),
    }


def update_scan_settings(store: Store, payload) -> dict:
    if payload.default_scan_profile not in PROFILES:
        raise ValidationError(f"Unknown scan profile: {payload.default_scan_profile}")
    values = {field: getattr(payload, field) for field in FIELDS}
    store.set_setting("scan", values)
    return values
