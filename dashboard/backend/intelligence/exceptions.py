"""Structured, client-safe exceptions for the Vibe Intelligence subsystem.

Every error carries a stable ``code`` so the API can return consistent responses
and the gateway can record why a task failed, without leaking internals.
"""

from __future__ import annotations


class IntelligenceError(RuntimeError):
    """Base class. ``message`` is always safe to show a client."""

    code = "intelligence_error"
    http_status = 400

    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        if code:
            self.code = code


class InvalidTaskError(IntelligenceError):
    """The request failed contract validation (bad/missing fields)."""

    code = "invalid_task"
    http_status = 400


class UnknownOperationError(IntelligenceError):
    """The requested operation is not one this gateway handles."""

    code = "unknown_operation"
    http_status = 404


class ProjectNotFoundError(IntelligenceError):
    """The referenced project/repository does not exist."""

    code = "project_not_found"
    http_status = 404


class AccessDeniedError(IntelligenceError):
    """The caller is not allowed to run this task on this project."""

    code = "access_denied"
    http_status = 403


class ProviderUnavailableError(IntelligenceError):
    """No capable provider is configured/available for the task."""

    code = "provider_unavailable"
    http_status = 503


class ProviderFailedError(IntelligenceError):
    """A provider was reachable but the call failed (timeout, HTTP error…)."""

    code = "provider_failed"
    http_status = 502


class RequestTooLargeError(IntelligenceError):
    """The prepared request exceeded a configured size budget."""

    code = "request_too_large"
    http_status = 413


__all__ = [
    "AccessDeniedError",
    "IntelligenceError",
    "InvalidTaskError",
    "ProjectNotFoundError",
    "ProviderFailedError",
    "ProviderUnavailableError",
    "RequestTooLargeError",
    "UnknownOperationError",
]
