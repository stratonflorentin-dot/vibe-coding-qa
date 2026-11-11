"""Worker-side target scope and DNS-address enforcement.

The API performs the same checks before it creates a job; the worker repeats
them immediately before execution. Private CIDRs are enabled only by the
worker operator and any per-job CIDRs must be a subset of those configured
networks. Cloud metadata and non-routable addresses remain blocked.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

METADATA = frozenset({"169.254.169.254", "100.100.100.200", "fd00:ec2::254"})


class TargetRejected(ValueError):
    pass


def _networks(values: list[str] | tuple[str, ...]) -> tuple:
    try:
        return tuple(ipaddress.ip_network(value, strict=False) for value in values)
    except ValueError as exc:
        raise TargetRejected("Worker contains an invalid authorized CIDR.") from exc


def _subset(requested, configured) -> bool:
    return all(
        any(scope.version == admin.version and scope.subnet_of(admin) for admin in configured)
        for scope in requested
    )


def validate_target(
    target: str,
    *,
    worker_cidrs: list[str] | tuple[str, ...] = (),
    requested_cidrs: list[str] | tuple[str, ...] = (),
    resolver=socket.getaddrinfo,
) -> tuple[str, list[str]]:
    """Validate URL/IP, resolve all answers, and enforce the worker scope."""
    text = (target or "").strip()
    if not text or len(text) > 2000:
        raise TargetRejected("A target up to 2000 characters is required.")
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TargetRejected("Only absolute HTTP(S) target URLs are allowed.")
        if parsed.username or parsed.password or parsed.fragment:
            raise TargetRejected("Target URLs cannot contain credentials or fragments.")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        canonical = text
    else:
        try:
            host = str(ipaddress.ip_address(text.strip("[]")))
        except ValueError:
            raise TargetRejected("A target must be an absolute HTTP(S) URL or IP address.") from None
        port = 443
        canonical = host

    configured = _networks(worker_cidrs)
    requested = _networks(requested_cidrs)
    if requested and (not configured or not _subset(requested, configured)):
        raise TargetRejected("Requested private scope is not approved by this worker.")
    effective = requested or configured

    try:
        literal = ipaddress.ip_address(host)
        resolved = [str(literal)]
    except ValueError:
        try:
            infos = resolver(host, port, proto=socket.IPPROTO_TCP)
            resolved = list(dict.fromkeys(info[4][0] for info in infos))
        except socket.gaierror as exc:
            raise TargetRejected("The target hostname could not be resolved.") from exc
    if not resolved:
        raise TargetRejected("The target hostname did not resolve to any address.")

    for value in resolved:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise TargetRejected("The target resolved to an invalid address.") from None
        if str(address) in METADATA:
            raise TargetRejected("Cloud metadata endpoints are never valid scan targets.")
        if requested and not any(
            address.version == net.version and address in net for net in requested
        ):
            raise TargetRejected("A resolved address is outside the requested authorized CIDRs.")
        if address.is_global:
            continue
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
            raise TargetRejected("Loopback, link-local, multicast, reserved, and unspecified targets are blocked.")
        if not any(address.version == net.version and address in net for net in effective):
            raise TargetRejected("Target resolves outside this worker's approved public/private scope.")
    return canonical, resolved


__all__ = ["TargetRejected", "validate_target"]
