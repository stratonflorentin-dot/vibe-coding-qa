"""SSRF guard: decide which network destinations a scan is allowed to reach.

The web scanner makes real outbound HTTP(S) requests to a target the user
supplies, and follows redirects. Without a guard, a hostile target (or a
redirect it returns) could point the scanner at loopback, private, link-local
or cloud-metadata addresses - a classic Server-Side Request Forgery. This module
is the single place that answers one question: *may we connect to this address?*

Two policies exist:

* :data:`PUBLIC` - the default for the public URL scanner. It permits only
  globally-routable public addresses and rejects everything internal.
* :func:`private_worker_policy` - for a customer's own in-network worker. It
  permits only explicitly authorised CIDR ranges, and still blocks cloud
  metadata so an authorised range can never become an unrestricted SSRF bypass.

The defence rests on validating the *resolved IP address*, not the hostname:
encoded addresses (``http://2130706433``), DNS names that resolve to private
space, and DNS rebinding are all caught because the destination is resolved,
every resolved address is checked, and the connection is pinned to the exact
address that was approved (see :func:`resolve_pinned` and the web fetcher).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class BlockedTargetError(Exception):
    """Raised when a URL, or an address it resolves to, is not an allowed target."""

    def __init__(self, message: str, *, url: str | None = None, address: str | None = None, reason: str | None = None):
        super().__init__(message)
        self.url = url
        self.address = address
        self.reason = reason


#: Well-known cloud/provider metadata service addresses. These are blocked under
#: every policy (even an authorised private range) because reaching them is never
#: a legitimate application-security check and is the classic SSRF escalation.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254",   # AWS, GCP, Azure, DigitalOcean, OpenStack, Oracle
    "fd00:ec2::254",     # AWS IMDS over IPv6
    "100.100.100.200",   # Alibaba Cloud
})


@dataclass(frozen=True)
class TargetPolicy:
    """What a scan is allowed to connect to.

    ``allowed_networks`` is the only way to permit an address that would
    otherwise be blocked (used by the private-network worker). An empty tuple is
    the strict public policy. Cloud-metadata addresses are always blocked.
    """

    allowed_networks: tuple[IPNetwork, ...] = ()
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    allowed_ports: frozenset[int] | None = None  # None => any port
    allow_metadata: bool = False


#: The default policy for the public URL scanner: public, routable addresses only.
PUBLIC = TargetPolicy()


def private_worker_policy(
    networks: "list[str] | tuple[str, ...]",
    *,
    allowed_ports: "frozenset[int] | set[int] | None" = None,
) -> TargetPolicy:
    """Build a policy that permits only the given customer-owned CIDR ranges."""
    nets = tuple(ipaddress.ip_network(str(n), strict=False) for n in networks)
    return TargetPolicy(
        allowed_networks=nets,
        allowed_ports=frozenset(allowed_ports) if allowed_ports else None,
    )


def _candidates(addr: IPAddress) -> list[IPAddress]:
    """Every address a destination effectively reaches, unwrapping v6 tunnels.

    ``::ffff:127.0.0.1`` (IPv4-mapped), 6to4 and Teredo all carry an embedded
    IPv4 address; classifying only the outer IPv6 form would miss a loopback or
    private target hidden inside it.
    """
    out: list[IPAddress] = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        for mapped in (addr.ipv4_mapped, addr.sixtofour):
            if mapped is not None:
                out.append(mapped)
        if addr.teredo is not None:
            out.append(addr.teredo[1])
    return out


def address_block_reason(addr: IPAddress, policy: TargetPolicy = PUBLIC) -> str | None:
    """Return why ``addr`` is blocked under ``policy``, or ``None`` if allowed."""
    for candidate in _candidates(addr):
        if not policy.allow_metadata and str(candidate) in METADATA_ADDRESSES:
            return "cloud-metadata endpoint"

    # An explicitly authorised network overrides the internal-address checks,
    # but never the metadata block above.
    for net in policy.allowed_networks:
        if addr.version == net.version and addr in net:
            return None

    for candidate in _candidates(addr):
        if candidate.is_loopback:
            return "loopback address"
        if candidate.is_link_local:
            return "link-local address"
        if candidate.is_multicast:
            return "multicast address"
        if candidate.is_unspecified:
            return "unspecified address"
        if candidate.is_reserved:
            return "reserved address"
        if candidate.is_private:
            return "private address"
        if not candidate.is_global:
            return "non-global address"
    return None


def validate_url(url: str, policy: TargetPolicy = PUBLIC) -> tuple[str, str, int]:
    """Validate the URL's shape (scheme, host, port) before any DNS lookup.

    Returns ``(scheme, host, port)``. Raises :class:`BlockedTargetError` for a
    disallowed scheme, embedded credentials, a missing host, or a port outside
    the policy. Address-level checks happen later, after DNS resolution.
    """
    parsed = urlsplit((url or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in policy.allowed_schemes:
        raise BlockedTargetError(
            f"URL scheme {scheme or '(none)'!r} is not allowed; use http or https.",
            url=url, reason="scheme",
        )
    if parsed.username or parsed.password:
        raise BlockedTargetError("URLs with embedded credentials are not allowed.", url=url, reason="credentials")
    host = parsed.hostname
    if not host:
        raise BlockedTargetError("The URL has no host.", url=url, reason="host")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:  # non-numeric / out-of-range port
        raise BlockedTargetError("The URL has an invalid port.", url=url, reason="port") from exc
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise BlockedTargetError(f"Port {port} is not in the allowed set.", url=url, reason="port")
    return scheme, host, port


def resolve_allowed_addresses(
    host: str,
    port: int,
    policy: TargetPolicy = PUBLIC,
    *,
    _resolver=socket.getaddrinfo,
) -> list[str]:
    """Resolve ``host`` and return its allowed IPs, or raise :class:`BlockedTargetError`.

    If *any* resolved address is blocked, the whole host is rejected. That is
    deliberately strict: it neutralises a DNS record that mixes a public and a
    private answer, and it is the first half of DNS-rebinding defence (the caller
    then pins the connection to one of the returned addresses).
    """
    try:
        infos = _resolver(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise BlockedTargetError(f"{host} could not be resolved.", reason="dns") from exc

    allowed: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip_str = info[4][0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            raise BlockedTargetError(f"{host} resolved to an unparseable address {ip_str!r}.", reason="address")
        reason = address_block_reason(addr, policy)
        if reason is not None:
            raise BlockedTargetError(
                f"{host} resolves to a blocked {reason} ({ip_str}).",
                address=ip_str, reason=reason,
            )
        allowed.append(ip_str)
    if not allowed:
        raise BlockedTargetError(f"{host} did not resolve to any address.", reason="dns")
    return allowed


def resolve_pinned(url: str, policy: TargetPolicy = PUBLIC, *, _resolver=socket.getaddrinfo) -> tuple[str, str, int, str]:
    """Validate ``url`` and resolve it to one approved address to pin.

    Returns ``(scheme, host, port, pinned_ip)``. The connection must be made to
    ``pinned_ip`` with the TLS SNI and HTTP ``Host`` kept as ``host`` so that
    the address that was approved is exactly the address that is dialled - which
    closes the resolve/connect gap a DNS-rebinding attack relies on.
    """
    scheme, host, port = validate_url(url, policy)
    addresses = resolve_allowed_addresses(host, port, policy, _resolver=_resolver)
    return scheme, host, port, addresses[0]


__all__ = [
    "BlockedTargetError",
    "METADATA_ADDRESSES",
    "PUBLIC",
    "TargetPolicy",
    "address_block_reason",
    "private_worker_policy",
    "resolve_allowed_addresses",
    "resolve_pinned",
    "validate_url",
]
