"""SSRF-defence tests for the public web scanner.

These exercise :mod:`vibe_coding_qa.scanners.net_guard` (the allow/block policy
and the resolve-and-pin step) and the :class:`HttpFetcher` integration that
re-validates every redirect hop. DNS is stubbed so the tests are deterministic
and never touch the network.
"""

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibe_coding_qa.scanners import net_guard
from vibe_coding_qa.scanners.net_guard import (
    BlockedTargetError,
    PUBLIC,
    address_block_reason,
    private_worker_policy,
    resolve_allowed_addresses,
    validate_url,
)
from vibe_coding_qa.scanners.web import HttpFetcher, WebResponse, WebScanLimits, WebSecurityScanner


def _resolver(mapping):
    """A fake getaddrinfo returning the given host -> [ip, ...] mapping.

    Each call can return different addresses for the same host, which lets a
    test model a DNS-rebinding answer that changes between lookups.
    """
    calls = {}

    def fake(host, port, *args, **kwargs):
        seq = mapping.get(host)
        if seq is None:
            import socket
            raise socket.gaierror(f"no fake record for {host}")
        # Allow either a flat list (constant) or a list-of-lists (per call).
        if seq and isinstance(seq[0], (list, tuple)):
            idx = min(calls.get(host, 0), len(seq) - 1)
            calls[host] = calls.get(host, 0) + 1
            addrs = seq[idx]
        else:
            addrs = seq
        out = []
        for ip in addrs:
            fam = 10 if ":" in ip else 2  # AF_INET6 / AF_INET
            out.append((fam, 1, 6, "", (ip, port)))
        return out

    return fake


class AddressClassificationTests(unittest.TestCase):
    def test_public_address_is_allowed(self):
        self.assertIsNone(address_block_reason(ipaddress.ip_address("93.184.216.34")))

    def test_blocked_ranges(self):
        cases = {
            "127.0.0.1": "loopback",
            "127.5.5.5": "loopback",
            "10.0.0.5": "private",
            "172.16.9.9": "private",
            "192.168.1.1": "private",
            "169.254.13.37": "link-local",
            "::1": "loopback",
            "fe80::1": "link-local",
            "fc00::1": "private",
            "0.0.0.0": "unspecified",
            "224.0.0.1": "multicast",
        }
        for ip, expect in cases.items():
            reason = address_block_reason(ipaddress.ip_address(ip))
            self.assertIsNotNone(reason, f"{ip} should be blocked")
            self.assertIn(expect.split("-")[0], reason, f"{ip} -> {reason}")

    def test_cloud_metadata_is_blocked(self):
        self.assertEqual(address_block_reason(ipaddress.ip_address("169.254.169.254")), "cloud-metadata endpoint")
        self.assertEqual(address_block_reason(ipaddress.ip_address("100.100.100.200")), "cloud-metadata endpoint")

    def test_ipv4_mapped_ipv6_loopback_is_unwrapped_and_blocked(self):
        self.assertIsNotNone(address_block_reason(ipaddress.ip_address("::ffff:127.0.0.1")))

    def test_private_worker_policy_allows_only_its_ranges(self):
        policy = private_worker_policy(["10.1.0.0/16"])
        self.assertIsNone(address_block_reason(ipaddress.ip_address("10.1.2.3"), policy))
        # An address outside the authorised range is still blocked.
        self.assertIsNotNone(address_block_reason(ipaddress.ip_address("10.2.2.3"), policy))
        # Metadata stays blocked even for a private-worker policy.
        self.assertEqual(
            address_block_reason(ipaddress.ip_address("169.254.169.254"), policy),
            "cloud-metadata endpoint",
        )


class UrlValidationTests(unittest.TestCase):
    def test_rejects_non_http_scheme(self):
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/"):
            with self.assertRaises(BlockedTargetError):
                validate_url(url)

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(BlockedTargetError):
            validate_url("http://user:pass@example.com/")

    def test_rejects_missing_host(self):
        with self.assertRaises(BlockedTargetError):
            validate_url("http:///nohost")

    def test_rejects_invalid_port(self):
        with self.assertRaises(BlockedTargetError):
            validate_url("http://example.com:not-a-port/")

    def test_port_policy(self):
        policy = net_guard.TargetPolicy(allowed_ports=frozenset({443}))
        self.assertEqual(validate_url("https://example.com/", policy), ("https", "example.com", 443))
        with self.assertRaises(BlockedTargetError):
            validate_url("http://example.com:8080/", policy)


class ResolveAndPinTests(unittest.TestCase):
    def test_public_host_resolves(self):
        resolver = _resolver({"example.com": ["93.184.216.34"]})
        self.assertEqual(
            resolve_allowed_addresses("example.com", 443, PUBLIC, _resolver=resolver),
            ["93.184.216.34"],
        )

    def test_private_resolution_is_blocked(self):
        resolver = _resolver({"internal": ["10.0.0.5"]})
        with self.assertRaises(BlockedTargetError):
            resolve_allowed_addresses("internal", 80, PUBLIC, _resolver=resolver)

    def test_encoded_ip_is_blocked_after_resolution(self):
        # http://2130706433 is 127.0.0.1 in decimal; resolution reveals it.
        resolver = _resolver({"2130706433": ["127.0.0.1"]})
        with self.assertRaises(BlockedTargetError):
            resolve_allowed_addresses("2130706433", 80, PUBLIC, _resolver=resolver)

    def test_mixed_public_and_private_dns_is_rejected(self):
        resolver = _resolver({"rebind.test": ["93.184.216.34", "127.0.0.1"]})
        with self.assertRaises(BlockedTargetError):
            resolve_allowed_addresses("rebind.test", 80, PUBLIC, _resolver=resolver)


class FetcherIntegrationTests(unittest.TestCase):
    """The fetcher must block/allow via net_guard before ever opening a socket."""

    def _fetcher(self, resolver, opener, policy=PUBLIC):
        fetcher = HttpFetcher(WebScanLimits(), policy)
        # Patch resolution (DNS) and the transport open (network) so no real
        # connection is made and the security path is exercised in isolation.
        net_guard.socket.getaddrinfo  # ensure attribute exists
        original = net_guard.resolve_pinned

        def pinned(url, pol, _resolver=None):
            return original(url, pol, _resolver=resolver)

        self._orig_pinned = net_guard.resolve_pinned
        net_guard.resolve_pinned = pinned
        self.addCleanup(lambda: setattr(net_guard, "resolve_pinned", self._orig_pinned))
        # Re-point the name the web module imported.
        import vibe_coding_qa.scanners.web as webmod
        self._orig_web_pinned = webmod.net_guard.resolve_pinned
        webmod.net_guard.resolve_pinned = pinned
        self.addCleanup(lambda: setattr(webmod.net_guard, "resolve_pinned", self._orig_web_pinned))
        fetcher._open = opener  # type: ignore[assignment]
        return fetcher

    def test_private_target_is_blocked_without_connecting(self):
        opened = []

        def opener(*args, **kwargs):
            opened.append(args)
            return WebResponse(url=args[4], status=200)

        resolver = _resolver({"internal.test": ["10.1.2.3"]})
        fetcher = self._fetcher(resolver, opener)
        resp = fetcher.get("http://internal.test/")
        self.assertEqual(resp.status, 0)
        self.assertIn("blocked", resp.error)
        self.assertEqual(opened, [], "no socket should be opened for a blocked target")

    def test_redirect_to_private_is_not_followed(self):
        opened = []

        def opener(scheme, host, port, pinned_ip, url, method, headers):
            opened.append(url)
            if host == "public.test":
                return WebResponse(url=url, status=302, headers={"location": "http://internal.test/secret"})
            return WebResponse(url=url, status=200, body=b"SHOULD NOT REACH")

        resolver = _resolver({"public.test": ["93.184.216.34"], "internal.test": ["127.0.0.1"]})
        fetcher = self._fetcher(resolver, opener)
        resp = fetcher.get("http://public.test/")
        # The redirect target is private: the hop is validated and refused.
        self.assertEqual(resp.status, 0)
        self.assertIn("blocked", resp.error)
        self.assertEqual(opened, ["http://public.test/"], "must not open the private redirect target")

    def test_dns_rebinding_between_hops_is_blocked(self):
        opened = []

        def opener(scheme, host, port, pinned_ip, url, method, headers):
            opened.append((url, pinned_ip))
            return WebResponse(url=url, status=200, body=b"ok")

        # First lookup public, second lookup private (rebinding).
        resolver = _resolver({"rebind.test": [["93.184.216.34"], ["10.0.0.9"]]})
        fetcher = self._fetcher(resolver, opener)
        first = fetcher.get("http://rebind.test/")
        self.assertEqual(first.status, 200)
        self.assertEqual(opened[0][1], "93.184.216.34")
        # A later request re-resolves and now sees the private address.
        second = fetcher.get("http://rebind.test/")
        self.assertEqual(second.status, 0)
        self.assertIn("blocked", second.error)


class WebScanResilienceTests(unittest.TestCase):
    """A flaky or hostile target must never fail the whole scan."""

    def test_connection_reset_mid_scan_is_noted_not_raised(self):
        class ResettingFetcher:
            requests = 1

            def get(self, url, *, follow=True, headers=None):
                raise ConnectionResetError(10054, "An existing connection was forcibly closed by the remote host")

            def options(self, url):
                raise ConnectionResetError(10054, "reset")

        # http:// target so the transport check needs no socket; the reset comes
        # from the base fetch, exactly like a target that drops the connection.
        scanner = WebSecurityScanner("http://example.test/", fetcher=ResettingFetcher())
        findings = scanner.scan()  # must not raise
        rules = {f.rule for f in findings}
        self.assertIn("web:insecure-transport", rules)
        self.assertTrue(
            any("network error" in note for note in scanner.notes),
            f"expected an interruption note, got {scanner.notes}",
        )


class ScannerTargetGuardTests(unittest.TestCase):
    def test_scanner_refuses_private_target(self):
        # Real fetcher (has a policy); resolution is stubbed to a private IP.
        resolver = _resolver({"internal.test": ["10.0.0.5"]})
        import vibe_coding_qa.scanners.web as webmod
        orig = webmod.net_guard.resolve_pinned
        webmod.net_guard.resolve_pinned = lambda url, pol, _resolver=None: orig(url, pol, _resolver=resolver)
        self.addCleanup(lambda: setattr(webmod.net_guard, "resolve_pinned", orig))

        scanner = WebSecurityScanner("http://internal.test/")
        findings = scanner.scan()
        rules = {f.rule for f in findings}
        self.assertIn("web:blocked-target", rules)
        self.assertEqual(scanner.fetcher.requests, 0, "a blocked target must make no requests")


if __name__ == "__main__":
    unittest.main()
