"""Optional security-worker orchestration and target authorization.

The API is an orchestrator only: it never launches a scanner binary. It talks
outbound to an independently deployed worker with a per-worker bearer token,
persists verified results, and re-checks the approved target scope before each
job submission.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import httpx

from vibe_coding_qa.scanners import net_guard
from vibe_coding_qa.scanners.web import HttpFetcher, WebScanLimits

from ..accounts import Role, role_at_least
from ..persistence.database import utcnow
from ..persistence.store import Store
from ..security import ValidationError, validate_web_target
from security_worker.normalize import Finding
from security_worker.profiles import PROFILES, get_profile

_TERMINAL = {"completed", "failed", "cancelled"}
_MAX_TARGET_BYTES = 2000
_MAX_FINDINGS_PER_JOB = 5000
_MAX_EVIDENCE_BYTES = 8_000_000


def _valid_worker_url(value: str) -> str:
    candidate = (value or "").strip().rstrip("/")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise ValidationError("Worker URL contains a control character.")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        raise ValidationError("Worker URL is malformed.") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValidationError("Worker URL must be absolute HTTP(S), without credentials or query parameters.")
    hostname = parsed.hostname.lower()
    local_aliases = {"localhost", "127.0.0.1", "::1", "security-worker"}
    if parsed.scheme != "https" and hostname not in local_aliases:
        raise ValidationError("Remote worker connections must use HTTPS.")
    try:
        address = ipaddress.ip_address(hostname)
        if str(address) in net_guard.METADATA_ADDRESSES:
            raise ValidationError("Cloud metadata endpoints cannot be registered as workers.")
    except ValueError:
        try:
            answers = socket.getaddrinfo(hostname, port or (443 if parsed.scheme == "https" else 80))
        except OSError:
            answers = []
        for answer in answers:
            try:
                ip = ipaddress.ip_address(answer[4][0])
            except ValueError:
                raise ValidationError("Worker URL resolved to an invalid address.") from None
            if str(ip) in net_guard.METADATA_ADDRESSES:
                raise ValidationError("Cloud metadata endpoints cannot be registered as workers.")
    return candidate


def _validate_worker_placement(value: str, placement: str) -> str:
    if placement not in {"same_vps", "remote_vps", "private_network"}:
        raise ValidationError("Worker placement must be same_vps, remote_vps, or private_network.")
    normalized = _valid_worker_url(value)
    parsed = urlsplit(normalized)
    local_aliases = {"localhost", "127.0.0.1", "::1", "security-worker"}
    if placement == "remote_vps":
        if parsed.scheme != "https" or parsed.hostname.lower() in local_aliases:
            raise ValidationError("Remote VPS workers must use a public HTTPS endpoint.")
        try:
            addresses = [ipaddress.ip_address(parsed.hostname)]
        except ValueError:
            try:
                answers = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
            except OSError:
                answers = []
            try:
                addresses = [ipaddress.ip_address(answer[4][0]) for answer in answers]
            except (IndexError, ValueError):
                raise ValidationError("Remote VPS worker URL resolved to an invalid address.") from None
        if not addresses:
            raise ValidationError("Remote VPS worker URL did not resolve to an address.")
        if any(not address.is_global for address in addresses):
            raise ValidationError("Remote VPS worker URLs must resolve only to public IP addresses.")
    return normalized


def _parse_cidrs(values: str | list[str] | tuple[str, ...] | None) -> tuple:
    if not values:
        return ()
    parts = values.split(",") if isinstance(values, str) else values
    try:
        return tuple(ipaddress.ip_network(str(item).strip(), strict=False) for item in parts if str(item).strip())
    except ValueError:
        raise ValidationError("One or more authorized CIDRs are invalid.") from None


def _is_private_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not address.is_global


def _resolve_target(value: str, allowed_networks=()) -> list[str]:
    if value.startswith(("http://", "https://")):
        policy = net_guard.TargetPolicy(allowed_networks=tuple(allowed_networks))
        _scheme, host, port = net_guard.validate_url(value, policy)
        return net_guard.resolve_allowed_addresses(host, port, policy)
    try:
        address = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        raise ValidationError("Target must be an HTTP(S) URL or an IP address.") from None
    reason = net_guard.address_block_reason(address, net_guard.TargetPolicy(allowed_networks=tuple(allowed_networks)))
    if reason:
        raise ValidationError(f"Target IP is blocked: {reason}.")
    return [str(address)]


def _require_addresses_in_scope(addresses: list[str], allowed_networks: tuple) -> None:
    if not allowed_networks:
        raise ValidationError("An explicit approved CIDR scope is required for a private target.")
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.is_global or address.is_loopback or address.is_link_local or address.is_reserved:
            raise ValidationError("Every private target DNS answer must be within the approved private CIDRs.")
        if not any(address.version == network.version and address in network for network in allowed_networks):
            raise ValidationError("A target address resolved outside the approved CIDR scope.")


class SecurityLabService:
    def __init__(self, store: Store, *, max_concurrency: int = 2):
        self.store = store
        self._pool = ThreadPoolExecutor(max_workers=max(1, min(int(max_concurrency), 4)), thread_name_prefix="vcqa-security")
        self._lock = threading.RLock()
        self._submitted: set[int] = set()

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def list_profiles(self) -> list[dict]:
        return [profile.to_dict() for profile in PROFILES.values()]

    @staticmethod
    def _public_worker(row: dict) -> dict:
        result = dict(row)
        result.pop("token", None)
        return result

    def workers(self) -> list[dict]:
        return [self._public_worker(worker) for worker in self.store.list_security_workers()]

    def require_worker(self, worker_id: int) -> dict:
        worker = self.store.get_security_worker(worker_id)
        if worker is None:
            raise KeyError(f"Security worker {worker_id} was not found.")
        return worker

    def register_worker(
        self,
        *,
        name: str,
        base_url: str,
        token: str,
        placement: str,
        allowed_networks: list[str],
    ) -> dict:
        if len(token) < 32 or len(token) > 512:
            raise ValidationError("Worker token must contain between 32 and 512 characters.")
        if placement not in {"same_vps", "remote_vps", "private_network"}:
            raise ValidationError("Worker placement must be same_vps, remote_vps, or private_network.")
        networks = _parse_cidrs(allowed_networks)
        normalized = _validate_worker_placement(base_url, placement)
        row = self.store.create_security_worker(
            name=name.strip()[:120],
            base_url=normalized,
            token=token,
            placement=placement,
            allowed_networks=",".join(str(network) for network in networks),
        )
        return self._public_worker(row)

    def update_worker(self, worker_id: int, **fields) -> dict:
        current = self.require_worker(worker_id)
        if "base_url" in fields or "placement" in fields:
            fields["base_url"] = _validate_worker_placement(
                fields.get("base_url", current["base_url"]),
                fields.get("placement", current["placement"]),
            )
        if "token" in fields and fields["token"] is not None:
            if len(fields["token"]) < 32:
                raise ValidationError("Worker token must contain at least 32 characters.")
        if "allowed_networks" in fields:
            fields["allowed_networks"] = ",".join(str(item) for item in _parse_cidrs(fields["allowed_networks"]))
        row = self.store.update_security_worker(worker_id, **fields)
        return self._public_worker(row)

    def revoke_worker(self, worker_id: int) -> dict:
        self.require_worker(worker_id)
        self.store.update_security_worker(worker_id, enabled=False, token=None, last_status="revoked")
        return {"detail": "Security worker credentials revoked and worker disabled."}

    def delete_worker(self, worker_id: int) -> bool:
        self.require_worker(worker_id)
        return self.store.delete_security_worker(worker_id)

    def worker_status(self, worker_id: int) -> dict:
        worker = self.require_worker(worker_id)
        if not worker["enabled"] or not worker["token"]:
            return self._record_worker_status(worker, ok=False, detail="Worker is disabled or revoked.")
        try:
            health = self._worker_request(worker, "GET", "/health")
            tools = self._worker_request(worker, "GET", "/tools").get("items", [])
            if not isinstance(tools, list):
                raise ValueError("Worker returned invalid tool inventory.")
            state = {
                "reachable": True,
                "status": "healthy",
                "worker_version": health.get("worker_version"),
                "tools": tools,
                "profiles": health.get("profiles", []),
            }
            self.store.update_security_worker(
                worker_id,
                last_seen_at=utcnow(),
                last_status="healthy",
                last_detail=None,
                worker_version=health.get("worker_version"),
                tools=tools,
            )
            return {**self._public_worker(worker), **state}
        except Exception:
            return self._record_worker_status(worker, ok=False, detail="Worker health check failed.")

    def _record_worker_status(self, worker: dict, *, ok: bool, detail: str) -> dict:
        self.store.update_security_worker(
            worker["id"],
            last_seen_at=utcnow(),
            last_status="healthy" if ok else "unreachable",
            last_detail=detail,
        )
        return {
            **self._public_worker(worker),
            "reachable": ok,
            "status": "healthy" if ok else "unreachable",
            "detail": detail,
            "tools": worker.get("tools") or [],
        }

    def _worker_request(self, worker: dict, method: str, path: str, payload: dict | None = None) -> dict:
        if not worker.get("enabled") or not worker.get("token"):
            raise ValidationError("Security worker is disabled or revoked.")
        base_url = _validate_worker_placement(worker["base_url"], worker["placement"])
        url = base_url.rstrip("/") + path
        with httpx.Client(
            timeout=httpx.Timeout(10.0, connect=4.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.request(
                method,
                url,
                json=payload,
                headers={"Authorization": f"Bearer {worker['token']}", "Accept": "application/json"},
            )
        if response.is_redirect:
            raise ValidationError("Worker redirects are not followed.")
        response.raise_for_status()
        try:
            value = response.json()
        except ValueError:
            raise ValidationError("Worker returned malformed JSON.") from None
        if not isinstance(value, dict):
            raise ValidationError("Worker returned a malformed response.")
        return value

    def _target_is_private(self, value: str) -> bool:
        return any(_is_private_address(address) for address in _resolve_target(value))

    def register_target(
        self,
        *,
        value: str,
        environment: str,
        ownership_confirmed: bool,
        scope: str | None,
        profile: str,
        rate_limit: int | None,
        worker_id: int | None,
        allowed_cidrs: list[str],
        notes: str | None,
        verify_method: str | None,
        actor: dict,
    ) -> dict:
        value = (value or "").strip()
        if not value or len(value) > _MAX_TARGET_BYTES:
            raise ValidationError("Target is required and must be at most 2000 characters.")
        if not ownership_confirmed:
            raise ValidationError("Confirm that you own or are authorized to test this target.")
        profile_obj = get_profile(profile)
        worker = self.require_worker(worker_id) if worker_id is not None else None
        if worker and not worker["enabled"]:
            raise ValidationError("Selected worker is disabled.")
        networks = _parse_cidrs(allowed_cidrs)
        if value.startswith(("http://", "https://")):
            value = validate_web_target(value)
        else:
            try:
                value = str(ipaddress.ip_address(value.strip("[]")))
            except ValueError:
                raise ValidationError("Target must be an HTTP(S) URL or IP address.") from None

        try:
            private = self._target_is_private(value)
        except net_guard.BlockedTargetError:
            # Explicit private-target handling happens below; all other invalid
            # resolutions fail closed.
            private = True

        admin = role_at_least(actor.get("role", Role.VIEWER), Role.ADMINISTRATOR)
        if private:
            if not admin:
                raise ValidationError("Private targets require explicit administrator approval.")
            if not worker:
                raise ValidationError("Private targets require the customer's authorized private worker.")
            if worker["placement"] != "private_network":
                raise ValidationError("Private targets can only be assigned to a private-network worker.")
            worker_networks = _parse_cidrs(worker.get("allowed_networks"))
            if not networks or any(
                not any(net.version == approved.version and net.subnet_of(approved) for approved in worker_networks)
                for net in networks
            ):
                raise ValidationError("Target CIDRs must be contained in the selected worker's approved networks.")
            try:
                addresses = _resolve_target(value, networks)
            except net_guard.BlockedTargetError as exc:
                raise ValidationError(f"Target scope validation failed: {exc}") from None
            _require_addresses_in_scope(addresses, networks)
            verify_method = "admin"
            verify_status = "verified"
            token = None
            verified_at = utcnow()
        else:
            if not value.startswith(("http://", "https://")):
                if not admin:
                    raise ValidationError("Public IP targets require explicit administrator approval.")
                verify_method = "admin"
                verify_status = "verified"
                token = None
                verified_at = utcnow()
            else:
                if verify_method not in {"dns", "http"}:
                    raise ValidationError("Public domain targets require DNS TXT or HTTP challenge verification.")
                token = secrets.token_urlsafe(32)
                verify_status = "pending"
                verified_at = None

        created = self.store.create_security_target(
            value=value,
            kind="url" if value.startswith(("http://", "https://")) else "ip",
            environment=environment,
            ownership_confirmed=True,
            scope=(scope or "").strip()[:2000] or None,
            profile=profile_obj.key,
            rate_limit=rate_limit,
            verify_method=verify_method,
            verify_token=token,
            allowed_cidrs=",".join(str(network) for network in networks) or None,
            worker_id=worker["id"] if worker else None,
            created_by=actor.get("id"),
            notes=(notes or "").strip()[:1000] or None,
        )
        if verify_status == "verified":
            created = self.store.update_security_target(
                created["id"], verify_status="verified", verify_detail="Approved by administrator.", verified_at=verified_at
            )
        return {"target": self._public_target(created), "verification_token": token}

    @staticmethod
    def _public_target(row: dict) -> dict:
        result = dict(row)
        result.pop("verify_token", None)
        return result

    def verify_target(self, target_id: int) -> dict:
        target = self.store.get_security_target(target_id)
        if target is None:
            raise KeyError(f"Security target {target_id} was not found.")
        if target["verify_status"] == "verified":
            return self._public_target(target)
        token = target.get("verify_token")
        if not token:
            raise ValidationError("Target verification challenge is unavailable; re-register the target.")
        try:
            if target["verify_method"] == "dns":
                ok, detail = self._verify_dns(target["value"], token)
            elif target["verify_method"] == "http":
                ok, detail = self._verify_http(target["value"], token)
            else:
                raise ValidationError("Unsupported target verification method.")
        except (OSError, net_guard.BlockedTargetError) as exc:
            ok, detail = False, str(exc)
        row = self.store.update_security_target(
            target_id,
            verify_status="verified" if ok else "pending",
            verify_detail=detail[:500],
            verified_at=utcnow() if ok else None,
            verify_token=None if ok else token,
        )
        return self._public_target(row)

    @staticmethod
    def _verify_dns(value: str, token: str) -> tuple[bool, str]:
        try:
            import dns.resolver
        except ImportError:
            raise ValidationError("DNS TXT verification requires dnspython; install the optional DNS verifier dependency.")
        hostname = urlsplit(value).hostname
        if not hostname:
            raise ValidationError("DNS verification requires a public domain.")
        name = f"_vcqa-verification.{hostname}"
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        expected = f"vcqa-verification={token}"
        found = any(expected in b"".join(record.strings).decode("utf-8", "replace") for record in answers)
        return found, "DNS TXT challenge matched." if found else f"Publish TXT {expected!r} at {name}."

    @staticmethod
    def _verify_http(value: str, token: str) -> tuple[bool, str]:
        parts = urlsplit(value)
        origin = f"{parts.scheme}://{parts.netloc}"
        challenge = origin + "/.well-known/vcqa-verification"
        fetcher = HttpFetcher(WebScanLimits(timeout=5, max_requests=1, max_body_bytes=2048, max_redirects=0))
        response = fetcher.get(challenge, follow=False, headers={"Accept": "text/plain"})
        found = response.ok and response.body.decode("utf-8", "replace").strip() == token
        return found, "HTTP challenge matched." if found else "HTTP challenge file is missing or does not match."

    def targets(self) -> list[dict]:
        return [self._public_target(target) for target in self.store.list_security_targets()]

    def require_target(self, target_id: int) -> dict:
        target = self.store.get_security_target(target_id)
        if target is None:
            raise KeyError(f"Security target {target_id} was not found.")
        return target

    def delete_target(self, target_id: int) -> bool:
        self.require_target(target_id)
        return self.store.delete_security_target(target_id)

    def start_scan(
        self,
        *,
        target_id: int,
        profile: str,
        rate_limit: int | None,
        explicit_authorization: bool,
        actor: dict,
        tools_override: list[str] | None = None,
        verification_finding_id: int | None = None,
    ) -> dict:
        target = self.require_target(target_id)
        if not target["ownership_confirmed"] or target["verify_status"] != "verified":
            raise ValidationError("Target ownership/scope must be verified before scanning.")
        profile_obj = get_profile(profile)
        if profile_obj.requires_explicit_authorization and not explicit_authorization:
            raise ValidationError(f"{profile_obj.name} requires an additional explicit authorization.")
        if target["environment"] == "production" and profile_obj.requires_explicit_authorization:
            raise ValidationError("Comprehensive scans are disabled for production targets.")
        worker_id = target.get("worker_id")
        if worker_id is None:
            raise ValidationError("No security worker is assigned to this authorized target.")
        worker = self.require_worker(worker_id)
        if not worker["enabled"] or not worker["token"]:
            raise ValidationError("Assigned security worker is disabled or revoked.")
        networks = _parse_cidrs(target.get("allowed_cidrs"))
        try:
            resolved = _resolve_target(target["value"], networks)
        except net_guard.BlockedTargetError as exc:
            raise ValidationError(f"Target failed network policy validation: {exc}") from None
        worker_networks = _parse_cidrs(worker.get("allowed_networks"))
        is_private = any(_is_private_address(address) for address in resolved)
        if is_private:
            _require_addresses_in_scope(resolved, networks)
        if is_private and (
            worker["placement"] != "private_network"
            or not networks
            or any(not any(net.version == allowed.version and net.subnet_of(allowed) for allowed in worker_networks) for net in networks)
        ):
            raise ValidationError("Private scan target is outside the worker's administrator-approved CIDR scope.")
        rate = rate_limit or target.get("rate_limit") or profile_obj.default_rate
        if not 1 <= int(rate) <= profile_obj.max_rate:
            raise ValidationError(f"Rate limit for {profile_obj.name} must be between 1 and {profile_obj.max_rate}.")
        tools = list(profile_obj.tools)
        if tools_override is not None:
            if not tools_override or any(tool not in profile_obj.tools for tool in tools_override):
                raise ValidationError("Verification tools must be selected from the original scan profile.")
            tools = list(dict.fromkeys(tools_override))
        job = self.store.create_security_job(
            target_id=target_id,
            worker_id=worker_id,
            profile=profile_obj.key,
            tools=tools,
            actor=actor.get("username"),
        )
        if verification_finding_id is not None:
            self.store.set_security_finding_verification(
                verification_finding_id, "pending", verification_job_id=job["id"]
            )
        with self._lock:
            self._submitted.add(job["id"])
        self._pool.submit(
            self._run_job, job["id"], target, worker, profile_obj, int(rate), networks, tools
        )
        return job

    def _run_job(
        self,
        job_id: int,
        target: dict,
        worker: dict,
        profile,
        rate: int,
        networks: tuple,
        tools: list[str],
    ) -> None:
        self.store.update_security_job(job_id, status="running", started_at=utcnow())
        try:
            current = self.store.get_security_job(job_id)
            if current and current.get("cancel_requested"):
                self.store.update_security_job(job_id, status="cancelled", completed_at=utcnow())
                self._finalize_verifications(job_id, "cancelled")
                return
            remote = self._worker_request(
                worker,
                "POST",
                "/jobs",
                {
                    "profile": profile.key,
                    "tools": tools,
                    "target": target["value"],
                    "rate_limit": rate,
                    "intrusive": False,
                    "authorized_cidrs": [str(network) for network in networks],
                },
            )
            remote_id = str(remote.get("id") or "")
            if not remote_id:
                raise ValidationError("Worker did not return a job id.")
            self.store.update_security_job(job_id, remote_job_id=remote_id, status="running")
            deadline = time.monotonic() + 3600
            while time.monotonic() < deadline:
                current = self.store.get_security_job(job_id)
                if current and current.get("cancel_requested"):
                    try:
                        self._worker_request(worker, "POST", f"/jobs/{remote_id}/cancel")
                    except Exception:
                        pass
                result = self._worker_request(worker, "GET", f"/jobs/{remote_id}")
                status = result.get("status")
                if status in _TERMINAL:
                    self._persist_result(job_id, target, result)
                    self.store.update_security_job(
                        job_id,
                        status=status,
                        completed_at=utcnow(),
                        findings_count=min(len(result.get("findings") or []), _MAX_FINDINGS_PER_JOB),
                        tools=result.get("tools") or {},
                        error=result.get("error"),
                    )
                    self._finalize_verifications(job_id, status)
                    return
                time.sleep(1)
            raise TimeoutError("Security worker job exceeded the orchestration deadline.")
        except Exception:
            self.store.update_security_job(
                job_id,
                status="failed",
                completed_at=utcnow(),
                error="Security worker job failed or became unreachable.",
            )
            self._finalize_verifications(job_id, "failed")
        finally:
            with self._lock:
                self._submitted.discard(job_id)

    def _persist_result(self, job_id: int, target: dict, result: dict) -> None:
        rows = result.get("findings")
        if not isinstance(rows, list):
            rows = []
        for raw in rows[:_MAX_FINDINGS_PER_JOB]:
            if not isinstance(raw, dict):
                continue
            try:
                normalized = Finding(
                    tool=str(raw.get("tool") or "unknown")[:80],
                    tool_version=str(raw.get("tool_version") or "")[:250] or None,
                    target=target["value"],
                    endpoint=str(raw.get("endpoint") or "")[:500] or None,
                    title=str(raw.get("title") or "Unnamed finding")[:300],
                    category=str(raw.get("category") or "general")[:120],
                    description=str(raw.get("description") or "")[:4000] or None,
                    severity=str(raw.get("severity") or "info"),
                    confidence=str(raw.get("confidence") or "medium"),
                    evidence=str(raw.get("evidence") or "")[:8000] or None,
                    remediation=str(raw.get("remediation") or "")[:4000] or None,
                    references=raw.get("references") if isinstance(raw.get("references"), list) else [],
                    detected_at=str(raw.get("detected_at") or utcnow())[:40],
                )
            except Exception:
                continue
            finding, _created = self.store.upsert_security_finding(
                job_id=job_id,
                target_id=target["id"],
                fingerprint=normalized.fingerprint,
                dedupe_key=normalized.dedupe_key,
                tool=normalized.tool,
                tool_version=normalized.tool_version,
                target=normalized.target,
                endpoint=normalized.endpoint,
                title=normalized.title,
                category=normalized.category,
                description=normalized.description,
                severity=normalized.severity,
                confidence=normalized.confidence,
                evidence=normalized.evidence,
                remediation=normalized.remediation,
                references=normalized.references,
                detected_at=normalized.detected_at,
            )
        artifacts = result.get("evidence")
        if isinstance(artifacts, dict):
            total = 0
            for tool, content in artifacts.items():
                if not isinstance(content, str) or total >= _MAX_EVIDENCE_BYTES:
                    continue
                limited = content[:_MAX_EVIDENCE_BYTES - total]
                total += len(limited.encode("utf-8", "replace"))
                self.store.add_security_evidence(
                    job_id=job_id,
                    finding_id=None,
                    tool=str(tool)[:80],
                    content=limited,
                    kind="raw",
                )

    def jobs(self, *, status: str | None = None, target_id: int | None = None, limit: int = 100, offset: int = 0):
        return self.store.list_security_jobs(status=status, target_id=target_id, limit=limit, offset=offset)

    def require_job(self, job_id: int) -> dict:
        job = self.store.get_security_job(job_id)
        if job is None:
            raise KeyError(f"Security job {job_id} was not found.")
        return job

    def cancel_job(self, job_id: int) -> dict:
        job = self.require_job(job_id)
        if job["status"] in _TERMINAL:
            raise ValidationError("Security job is already in a terminal state.")
        self.store.update_security_job(job_id, cancel_requested=True, message="Cancellation requested.")
        return self.store.get_security_job(job_id)

    def findings(self, **filters):
        return self.store.list_security_findings(**filters)

    def severity_counts(self, target_id: int | None = None) -> dict[str, int]:
        if target_id is not None:
            self.require_target(target_id)
        return self.store.security_severity_counts(target_id)

    def require_finding(self, finding_id: int) -> dict:
        finding = self.store.get_security_finding(finding_id)
        if finding is None:
            raise KeyError(f"Security finding {finding_id} was not found.")
        return finding

    def set_finding_status(self, finding_id: int, status: str) -> dict:
        if status not in {"open", "reviewed", "resolved", "dismissed"}:
            raise ValidationError("Unsupported security finding status.")
        self.require_finding(finding_id)
        return self.store.set_security_finding_status(finding_id, status)

    def verify_finding(self, finding_id: int, actor: dict) -> dict:
        finding = self.require_finding(finding_id)
        target = self.require_target(finding["target_id"])
        job = self.require_job(finding["job_id"])
        if job["status"] != "completed":
            raise ValidationError("Only findings from completed deterministic scans can be verified.")
        # Re-run the profile that originally detected the finding. A future
        # version will scope this to just the original tool/check.
        if job["profile"] == "comprehensive":
            raise ValidationError("For a comprehensive scan, start a separately authorized safe profile to verify this finding.")
        verification = self.start_scan(
            target_id=target["id"],
            profile=job["profile"],
            rate_limit=target.get("rate_limit"),
            explicit_authorization=False,
            actor=actor,
            tools_override=[finding["tool"]],
            verification_finding_id=finding_id,
        )
        return {
            "finding": self.require_finding(finding_id),
            "verification_job_id": verification["id"],
            "status": "pending",
        }

    def evidence(self, *, job_id: int | None = None, finding_id: int | None = None, limit: int = 100):
        return self.store.list_security_evidence(job_id=job_id, finding_id=finding_id, limit=limit)

    def require_evidence(self, evidence_id: int) -> dict:
        item = self.store.get_security_evidence(evidence_id)
        if item is None:
            raise KeyError(f"Security evidence {evidence_id} was not found.")
        return item

    def report(self, *, target_id: int | None = None) -> dict:
        target = self.require_target(target_id) if target_id is not None else None
        findings, total = self.store.list_security_findings(target_id=target_id, limit=5000)
        jobs, job_count = self.store.list_security_jobs(target_id=target_id, limit=500)
        return {
            "generated_at": utcnow(),
            "target": self._public_target(target) if target else None,
            "summary": self.store.security_severity_counts(target_id),
            "finding_count": total,
            "job_count": job_count,
            "findings": findings,
            "jobs": jobs,
        }

    def _finalize_verifications(self, job_id: int, status: str) -> None:
        linked, _ = self.store.list_security_findings(
            verification_job_id=job_id, limit=_MAX_FINDINGS_PER_JOB
        )
        if not linked:
            return
        observed, _ = self.store.list_security_findings(
            job_id=job_id, limit=_MAX_FINDINGS_PER_JOB
        )
        observed_keys = {row["dedupe_key"] for row in observed}
        for finding in linked:
            outcome = (
                "verified"
                if status == "completed" and finding["dedupe_key"] not in observed_keys
                else "still_present" if status == "completed" else "inconclusive"
            )
            self.store.set_security_finding_verification(
                finding["id"], outcome, verification_job_id=job_id
            )


__all__ = ["SecurityLabService"]
