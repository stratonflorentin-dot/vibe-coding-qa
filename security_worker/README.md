# Security Worker Deployment

The worker is an optional, separately deployed service. It runs the allowlisted scanner commands; the dashboard API only sends authenticated jobs and stores their results. Never mount the Docker socket into either service.

## Before deployment

- Use Docker Engine with Compose v2 and an administrator-controlled host.
- Decide which exact public domains or private CIDRs are authorized for testing. Private targets require an administrator-approved CIDR and a worker placed inside that network.
- Apply host/cloud firewall egress rules for the worker and ZAP containers. Permit only the approved destination ranges and required DNS; deny cloud metadata, loopback, link-local, and other internal networks. DNS checks in the application are defense in depth, not a substitute for network enforcement.
- For a remote VPS, put the worker behind HTTPS or a private VPN. Never publish its plain HTTP port to the Internet. The bearer token grants scan capability.
- Keep production targets out of comprehensive scans. Start with a staging system you control.

## Start a local worker

From the repository root, create the dedicated Docker network once:

```powershell
docker network create vcqa-security
```

Set strong random secrets in the same PowerShell session used to start Compose. The ZAP key is required by Compose even when its optional profile is disabled:

```powershell
$env:VCQA_WORKER_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:VCQA_ZAP_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:VCQA_SECURITY_NETWORK = 'vcqa-security'
$env:VCQA_WORKER_HOST_PORT = '8765'
```

Build and start the worker:

```powershell
docker compose --profile security-worker -f security_worker/docker-compose.yml up -d --build security-worker
```

The host port is bound to `127.0.0.1` only. When the dashboard API runs directly on this same host, register the worker URL as `http://127.0.0.1:8765`. If the API itself runs in Docker and is attached to the same dedicated network, use `http://security-worker:8765` instead. Do not change the host binding to `0.0.0.0`.

To also run OWASP ZAP's passive scanner:

```powershell
docker compose --profile security-worker --profile zap -f security_worker/docker-compose.yml up -d --build security-worker zap
```

ZAP has no published host port; only the worker can reach it on the Docker network. Its API key is passed internally. The worker only runs the ZAP spider and passive scanner; it does not invoke active scanning.

## Tool availability

The dashboard reports a tool as available only after the worker verifies its executable and version, or successfully queries ZAP's version endpoint. Missing tools are reported as unavailable, not inferred from the selected image.

Nuclei runs only when an operator supplies an approved templates directory. Review and pin the template source/version before placing YAML templates under `security_worker/nuclei-templates`; the directory is mounted read-only. Do not enable automatic template downloads on the worker. Without approved templates, Nuclei correctly reports unavailable.

The worker image includes Nmap, Nuclei, WhatWeb, and testssl.sh. Other registered tools (including Nikto, SQLmap, and Gobuster) may remain unavailable unless deliberately installed and verified. SQLmap and Gobuster are gated and are not part of the standard scan profiles.

## Register and authorize

1. Sign in as an administrator and open **Security Lab → Worker settings**.
2. Register the worker using the correct URL above and the exact `VCQA_WORKER_TOKEN` value. Choose `Same VPS` for the loopback worker. For a remote worker, use its HTTPS/VPN URL and choose `Remote VPS`. For private targets, choose `Authorized private network` and enter only administrator-approved CIDRs.
3. Use **Check health and tools**. Confirm the reported worker version and actual tool inventory.
4. Register a target you control, select its worker, and confirm the authorization statement. A public domain remains unavailable for scanning until its DNS TXT or HTTP challenge is published and verified. Private IPs/domains require an administrator, the private-network worker, and CIDRs contained in that worker's approved ranges.
5. Begin with the least-impact profile suitable for the target. Comprehensive scans require a second explicit authorization and are disabled for production targets.
6. Review the job status, findings, tool versions, and evidence. Finding verification requires a completed follow-up scan and is inconclusive when the scan fails or is incomplete.

Revoking a worker clears its stored token and disables it. Rotate the worker's `VCQA_WORKER_TOKEN` and register the new credential after a suspected exposure.

## Limits and operations

The container runs as an unprivileged UID with a read-only root filesystem, dropped Linux capabilities, no-new-privileges, bounded CPU, memory, process count, temporary storage, job concurrency, per-tool timeout, and captured output. The dashboard and worker both revalidate target scope. These controls do not make arbitrary Internet egress safe: firewall allowlists remain mandatory, especially because external scanner binaries resolve hostnames when they connect.

Useful checks:

```powershell
docker compose -f security_worker/docker-compose.yml ps
docker compose -f security_worker/docker-compose.yml logs --tail=100 security-worker
docker compose --profile security-worker --profile zap -f security_worker/docker-compose.yml logs --tail=100 zap
```

The worker keeps job state in memory; the dashboard database is authoritative for history and findings. Restarting the worker interrupts active jobs. Rebuild and review the pinned Kali base digest deliberately when updating the image; confirm versions with the authenticated tool inventory before scanning.
