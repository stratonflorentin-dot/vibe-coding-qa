# Vibe Coding Work Templates

Copy only the sections needed for the current task. Replace bracketed prompts with verified project information. Leave unknowns marked unknown; do not turn assumptions into facts.

## 1. Feature brief

```text
Feature:
Problem and intended outcome:
Users and roles:
In-scope behavior:
Out-of-scope behavior:
Data read / written / retained:
Sensitive data, minors, payments, or external providers:
Authentication and authorization rules:
Validation and abuse/cost controls:
Accessibility and responsive acceptance criteria:
Failure, empty, loading, and recovery states:
Deployment / migration constraints:
Acceptance checks:
Open decisions and assumptions:
```

## 2. System and trust-boundary inventory

| Component / route / table | Data or operation | Caller / identity | Trust boundary | Required access rule | Existing evidence / gap |
| --- | --- | --- | --- | --- | --- |
| [name] | [read/write/action] | [anonymous/role/service] | [browser/API/provider] | [rule] | [test, config, unknown] |

Include browser-to-server, server-to-database, server-to-provider, webhook, file storage, admin, and background-job paths when present. Never place credentials or personal data in this inventory.

## 3. Verification matrix

| Scenario | Identity / role | Request or action | Expected result | Actual result / evidence | Status |
| --- | --- | --- | --- | --- | --- |
| Anonymous access | Anonymous | [direct request] | [deny or intentional public response] | [command, test, timestamp] | Not run |
| Own resource | Authenticated owner | [action] | [allow only permitted fields] | [evidence] | Not run |
| Other user's resource | Authenticated non-owner | [forged ID/action] | [deny without leaking data] | [evidence] | Not run |
| Privileged field tampering | Ordinary user | [modify role/tenant/price] | [reject; preserve trusted value] | [evidence] | Not run |
| Invalid / oversized input | Relevant role | [malformed payload] | [safe validation failure] | [evidence] | Not run |
| Repeated costly request | Relevant role | [bounded load] | [limit, timeout, or quota behavior] | [evidence] | Not run |
| CSRF / untrusted origin | Cookie-authenticated | [state-changing request] | [reject according to design] | [evidence] | Not run |

Adapt cases to actual architecture. Do not perform load tests, mutate production data, or exercise a third-party service without authorization and safe limits.

## 4. Security finding

```text
Title:
Severity: Critical / High / Medium / Low
Status: Open / Fixed / Accepted / Not reproducible
Affected component and location:
Preconditions and attacker capability:
Evidence and reproduction (redact secrets and personal data):
Impact:
Root cause:
Recommended remediation:
Regression test:
Owner and target date:
Residual risk / acceptance authority:
```

Use **Critical** for demonstrated severe compromise or broad exposure; **High** for material unauthorized access, privilege escalation, or likely significant impact; **Medium** for bounded but real security impact or meaningful defense gap; **Low** for limited impact or hardening. Explain context and exploitability rather than assigning severity from a label alone. Mark speculative concerns as hypotheses, not findings.

## 5. Change verification record

```text
Change summary:
Files / components / data boundaries affected:
Security properties changed:
Checks actually run (exact command/tool and result):
Checks not run and why:
Build / migration / rollback notes:
Manual browser or API scenarios checked:
Known limitations:
Residual risks and owner:
```

Distinguish tests added from tests run. Report failures and environment limitations accurately; do not say “all tests pass” when only a subset ran.

## 6. Launch decision

```text
Decision: Not ready / Ready with accepted risks / Ready
Release and environment reviewed:
Critical / High findings remaining:
Required checks completed and evidence locations:
Blocked or not-applicable checks with rationale:
Data migration, backups, restore, rollback:
Monitoring, alerting, and incident owner:
Accepted residual risks (risk owner and approval):
Approver and date:
```

Treat unresolved critical findings, unverified production access boundaries, exposed credentials, or missing rollback for a risky migration as launch blockers unless an authorized owner explicitly accepts a lawful and documented exception. Do not make the release decision on behalf of the accountable organization.