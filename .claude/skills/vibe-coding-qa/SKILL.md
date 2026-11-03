---
name: vibe-coding-qa
description: "This skill should be used when researching, planning, building, hardening, auditing, or preparing AI-assisted web products for launch. It covers Claude Code, global product and competitor research, feasibility and MVP strategy, software architecture, deterministic code-quality gates, UI resilience and motion, authorized security research, API integrations, authentication, database RLS, secrets, validation, rate limits, performance, email, and Tanzania-focused privacy and market checks."
---

# Vibe Coding Lifecycle and Pre-Launch QA

## Purpose

Guide AI-assisted web projects from idea and product research through specification, prototype, deterministic hardening, verification, and an evidence-based go-live decision. Treat generated code and external research claims as untrusted until inspected and sourced. For pre-build market and product strategy, use `references/product-intelligence.md` and its report template; for codebase research and advanced QA, use `references/research-and-advanced-qa.md`; for implementation and launch, use `references/launch-framework.md` and `references/work-templates.md`.

## Operating Rules

- Inspect the repository, applicable `CLAUDE.md`/`AGENTS.md`, package scripts, architecture, and current git status before proposing or changing code. Follow repository instructions and established patterns.
- Separate verified facts, assumptions, and recommendations. Never claim a scanner grade, compliance status, test result, or deployment check without actually running it and recording the evidence.
- Prefer small, reviewable changes. Use planning mode for broad or high-impact work; resolve requirements that materially affect architecture, data, security, or compliance before implementation.
- Keep project decisions in repository documentation when requested or useful. Do not overwrite existing project guidance or security controls without reviewing them.
- Use stronger reasoning for architecture, schema, security, and difficult diagnosis; reserve rapid iteration for bounded, reversible UI work.
- Do not expose, print, commit, or transmit secrets. Do not run destructive migrations, change live infrastructure, publish, or send real messages without explicit authorization.
- Treat legal, regulatory, certification, and provider requirements as matters to verify against current primary sources and qualified specialists. A technical checklist is not a legal opinion or certification.
- Never add consent preselected by default. Collect only necessary personal data, make purposes and choices clear, and distinguish consent from other lawful bases.

## Workflow

### Product intelligence mode

When a user presents a product idea, design, specification, or market-research question, first extract confirmed requirements, assumptions, and unknowns. Select a quick, focused, deep, or build-blueprint mode in `references/product-intelligence.md`; default to a right-sized research scope, cite important claims, and keep research separate from implementation approval. Do not force market research onto a direct coding request that does not need it.

### 1. Establish scope and blueprint

1. Identify the product, users, data types, trust boundaries, critical flows, deployment target, and launch criteria.
2. Ask focused questions when a missing decision changes access control, data location, consent, payments, authentication, or irreversible behavior. Otherwise state a conservative assumption and proceed.
3. Map routes, components, services, database entities, external providers, and privileged operations. Identify sensitive data, minors, roles, and money-related actions.
4. Record architecture, stack, design tokens, state-management conventions, testing commands, and prohibited patterns in the project’s existing memory/documentation convention.
5. Define acceptance checks before implementation, including unauthenticated and authenticated behavior and mobile/responsive states.

### 2. Prototype with constraints

1. Reuse the established component library and design tokens. Avoid arbitrary inline styles and one-off visual patterns where project conventions exist.
2. Build accessible, semantic components with keyboard support, visible focus, suitable contrast, responsive layouts, and explicit loading, empty, error, and success states.
3. Verify important screens and transitions in the available preview/browser or test environment, including narrow layouts and theme variants where supported.
4. Keep prototype-only mock data, overlays, and diagnostics clearly separated from production paths.

### 3. Refactor and harden

1. Follow the existing language and framework. Prefer typed, validated boundaries over broad casts, untrusted `any`, or assumptions about request data.
2. Validate and normalize all untrusted input on the server before authorization-sensitive processing or database writes. Return safe errors and avoid leaking internals.
3. Trace every route and data operation through authentication, authorization, ownership checks, validation, CSRF/origin protection where applicable, and rate/cost controls.
4. Review database grants and policies; verify access with realistic roles and direct API requests, not only the UI. Make privileged fields server-controlled.
5. Search for secrets in source, configuration, build output, logs, and history as appropriate. Keep private credentials server-side; distinguish publishable client keys from secrets.
6. Add or use targeted tests and static/security checks consistent with the repository. Make no claim that an unrun tool or MCP audit passed.

### 4. Optimize, verify, and gate release

1. Run the repository’s targeted lint, typecheck, tests, and production build; then relevant broader checks. Investigate failures rather than suppressing them.
2. Inspect built assets for private credentials, debug overlays, accidental development configuration, and unwanted diagnostics. Remove debug output through framework/build configuration when appropriate, not brittle text replacement.
3. Measure field or lab performance for critical flows where tooling and access permit. Optimize evidenced bottlenecks, especially long main-thread tasks and slow interaction feedback.
4. Verify deployment-specific HTTPS, headers, caching, DNS, and email configuration against the actual hosting platform. Do not apply Nginx settings to a platform that does not use Nginx.
5. Complete the applicable checklist in `references/launch-framework.md`. Mark each item verified, failed, not applicable, or blocked, with evidence and an owner for unresolved risks.
6. Present a concise launch decision: ready, not ready, or ready with explicitly accepted residual risks. Never infer production readiness from a successful local build alone.

### 5. Run the repository auditor when available

1. Use the repository's installed QA engine or invoke `python -m vibe_coding_qa` from its root. Start with `python -m vibe_coding_qa gate --repo .` for a non-executing audit; this must report `NOT VERIFIED` unless project tests were actually run.
2. Do not execute repository test scripts without explicit user permission. With permission, run `python -m vibe_coding_qa gate --repo . --explicit-permission` and configure `--test-timeout`, `--max-memory-mb`, `--max-cpu-seconds`, and `--test-image` when appropriate. Test execution requires a running Docker daemon and a locally available image; the CLI does not pull images or install dependencies.
3. Inspect generated Markdown, JSON, and HTML reports; verify the same authoritative release decision, scanner notes, findings, test state, and coverage gaps appear consistently.
4. Treat static findings as evidence-backed leads, not proof of exploitability or proof of security. Docker test isolation reduces exposure but cannot rule out runtime or kernel vulnerabilities; use a disposable VM for high-risk untrusted projects.
5. Dependency advisory lookups are offline by default. Enable `VCQA_OSV_ENABLED=1` only when network access is appropriate and confirm its coverage notes before interpreting results.

## Security Questions to Always Ask

- Can an unauthenticated user read or mutate data through direct requests?
- Can an authenticated user access another user’s records or change roles/privileges?
- Can a caller bypass client validation by editing the payload?
- Are state-changing routes protected against CSRF or unauthorized cross-origin use where relevant?
- Can repeated or expensive requests create abuse, quota exhaustion, or financial loss?
- Are secrets absent from frontend bundles, browser storage, logs, and responses?
- Do logout, account recovery, and role changes invalidate or re-evaluate active sessions appropriately?

## Deliverable Style

For implementation tasks, make scoped changes and report what changed, what was actually verified, and any material residual risks. For audits, prioritize findings by severity and exploitability; include affected location, evidence, impact, and a concrete remediation. Separate blockers from recommendations and avoid speculative vulnerabilities presented as confirmed facts.

## CLI Tool

The skill includes a Python CLI at `scripts/vibe_coding_qa.py` for programmatic access to workflows and templates.

```bash
# From the skill directory
python scripts/vibe_coding_qa.py --help

# Product research
python scripts/vibe_coding_qa.py research --product "AI code review tool" --mode deep --output research-brief.md

# Pre-launch audit checklists
python scripts/vibe_coding_qa.py audit --checklist launch
python scripts/vibe_coding_qa.py audit --checklist security
python scripts/vibe_coding_qa.py audit --checklist tanzania

# Work templates
python scripts/vibe_coding_qa.py template --type feature-brief
python scripts/vibe_coding_qa.py template --type verification
python scripts/vibe_coding_qa.py template --type finding
python scripts/vibe_coding_qa.py template --type launch-decision

# Install skill into another project
python scripts/vibe_coding_qa.py init --path /path/to/project

# Validate skill structure
python scripts/vibe_coding_qa.py validate
```

The CLI loads reference files from `references/` and can be used independently of the agent skill. It does not perform live web research; it provides the methodology, templates, and checklists for the agent to execute with appropriate tools. For external-tool commands, environment setup, and safety boundaries, follow `scripts/tool-integrations.md`. Optional tools are never silently installed, PentAGI never starts flows through this adapter, REA evidence is written to an explicit file, and API Anything writes require a reviewed dry run plus explicit confirmation.