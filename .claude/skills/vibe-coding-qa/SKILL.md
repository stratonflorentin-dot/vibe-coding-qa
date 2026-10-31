---
name: vibe-coding-qa
description: "This skill should be used when planning, building, hardening, auditing, or preparing AI-assisted web applications for launch. It covers Claude Code workflows; architecture; deterministic code-quality gates; UI resilience and motion; security and authorized testing; API integrations; evidence-based research; authentication, database RLS, secrets, validation and rate limits; performance; email; and Tanzania-focused privacy, messaging, domain, bilingual, and education checks."
---

# Vibe Coding Lifecycle and Pre-Launch QA

## Purpose

Guide AI-assisted web projects from a clear specification through prototype, deterministic hardening, verification, and an evidence-based go-live decision. Treat generated code as untrusted until inspected and tested. Apply `references/launch-framework.md` for launch audits, `references/work-templates.md` for briefs and verification records, and `references/research-and-advanced-qa.md` for repository intelligence, advanced UI checks, safe security research, API discovery, and bounded agent delegation.

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