# Full Lifecycle and Pre-Launch Reference

Use this checklist selectively according to the project’s stack, data, users, and deployment. Mark each item **verified**, **failed**, **not applicable**, or **blocked**. Record evidence, owner, and remediation; do not assume that absence of evidence means a pass.

## A. Lifecycle checkpoints

### Blueprint

- Define users, critical workflows, data classes, trust boundaries, external services, and deployment constraints.
- Map routes, services, database tables, roles, privileged actions, and data flows.
- Agree on architecture, design tokens, accessible component conventions, test/build commands, and measurable acceptance criteria.
- Keep durable decisions in the project’s established memory file; use clean git checkpoints after meaningful security changes. Never discard uncommitted user work.

### Prototype

- Compose UI from the project’s tokens and accessible primitives.
- Test responsive layouts, keyboard/focus states, theme variants, loading/error/empty/success transitions, and representative user journeys.
- Clearly distinguish mock data and preview-only utilities from production functionality.

### Hardening

- Add typed, schema-validated server boundaries; do not trust browser validation, hidden UI controls, or client role fields.
- Review authentication and authorization at every route and data access boundary.
- Verify database permissions and RLS policies with multiple identities, including anonymous, owner, and non-owner accounts.
- Inspect dependency/security checks, logs, output bundles, configuration, and integration cost controls.

### Release

- Run clean production build and the repository’s applicable static checks and tests.
- Verify production-domain TLS, response headers, DNS, email authentication, cache behavior, redirects, and monitoring on the real platform.
- Confirm migration/rollback and incident-response ownership for material data or infrastructure changes.
- Document outstanding risks and obtain the appropriate human sign-off before deployment.

## B. Seven risk areas

| Risk | Verification | Typical control |
| --- | --- | --- |
| Missing or permissive database RLS | Enumerate tables/views/functions and grants; query directly as anonymous, ordinary user, owner, and privileged role. Test cross-tenant reads and writes. | Enable RLS where supported; least-privilege grants; explicit ownership/tenant predicates; deny-by-default policies. Check views, functions, storage buckets, and service-role bypasses too. |
| Client-editable role or privilege attributes | Change role, tenant, price, account status, or moderation fields in a forged request. | Assign sensitive attributes only through trusted server-side administration; whitelist mutable fields; re-check authorization on every operation. |
| Exposed secrets | Search source and built assets; inspect client environment prefixes, source maps, logs, and responses. Rotate any credential confirmed exposed. | Keep private keys on server-side secret stores; expose only intentionally public tokens; scope and rotate credentials. Never paste secrets into audit output. |
| Unbounded spend or abuse | Identify costly endpoints and provider calls; test repeated requests and concurrency using safe limits. | Server-side per-identity/IP rate limits as appropriate, quotas, timeouts, request-size limits, idempotency where needed, alerts, and provider spending limits. IP-only controls are insufficient for authenticated abuse. |
| Unsafe state-changing endpoints | Enumerate POST/PUT/PATCH/DELETE and webhook handlers; test invalid, oversized, replayed, and cross-origin requests. | Server-side schema validation; authorization; safe output encoding; CSRF defenses for cookie-authenticated browsers; webhook signature verification and replay protection. |
| Anonymous or weakly authorized backend execution | Call private handlers without credentials and with expired/low-privilege credentials. | Central authentication middleware plus per-resource authorization. Keep intentionally public routes narrow, bounded, and documented. |
| Security regressions | Review patch history and CI; verify protections survive refactors and generated code changes. | Small git checkpoints, regression tests, code review, dependency and secret scanning, and CI release gates. A checkpoint alone does not prevent regressions. |

## C. Access, API, and database verification

- Build an endpoint/data-operation inventory with required identity, role, ownership scope, allowed fields, and expected status for anonymous and authenticated requests.
- Test direct requests independently of the browser UI. Include cross-user and cross-tenant access, forged owner IDs, role escalation, mass assignment, stale sessions, and invalid inputs.
- Validate schema on the server, cap payload sizes, handle parser/database/provider errors safely, and avoid returning sensitive fields by default.
- Use parameterized queries or safe ORM APIs; review dynamic SQL, template rendering, file paths, redirects, upload type/size, and output encoding.
- For PostgreSQL/Supabase, inspect table RLS, policies, grants, `SECURITY DEFINER` functions, views, storage policies, and service-role usage. Confirm the app does not depend on a privileged key from the browser.
- For payment, messaging, AI, or other billable APIs, combine authentication/authorization with limits, timeouts, spend alerts, and abuse monitoring.

## D. Transport and response headers

Apply controls at the actual ingress/application platform and verify them against live responses. Use current platform guidance and avoid conflicting duplicate headers.

- HTTPS only in production; allow modern TLS (normally TLS 1.2/1.3) and disable obsolete protocols. Validate certificates, renewal, redirects, and relevant subdomains.
- Consider HSTS only after confirming HTTPS coverage for every included subdomain. `includeSubDomains` and preload create operational commitments; do not copy blindly.
- Set a Content Security Policy tailored to actual scripts, styles, images, connections, frames, and nonce/hash strategy. Do not claim a strict CSP while allowing broad unsafe directives.
- Set `X-Content-Type-Options: nosniff` and an intentional `Referrer-Policy`; use `frame-ancestors` in CSP and/or `X-Frame-Options` for older clients.
- Use a restrictive `Permissions-Policy` matching product needs. Do not break required camera, microphone, location, or payment features.
- Evaluate secure cache policy for authenticated or sensitive responses, secure cookie attributes, CORS allowlists, and error-page behavior.
- Treat scanner grades as evidence only for the scanned host/configuration and timestamp, not as proof that the application is secure.

A reverse-proxy TLS snippet is platform-specific. If Nginx is actually used, configure certificate paths, supported TLS versions, cipher policy, session settings, OCSP/resolver behavior, and HSTS using current Nginx and platform documentation; test configuration before reload. Never copy sample domains, resolver settings, or preload directives unchanged into production.

## E. Authentication, sessions, and CSRF

- Use a maintained identity/session library where possible. Select assurance and MFA requirements based on account impact and current NIST guidance; do not treat an old AAL summary as a universal product requirement.
- Store passwords only through a reputable password-hashing implementation with per-password salts and suitable current work factors; never use reversible encryption or a fast general-purpose hash. Follow the current password policy standard for length, blocklists, and MFA rather than imposing arbitrary composition or periodic-change rules.
- Generate session identifiers with a CSPRNG using the framework’s secure defaults. Regenerate after login or privilege changes, expire appropriately, and revoke server-side on logout and relevant account events.
- For cookies, prefer `Secure`, `HttpOnly`, an appropriate `SameSite` value, narrow scope, and short practical lifetime. Consider the `__Host-` prefix where its constraints fit. Never store bearer session secrets in local storage.
- For cookie-authenticated state-changing requests, choose an appropriate CSRF defense: synchronizer token or correctly implemented signed double-submit, plus origin/fetch-metadata checks where suitable. SameSite and custom headers are defense-in-depth, not an excuse to skip threat analysis.
- Restrict CORS to required origins and methods. CORS is not authentication and does not prevent non-browser clients from calling an endpoint.
- Test logout, token expiry/revocation, session fixation, account recovery, MFA reset, and role changes.

## F. Build hygiene and performance

- Run the production build and inspect assets/source maps for private values, test credentials, debug overlays, preview-only code, and unnecessary diagnostics.
- Disable or remove noisy debug output through framework/compiler production settings while preserving appropriate error reporting and telemetry. Do not strip all warnings/errors without evaluating operational impact.
- Use code splitting, tree-shaking, compression, caching, and image/font optimization based on the actual stack and measurements.
- Measure Core Web Vitals using field data when available. INP below 200 ms is a “good” target at the 75th percentile, not a guarantee for every interaction or a substitute for measurement.
- Prioritize perceived responsiveness: render immediate loading/optimistic states safely, minimize long main-thread work, break up expensive tasks, and use supported scheduling APIs with fallbacks only when profiling supports it.
- Test critical flows on representative mobile devices/network conditions; monitor regressions after release.

## G. Email and messaging

- Configure SPF, DKIM, and DMARC for the actual sender domains; verify alignment and monitor reports. Move to an enforcement policy deliberately after validating legitimate senders.
- Apply bulk-sender and provider rules to the message category and jurisdictions involved. RFC 8058 one-click headers are required for certain subscription/marketing mail under applicable sender/provider rules; do not assume every transactional message has the same requirement.
- Where one-click unsubscribe applies, use HTTPS `List-Unsubscribe` and `List-Unsubscribe-Post` headers and a signed/opaque recipient token. Accept the specified POST without login or an intervening confirmation; suppress future applicable mail promptly and return the required successful response. Prevent token enumeration and unsubscribe CSRF/replay issues.
- Verify bounce/complaint handling, suppression lists, sender reputation, templates, and unsubscribe behavior using test addresses before sending real campaigns.
- For SMS, verify provider and regulator rules, sender-ID registration, consent, message purpose, and localized opt-out handling. Ensure STOP/ONDOA requests enter the suppression workflow and are honored promptly.

## H. Tanzania and localized product checks

Apply this section when the product processes data in Tanzania, targets Tanzanian users, or uses Tanzanian infrastructure. Verify current requirements with the PDPC, TCRA, tzNIC, official legal texts, counsel, and relevant providers; this checklist does not establish legal compliance.

- Identify controller/processor roles, data subjects (including children), purposes, data categories, retention, recipients, processors, hosting locations, and cross-border transfers.
- Verify current PDPA 2022/implementing-rule obligations, registration applicability, lawful basis, notices, data-subject rights, security, retention, breach response, and DPO requirements for the specific organization and processing.
- Obtain clear affirmative consent when consent is the appropriate legal basis. Keep optional purposes separate, unchecked by default, and logged with notice/version, timestamp, channel, and withdrawal history. Avoid collecting unnecessary IP/device identifiers in consent records.
- Minimize children’s data and establish age/guardian processes where required. Confirm safeguards and lawful basis before processing sensitive or student data.
- Review processor agreements, access controls, retention/deletion, backup location, breach escalation, and transfer safeguards.
- For `.tz` domains, verify eligibility/namespace, registrar and registry rules, DNS hosting diversity, DNSSEC delegation/signing, renewal, and account security with current tzNIC/registrar guidance.
- For organization/school sites, use accurate `EducationalOrganization` JSON-LD only when applicable and validate it. Add FAQ structured data only for eligible, visible, genuine FAQ content and current search guidelines.
- Provide tested English and Kiswahili flows where promised; have qualified reviewers check translations, education terms, consent, error states, dates, currencies, and SMS wording.

## I. Launch evidence matrix

| Verification vector | Evidence to capture | Status |
| --- | --- | --- |
| TLS and headers | Live response/header scan, host, date, relevant routes | Not run |
| Access control and RLS | Policy/grant review plus anonymous, owner, non-owner, and admin test results | Not run |
| CSRF and API validation | Tests for missing/invalid token, forged payload, origin, and malformed input | Not run |
| Authentication/session | Cookie inspection, expiry/revocation tests, MFA/recovery review where applicable | Not run |
| Secret boundaries | Secret scan and built asset inspection; do not include secret values | Not run |
| Abuse and cost limits | Endpoint inventory, rate-limit tests, quota/alert configuration | Not run |
| Build and code quality | Exact lint/typecheck/test/build commands and results | Not run |
| Performance/accessibility | Test device/tool/data source, key metrics, keyboard/contrast/responsive results | Not run |
| Email/SMS | DNS/provider verification and safe end-to-end suppression test | Not run |
| Tanzania/privacy/localization | Applicability review, notices/consent/data-flow review, domain/schema/content evidence | Not run |
| Operations | Monitoring, backup/restore, incident owner, migration/rollback plan | Not run |

Replace “Not run” only after performing the applicable check. Record blockers and risk acceptance explicitly; do not label the matrix “verified” by template.