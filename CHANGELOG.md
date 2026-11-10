# Changelog

All notable changes to the Vibe Coding QA engine are documented here.

## [0.5.1] - 2026-11-10

### Dashboard

- Added a cinematic boot splash: the Mario/Luigi mascots reveal with a spinning halo and a light glint before the dashboard loads. It plays on each app open, is dismissible, and respects `prefers-reduced-motion`.
- Packaged for pip/pipx: `pipx install vibe-coding-qa` then run `vibe-coding-qa` to launch the local dashboard (the frontend ships prebuilt, so no Node is needed). The database defaults to a per-user location (`~/.vibe-coding-qa`); added a browser-opening launcher and a `vcqa` CLI entry point.
- Refreshed the interface: indigo/violet accent, restyled buttons with hover lift and glow, deeper cards, a circular Mario/Luigi logo, and a draggable "Ask AI" launcher.
- Performance: the repository profile is persisted at scan time and cached, so the Architecture and Dependencies pages load instantly instead of re-walking the working tree on every request.

## [0.5.0] - 2026-11-08

### Dashboard

- Added an optional FastAPI and SQLite dashboard backend that reuses the existing Python scan engine, persists scan history, exposes OpenAPI documentation, and streams actual scan events over SSE.
- Added a React, TypeScript, Vite, Tailwind, and Recharts frontend with repository management, overview analytics, scan workflows and comparisons, finding triage/details, architecture and dependency views, AI assistance, remediation review, reports, and settings.
- Added named scan profiles that select real scanner modules and release-gate score thresholds. The dashboard keeps the deterministic engine authoritative and requires explicit permission before test execution.
- Added optional dashboard dependency instructions, backend API integration coverage in CI, and frontend type-check, lint, and production-build jobs.
- Kept AI credentials in backend environment variables, restricted default API binding and CORS to loopback, validated repository sources and file paths, and made patch application explicit with backup and guarded rollback.

### Notes and limitations

- The dashboard has no authentication and must remain local. GitHub pull-request/CI integration, SARIF export, server-side PDF output, and verified post-patch rescans are not included in this release.
- Docker integration behavior still requires a successful run of the dedicated CI job; local test execution was not part of this change's verification.

## [0.4.0] - 2026-11-08

Production reliability and security upgrade.

### Security

- **Secret detection no longer suppresses real credentials.** The synthetic-credential check now inspects only the matched credential value instead of the whole line, so real secrets are still reported inside test, fixture, mock, and example files, and when assigned to variables such as `TEST_API_KEY`. Private keys are always reported; only genuine placeholders (for example `your-api-key-here`) are suppressed.
- Test execution mounts a secret-filtered snapshot **read-only** and runs inside an isolated, size-bounded writable workspace, so the audited repository is never modified.

### Test verification and release gate

- Test results are now classified by parsing runner output (unittest, pytest, Jest, Vitest) and counting discovered/executed/passed/failed/skipped/errored tests. A zero exit code alone never yields `PASS`.
- Rules: at least one test executed with no failures and exit code 0 → `PASS`; any failure → `FAIL`; all skipped, zero discovered, unrecognized output, or unavailable infrastructure → `NOT VERIFIED`; timeout or exceeded output/resource limits → `FAIL`.
- The CLI, release gate, and Markdown/JSON/HTML reports share the same authoritative decision.
- Fixes are verified against a fresh post-fix scan. A finding is `resolved` only when the rule no longer appears for that file; line-number shifts or file edits are never treated as resolution. Multiple occurrences are counted so partial fixes are reported as `partially_resolved`, and a failing test suite marks all applied fixes `unverifiable`.

### Docker isolation and dependency preparation

- Workspace redesign: the snapshot is bind-mounted at `/vcqa-src` (read-only) and copied into a bounded writable tmpfs `/workspace`; the container root filesystem remains read-only and the network is disabled. The snapshot is cleaned up on all paths.
- Dependency preparation is documented. The engine never installs packages or pulls images; a missing dependency produces a `NOT VERIFIED` result instead of a misleading `PASS`. A locally prepared custom image can be selected with `--test-image`.

### Dependency vulnerability detection

- Replaced exact-version lists with accurate version-range matching, correcting jQuery: 3.5.0/3.5.1 are no longer flagged while older affected versions still are.
- OSV lookups are bounded (concurrency and request timeouts), run under a global time budget, use a process-level TTL cache, cover transitive/resolved lockfile dependencies, and deduplicate results.
- Failed, skipped, or budget-exceeded lookups are reported as incomplete coverage and never turned into a clean result.

### Repository scanning

- Added a shared repository file walker that respects `.vcqaignore` and prunes generated/vendored directories (`.git`, `node_modules`, virtualenvs, caches, `dist`, `build`, `coverage`, and others). Language, framework, and test detection reuse it, so generated code is not counted and dependency directories are not scanned. Symbolic links are not followed and traversal never escapes the repository. Completeness impact is reported when exclusions apply.
- Database RLS analysis uses identifier-aware matching for schema-qualified and quoted names, `CREATE/ALTER/DROP TABLE`, `ENABLE/DISABLE/FORCE ROW LEVEL SECURITY`, `CREATE/DROP POLICY`, policy roles, `USING`, and `WITH CHECK`. It explicitly discloses that it is a conservative heuristic rather than a full PostgreSQL parser, records coverage limitations for dynamic SQL, and uses optional `pglast` when available.

### CI

- Added a `docker-integration` CI job that runs real containers through the production code path (network isolation, read-only input mount, writable workspace, resource limits, timeout, environment non-inheritance, secret redaction, and pass/fail/not-verified classification). It fails when Docker is expected but unavailable. The unittest matrix (Python 3.10/3.11/3.12) remains and does not require Docker.

### Documentation

- README updated: removed the outdated claim that secret detection skips test/fixture files; documented test status classification, the Docker workspace design, dependency preparation, supported runners, limitations, and recommended branch-protection settings.
- Added workspace resource-limit CLI options to the `fix` command.

## [0.3.0]

- Prior release. See repository history for details.
