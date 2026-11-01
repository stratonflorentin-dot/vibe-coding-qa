# Vibe Coding QA

<p align="center">
  <img src="phone-mascots.gif" alt="Looping cartoon of Mario and Luigi in red and green outfits" width="560">
</p>

A Claude Code skill and Python engine for taking product ideas and AI-assisted web projects from research to a safer, evidence-based launch. It helps assess product opportunities before building, then **inspect real repositories, run automated security and quality checks, map findings to file and line numbers, suggest or apply fixes, rerun tests, and block release** when critical issues remain.

## Install

Clone this repository and open it in Claude Code; the skill is available at `.claude/skills/vibe-coding-qa/SKILL.md`.

To add it to another project, copy the `vibe-coding-qa` folder into that project's `.claude/skills/` directory.

[Download the skill bundle](https://github.com/stratonflorentin-dot/vibe-coding-qa/raw/refs/heads/main/vibe-coding-qa.zip)

## What it helps with

- **Product intelligence:** research product ideas, markets, competitors, customer pain, feasibility, and MVP strategy before investing in a build.
- **Engineering QA:** clone or point to a repo and scan actual source code for security, quality, database, infrastructure, performance, and compliance issues.
- **File-and-line findings:** every issue includes the file path and line number.
- **Fixes:** preview or apply safe automated fixes (e.g. remove `console.log`, strip `debugger`).
- **Tests:** run the project's own test suite as part of the gate.
- **Release gate:** score the repo 0-100 and exit non-zero when critical findings remain.
- **Framework guidance:** plan features, trust boundaries, authentication, RLS, secrets, input validation, CSRF, API abuse controls, TLS/headers, email/SMS flows, and Tanzania-focused privacy checks.
- **External tools:** optionally integrate Fallow, REA, PentAGI, API Anything, and UI guidance.

## What to expect

It won’t do everything automatically: external tools must be installed and configured, the research command creates a brief rather than conducting live research, and static analysis can only find patterns, not prove runtime behavior. The engine distinguishes high-confidence detections from heuristics and asks a human to verify anything that requires runtime context.

## Automated QA Engine

The new Python engine turns the framework into an actual production-readiness tool. It runs entirely with the Python standard library (no install step beyond Python and `git`).

```bash
# Scan a local repository
python -m vibe_coding_qa.cli scan --repo /path/to/project --output vcqa-reports

# Scan a public GitHub repository
python -m vibe_coding_qa.cli scan --repo stratonflorentin-dot/vibe-coding-qa --output vcqa-reports

# Skip running the project test suite
python -m vibe_coding_qa.cli scan --repo /path/to/project --no-tests --output vcqa-reports

# Preview safe fixes
python -m vibe_coding_qa.cli fix --repo /path/to/project --output vcqa-reports

# Apply safe fixes (review the report first)
python -m vibe_coding_qa.cli fix --repo /path/to/project --apply --output vcqa-reports

# Release gate only (exit 2 if blocked)
python -m vibe_coding_qa.cli gate --repo /path/to/project --output vcqa-reports
```

Reports are written as `vcqa-report.md`, `vcqa-report.json`, and `vcqa-report.html` in the output directory.

### What the engine checks

| Module | Examples |
|--------|----------|
| **Security** | exposed secrets, client-side API keys, `.env` files, insecure eval, wildcard CORS, SQL injection patterns |
| **Quality** | `console.log`, `debugger`, `TODO/FIXME`, `any` types, missing error boundaries |
| **Database** | missing RLS, weak RLS policies, editable role fields, client-side role updates, Supabase query auth review |
| **Infrastructure** | weak TLS, missing HSTS/CSP/X-Frame-Options, Docker `latest` tags |
| **Performance** | blocking handlers, large images, large source files |
| **Compliance** | Tanzania PDPA consent checkboxes, RFC 8058 unsubscribe, TCRA SMS opt-out, DPO/PDPC documentation |

The engine returns a weighted 0-100 score and blocks release when critical findings or failing tests remain.

### Limitations

- Static analysis only: it cannot prove runtime behavior, access control bypasses, or business-logic bugs.
- Pattern-based detection produces false positives and false negatives; treat every finding as a review prompt, not a certification.
- Secret detection skips test/fixture files to reduce noise; manually review those files.
- Compliance checks are heuristics, not legal advice; confirm requirements with official sources and qualified specialists.

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
