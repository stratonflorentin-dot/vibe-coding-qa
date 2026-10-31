# Vibe Coding QA

<p align="center">
  <img src="phone-mascots.gif" alt="Looping cartoon of two teenagers in colorful streetwear" width="560">
</p>

A Claude Code skill for taking product ideas and AI-assisted web projects from research to a safer, evidence-based launch. It helps assess product opportunities before building, then plan, implement, review, and verify applications without treating a successful build as proof of security or compliance.

## Install

Clone this repository and open it in Claude Code; the skill is available at `.claude/skills/vibe-coding-qa/SKILL.md`.

To add it to another project, copy the `vibe-coding-qa` folder into that project's `.claude/skills/` directory.

[Download the skill bundle](https://github.com/stratonflorentin-dot/vibe-coding-qa/raw/refs/heads/main/vibe-coding-qa.zip)

## What it helps with

- Research product ideas, markets, competitors, customer pain, feasibility, and MVP strategy before investing in a build.
- Plan features, trust boundaries, and acceptance checks before implementation.
- Review code quality with incremental gates, baseline-aware findings, and dry-run fixes.
- Build accessible, responsive interfaces; stress-test realistic edge data and motion.
- Review authentication, authorization, database RLS, secrets, input validation, CSRF, and API abuse controls.
- Integrate APIs with explicit contracts, holdout checks, and guarded read/write behavior.
- Check production builds, performance, TLS and response headers, email/SMS flows, and launch readiness.
- Apply Tanzania-focused privacy, messaging, domain, education-schema, and bilingual-content checks when relevant.

## Included references

- `references/launch-framework.md` — lifecycle, security audit, performance, transport, messaging, and localized pre-launch checks.
- `references/work-templates.md` — feature briefs, trust-boundary inventories, verification matrices, findings, and launch decisions.
- `references/research-and-advanced-qa.md` — source-backed patterns for code-quality tools, safe research, API contracts, UI stress testing, motion, and agent boundaries.
- `references/product-intelligence.md` — market, competitor, customer, failure, business-model, technical, regulatory, and MVP research workflow.
- `references/product-research-report-template.md` — structured, evidence-linked strategy report template.

## Try it

Research modes include **quick scan**, **focused study**, **deep strategy**, and **build blueprint**.

Ask Claude Code to **research this product idea before building**, **compare its competitors and risks**, **turn the findings into an MVP plan**, **threat-model a sign-in flow**, or **prepare an evidence-based pre-launch checklist**.

The skill records what was actually verified and flags unknowns. Its regulatory checklists are not legal advice or compliance certification; confirm current requirements with official sources and qualified specialists.

## Mascot animation

The looping cartoon GIF is generated with Python and Pillow. Recreate it from the repository root with:

```sh
python -m pip install pillow
python scripts/generate_mascots.py
```
