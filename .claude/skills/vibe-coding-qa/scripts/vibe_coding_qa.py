#!/usr/bin/env python3
"""
Vibe Coding QA - CLI Tool

Provides programmatic access to the skill's workflows:
- Product research and intelligence
- Pre-launch audit checklists
- Security verification matrices
- Work templates for briefs, findings, and launch decisions

Usage:
    python -m vibe_coding_qa --help
    python -m vibe_coding_qa research --product "AI code review tool" --mode deep
    python -m vibe_coding_qa audit --checklist launch
    python -m vibe_coding_qa template --type feature-brief
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

SKILL_ROOT = Path(__file__).parent.parent
REFERENCES = SKILL_ROOT / "references"


def load_reference(name: str) -> str:
    """Load a reference file from the skill's references directory."""
    path = REFERENCES / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return f"Reference file not found: {name}"


def cmd_research(args: argparse.Namespace) -> int:
    """Run product intelligence research workflow."""
    print(f"Product Research Mode: {args.mode}")
    print(f"Product: {args.product}")
    if args.markets:
        print(f"Target markets: {args.markets}")
    if args.output:
        print(f"Output: {args.output}")

    # Load the research methodology
    methodology = load_reference("product-intelligence.md")
    template = load_reference("product-research-report-template.md")

    if args.mode == "quick":
        print("\n=== QUICK SCAN MODE ===")
        print("Sections: Product understanding, 3-5 analogues, key risks, next validation step")
    elif args.mode == "focused":
        print("\n=== FOCUSED STUDY MODE ===")
        print("Sections: Named markets/competitors, customer problems, business model, technical feasibility")
    elif args.mode == "deep":
        print("\n=== DEEP STRATEGY MODE ===")
        print("Sections: Full market, competitor, failure, customer, commercial, technical, regulatory, roadmap")
    elif args.mode == "blueprint":
        print("\n=== BUILD BLUEPRINT MODE ===")
        print("Sections: MVP scope, architecture, roadmap, validation plan, go/revise/no-go")

    if args.template:
        print("\n--- Report Template ---")
        print(template[:2000] + "..." if len(template) > 2000 else template)

    if args.methodology:
        print("\n--- Methodology ---")
        print(methodology[:2000] + "..." if len(methodology) > 2000 else methodology)

    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Run pre-launch audit checklist."""
    print(f"Audit Checklist: {args.checklist}")

    framework = load_reference("launch-framework.md")

    if args.checklist == "launch":
        print("\n=== PRE-LAUNCH EVIDENCE MATRIX ===")
        # Extract the matrix section
        lines = framework.split("\n")
        in_matrix = False
        for line in lines:
            if "Launch evidence matrix" in line or "Verification vector" in line:
                in_matrix = True
            if in_matrix:
                print(line)
    elif args.checklist == "security":
        print("\n=== SEVEN RISK AREAS ===")
        lines = framework.split("\n")
        in_section = False
        for line in lines:
            if "Seven risk areas" in line or "Risk | Verification" in line:
                in_section = True
            if in_section and line.startswith("## ") and "Seven risk areas" not in line:
                break
            if in_section:
                print(line)
    elif args.checklist == "tanzania":
        print("\n=== TANZANIA COMPLIANCE ===")
        lines = framework.split("\n")
        in_section = False
        for line in lines:
            if "Tanzania" in line and "checks" in line.lower():
                in_section = True
            if in_section and line.startswith("## ") and "Tanzania" not in line:
                break
            if in_section:
                print(line)
    elif args.checklist == "all":
        print(framework)

    return 0


def cmd_template(args: argparse.Namespace) -> int:
    """Output a work template."""
    templates = load_reference("work-templates.md")

    if args.type == "all":
        print(templates)
        return 0

    # Extract specific template section
    sections = {
        "feature-brief": "## 1. Feature brief",
        "inventory": "## 2. System and trust-boundary inventory",
        "verification": "## 3. Verification matrix",
        "finding": "## 4. Security finding",
        "change-record": "## 5. Change verification record",
        "launch-decision": "## 6. Launch decision",
    }

    if args.type not in sections:
        print(f"Unknown template type: {args.type}")
        print(f"Available: {', '.join(sections.keys())}, all")
        return 1

    header = sections[args.type]
    lines = templates.split("\n")
    in_section = False
    output = []

    for line in lines:
        if line.startswith(header):
            in_section = True
        elif in_section and line.startswith("## ") and line != header:
            break
        if in_section:
            output.append(line)

    print("\n".join(output))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize skill files in a project."""
    target = Path(args.path).resolve()
    skill_dir = target / ".claude" / "skills" / "vibe-coding-qa"

    if skill_dir.exists() and not args.force:
        print(f"Skill already exists at {skill_dir}. Use --force to overwrite.")
        return 1

    import shutil
    shutil.copytree(SKILL_ROOT, skill_dir, dirs_exist_ok=True)
    print(f"Installed vibe-coding-qa skill to {skill_dir}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate skill structure and references."""
    print("Validating vibe-coding-qa skill structure...")

    required = [
        "SKILL.md",
        "references/launch-framework.md",
        "references/work-templates.md",
        "references/research-and-advanced-qa.md",
        "references/product-intelligence.md",
        "references/product-research-report-template.md",
    ]

    all_ok = True
    for rel in required:
        path = SKILL_ROOT / rel
        if path.exists():
            size = path.stat().st_size
            print(f"  ✓ {rel} ({size} bytes)")
        else:
            print(f"  ✗ {rel} MISSING")
            all_ok = False

    # Check frontmatter
    skill_md = SKILL_ROOT / "SKILL.md"
    if skill_md.exists():
        content = skill_md.read_text(encoding="utf-8")
        if content.startswith("---\nname: vibe-coding-qa\n"):
            print("  ✓ Frontmatter valid")
        else:
            print("  ✗ Frontmatter invalid or missing")
            all_ok = False

    if all_ok:
        print("\n✓ All checks passed")
        return 0
    else:
        print("\n✗ Validation failed")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vibe-coding-qa",
        description="Vibe Coding QA - Product research, pre-launch audit, and workflow templates",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Research command
    research = subparsers.add_parser("research", help="Run product intelligence research")
    research.add_argument("--product", required=True, help="Product idea or description")
    research.add_argument(
        "--mode",
        choices=["quick", "focused", "deep", "blueprint"],
        default="deep",
        help="Research depth mode",
    )
    research.add_argument("--markets", help="Comma-separated target markets")
    research.add_argument("--output", help="Output file for report")
    research.add_argument("--template", action="store_true", help="Include report template")
    research.add_argument("--methodology", action="store_true", help="Include methodology")
    research.set_defaults(func=cmd_research)

    # Audit command
    audit = subparsers.add_parser("audit", help="Run pre-launch audit checklist")
    audit.add_argument(
        "--checklist",
        choices=["launch", "security", "tanzania", "all"],
        default="launch",
        help="Which checklist to display",
    )
    audit.set_defaults(func=cmd_audit)

    # Template command
    template = subparsers.add_parser("template", help="Output a work template")
    template.add_argument(
        "--type",
        choices=["feature-brief", "inventory", "verification", "finding", "change-record", "launch-decision", "all"],
        default="all",
        help="Template type to output",
    )
    template.set_defaults(func=cmd_template)

    # Init command
    init = subparsers.add_parser("init", help="Install skill into a project")
    init.add_argument("--path", default=".", help="Target project root")
    init.add_argument("--force", action="store_true", help="Overwrite existing")
    init.set_defaults(func=cmd_init)

    # Validate command
    validate = subparsers.add_parser("validate", help="Validate skill structure")
    validate.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())