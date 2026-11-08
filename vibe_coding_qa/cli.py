"""Command-line interface for the Vibe Coding QA engine."""

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import run_pipeline
from .gates import release_decision


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibe-coding-qa",
        description="Automated Vibe Coding QA and production-readiness engineering tool.",
    )
    parser.add_argument("--version", action="version", version=f"vibe-coding-qa {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository and generate reports.")
    scan.add_argument("--repo", required=True, help="Local path or GitHub owner/repo (or full git URL).")
    scan.add_argument("--output", "-o", default="vcqa-reports", help="Directory for Markdown/JSON/HTML reports.")
    scan.add_argument("--no-tests", action="store_true", help="Skip running the project test suite.")
    scan.add_argument("--no-execution", action="store_true", help="Run static analysis only; do not execute project tests.")
    scan.add_argument("--explicit-permission", action="store_true", help="Explicitly allow test execution (required to run tests).")
    scan.add_argument("--test-command", help="Override the test command (e.g. 'npm run test:ci').")
    scan.add_argument("--test-timeout", type=int, default=300, help="Maximum test duration in seconds.")
    scan.add_argument("--max-memory-mb", type=int, default=512, help="Test memory limit inside the sandbox.")
    scan.add_argument("--max-cpu-seconds", type=int, default=60, help="Test process CPU limit inside the sandbox.")
    scan.add_argument("--test-image", help="Locally available Docker image for isolated tests (does not pull images).")
    scan.add_argument("--max-snapshot-mb", type=int, default=256, help="Maximum snapshot input size in MiB.")
    scan.add_argument("--max-write-mb", type=int, default=64, help="Combined tmp and shared-memory capacity in MiB.")
    scan.add_argument("--keep-clone", action="store_true", help="Keep the temporary cloned repository.")

    fix = sub.add_parser("fix", help="Apply safe automated fixes (default dry-run).")
    fix.add_argument("--repo", required=True, help="Local path or GitHub owner/repo.")
    fix.add_argument("--apply", action="store_true", help="Actually modify files; without this, fixes are previewed.")
    fix.add_argument("--output", "-o", default="vcqa-reports", help="Directory for reports.")
    fix.add_argument("--explicit-permission", action="store_true", help="Allow isolated tests after applying fixes.")
    fix.add_argument("--test-command", help="Override the detected test command.")
    fix.add_argument("--test-image", help="Locally prepared Docker image for tests.")
    fix.add_argument("--test-timeout", type=int, default=300, help="Maximum test duration in seconds.")
    fix.add_argument("--max-memory-mb", type=int, default=512, help="Test memory limit inside the sandbox.")
    fix.add_argument("--max-cpu-seconds", type=int, default=60, help="Test process CPU limit inside the sandbox.")
    fix.add_argument("--max-snapshot-mb", type=int, default=256, help="Maximum snapshot input size in MiB.")
    fix.add_argument("--max-write-mb", type=int, default=64, help="Combined tmp and workspace capacity in MiB.")

    gate = sub.add_parser("gate", help="Return a release gate decision and exit non-zero when blocked.")
    gate.add_argument("--repo", required=True, help="Local path or GitHub owner/repo.")
    gate.add_argument("--output", "-o", default="vcqa-reports", help="Directory for reports.")
    gate.add_argument("--no-execution", action="store_true", help="Static gate only; do not execute tests.")
    gate.add_argument("--explicit-permission", action="store_true", help="Explicitly allow test execution (required to run tests).")
    gate.add_argument("--test-command", help="Override the detected test command.")
    gate.add_argument("--test-timeout", type=int, default=300, help="Maximum test duration in seconds.")
    gate.add_argument("--max-memory-mb", type=int, default=512, help="Test memory limit inside the sandbox.")
    gate.add_argument("--max-cpu-seconds", type=int, default=60, help="Test process CPU limit inside the sandbox.")
    gate.add_argument("--test-image", help="Locally available Docker image for isolated tests (does not pull images).")
    gate.add_argument("--max-snapshot-mb", type=int, default=256, help="Maximum snapshot input size in MiB.")
    gate.add_argument("--max-write-mb", type=int, default=64, help="Combined tmp and shared-memory capacity in MiB.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        result = run_pipeline(
            args.repo,
            output_dir=args.output,
            run_tests_flag=not args.no_tests,
            no_execution=args.no_execution,
            explicit_permission=args.explicit_permission,
            test_command=args.test_command,
            test_timeout=args.test_timeout,
            max_memory_mb=args.max_memory_mb,
            max_cpu_seconds=args.max_cpu_seconds,
            test_image=args.test_image,
            max_snapshot_mb=args.max_snapshot_mb,
            max_write_mb=args.max_write_mb,
            github_token=os.environ.get("VCQA_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"),
            keep_clone=args.keep_clone,
        )
        print(release_decision(result))
        print(f"Reports written to: {Path(args.output).resolve()}")
        # Use authoritative gate for exit code
        gate = getattr(result, 'gate', 'unknown')
        if gate == "block":
            return 2
        if gate == "fail":
            return 1
        if gate == "not_verified":
            return 3  # New exit code for not verified
        return 0

    if args.command == "fix":
        result = run_pipeline(
            args.repo,
            output_dir=args.output,
            run_tests_flag=args.apply and args.explicit_permission,
            explicit_permission=args.explicit_permission,
            test_command=args.test_command,
            test_image=args.test_image,
            test_timeout=args.test_timeout,
            max_memory_mb=args.max_memory_mb,
            max_cpu_seconds=args.max_cpu_seconds,
            max_snapshot_mb=args.max_snapshot_mb,
            max_write_mb=args.max_write_mb,
            apply_fixes=args.apply,
            dry_run_fixes=not args.apply,
            github_token=os.environ.get("VCQA_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"),
        )
        print(release_decision(result))
        mode = "applied" if args.apply else "previewed"
        print(f"Fixes {mode}; reports written to: {Path(args.output).resolve()}")
        gate = getattr(result, 'gate', 'unknown')
        if gate == "block":
            return 2
        if gate == "fail":
            return 1
        if gate == "not_verified":
            return 3
        return 0

    if args.command == "gate":
        result = run_pipeline(
            args.repo,
            output_dir=args.output,
            run_tests_flag=True,
            no_execution=args.no_execution,
            explicit_permission=args.explicit_permission,
            test_command=args.test_command,
            test_timeout=args.test_timeout,
            max_memory_mb=args.max_memory_mb,
            max_cpu_seconds=args.max_cpu_seconds,
            test_image=args.test_image,
            max_snapshot_mb=args.max_snapshot_mb,
            max_write_mb=args.max_write_mb,
            github_token=os.environ.get("VCQA_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"),
        )
        print(release_decision(result))
        gate = getattr(result, 'gate', 'unknown')
        if gate == "block":
            return 2
        if gate == "fail":
            return 1
        if gate == "not_verified":
            return 3
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
