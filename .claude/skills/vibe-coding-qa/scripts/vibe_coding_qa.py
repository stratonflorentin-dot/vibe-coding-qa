import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

SKILL_ROOT = Path(__file__).resolve().parent.parent
REFERENCES = SKILL_ROOT / "references"
MAX_CAPTURE_BYTES = 5 * 1024 * 1024
MAX_ERROR_BYTES = 32 * 1024


class ToolError(Exception):
    pass


def load_reference(name):
    candidate = (REFERENCES / name).resolve()
    try:
        candidate.relative_to(REFERENCES.resolve())
    except ValueError as exc:
        raise ToolError("Reference path is outside the skill reference directory") from exc
    if not candidate.is_file():
        raise ToolError(f"Reference not found: {name}")
    return candidate.read_text(encoding="utf-8")


def extract_section(document, heading):
    lines = document.splitlines()
    start = next((index for index, line in enumerate(lines) if line.strip() == heading), None)
    if start is None:
        raise ToolError(f"Section not found: {heading}")
    level = len(heading) - len(heading.lstrip("#"))
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("#"):
            current_level = len(line) - len(line.lstrip("#"))
            if current_level <= level:
                end = index
                break
    return "\n".join(lines[start:end]).strip()


def redact_text(value):
    value = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|cookie)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", value)
    return value


def redact_value(value, key=""):
    if re.search(r"(?i)(token|secret|password|cookie|authorization|api[_-]?key|credential)", key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {item_key: redact_value(item, item_key) for item_key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def emit_process_result(result):
    output = result.stdout.strip()
    if output:
        try:
            parsed = json.loads(output)
            print(json.dumps(redact_value(parsed), ensure_ascii=False, indent=2))
        except json.JSONDecodeError:
            print(redact_text(output))
    error = redact_text(result.stderr.strip())
    if error:
        print(error, file=sys.stderr)
    return result.returncode


def run_capture(argv, timeout, cwd=None, max_bytes=MAX_CAPTURE_BYTES):
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"Executable not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Command timed out after {timeout} seconds") from exc
    if len(result.stdout) > max_bytes or len(result.stderr) > MAX_ERROR_BYTES:
        raise ToolError(f"Command output exceeded the {max_bytes}-byte safety limit")
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        result.stdout.decode("utf-8", errors="replace"),
        result.stderr.decode("utf-8", errors="replace"),
    )


def run_to_file(argv, destination, timeout, max_bytes, cwd=None):
    destination = Path(destination).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".rea-evidence-", delete=False) as output_file:
            temporary_path = Path(output_file.name)
            process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            errors = bytearray()
            stderr_overflow = threading.Event()

            def drain_stderr():
                while True:
                    chunk = process.stderr.read(8192)
                    if not chunk:
                        break
                    remaining = MAX_ERROR_BYTES - len(errors)
                    if remaining > 0:
                        errors.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        stderr_overflow.set()

            stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
            stderr_thread.start()
            timer_expired = threading.Event()

            def stop_process():
                timer_expired.set()
                process.kill()

            timer = threading.Timer(timeout, stop_process)
            timer.daemon = True
            timer.start()
            total = 0
            exceeded = False
            try:
                while True:
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        exceeded = True
                        process.kill()
                        break
                    output_file.write(chunk)
                output_file.flush()
                return_code = process.wait()
            finally:
                timer.cancel()
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
                stderr_thread.join(timeout=5)
                process.stderr.close()
            if timer_expired.is_set():
                raise ToolError(f"Analysis timed out after {timeout} seconds")
            if exceeded:
                raise ToolError(f"Evidence exceeded the {max_bytes}-byte limit; no report was kept")
            if stderr_overflow.is_set():
                raise ToolError("Analysis diagnostics exceeded the safety limit")
            if return_code != 0:
                diagnostic = redact_text(errors.decode("utf-8", errors="replace").strip())
                raise ToolError(f"Analysis exited with status {return_code}: {diagnostic or 'no diagnostic output'}")
        if destination.exists() and not getattr(run_to_file, "overwrite", False):
            raise ToolError(f"Output already exists: {destination}; choose another path or use --overwrite")
        temporary_path.replace(destination)
        temporary_path = None
        return destination, total
    except FileNotFoundError as exc:
        raise ToolError(f"Executable not found: {argv[0]}") from exc
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def ensure_executable(name, install_hint):
    executable = shutil.which(name)
    if not executable:
        raise ToolError(f"{name} is not installed or not on PATH. {install_hint}")
    return executable


def command_doctor(_args):
    integrations = {
        "fallow": ("fallow", "https://fallow.tools/docs/"),
        "rea": ("rea", "https://github.com/morluto/rea/blob/main/docs/installation.md"),
        "api-anything": ("api-anything", "https://github.com/goodnight000/api-anything/blob/main/docs/QUICKSTART.md"),
        "node": ("node", "https://nodejs.org/"),
        "npx": ("npx", "https://nodejs.org/"),
        "skills": ("skills", "https://skills.sh/"),
    }
    for label, (executable, documentation) in integrations.items():
        path = shutil.which(executable)
        state = path if path else f"not installed; see {documentation}"
        print(f"{label}: {state}")
    configured = bool(os.environ.get("PENTAGI_BASE_URL") and os.environ.get("PENTAGI_API_TOKEN"))
    print(f"pentagi: {'configured for explicit read-only status checks' if configured else 'not configured; set PENTAGI_BASE_URL and PENTAGI_API_TOKEN'}")
    print("UI guidance: included in references/research-and-advanced-qa.md; no external UI scanner is implied")
    return 0


def command_fallow(args):
    executable = ensure_executable("fallow", "Install Fallow using its official documentation: https://fallow.tools/docs/")
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        raise ToolError(f"Project root is not a directory: {root}")
    argv = [executable]
    if args.action == "audit":
        argv += ["audit", "--format", "json", "--quiet", "--root", str(root)]
        if args.base:
            argv += ["--base", args.base]
    elif args.action == "dead-code":
        argv += ["dead-code", "--format", "json", "--quiet", "--root", str(root)]
        if args.changed_since:
            argv += ["--changed-since", args.changed_since]
    elif args.action == "dupes":
        argv += ["dupes", "--format", "json", "--quiet", "--root", str(root)]
        if args.changed_since:
            argv += ["--changed-since", args.changed_since]
    elif args.action == "fix-preview":
        argv += ["fix", "--dry-run", "--format", "json", "--quiet", "--root", str(root)]
    elif args.action == "fix-apply":
        if not args.apply:
            raise ToolError("Applying fixes changes files; pass --apply explicitly after reviewing fix-preview output")
        argv += ["fix", "--yes", "--format", "json", "--quiet", "--root", str(root)]
    result = run_capture(argv, args.timeout)
    return emit_process_result(result)


def command_rea(args):
    target = Path(args.target).expanduser().resolve()
    if not target.exists() or not (target.is_dir() or target.suffix.lower() == ".asar"):
        raise ToolError("REA static app analysis requires an existing local directory or .asar file")
    if args.npx:
        executable = shutil.which("npx")
        if not executable:
            raise ToolError("npx was not found; install Node.js or use an installed rea executable")
        argv = [executable, "--yes", "rea-agents@latest", "analyze-javascript-application", str(target), "--json"]
    else:
        executable = ensure_executable("rea", "Install REA from https://github.com/morluto/rea/blob/main/docs/installation.md; use --npx to explicitly allow npx package acquisition")
        argv = [executable, "analyze-javascript-application", str(target), "--json"]
    output = Path(args.output).expanduser().resolve()
    if output.exists() and not args.overwrite:
        raise ToolError(f"Output already exists: {output}; use --overwrite or choose a new path")
    run_to_file.overwrite = args.overwrite
    path, size = run_to_file(argv, output, args.timeout, args.max_output_mb * 1024 * 1024)
    print(json.dumps({"status": "ok", "tool": "rea", "artifact": str(path), "bytes": size, "note": "Evidence saved; inspect coverage, limitations, and unknowns before drawing conclusions."}, indent=2))
    return 0


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def validate_pentagi_url(value):
    parsed = urlsplit(value)
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ToolError("PentAGI base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ToolError("PentAGI base URL cannot contain credentials, query parameters, or a fragment")
    if parsed.scheme != "https" and parsed.hostname.lower() not in local_hosts:
        raise ToolError("Non-local PentAGI endpoints must use HTTPS")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}/api/v1/flows"


def command_pentagi(args):
    base_url = args.base_url or os.environ.get("PENTAGI_BASE_URL")
    token = os.environ.get("PENTAGI_API_TOKEN")
    if not base_url:
        raise ToolError("Set PENTAGI_BASE_URL or pass --base-url")
    if not args.probe:
        print(json.dumps({"status": "configured", "base_url": base_url, "probe": "not run", "next": "Pass --probe for a single read-only GET /api/v1/flows request."}, indent=2))
        return 0
    if not token:
        raise ToolError("Set PENTAGI_API_TOKEN in the environment; never pass tokens as command arguments")
    endpoint = validate_pentagi_url(base_url)
    request = Request(endpoint, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, method="GET")
    opener = build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = response.status
    except HTTPError as exc:
        status = exc.code
    except URLError as exc:
        raise ToolError(f"PentAGI status request failed: {redact_text(str(exc.reason))}") from exc
    print(json.dumps({"status": "reachable" if 200 <= status < 300 else "http_error", "http_status": status, "endpoint": endpoint, "operation": "GET /api/v1/flows"}, indent=2))
    return 0 if 200 <= status < 300 else 1


def api_executable(use_npx):
    executable = shutil.which("api-anything")
    if executable:
        return [executable]
    if use_npx:
        npx = shutil.which("npx")
        if not npx:
            raise ToolError("npx is not installed; install Node.js 22.13+ first")
        return [npx, "--yes", "api-anything"]
    raise ToolError("api-anything is not installed; see https://github.com/goodnight000/api-anything/blob/main/docs/QUICKSTART.md; pass --npx to explicitly permit npx package acquisition")


def find_operation_record(value, name):
    if isinstance(value, dict):
        identity = [value.get(key) for key in ("name", "operation", "op", "id", "key")]
        if name in identity:
            return value
        for child in value.values():
            found = find_operation_record(child, name)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_operation_record(child, name)
            if found is not None:
                return found
    return None


def operation_access(record):
    if not isinstance(record, dict):
        return "unknown"
    if record.get("write") is True or record.get("isWrite") is True or record.get("is_write") is True or record.get("readOnly") is False or record.get("read_only") is False:
        return "write"
    if record.get("read") is True or record.get("readOnly") is True or record.get("read_only") is True or record.get("write") is False:
        return "read"
    method = str(record.get("method", record.get("httpMethod", ""))).upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    return "unknown"


def command_api_anything(args):
    command = api_executable(args.npx)
    if args.action == "sites":
        argv = command + ["sites"]
    elif args.action == "ops":
        argv = command + ["ops", args.site]
    elif args.action == "call":
        argv = command + ["call", args.site, args.operation] + args.argument
        if args.dry_run:
            argv += ["--dry", "--allow-writes"]
        elif args.execute_read:
            ops = run_capture(command + ["ops", args.site, args.operation, "--schema"], args.timeout)
            try:
                metadata = json.loads(ops.stdout)
            except json.JSONDecodeError as exc:
                raise ToolError("Could not parse api-anything operation schema; refusing to execute") from exc
            record = find_operation_record(metadata, args.operation)
            if operation_access(record) != "read":
                raise ToolError("Operation is not explicitly marked read-only; refusing execution. Use --dry-run to inspect it.")
            argv += ["--max-tier", "1"]
        elif args.execute_write:
            ops = run_capture(command + ["ops", args.site, args.operation, "--schema"], args.timeout)
            try:
                metadata = json.loads(ops.stdout)
            except json.JSONDecodeError as exc:
                raise ToolError("Could not parse api-anything operation schema; refusing to execute") from exc
            record = find_operation_record(metadata, args.operation)
            if operation_access(record) != "write":
                raise ToolError("Operation is not explicitly marked as a write; refusing execution")
            if args.confirm_write != f"{args.site}.{args.operation}":
                raise ToolError(f"Writes require --confirm-write {args.site}.{args.operation} after reviewing a dry run")
            argv += ["--allow-writes"]
        else:
            raise ToolError("Calls are dry-run by default; pass --execute-read for a schema-verified tier-1 read")
    elif args.action == "login":
        if not args.confirm_login:
            raise ToolError("Login opens or refreshes an authenticated browser session; pass --confirm-login to continue")
        argv = command + ["login", args.site]
    else:
        raise ToolError(f"Unsupported API Anything action: {args.action}")
    result = run_capture(argv, args.timeout)
    return emit_process_result(result)


def command_ui_guide(args):
    document = load_reference("research-and-advanced-qa.md")
    heading = "## 2. UI craft, motion, and adversarial data"
    section = extract_section(document, heading)
    if args.topic == "all":
        print(section)
        print("\nThis is a review guide, not an automated browser test. Use the project's browser/test tooling to verify actual renders.")
        return 0
    subsections = {
        "review": "### UI review",
        "stress": "### Worst-case UI verification",
    }
    print(extract_section(section, subsections[args.topic]))
    print("\nThis is guidance, not a test result; verify the actual UI in its supported browser/runtime.")
    return 0


def command_research(args):
    methodology = load_reference("product-intelligence.md")
    template = load_reference("product-research-report-template.md")
    brief = {
        "product": args.product,
        "mode": args.mode,
        "markets": args.markets or "Not specified; determine relevant regions during research.",
        "research_is_live": False,
        "note": "This local command creates a research brief/template. The agent must use authorized live research tools to gather and cite sources.",
    }
    body = json.dumps(brief, ensure_ascii=False, indent=2) + "\n\n" + template
    if args.methodology:
        body += "\n\n## Research methodology\n\n" + methodology
    if args.output:
        output = Path(args.output).expanduser().resolve()
        if output.exists() and not args.overwrite:
            raise ToolError(f"Output already exists: {output}; pass --overwrite to replace it")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body, encoding="utf-8")
        print(f"Research brief written to {output}; this command did not perform live research.")
    else:
        print(body)
    return 0


def command_audit(args):
    sections = {
        "launch": ["## I. Launch evidence matrix"],
        "security": ["## B. Seven risk areas", "## C. Access, API, and database verification"],
        "tanzania": ["## H. Tanzania and localized product checks"],
        "all": None,
    }
    framework = load_reference("launch-framework.md")
    if args.checklist == "all":
        print(framework)
        return 0
    for heading in sections[args.checklist]:
        print(extract_section(framework, heading))
        print()
    print("Checklist template only: run and record each applicable check before marking it verified.")
    return 0


def command_template(args):
    templates = load_reference("work-templates.md")
    product_template = load_reference("product-research-report-template.md")
    sections = {
        "feature-brief": (templates, "## 1. Feature brief"),
        "inventory": (templates, "## 2. System and trust-boundary inventory"),
        "verification": (templates, "## 3. Verification matrix"),
        "finding": (templates, "## 4. Security finding"),
        "change-record": (templates, "## 5. Change verification record"),
        "launch-decision": (templates, "## 6. Launch decision"),
        "product-report": (product_template, "## 1. Executive decision"),
    }
    if args.type == "all":
        print(templates + "\n\n" + product_template)
        return 0
    if args.type == "product-report":
        print(product_template)
        return 0
    document, heading = sections[args.type]
    print(extract_section(document, heading))
    return 0


def command_init(args):
    target = Path(args.path).expanduser().resolve()
    if not target.is_dir():
        raise ToolError(f"Project path must already exist: {target}")
    skill_dir = target / ".claude" / "skills" / "vibe-coding-qa"
    if skill_dir.exists() and not args.force:
        raise ToolError(f"Skill already exists at {skill_dir}; use --force to merge updated files")
    shutil.copytree(SKILL_ROOT, skill_dir, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    print(f"Installed skill files to {skill_dir}; existing files were merged, not deleted.")
    return 0


def command_validate(_args):
    required = [
        "SKILL.md",
        "references/launch-framework.md",
        "references/work-templates.md",
        "references/research-and-advanced-qa.md",
        "references/product-intelligence.md",
        "references/product-research-report-template.md",
        "scripts/vibe_coding_qa.py",
        "scripts/tool-integrations.md",
    ]
    missing = [relative for relative in required if not (SKILL_ROOT / relative).is_file()]
    if missing:
        print("Missing required files:\n" + "\n".join(missing), file=sys.stderr)
        return 1
    content = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    if not content.startswith("---\nname: vibe-coding-qa\n") or "description:" not in content.split("---", 2)[1]:
        raise ToolError("SKILL.md frontmatter is missing the expected name/description")
    for reference in required[1:6]:
        load_reference(Path(reference).name)
    print(json.dumps({"status": "ok", "files_checked": len(required), "frontmatter": "ok", "references": "present"}, indent=2))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="vibe-coding-qa", description="Research, review, and verify AI-assisted web products")
    subparsers = parser.add_subparsers(dest="command", required=True)

    research = subparsers.add_parser("research", help="Create a product research brief; live research is performed by the agent")
    research.add_argument("--product", required=True)
    research.add_argument("--mode", choices=["quick", "focused", "deep", "blueprint"], default="deep")
    research.add_argument("--markets")
    research.add_argument("--output")
    research.add_argument("--overwrite", action="store_true")
    research.add_argument("--methodology", action="store_true")
    research.set_defaults(func=command_research)

    audit = subparsers.add_parser("audit", help="Print a checklist; this does not mark checks verified")
    audit.add_argument("--checklist", choices=["launch", "security", "tanzania", "all"], default="launch")
    audit.set_defaults(func=command_audit)

    template = subparsers.add_parser("template", help="Print report and work templates")
    template.add_argument("--type", choices=["feature-brief", "inventory", "verification", "finding", "change-record", "launch-decision", "product-report", "all"], default="all")
    template.set_defaults(func=command_template)

    init = subparsers.add_parser("init", help="Install or merge the skill into an existing project")
    init.add_argument("--path", default=".")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=command_init)

    validate = subparsers.add_parser("validate", help="Validate skill files and frontmatter")
    validate.set_defaults(func=command_validate)

    tools = subparsers.add_parser("tools", help="Run supported external tool integrations")
    tool_subparsers = tools.add_subparsers(dest="tool", required=True)

    doctor = tool_subparsers.add_parser("doctor", help="Check which optional integrations are installed/configured")
    doctor.set_defaults(func=command_doctor)

    fallow = tool_subparsers.add_parser("fallow", help="Run Fallow JavaScript/TypeScript analysis")
    fallow.add_argument("--action", choices=["audit", "dead-code", "dupes", "fix-preview", "fix-apply"], default="audit")
    fallow.add_argument("--root", default=".")
    fallow.add_argument("--base")
    fallow.add_argument("--changed-since")
    fallow.add_argument("--apply", action="store_true", help="Explicitly authorize applying Fallow fixes")
    fallow.add_argument("--timeout", type=int, default=120)
    fallow.set_defaults(func=command_fallow)

    rea = tool_subparsers.add_parser("rea", help="Run REA static JavaScript/Electron analysis")
    rea.add_argument("target", help="Existing local app directory or .asar file")
    rea.add_argument("--output", required=True, help="Evidence JSON output path; existing files are protected")
    rea.add_argument("--overwrite", action="store_true")
    rea.add_argument("--npx", action="store_true", help="Explicitly permit npx to acquire rea-agents")
    rea.add_argument("--timeout", type=int, default=900)
    rea.add_argument("--max-output-mb", type=int, default=512)
    rea.set_defaults(func=command_rea)

    pentagi = tool_subparsers.add_parser("pentagi", help="Read-only PentAGI configuration/status integration")
    pentagi.add_argument("--base-url", help="Defaults to PENTAGI_BASE_URL")
    pentagi.add_argument("--probe", action="store_true", help="Issue exactly one read-only GET /api/v1/flows; never starts a flow")
    pentagi.add_argument("--timeout", type=int, default=10)
    pentagi.set_defaults(func=command_pentagi)

    api_anything = tool_subparsers.add_parser("api-anything", help="Inspect operations or make guarded calls")
    api_anything.add_argument("action", choices=["sites", "ops", "call", "login"])
    api_anything.add_argument("site", nargs="?")
    api_anything.add_argument("operation", nargs="?")
    api_anything.add_argument("--arg", dest="argument", action="append", default=[])
    api_anything.add_argument("--dry-run", action="store_true", help="Default; pass the upstream --dry preview")
    api_anything.add_argument("--execute-read", action="store_true", help="Execute only metadata-verified read operations via HTTP tier 1")
    api_anything.add_argument("--execute-write", action="store_true")
    api_anything.add_argument("--confirm-write", help="Must exactly equal SITE.OP after reviewing a dry run")
    api_anything.add_argument("--confirm-login", action="store_true")
    api_anything.add_argument("--npx", action="store_true", help="Explicitly permit npx package acquisition")
    api_anything.add_argument("--timeout", type=int, default=120)
    api_anything.set_defaults(func=command_api_anything)

    ui = tool_subparsers.add_parser("ui-guide", help="Print source-informed UI review guidance")
    ui.add_argument("--topic", choices=["review", "stress", "all"], default="all")
    ui.set_defaults(func=command_ui_guide)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "tools" and args.tool == "api-anything":
            if args.action in {"ops", "call", "login"} and not args.site:
                raise ToolError(f"{args.action} requires SITE")
            if args.action == "call" and not args.operation:
                raise ToolError("call requires SITE and OPERATION")
            if args.action == "call" and args.execute_read and args.execute_write:
                raise ToolError("Choose only one of --execute-read or --execute-write")
            if args.action == "call" and not args.dry_run and not args.execute_read and not args.execute_write:
                raise ToolError("Calls are dry-run by default; select --execute-read to execute a verified read")
        if args.command == "tools" and args.tool == "rea" and args.max_output_mb < 1:
            raise ToolError("--max-output-mb must be at least 1")
        return args.func(args)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
