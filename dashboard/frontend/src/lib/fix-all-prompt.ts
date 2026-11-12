import type { IssueGroup } from "@/lib/finding-groups";
import type { Finding } from "@/types/api";

/**
 * Build one comprehensive remediation prompt covering every grouped issue in
 * scope, organised by category (scanner module) and severity. Paste the result
 * into an AI coding agent (Claude Code, Cursor, …) pointed at the scanned repo.
 *
 * It lists the unique issues (rule + occurrence count + a representative file
 * and the scanner's own suggestion), and bakes in guardrails so the agent fixes
 * root causes instead of hiding findings.
 */

export interface FixAllMeta {
  scanId?: number;
  repoName?: string | null;
}

const CATEGORY_ORDER = [
  "security",
  "database",
  "compliance",
  "quality",
  "dependencies",
  "performance",
  "infrastructure",
  "web",
];

const CATEGORY_TITLES: Record<string, string> = {
  security: "SECURITY",
  database: "DATABASE / ROW-LEVEL SECURITY",
  compliance: "COMPLIANCE (Tanzania PDPA 2022 / TCRA)",
  quality: "CODE QUALITY",
  dependencies: "DEPENDENCIES",
  performance: "PERFORMANCE",
  infrastructure: "INFRASTRUCTURE",
  web: "LIVE WEB TARGET",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function sev(group: IssueGroup<Finding>): string {
  return (group.representative.severity || "").toLowerCase();
}

export function buildFixAllPrompt(groups: IssueGroup<Finding>[], meta: FixAllMeta = {}): string {
  if (!groups.length) return "There are no open findings in scope to fix.";

  const totalFindings = groups.reduce((n, g) => n + g.occurrences.length, 0);
  const severitySummary = SEVERITY_ORDER.map((s) => {
    const inSev = groups.filter((g) => sev(g) === s);
    const occ = inSev.reduce((n, g) => n + g.occurrences.length, 0);
    return { s, unique: inSev.length, occ };
  })
    .filter((x) => x.unique > 0)
    .map((x) => `${x.occ} ${x.s} (${x.unique} unique)`)
    .join(", ");

  const byCategory = new Map<string, IssueGroup<Finding>[]>();
  for (const group of groups) {
    const category = (group.representative.module || "other").toLowerCase();
    const bucket = byCategory.get(category);
    if (bucket) bucket.push(group);
    else byCategory.set(category, [group]);
  }
  const categories = [...byCategory.keys()].sort((a, b) => {
    const ia = CATEGORY_ORDER.indexOf(a);
    const ib = CATEGORY_ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });

  const out: string[] = [];
  out.push(
    "Act as a senior application-security engineer and full-stack developer. Fix EVERY",
  );
  out.push(
    `issue found by the Vibe Coding QA scan of this repository${
      meta.repoName ? ` (${meta.repoName})` : ""
    }, across all`,
  );
  out.push("categories listed below, and prove the fixes with a fresh rescan.");
  out.push("");
  out.push(
    `Scan summary${meta.scanId ? ` (scan #${meta.scanId})` : ""}: ${totalFindings} findings in ${
      groups.length
    } unique issues — ${severitySummary}.`,
  );
  out.push("");
  out.push("GROUND RULES");
  out.push("- Verify each finding in the real code before changing anything.");
  out.push("- Make the smallest behavior-preserving fix that removes the root cause.");
  out.push("- Do NOT game the score: never suppress rules, exclude files, weaken tests or");
  out.push("  change scanner config. A finding is fixed only when the real risk is gone.");
  out.push("- Add or update tests for every security and data fix; then run the suite.");
  out.push("- Never commit secrets; never expose provider/API keys to the frontend.");
  out.push("- Work one category at a time; after each, re-run the scan and report the");
  out.push("  before/after counts for that category.");
  out.push("");

  let index = 1;
  for (const category of categories) {
    const bucket = byCategory
      .get(category)!
      .slice()
      .sort((a, b) => {
        const sa = SEVERITY_ORDER.indexOf(sev(a));
        const sb = SEVERITY_ORDER.indexOf(sev(b));
        if (sa !== sb) return (sa === -1 ? 99 : sa) - (sb === -1 ? 99 : sb);
        return b.occurrences.length - a.occurrences.length;
      });
    out.push(`${index}) ${CATEGORY_TITLES[category] ?? category.toUpperCase()}`);
    for (const group of bucket) {
      const r = group.representative;
      const location = r.file ? ` e.g. ${r.file}${r.line ? `:${r.line}` : ""}` : "";
      const message = (r.message || "").trim();
      const suggestion = (r.suggestion || "").trim();
      out.push(
        `- [${(r.severity || "").toUpperCase()}] ${r.rule} (${group.occurrences.length}×)${
          message ? ` — ${message}` : ""
        }${location}.`,
      );
      if (suggestion) out.push(`    Fix: ${suggestion}`);
    }
    out.push("");
    index += 1;
  }

  out.push("DELIVERABLES");
  out.push("- The list of files changed and what each fix does.");
  out.push("- Actual test output (not claimed) and the fresh rescan counts per category,");
  out.push("  before vs after.");
  out.push("- Any finding you intentionally did not change, with the reason, and a");
  out.push("  prioritized list of anything still open.");
  out.push("Do not claim a category is clean unless the rescan shows it.");

  return out.join("\n");
}
