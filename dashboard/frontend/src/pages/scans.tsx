import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, Copy, Radar, Sparkles, WandSparkles } from "lucide-react";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
import { ScanStatusBadge } from "@/components/common/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { ApiError, api } from "@/lib/api";
import { groupIssues } from "@/lib/finding-groups";
import {
  formatCount,
  formatDuration,
  formatRelative,
  titleCase,
} from "@/lib/format";
import type { Finding, Scan } from "@/types/api";

const LIMIT = 25;
const MAX_PROMPT_FINDINGS = 60;

const STATUSES: Array<{ value: string; label: string }> = [
  { value: "all", label: "All statuses" },
  { value: "queued", label: "Queued" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

export function ScansPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { repositories } = useApp();

  const [repositoryFilter, setRepositoryFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Scan[]>([]);
  const [promptScan, setPromptScan] = useState<Scan | null>(null);
  const [improvementPrompt, setImprovementPrompt] = useState("");
  const [executiveSummary, setExecutiveSummary] = useState("");
  const [promptLoading, setPromptLoading] = useState(false);
  const [promptError, setPromptError] = useState<string | null>(null);

  const scans = useAsync(
    () =>
      api.scans.list({
        repository_id: repositoryFilter === "all" ? undefined : Number(repositoryFilter),
        status: statusFilter === "all" ? undefined : statusFilter,
        limit: LIMIT,
        offset,
      }),
    [repositoryFilter, statusFilter, offset],
  );
  const reloadScans = scans.reload;

  const items = scans.data?.items ?? [];
  const total = scans.data?.total ?? 0;
  const active = items.some((scan) => scan.status === "queued" || scan.status === "running");

  // Poll while any listed scan is queued or running. Nothing is fabricated here.
  useEffect(() => {
    if (!active) return;
    const interval = window.setInterval(() => {
      void reloadScans(true);
    }, 3000);
    return () => window.clearInterval(interval);
  }, [active, reloadScans]);

  useEffect(() => {
    setSelected([]);
  }, [repositoryFilter, statusFilter, offset]);

  const canCompare = selected.length === 2;
  const prevDisabled = offset === 0;
  const nextDisabled = offset + LIMIT >= total;

  async function openRecommendations(scan: Scan) {
    setPromptScan(scan);
    setImprovementPrompt("");
    setExecutiveSummary("");
    setPromptError(null);
    setPromptLoading(true);
    try {
      const result = await loadScanFindings(scan.id);
      setExecutiveSummary(buildExecutiveSummary(scan, result.items, result.total));
      setImprovementPrompt(buildImprovementPrompt(scan, result.items, result.total));
    } catch (error) {
      setPromptError(
        error instanceof ApiError
          ? error.message
          : "The improvement prompt could not be prepared.",
      );
    } finally {
      setPromptLoading(false);
    }
  }

  async function copyImprovementPrompt() {
    try {
      await navigator.clipboard.writeText(improvementPrompt);
      toast({
        title: "Improvement prompt copied",
        description: "Paste it into your coding assistant, then rerun the same scan profile.",
        variant: "success",
      });
    } catch {
      toast({
        title: "Could not copy the prompt",
        description: "Select the prompt text and copy it manually.",
        variant: "error",
      });
    }
  }

  function toggleSelected(scan: Scan) {
    setSelected((current) => {
      if (current.some((item) => item.id === scan.id)) {
        return current.filter((item) => item.id !== scan.id);
      }
      if (current.length >= 2) return current;
      return [...current, scan];
    });
  }

  function handleCompare() {
    if (selected.length !== 2) return;
    const [first, second] = selected;
    if (first.repository_id !== second.repository_id) {
      toast({
        title: "Scans must share a repository",
        description: "A comparison is only possible between two scans of the same repository.",
        variant: "error",
      });
      return;
    }
    const ordered = [first, second].sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    );
    navigate(`/scans/compare?base=${ordered[0].id}&head=${ordered[1].id}`);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scans"
        description="Every scan the engine has queued, run, or finished."
        actions={
          <>
            <Button variant="outline" size="sm" disabled={!canCompare} onClick={handleCompare}>
              Compare selected
            </Button>
            <Button asChild size="sm">
              <Link to="/scans/new">
                <Radar />
                New scan
              </Link>
            </Button>
          </>
        }
      />

      <Card>
        <CardContent className="flex flex-col gap-3 p-5 sm:flex-row sm:items-end">
          <div className="w-full space-y-2 sm:w-64">
            <Label>Repository</Label>
            <Select
              value={repositoryFilter}
              onValueChange={(value) => {
                setRepositoryFilter(value);
                setOffset(0);
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All repositories</SelectItem>
                {repositories.map((repository) => (
                  <SelectItem key={repository.id} value={String(repository.id)}>
                    {repository.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="w-full space-y-2 sm:w-56">
            <Label>Status</Label>
            <Select
              value={statusFilter}
              onValueChange={(value) => {
                setStatusFilter(value);
                setOffset(0);
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUSES.map((status) => (
                  <SelectItem key={status.value} value={status.value}>
                    {status.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <p className="text-xs text-muted-foreground sm:pb-2">
            Select two scans of the same repository to compare them.
          </p>
        </CardContent>
      </Card>

      <DataState
        loading={scans.loading}
        error={scans.error}
        onRetry={() => void scans.reload()}
        loadingRows={4}
      >
        {items.length === 0 ? (
          <EmptyState
            icon={Radar}
            title="No scans found"
            description="No scans match the current filters. Start a scan to populate this list."
            action={
              <Button asChild size="sm" variant="outline">
                <Link to="/scans/new">Start a scan</Link>
              </Button>
            }
          />
        ) : (
          <div className="space-y-4">
            <Card>
              <CardContent className="px-0 pb-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8" />
                      <TableHead>Id</TableHead>
                      <TableHead>Repository</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Profile</TableHead>
                      <TableHead>Feedback prompt</TableHead>
                      <TableHead>Gate</TableHead>
                      <TableHead>Critical / High</TableHead>
                      <TableHead>Findings</TableHead>
                      <TableHead>Tests</TableHead>
                      <TableHead>Duration</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((scan) => {
                      const checked = selected.some((item) => item.id === scan.id);
                      return (
                        <TableRow key={scan.id} data-state={checked ? "selected" : undefined}>
                          <TableCell>
                            <input
                              type="checkbox"
                              className="h-4 w-4 rounded border-input"
                              checked={checked}
                              onChange={() => toggleSelected(scan)}
                              aria-label={`Select scan ${scan.id}`}
                            />
                          </TableCell>
                          <TableCell>
                            <Link
                              to={`/scans/${scan.id}`}
                              className="font-medium tabular-nums hover:text-primary"
                            >
                              #{scan.id}
                            </Link>
                          </TableCell>
                          <TableCell>{scan.repository_name ?? "—"}</TableCell>
                          <TableCell>
                            <ScanStatusBadge status={scan.status} />
                          </TableCell>
                          <TableCell>{scan.profile}</TableCell>
                          <TableCell>
                            {scan.status === "completed" && scan.overall_score !== null ? (
                              <Button asChild size="sm" className="improve-cta">
                                <Link to={findingsPath(scan)}>
                                  <Sparkles />
                                  {scan.overall_score >= 97 ? "Maintain 97+" : "Improve to 97+"}
                                  <ArrowRight className="improve-cta-arrow" />
                                </Link>
                              </Button>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <GateBadge gate={scan.gate} />
                          </TableCell>
                          <TableCell className="tabular-nums">
                            <span className="text-severity-critical">
                              {formatCount(scan.critical_count)}
                            </span>
                            <span className="px-1 text-muted-foreground">/</span>
                            <span className="text-severity-high">{formatCount(scan.high_count)}</span>
                          </TableCell>
                          <TableCell className="tabular-nums">
                            {formatCount(scan.total_findings)}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {scan.test_status ? titleCase(scan.test_status) : "—"}
                          </TableCell>
                          <TableCell className="tabular-nums">
                            {formatDuration(scan.duration_ms)}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatRelative(scan.created_at)}
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-col items-start gap-1">
                              {scan.status === "completed" ? (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="recommendations-cta"
                                  onClick={() => void openRecommendations(scan)}
                                >
                                  <WandSparkles />
                                  Fix & recommendations
                                </Button>
                              ) : null}
                              <Button asChild variant="ghost" size="sm">
                                <Link to={`/scans/${scan.id}`}>Open scan</Link>
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                Showing {offset + 1}–{Math.min(offset + LIMIT, total)} of {formatCount(total)}
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={prevDisabled}
                  onClick={() => setOffset(Math.max(0, offset - LIMIT))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={nextDisabled}
                  onClick={() => setOffset(offset + LIMIT)}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        )}
      </DataState>

      <Dialog
        open={promptScan !== null}
        onOpenChange={(open) => {
          if (!open) setPromptScan(null);
        }}
      >
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>
              {promptScan
                ? `Fix & recommendations · Scan #${promptScan.id}`
                : "Fix & recommendations"}
            </DialogTitle>
            <DialogDescription>
              A scan-grounded executive summary and coding prompt. The 97+ target must be verified
              by rerunning this scan profile; no prompt can guarantee a score.
            </DialogDescription>
          </DialogHeader>

          {promptLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Preparing a prompt from this scan's findings…
            </p>
          ) : null}

          {promptError ? (
            <Alert variant="destructive">
              <AlertTitle>Could not prepare prompt</AlertTitle>
              <AlertDescription>{promptError}</AlertDescription>
            </Alert>
          ) : null}

          {!promptLoading && !promptError && improvementPrompt ? (
            <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-1">
              <Card>
                <CardContent className="space-y-2 p-4">
                  <h3 className="text-sm font-semibold">Executive summary</h3>
                  <p className="whitespace-pre-wrap text-sm leading-relaxed text-muted-foreground">
                    {executiveSummary}
                  </p>
                </CardContent>
              </Card>
              <div className="space-y-2">
                <Label htmlFor="scan-improvement-prompt">97+ improvement prompt</Label>
                <Textarea
                  id="scan-improvement-prompt"
                  aria-label="Score improvement prompt"
                  className="min-h-64 resize-y bg-muted/40 font-mono text-xs leading-relaxed"
                  readOnly
                  value={improvementPrompt}
                />
              </div>
            </div>
          ) : null}

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setPromptScan(null)}
            >
              Close
            </Button>
            <Button
              variant="secondary"
              disabled={!promptScan}
              onClick={() => {
                if (!promptScan) return;
                navigate(findingsPath(promptScan));
                setPromptScan(null);
              }}
            >
              View findings
            </Button>
            <Button
              onClick={() => void copyImprovementPrompt()}
              disabled={promptLoading || Boolean(promptError) || !improvementPrompt}
            >
              <Copy />
              Copy prompt
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

async function loadScanFindings(scanId: number): Promise<{ items: Finding[]; total: number }> {
  const items: Finding[] = [];
  const limit = 200;
  let offset = 0;
  let total = 0;

  do {
    const page = await api.findings.list({ scan_id: scanId, limit, offset });
    items.push(...page.items);
    total = page.total;
    if (!page.items.length) break;
    offset += page.items.length;
  } while (offset < total);

  return { items, total };
}

function findingsPath(scan: Scan): string {
  const params = new URLSearchParams({ scan_id: String(scan.id) });
  if ((scan.critical_count ?? 0) > 0) params.set("priority", "critical");
  else if ((scan.high_count ?? 0) > 0) params.set("priority", "high");
  return `/findings?${params.toString()}`;
}

function buildExecutiveSummary(scan: Scan, findings: Finding[], totalFindings: number): string {
  const groups = groupIssues(findings);
  const severityCounts = findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    return counts;
  }, {});
  const fileCount = new Set(findings.map((finding) => `${finding.repository_id}:${finding.file}`)).size;
  const topIssues = groups.slice(0, 5).map((group) => {
    const finding = group.representative;
    return `- ${finding.rule}: ${formatCount(group.occurrences.length)} occurrences across ${formatCount(
      new Set(group.occurrences.map((item) => `${item.repository_id}:${item.file}`)).size,
    )} files (${titleCase(finding.severity)}).`;
  });

  return [
    `Scan #${scan.id} of ${scan.repository_name ?? `repository #${scan.repository_id}`} scored ${scan.overall_score?.toFixed(1) ?? "N/A"}/100 with a ${scan.gate ?? "not reported"} release gate.`,
    `${formatCount(totalFindings)} finding occurrences were consolidated into ${formatCount(groups.length)} unique issue patterns across ${formatCount(fileCount)} files.`,
    `Severity breakdown: ${formatCount(severityCounts.critical ?? 0)} critical, ${formatCount(severityCounts.high ?? 0)} high, ${formatCount(severityCounts.medium ?? 0)} medium, ${formatCount(severityCounts.low ?? 0)} low, and ${formatCount(severityCounts.info ?? 0)} informational.`,
    "",
    "Most repeated issue patterns:",
    ...(topIssues.length ? topIssues : ["- No findings were recorded. Review scan coverage and test results before drawing conclusions."]),
    "",
    `Tests: ${scan.test_status ? titleCase(scan.test_status) : "not reported"}; ${formatCount(scan.tests_passed ?? 0)} passed and ${formatCount(scan.tests_failed ?? 0)} failed.`,
    `Coverage gaps: ${scan.coverage_gaps.length ? scan.coverage_gaps.join("; ") : "none reported"}.`,
    "Prioritize verified critical and high findings, make focused fixes, then rerun this same scan profile to validate the score.",
  ].join("\n");
}

function buildImprovementPrompt(scan: Scan, findings: Finding[], totalFindings: number): string {
  const targetMet = (scan.overall_score ?? 0) >= 97;
  const groups = groupIssues(findings);
  const included = groups.slice(0, MAX_PROMPT_FINDINGS);
  const omittedCount = Math.max(0, groups.length - included.length);
  const findingNotes = included.length
    ? included.map((group) => {
        const finding = group.representative;
        const fileCount = new Set(
          group.occurrences.map((item) => `${item.repository_id}:${item.file}`),
        ).size;
        const locations = group.occurrences
          .slice(0, 6)
          .map((item) => `${item.file}:${item.line}`)
          .join(", ");
        const details = [
          `- [${finding.severity.toUpperCase()}] ${finding.rule} (${finding.module}) — ${group.occurrences.length} occurrences across ${fileCount} files.`,
          `  Example locations: ${locations}${group.occurrences.length > 6 ? ", …" : ""}`,
          finding.message ? `  Finding: ${finding.message.slice(0, 400)}` : "",
          finding.suggestion ? `  Scanner suggestion: ${finding.suggestion.slice(0, 400)}` : "",
        ].filter(Boolean);
        return details.join("\n");
      }).join("\n")
    : "- No findings were recorded for this scan. Inspect the scan's coverage gaps, test results, and scoring criteria before proposing changes.";

  return [
    "Act as a careful senior engineer improving this repository based on verified scan evidence.",
    `Goal: ${targetMet ? "maintain a score of at least 97/100" : "raise the score to at least 97/100"} on a fresh rerun of the same scan profile.`,
    "",
    `Repository: ${scan.repository_name ?? `repository #${scan.repository_id}`}`,
    `Scan: #${scan.id}`,
    `Profile: ${scan.profile}`,
    `Current score: ${scan.overall_score?.toFixed(1) ?? "not available"}/100`,
    `Gate: ${scan.gate ?? "not available"}`,
    `Findings: ${totalFindings} total occurrences in ${groups.length} unique issue groups; ${scan.critical_count ?? 0} critical and ${scan.high_count ?? 0} high`,
    `Tests: ${scan.test_status ?? "not reported"}; ${scan.tests_passed ?? 0} passed, ${scan.tests_failed ?? 0} failed`,
    `Coverage gaps: ${scan.coverage_gaps.length ? scan.coverage_gaps.join("; ") : "none reported"}`,
    "",
    "Grouped scan findings, ordered by severity and repeated impact:",
    findingNotes,
    omittedCount
      ? `\nThe prompt includes ${included.length} unique issue groups; ${omittedCount} additional groups were omitted. Review the remaining groups before concluding.`
      : "",
    "",
    "Instructions:",
    "1. Inspect the relevant code and verify each finding before changing anything.",
    "2. Prioritize confirmed critical and high-severity root causes, then address remaining findings and coverage gaps that affect the score.",
    "3. Make the smallest behavior-preserving fixes. Add or update tests where appropriate.",
    "4. Do not game the score by suppressing rules, excluding files, weakening tests, or changing scanner configuration.",
    "5. Run the project's relevant tests, then rerun the same scan profile and report the actual score, gate, and any unresolved findings.",
    "6. Never claim the 97+ target was reached unless a fresh scan reports at least 97. If that target is not safely achievable, explain why and list the remaining work.",
  ].filter(Boolean).join("\n");
}
