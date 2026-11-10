import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  AlertOctagon,
  Compass,
  Download,
  Gauge,
  ListChecks,
  Play,
  Radar,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
import { ScanPhases } from "@/components/common/scan-phases";
import { SeverityBadge } from "@/components/common/severity-badge";
import { FindingStatusBadge, ScanStatusBadge } from "@/components/common/status-badge";
import { StatCard } from "@/components/common/stat-card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { ApiError, api, streamScanEvents } from "@/lib/api";
import {
  formatCount,
  formatDuration,
  formatRelative,
  formatScore,
  scoreColor,
  titleCase,
} from "@/lib/format";
import type { ComparedFinding, Finding, Scan, ScanEvent } from "@/types/api";

export function ScanDetailPage() {
  const params = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();

  const scanId = Number.parseInt(params.scanId ?? "", 10);
  const invalid = !Number.isFinite(scanId);

  const scan = useAsync(() => api.scans.get(scanId), [scanId], { enabled: !invalid });
  const seed = useAsync(() => api.scans.events(scanId, 0), [scanId], { enabled: !invalid });
  const findings = useAsync(() => api.findings.list({ scan_id: scanId, limit: 100 }), [scanId], {
    enabled: !invalid,
  });

  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [cancelling, setCancelling] = useState(false);
  const [downloadingReport, setDownloadingReport] = useState(false);

  // Seed the timeline from persisted events so a finished scan still shows it.
  useEffect(() => {
    const initial = seed.data;
    if (!initial) return;
    setEvents((current) => {
      const merged = new Map<number, ScanEvent>();
      for (const event of initial) merged.set(event.id, event);
      for (const event of current) merged.set(event.id, event);
      return [...merged.values()].sort((a, b) => a.id - b.id);
    });
  }, [seed.data]);

  // Live events from the engine's SSE stream. Nothing here is fabricated.
  useEffect(() => {
    if (invalid) return;
    const dispose = streamScanEvents(scanId, {
      onEvent: (event) =>
        setEvents((current) =>
          current.some((item) => item.id === event.id)
            ? current
            : [...current, event].sort((a, b) => a.id - b.id),
        ),
      onEnd: () => void scan.reload(true),
    });
    return dispose;
  }, [invalid, scanId, scan.reload]);

  // A terminal scan emits no further events; refresh once for the final persisted state.
  useEffect(() => {
    if (invalid) return;
    const status = scan.data?.status;
    if (status && status !== "queued" && status !== "running") {
      void scan.reload(true);
    }
  }, [invalid, scanId, scan.data?.status, scan.reload]);

  if (invalid) {
    return (
      <EmptyState
        icon={Compass}
        title="That scan does not exist"
        description="The scan id in the address is not a number."
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/scans">Back to scans</Link>
          </Button>
        }
      />
    );
  }

  const data = scan.data;

  async function handleCancel() {
    setCancelling(true);
    try {
      await api.scans.cancel(scanId);
      toast({ title: "Scan cancelled", description: `Scan #${scanId} was cancelled.`, variant: "success" });
      await scan.reload(true);
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "The scan could not be cancelled.";
      toast({ title: "Cancellation failed", description: message, variant: "error" });
    } finally {
      setCancelling(false);
    }
  }

  async function handleDownloadRecommendations() {
    if (!data) return;
    setDownloadingReport(true);
    try {
      const findings = await getAllScanFindings(scanId);
      const report = buildRecommendationsReport(data, findings.items, findings.complete);
      const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${safeFilename(data.repository_name ?? "repository")}-scan-${scanId}-recommendations.md`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
      toast({
        title: "Recommendations downloaded",
        description: `Created a Markdown report for scan #${scanId}.`,
        variant: "success",
      });
    } catch (error) {
      const message =
        error instanceof ApiError ? error.message : "The recommendations report could not be created.";
      toast({ title: "Report download failed", description: message, variant: "error" });
    } finally {
      setDownloadingReport(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Scan #${scanId}`}
        description={
          data
            ? `${data.repository_name ?? "Unknown repository"} · profile ${data.profile}`
            : "Loading scan..."
        }
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              disabled={
                !data ||
                downloadingReport ||
                data.status === "queued" ||
                data.status === "running"
              }
              onClick={() => void handleDownloadRecommendations()}
            >
              <Download />
              {downloadingReport
                ? "Preparing report..."
                : data?.status === "queued" || data?.status === "running"
                  ? "Available after scan"
                  : "Download recommendations"}
            </Button>
            <Button variant="outline" size="sm" onClick={() => navigate("/scans/new")}>
              <Play />
              Run again
            </Button>
            {data?.status === "queued" ? (
              <Button
                variant="destructive"
                size="sm"
                disabled={cancelling}
                onClick={() => void handleCancel()}
              >
                <XCircle />
                {cancelling ? "Cancelling..." : "Cancel scan"}
              </Button>
            ) : null}
          </>
        }
      />

      <DataState
        loading={scan.loading}
        error={scan.error}
        onRetry={() => void scan.reload()}
        loadingRows={3}
      >
        {data ? (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-3">
              <ScanStatusBadge status={data.status} />
              <span className="text-xs text-muted-foreground">
                Created {formatRelative(data.created_at)}
              </span>
              {data.started_at ? (
                <span className="text-xs text-muted-foreground">
                  Started {formatRelative(data.started_at)}
                </span>
              ) : null}
              {data.completed_at ? (
                <span className="text-xs text-muted-foreground">
                  Completed {formatRelative(data.completed_at)}
                </span>
              ) : null}
              {data.commit_sha ? (
                <span className="font-mono text-xs text-muted-foreground">
                  {data.commit_sha.slice(0, 10)}
                </span>
              ) : null}
            </div>

            {data.error ? (
              <Alert variant="destructive">
                <AlertTitle>Scan error</AlertTitle>
                <AlertDescription>{data.error}</AlertDescription>
              </Alert>
            ) : null}

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Score"
                value={
                  <span className={scoreColor(data.overall_score)}>
                    {formatScore(data.overall_score)}
                  </span>
                }
                icon={Gauge}
              />
              <StatCard
                label="Critical"
                value={formatCount(data.critical_count)}
                tone="critical"
                icon={AlertOctagon}
              />
              <StatCard
                label="High"
                value={formatCount(data.high_count)}
                tone="high"
                icon={ShieldAlert}
              />
              <StatCard
                label="Total findings"
                value={formatCount(data.total_findings)}
                icon={ListChecks}
              />
            </div>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Result</CardTitle>
                <CardDescription>Verdict, tests and AI review for this scan.</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
                <FactRow label="Gate" value={<GateBadge gate={data.gate} />} />
                <FactRow label="Duration" value={formatDuration(data.duration_ms)} />
                <FactRow
                  label="Test status"
                  value={data.test_status ? titleCase(data.test_status) : "—"}
                />
                <FactRow
                  label="AI review"
                  value={data.ai_review_status ? titleCase(data.ai_review_status) : "Not requested"}
                />
                <FactRow label="Tests executed" value={formatCount(data.tests_executed)} />
                <FactRow label="Tests passed" value={formatCount(data.tests_passed)} />
                <FactRow label="Tests failed" value={formatCount(data.tests_failed)} />
                <FactRow label="Tests skipped" value={formatCount(data.tests_skipped)} />
              </CardContent>
            </Card>

            {data.coverage_gaps.length ? (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>Coverage gaps</CardTitle>
                  <CardDescription>What the engine could not analyse.</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                    {data.coverage_gaps.map((gap, index) => (
                      <li key={index}>{gap}</li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ) : null}

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Scan progress</CardTitle>
                <CardDescription>The phases the engine works through, in order.</CardDescription>
              </CardHeader>
              <CardContent>
                <ScanPhases events={events} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Event timeline</CardTitle>
                <CardDescription>Events emitted by the scan engine.</CardDescription>
              </CardHeader>
              <CardContent>
                {events.length ? (
                  <ol className="space-y-3">
                    {events.map((event) => (
                      <li key={event.id} className="flex gap-3">
                        <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-primary" />
                        <div className="min-w-0 flex-1 space-y-0.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-medium">{titleCase(event.stage)}</span>
                            {event.status ? (
                              <Badge variant="muted">{titleCase(event.status)}</Badge>
                            ) : null}
                            <span className="text-[11px] text-muted-foreground">
                              {formatRelative(event.ts)}
                            </span>
                          </div>
                          {event.message ? (
                            <p className="text-sm text-muted-foreground">{event.message}</p>
                          ) : null}
                        </div>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="py-6 text-center text-sm text-muted-foreground">
                    The engine has not emitted any events for this scan yet.
                  </p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Findings</CardTitle>
                <CardDescription>
                  {findings.data ? `${formatCount(findings.data.total)} recorded` : "Loading findings..."}
                </CardDescription>
              </CardHeader>
              <CardContent className="px-0 pb-0">
                <DataState
                  loading={findings.loading}
                  error={findings.error}
                  onRetry={() => void findings.reload()}
                  loadingRows={2}
                >
                  {(findings.data?.items ?? []).length ? (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Severity</TableHead>
                          <TableHead>Rule</TableHead>
                          <TableHead>Location</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(findings.data?.items ?? []).map((finding) => (
                          <TableRow key={finding.id}>
                            <TableCell>
                              <SeverityBadge severity={finding.severity} />
                            </TableCell>
                            <TableCell className="font-medium">{finding.rule}</TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground">
                              {finding.file}:{finding.line}
                            </TableCell>
                            <TableCell>
                              <FindingStatusBadge status={finding.status} />
                            </TableCell>
                            <TableCell>
                              <Button asChild variant="ghost" size="sm">
                                <Link to={`/findings/${finding.id}`}>Open</Link>
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  ) : (
                    <p className="px-5 py-8 text-center text-sm text-muted-foreground">
                      No findings were recorded for this scan.
                    </p>
                  )}
                </DataState>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </DataState>
    </div>
  );
}

const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const MANUAL_REVIEW_AREAS = [
  "Authentication, authorization, and access-control boundaries",
  "Input validation, output encoding, and injection resistance",
  "Secrets handling, privacy, and sensitive-data exposure",
  "Dependency provenance, known vulnerabilities, and supply-chain controls",
  "API contracts, data integrity, and database transaction behavior",
  "Error handling, logging, monitoring, and recovery behavior",
  "Performance, scalability, and resource-exhaustion behavior",
  "Accessibility, keyboard navigation, and assistive-technology support",
  "Deployment configuration, TLS, backups, and operational readiness",
  "Test quality, edge cases, and regression coverage beyond this scan",
  "Architecture boundaries, maintainability, and technical debt",
  "User and operator documentation, setup, and incident procedures",
];

async function getAllScanFindings(
  scanId: number,
): Promise<{ items: Finding[]; complete: boolean }> {
  const pageSize = 200;
  const items: Finding[] = [];
  let total = 0;
  let offset = 0;

  do {
    const page = await api.findings.list({ scan_id: scanId, limit: pageSize, offset });
    items.push(...page.items);
    total = page.total;
    if (!page.items.length) break;
    offset += page.items.length;
  } while (offset < total);

  return { items, complete: items.length >= total };
}

function buildRecommendationsReport(scan: Scan, findings: Finding[], findingsComplete: boolean): string {
  const actionableFindings = findings.filter(
    (finding) => finding.status !== "resolved" && finding.status !== "dismissed",
  );
  const closedFindings = findings.length - actionableFindings.length;
  const lines = [
    `# Post-scan recommendations: ${scan.repository_name ?? "Unknown repository"}`,
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "> This report is based on persisted results for this scan. Recommendations are not a substitute for reviewing the evidence and validating each change.",
    "",
    "## Scan summary",
    "",
    `- Scan: #${scan.id}`,
    `- Repository: ${scan.repository_name ?? "Unknown"}`,
    `- Source: ${scan.repository_source ?? "Not recorded"}`,
    `- Status: ${titleCase(scan.status)}`,
    `- Profile: ${scan.profile}`,
    `- Commit: ${scan.commit_sha ?? "Not recorded"}`,
    `- Score: ${scan.overall_score === null ? "Not available" : `${scan.overall_score.toFixed(1)} / 100`}`,
    `- Gate: ${scan.gate ?? "Not recorded"}`,
    `- Findings: ${findings.length}${findingsComplete ? "" : ` of ${scan.total_findings ?? "unknown"} loaded`}`,
    `- Findings marked for action: ${actionableFindings.length}`,
    `- Critical / high: ${scan.critical_count ?? "Not recorded"} / ${scan.high_count ?? "Not recorded"}`,
    `- Test status: ${scan.test_status ?? "Not recorded"}`,
    `- Tests executed / passed / failed / skipped: ${scan.tests_executed ?? "Not recorded"} / ${scan.tests_passed ?? "Not recorded"} / ${scan.tests_failed ?? "Not recorded"} / ${scan.tests_skipped ?? "Not recorded"}`,
    "",
    "## Prioritized recommendations",
    "",
  ];

  lines.push(
    `Resolved or dismissed findings excluded from the action list: ${closedFindings}.`,
    "",
  );
  if (!actionableFindings.length) {
    lines.push(
      !findingsComplete
        ? "No actionable findings were loaded, but the finding list is incomplete. Inspect the remaining results in the dashboard."
        : findings.length
          ? "No findings currently marked for action. Confirm resolved or dismissed findings remain valid and rerun the scan after changes."
          : "No findings were recorded. Review the coverage gaps and manual checklist below; absence of findings does not prove the repository is defect-free.",
      "",
    );
  } else {
    for (const severity of FINDING_SEVERITIES) {
      const group = actionableFindings.filter((finding) => finding.severity === severity);
      if (!group.length) continue;
      lines.push(`### ${titleCase(severity)} (${group.length})`, "");
      for (const finding of group) {
        lines.push(
          `- **${finding.rule}** (${finding.module}; ${finding.status})`,
          `  - Location: ${finding.file}:${finding.line}${finding.column ? `:${finding.column}` : ""}`,
          `  - Finding: ${finding.message ?? "No message recorded."}`,
          `  - Scanner suggestion: ${finding.suggestion ?? "No specific suggestion provided. Inspect the finding evidence, confirm it applies, make the smallest safe correction, and add regression coverage."}`,
          `  - Confidence / fixable: ${finding.confidence ?? "Not recorded"} / ${finding.fixable ? "Yes" : "Not marked fixable"}`,
        );
      }
      lines.push("");
    }
  }

  if (!findingsComplete) {
    lines.push(
      "> Some findings could not be loaded. Treat the recommendations above as incomplete and open the scan in the dashboard to inspect the remaining results.",
      "",
    );
  }

  lines.push("## Test and coverage actions", "");
  if (scan.tests_failed) {
    lines.push(`- Fix the ${scan.tests_failed} failing test(s), then rerun the affected tests and the scan profile.`, "");
  } else if (!scan.tests_executed) {
    lines.push("- No tests are recorded as executed. Run the project test suite and ensure the scan profile is configured to execute tests where supported.", "");
  } else if (scan.tests_skipped) {
    lines.push(`- Review why ${scan.tests_skipped} test(s) were skipped and run them in an appropriate environment if possible.`, "");
  } else if (scan.test_status) {
    lines.push(`- Tests report \`${scan.test_status}\`. Preserve the passing checks and add regression tests for any fixes above.`, "");
  } else {
    lines.push("- Test execution status was not recorded. Verify test coverage independently and add regression checks for fixes.", "");
  }

  if (scan.coverage_gaps.length) {
    lines.push("Coverage gaps reported by the scanner:", "");
    for (const gap of scan.coverage_gaps) lines.push(`- ${gap}`);
    lines.push("", "Resolve or explicitly accept each gap, then rerun the scan so the result reflects the additional coverage.", "");
  } else {
    lines.push("The scanner recorded no coverage gaps. This does not establish that every quality or security area was assessed.", "");
  }

  lines.push(
    "## Scanner versions and options",
    "",
    "Recorded scanner versions:",
    "",
    "```json",
    JSON.stringify(scan.scanner_versions, null, 2),
    "```",
    "",
    "Recorded scan options:",
    "",
    "```json",
    JSON.stringify(scan.options, null, 2),
    "```",
    "",
  );

  lines.push(
    "## Broader manual review checklist",
    "",
    "These areas are not established by this scan report. Review them separately; scanner coverage should only be claimed where scan evidence explicitly supports it.",
    "",
  );
  for (const area of MANUAL_REVIEW_AREAS) {
    lines.push(`- [ ] **Not assessed by this scan:** ${area}`);
  }

  lines.push(
    "",
    "## Verification before closing",
    "",
    "- Review each finding's evidence and confirm it is valid before changing code.",
    "- Fix root causes without suppressing scanner rules, weakening tests, or hiding findings.",
    "- Add or update regression tests and run the relevant test suite.",
    "- Rerun the same scan profile against the updated commit and compare fresh findings.",
    "- Verify the gate passes and target a score of 97 or higher; report only what the new scan confirms.",
    "",
  );

  return lines.join("\n");
}

function safeFilename(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "repository";
}

export function ScanComparePage() {
  const [searchParams] = useSearchParams();
  const base = Number.parseInt(searchParams.get("base") ?? "", 10);
  const head = Number.parseInt(searchParams.get("head") ?? "", 10);
  const valid = Number.isFinite(base) && Number.isFinite(head) && base !== head;

  const comparison = useAsync(() => api.scans.compare(base, head), [base, head], { enabled: valid });

  if (!valid) {
    return (
      <EmptyState
        icon={Radar}
        title="Nothing to compare"
        description="Pick two different scans of the same repository on the scans page to compare their findings."
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/scans">Back to scans</Link>
          </Button>
        }
      />
    );
  }

  const data = comparison.data;
  const delta = data?.score_delta ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan comparison"
        description={
          data
            ? `Scan #${data.base_scan_id} (base) against scan #${data.head_scan_id} (head).`
            : "Comparing two scans."
        }
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to="/scans">All scans</Link>
          </Button>
        }
      />

      <DataState
        loading={comparison.loading}
        error={comparison.error}
        onRetry={() => void comparison.reload()}
        loadingRows={2}
      >
        {data ? (
          <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-3">
              <StatCard
                label="Base score"
                value={
                  <span className={scoreColor(data.base_score)}>{formatScore(data.base_score)}</span>
                }
              />
              <StatCard
                label="Head score"
                value={
                  <span className={scoreColor(data.head_score)}>{formatScore(data.head_score)}</span>
                }
              />
              <StatCard
                label="Score delta"
                value={delta === null ? "—" : `${delta > 0 ? "+" : ""}${delta.toFixed(1)}`}
                tone={delta === null ? "default" : delta >= 0 ? "pass" : "fail"}
                hint={
                  delta === null
                    ? "A score is missing from one of the scans."
                    : delta >= 0
                      ? "The head scan improved."
                      : "The head scan regressed."
                }
              />
            </div>

            <FindingDeltaList
              title="Added findings"
              description="Present in the head scan but not the base scan."
              items={data.added}
              emptyText="No new findings were introduced."
            />
            <FindingDeltaList
              title="Resolved findings"
              description="Present in the base scan but no longer reported."
              items={data.resolved}
              emptyText="No findings were resolved."
            />

            <Card>
              <CardContent className="p-5 text-sm">
                <span className="text-muted-foreground">Unchanged findings: </span>
                <span className="font-medium tabular-nums">{formatCount(data.unchanged_count)}</span>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </DataState>
    </div>
  );
}

function FindingDeltaList({
  title,
  description,
  items,
  emptyText,
}: {
  title: string;
  description: string;
  items: ComparedFinding[];
  emptyText: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className={items.length ? "px-0 pb-0" : ""}>
        {items.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Message</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item, index) => (
                <TableRow key={`${item.rule}-${item.file}-${item.line}-${index}`}>
                  <TableCell>
                    <SeverityBadge severity={item.severity} />
                  </TableCell>
                  <TableCell className="font-medium">{item.rule}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {item.file}:{item.line}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{item.message ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <p className="text-sm text-muted-foreground">{emptyText}</p>
        )}
      </CardContent>
    </Card>
  );
}

function FactRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="font-medium">{value}</div>
    </div>
  );
}
