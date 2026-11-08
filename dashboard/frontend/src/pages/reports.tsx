import { AlertOctagon, FileBarChart, Gauge, Printer, ShieldAlert, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { Markdown } from "@/components/common/markdown";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import { StatCard } from "@/components/common/stat-card";
import { ScanStatusBadge } from "@/components/common/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAsync } from "@/hooks/use-async";
import { ApiError, api } from "@/lib/api";
import {
  formatCount,
  formatDateTime,
  formatDuration,
  formatScore,
  scoreColor,
  SEVERITY_ORDER,
  titleCase,
} from "@/lib/format";
import type { SummaryResponse } from "@/types/api";

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "The request failed.";
}

/** Render an arbitrary stored option value without inventing anything. */
function displayValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function ReportsPage() {
  const { repositories, activeRepositoryId, setActiveRepositoryId } = useApp();

  const [scanId, setScanId] = useState<number | null>(null);
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const scans = useAsync(
    () => api.scans.list({ repository_id: activeRepositoryId ?? undefined, limit: 100 }),
    [activeRepositoryId],
    { enabled: activeRepositoryId !== null },
  );

  // Keep the scan selection valid whenever the repository (and its scan list) changes.
  useEffect(() => {
    const items = scans.data?.items ?? [];
    if (!items.length) {
      setScanId(null);
      return;
    }
    if (!items.some((scan) => scan.id === scanId)) {
      setScanId(items[0].id);
    }
  }, [scans.data, scanId]);

  const scanItems = scans.data?.items ?? [];
  const selectedScan = scanItems.find((scan) => scan.id === scanId) ?? null;

  const findings = useAsync(
    () => api.findings.list({ scan_id: scanId ?? 0, limit: 200 }),
    [scanId],
    { enabled: scanId !== null },
  );

  const groupedFindings = useMemo(() => {
    const items = findings.data?.items ?? [];
    return SEVERITY_ORDER.map((severity) => ({
      severity,
      items: items.filter((finding) => finding.severity === severity),
    })).filter((group) => group.items.length > 0);
  }, [findings.data]);

  async function handleGenerate() {
    if (!selectedScan) return;
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const response = await api.ai.summary({
        repository_id: selectedScan.repository_id,
        scan_id: selectedScan.id,
      });
      setSummary(response);
    } catch (caught) {
      setSummaryError(errorMessage(caught));
    } finally {
      setSummaryLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="A factual report for one scan, plus an optional AI-written executive summary."
        actions={
          <Button variant="outline" size="sm" onClick={() => window.print()}>
            <Printer />
            Print / Save as PDF
          </Button>
        }
      />

      {!repositories.length ? (
        <EmptyState
          icon={FileBarChart}
          title="No repositories to report on"
          description="Register a repository and run a scan first. Reports are built strictly from persisted scan results."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/repositories">Add a repository</Link>
            </Button>
          }
        />
      ) : (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle>Report scope</CardTitle>
              <CardDescription>Choose the repository and the scan to report on.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="report-repository">Repository</Label>
                <Select
                  value={activeRepositoryId === null ? undefined : String(activeRepositoryId)}
                  onValueChange={(value) => setActiveRepositoryId(Number(value))}
                >
                  <SelectTrigger id="report-repository">
                    <SelectValue placeholder="Select a repository" />
                  </SelectTrigger>
                  <SelectContent>
                    {repositories.map((repository) => (
                      <SelectItem key={repository.id} value={String(repository.id)}>
                        {repository.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="report-scan">Scan</Label>
                <DataState
                  loading={scans.loading}
                  error={scans.error}
                  onRetry={() => void scans.reload()}
                  loadingRows={1}
                >
                  <Select
                    value={scanId === null ? undefined : String(scanId)}
                    onValueChange={(value) => setScanId(Number(value))}
                    disabled={!scanItems.length}
                  >
                    <SelectTrigger id="report-scan">
                      <SelectValue
                        placeholder={
                          activeRepositoryId === null
                            ? "Select a repository first"
                            : "Select a scan"
                        }
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {scanItems.map((scan) => (
                        <SelectItem key={scan.id} value={String(scan.id)}>
                          {`#${scan.id} · ${titleCase(scan.profile)} · ${formatDateTime(
                            scan.created_at,
                          )}`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </DataState>
              </div>
            </CardContent>
          </Card>

          {!selectedScan ? (
            <EmptyState
              icon={FileBarChart}
              title="No scan selected"
              description={
                activeRepositoryId === null
                  ? "Select a repository to list its scans."
                  : "This repository has no scans yet. A scan is required to build a report."
              }
              action={
                <Button asChild size="sm" variant="outline">
                  <Link to="/scans/new">Run a scan</Link>
                </Button>
              }
            />
          ) : (
            <Tabs defaultValue="overview">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="findings">Findings</TabsTrigger>
                <TabsTrigger value="summary">Executive summary</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <StatCard
                    label="Overall score"
                    value={
                      <span className={scoreColor(selectedScan.overall_score)}>
                        {formatScore(selectedScan.overall_score)}
                      </span>
                    }
                    icon={Gauge}
                  />
                  <StatCard
                    label="Critical"
                    value={formatCount(selectedScan.critical_count)}
                    tone="critical"
                    icon={AlertOctagon}
                  />
                  <StatCard
                    label="High"
                    value={formatCount(selectedScan.high_count)}
                    tone="high"
                    icon={ShieldAlert}
                  />
                  <StatCard
                    label="Total findings"
                    value={formatCount(selectedScan.total_findings)}
                    icon={FileBarChart}
                  />
                </div>

                {selectedScan.error ? (
                  <Alert variant="destructive">
                    <AlertTitle>Scan error</AlertTitle>
                    <AlertDescription>{selectedScan.error}</AlertDescription>
                  </Alert>
                ) : null}

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>Scan facts</CardTitle>
                    <CardDescription>Every value comes from the stored scan record.</CardDescription>
                  </CardHeader>
                  <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    <Field label="Scan">
                      <Link
                        to={`/scans/${selectedScan.id}`}
                        className="text-primary hover:underline"
                      >
                        #{selectedScan.id}
                      </Link>
                    </Field>
                    <Field label="Status">
                      <ScanStatusBadge status={selectedScan.status} />
                    </Field>
                    <Field label="Profile">{titleCase(selectedScan.profile)}</Field>
                    <Field label="Created">{formatDateTime(selectedScan.created_at)}</Field>
                    <Field label="Started">{formatDateTime(selectedScan.started_at)}</Field>
                    <Field label="Completed">{formatDateTime(selectedScan.completed_at)}</Field>
                    <Field label="Duration">{formatDuration(selectedScan.duration_ms)}</Field>
                    <Field label="Gate">
                      <GateBadge gate={selectedScan.gate} />
                    </Field>
                    <Field label="AI review status">{selectedScan.ai_review_status ?? "—"}</Field>
                    <Field label="Test status">{selectedScan.test_status ?? "—"}</Field>
                    <Field label="Tests executed">{formatCount(selectedScan.tests_executed)}</Field>
                    <Field label="Tests passed">{formatCount(selectedScan.tests_passed)}</Field>
                    <Field label="Tests failed">{formatCount(selectedScan.tests_failed)}</Field>
                    <Field label="Tests skipped">{formatCount(selectedScan.tests_skipped)}</Field>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>Coverage gaps</CardTitle>
                    <CardDescription>Checks that could not be completed for this scan.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {selectedScan.coverage_gaps.length ? (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedScan.coverage_gaps.map((gap) => (
                          <Badge key={gap} variant="muted">
                            {gap}
                          </Badge>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No coverage gaps reported.</p>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>Scan options</CardTitle>
                    <CardDescription>The options this scan was started with.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {Object.keys(selectedScan.options).length ? (
                      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                        {Object.entries(selectedScan.options).map(([key, value]) => (
                          <div key={key} className="space-y-0.5">
                            <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                              {titleCase(key)}
                            </dt>
                            <dd className="text-sm">{displayValue(value)}</dd>
                          </div>
                        ))}
                      </dl>
                    ) : (
                      <p className="text-sm text-muted-foreground">No options were recorded.</p>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="findings" className="space-y-4">
                <DataState
                  loading={findings.loading}
                  error={findings.error}
                  onRetry={() => void findings.reload()}
                  loadingRows={3}
                >
                  {groupedFindings.length ? (
                    <div className="space-y-4">
                      {groupedFindings.map((group) => (
                        <Card key={group.severity}>
                          <CardHeader className="flex-row items-center justify-between pb-2">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={group.severity} />
                              <CardTitle>{titleCase(group.severity)}</CardTitle>
                            </div>
                            <span className="text-sm text-muted-foreground">
                              {formatCount(group.items.length)}
                            </span>
                          </CardHeader>
                          <CardContent className="px-0 pb-0">
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead>Rule</TableHead>
                                  <TableHead>File</TableHead>
                                  <TableHead>Message</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {group.items.map((finding) => (
                                  <TableRow key={finding.id}>
                                    <TableCell className="font-medium">{finding.rule}</TableCell>
                                    <TableCell className="font-mono text-xs">
                                      {finding.file}
                                      <span className="text-muted-foreground">:{finding.line}</span>
                                    </TableCell>
                                    <TableCell className="max-w-[420px] text-sm text-muted-foreground">
                                      {finding.message ?? "—"}
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      icon={ShieldAlert}
                      title="No findings recorded"
                      description="This scan recorded no findings."
                    />
                  )}
                </DataState>
              </TabsContent>

              <TabsContent value="summary" className="space-y-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>Executive summary</CardTitle>
                    <CardDescription>
                      Generated from this scan's persisted results. The report works fully without
                      AI.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <Button onClick={() => void handleGenerate()} disabled={summaryLoading}>
                      <Sparkles />
                      {summaryLoading ? "Generating…" : "Generate executive summary"}
                    </Button>

                    {summaryError ? (
                      <Alert variant="warning">
                        <AlertTitle>AI request failed</AlertTitle>
                        <AlertDescription>{summaryError}</AlertDescription>
                      </Alert>
                    ) : null}

                    {summary && (!summary.configured || summary.error) ? (
                      <Alert variant="warning">
                        <AlertTitle>AI is not configured</AlertTitle>
                        <AlertDescription>
                          {summary.error
                            ? summary.error
                            : "No AI provider is configured, so no summary was generated. Configure one in Settings to enable executive summaries."}
                        </AlertDescription>
                      </Alert>
                    ) : null}

                    {summary && summary.configured && !summary.error ? (
                      <div className="space-y-3">
                        {summary.text.trim() ? (
                          <Markdown text={summary.text} />
                        ) : (
                          <p className="text-sm text-muted-foreground">
                            The provider returned an empty summary.
                          </p>
                        )}
                        {summary.provider || summary.model ? (
                          <p className="text-xs text-muted-foreground">
                            {summary.provider ? `Provider: ${summary.provider}` : ""}
                            {summary.provider && summary.model ? " · " : ""}
                            {summary.model ? `Model: ${summary.model}` : ""}
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          )}
        </>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="text-sm">{children}</div>
    </div>
  );
}
