import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AlertOctagon, Compass, Gauge, ListChecks, Play, Radar, ShieldAlert, XCircle } from "lucide-react";

import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
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
import type { ComparedFinding, ScanEvent } from "@/types/api";

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
