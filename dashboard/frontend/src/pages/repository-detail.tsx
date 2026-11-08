import { Radar, RefreshCw, SearchX, Trash2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
import { ScanStatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { ApiError, api } from "@/lib/api";
import {
  formatCount,
  formatDateTime,
  formatDuration,
  formatScore,
  scoreColor,
  titleCase,
} from "@/lib/format";
import { cn } from "@/lib/utils";

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "The request failed.";
}

export function RepositoryDetailPage() {
  const params = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { reload } = useApp();

  const id = Number.parseInt(params.repositoryId ?? "", 10);
  const valid = Number.isFinite(id);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const repository = useAsync(() => api.repositories.get(id), [id], { enabled: valid });
  const scans = useAsync(() => api.repositories.scans(id, { limit: 20 }), [id], { enabled: valid });

  if (!valid) {
    return (
      <EmptyState
        icon={SearchX}
        title="Repository not found"
        description="The repository id in the URL is not a number."
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/repositories">Back to repositories</Link>
          </Button>
        }
      />
    );
  }

  const data = repository.data;
  const latest = data?.latest_scan ?? null;
  const scanItems = scans.data?.items ?? [];
  // The full scan record carries tests and duration the summary omits.
  const latestFull = latest ? scanItems.find((scan) => scan.id === latest.id) ?? null : null;

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await api.repositories.refresh(id);
      toast({ title: "Metadata refreshed", variant: "success" });
      await repository.reload(true);
    } catch (caught) {
      toast({ title: "Refresh failed", description: errorMessage(caught), variant: "error" });
    } finally {
      setRefreshing(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await api.repositories.remove(id);
      toast({ title: "Repository deleted", variant: "success" });
      await reload();
      navigate("/repositories");
    } catch (caught) {
      toast({ title: "Delete failed", description: errorMessage(caught), variant: "error" });
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={data?.name ?? `Repository #${id}`}
        description={data ? `${data.source} · ${titleCase(data.source_type)}` : "Repository details."}
        actions={
          <>
            <Button asChild size="sm">
              <Link to="/scans/new">
                <Radar />
                New scan
              </Link>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleRefresh()}
              disabled={refreshing || !data}
            >
              <RefreshCw className={refreshing ? "animate-spin" : undefined} />
              Refresh metadata
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:text-destructive"
              onClick={() => setConfirmOpen(true)}
              disabled={!data}
            >
              <Trash2 />
              Delete
            </Button>
          </>
        }
      />

      <DataState
        loading={repository.loading}
        error={repository.error}
        onRetry={() => void repository.reload()}
        loadingRows={3}
      >
        {data ? (
          <>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Metadata</CardTitle>
                <CardDescription>Detected from the repository by static analysis.</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Field label="Main language">{data.main_language ?? "—"}</Field>
                <Field label="Package manager">{data.package_manager ?? "—"}</Field>
                <Field label="Default branch">{data.default_branch ?? "—"}</Field>
                <Field label="Last commit">
                  {data.last_commit_sha ? data.last_commit_sha.slice(0, 7) : "—"}
                </Field>
                <Field label="Source type">
                  <Badge variant="muted">{titleCase(data.source_type)}</Badge>
                </Field>
                <Field label="Source">{data.source}</Field>
                <Field label="Frameworks">
                  <Chips values={data.frameworks} />
                </Field>
                <Field label="Databases">
                  <Chips values={data.database_tech} />
                </Field>
                <Field label="Auth">
                  <Chips values={data.auth_tech} />
                </Field>
                <Field label="Deployment">
                  <Chips values={data.deployment} />
                </Field>
                <Field label="Created">{formatDateTime(data.created_at)}</Field>
                <Field label="Updated">{formatDateTime(data.updated_at)}</Field>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Latest scan</CardTitle>
                <CardDescription>The most recent scan recorded for this repository.</CardDescription>
              </CardHeader>
              <CardContent>
                {latest ? (
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    <Field label="Score">
                      <span
                        className={cn(
                          "text-lg font-semibold tabular-nums",
                          scoreColor(latest.overall_score),
                        )}
                      >
                        {formatScore(latest.overall_score)}
                      </span>
                    </Field>
                    <Field label="Gate">
                      <GateBadge gate={latest.gate} />
                    </Field>
                    <Field label="Status">
                      <ScanStatusBadge status={latest.status} />
                    </Field>
                    <Field label="Critical">{formatCount(latest.critical_count)}</Field>
                    <Field label="High">{formatCount(latest.high_count)}</Field>
                    <Field label="Tests">
                      {latestFull && latestFull.tests_executed !== null
                        ? `${formatCount(latestFull.tests_passed)} / ${formatCount(
                            latestFull.tests_executed,
                          )} passed`
                        : latest.test_status ?? "—"}
                    </Field>
                    <Field label="Duration">{formatDuration(latestFull?.duration_ms ?? null)}</Field>
                    <Field label="Completed">{formatDateTime(latest.completed_at)}</Field>
                    <Field label="Scan">
                      <Link to={`/scans/${latest.id}`} className="text-primary hover:underline">
                        Open scan #{latest.id}
                      </Link>
                    </Field>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    This repository has not been scanned yet.
                  </p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex-row items-center justify-between pb-2">
                <div className="space-y-1.5">
                  <CardTitle>Scan history</CardTitle>
                  <CardDescription>The 20 most recent scans for this repository.</CardDescription>
                </div>
                <Link to="/findings" className="text-sm text-primary hover:underline">
                  View findings
                </Link>
              </CardHeader>
              <CardContent className="px-0 pb-0">
                <div className="px-5 pb-3">
                  <p className="text-xs text-muted-foreground">
                    The findings page is filtered by the repository selected in the top bar.
                  </p>
                </div>
                <DataState
                  loading={scans.loading}
                  error={scans.error}
                  onRetry={() => void scans.reload()}
                  loadingRows={3}
                >
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Scan</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Profile</TableHead>
                        <TableHead>Score</TableHead>
                        <TableHead>Gate</TableHead>
                        <TableHead>Findings</TableHead>
                        <TableHead>Started</TableHead>
                        <TableHead>Completed</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {scanItems.map((scan) => (
                        <TableRow key={scan.id}>
                          <TableCell>
                            <Link
                              to={`/scans/${scan.id}`}
                              className="font-medium hover:text-primary"
                            >
                              #{scan.id}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <ScanStatusBadge status={scan.status} />
                          </TableCell>
                          <TableCell>{titleCase(scan.profile)}</TableCell>
                          <TableCell
                            className={cn(
                              "font-semibold tabular-nums",
                              scoreColor(scan.overall_score),
                            )}
                          >
                            {formatScore(scan.overall_score)}
                          </TableCell>
                          <TableCell>
                            <GateBadge gate={scan.gate} />
                          </TableCell>
                          <TableCell className="tabular-nums">
                            {formatCount(scan.total_findings)}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDateTime(scan.started_at)}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDateTime(scan.completed_at)}
                          </TableCell>
                        </TableRow>
                      ))}
                      {!scanItems.length ? (
                        <TableRow>
                          <TableCell
                            colSpan={8}
                            className="py-8 text-center text-sm text-muted-foreground"
                          >
                            No scans recorded yet.
                          </TableCell>
                        </TableRow>
                      ) : null}
                    </TableBody>
                  </Table>
                </DataState>
              </CardContent>
            </Card>
          </>
        ) : null}
      </DataState>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete repository</DialogTitle>
            <DialogDescription>
              This removes {data?.name ?? `repository #${id}`} and its scan history from the
              dashboard. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={deleting}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void handleDelete()} disabled={deleting}>
              <Trash2 />
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="text-sm">{children}</div>
    </div>
  );
}

function Chips({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-sm text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <Badge key={value} variant="muted">
          {value}
        </Badge>
      ))}
    </div>
  );
}
