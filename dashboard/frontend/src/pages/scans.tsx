import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Radar } from "lucide-react";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
import { ScanStatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { api } from "@/lib/api";
import {
  formatCount,
  formatDuration,
  formatRelative,
  formatScore,
  scoreColor,
  titleCase,
} from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Scan } from "@/types/api";

const LIMIT = 25;

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

  const items = scans.data?.items ?? [];
  const total = scans.data?.total ?? 0;
  const active = items.some((scan) => scan.status === "queued" || scan.status === "running");

  // Poll while any listed scan is queued or running. Nothing is fabricated here.
  useEffect(() => {
    if (!active) return;
    const interval = window.setInterval(() => {
      void scans.reload(true);
    }, 3000);
    return () => window.clearInterval(interval);
  }, [active, scans.reload]);

  useEffect(() => {
    setSelected([]);
  }, [repositoryFilter, statusFilter, offset]);

  const canCompare = selected.length === 2;
  const prevDisabled = offset === 0;
  const nextDisabled = offset + LIMIT >= total;

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
                      <TableHead>Score</TableHead>
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
                          <TableCell
                            className={cn("font-semibold tabular-nums", scoreColor(scan.overall_score))}
                          >
                            {formatScore(scan.overall_score)}
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
                            <Button asChild variant="ghost" size="sm">
                              <Link to={`/scans/${scan.id}`}>Open</Link>
                            </Button>
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
    </div>
  );
}
