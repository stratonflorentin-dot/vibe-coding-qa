import {
  Activity,
  AlertOctagon,
  ArrowUpRight,
  Gauge,
  GitBranchPlus,
  Radar,
  ShieldAlert,
  TestTube2,
} from "lucide-react";
import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import { StatCard } from "@/components/common/stat-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAsync } from "@/hooks/use-async";
import { api } from "@/lib/api";
import {
  formatCount,
  formatDuration,
  formatRelative,
  formatScore,
  gateLabel,
  scoreColor,
  severityHex,
  SEVERITY_ORDER,
  titleCase,
} from "@/lib/format";
import { cn } from "@/lib/utils";

export function OverviewPage() {
  const { activeRepositoryId, activeRepository, repositories } = useApp();

  const overview = useAsync(() => api.dashboard.overview(activeRepositoryId ?? undefined), [
    activeRepositoryId,
  ]);
  const activity = useAsync(() => api.dashboard.activity(12), []);

  const severityData = useMemo(() => {
    const breakdown = overview.data?.severity_breakdown ?? {};
    return SEVERITY_ORDER.filter((severity) => (breakdown[severity] ?? 0) > 0).map((severity) => ({
      severity,
      label: titleCase(severity),
      count: breakdown[severity] ?? 0,
      color: severityHex(severity),
    }));
  }, [overview.data]);

  const categoryData = useMemo(
    () =>
      Object.entries(overview.data?.category_breakdown ?? {})
        .map(([module, count]) => ({ module: titleCase(module), count }))
        .sort((a, b) => b.count - a.count),
    [overview.data],
  );

  const scoreSeries = useMemo(
    () =>
      (overview.data?.score_history ?? [])
        .filter((row) => row.score !== null && row.score !== undefined)
        .map((row) => ({
          label: shortLabel(row.at as string | null, row.scan_id as number),
          score: Number(row.score),
          repository: String(row.repository ?? ""),
        })),
    [overview.data],
  );

  const hasData = overview.data?.has_data ?? false;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        description={
          activeRepository
            ? `Health and history for ${activeRepository.name}.`
            : "Health and history across every registered repository."
        }
        actions={
          <Button asChild size="sm">
            <Link to="/scans/new">
              <Radar />
              New scan
            </Link>
          </Button>
        }
      />

      <DataState
        loading={overview.loading}
        error={overview.error}
        onRetry={() => void overview.reload()}
        loadingRows={2}
      >
        {!hasData ? (
          <EmptyState
            icon={Radar}
            title="No completed scan yet"
            description={
              repositories.length
                ? "Run a scan to populate the dashboard. Every number here comes from persisted scan results — nothing is estimated."
                : "Register a repository first, then run a scan. The dashboard only reports real results."
            }
            action={
              <Button asChild size="sm" variant="outline">
                <Link to={repositories.length ? "/scans/new" : "/repositories"}>
                  {repositories.length ? "Run a scan" : "Add a repository"}
                </Link>
              </Button>
            }
          />
        ) : null}
      </DataState>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Latest score"
          value={
            <span className={scoreColor(overview.data?.summary.overall_score)}>
              {formatScore(overview.data?.summary.overall_score)}
            </span>
          }
          hint={
            overview.data?.summary.overall_score === null
              ? "The latest scan produced no score."
              : "Weighted from real findings."
          }
          icon={Gauge}
        />
        <StatCard
          label="Critical"
          value={formatCount(overview.data?.summary.critical)}
          tone="critical"
          hint="In the newest completed scan."
          icon={AlertOctagon}
        />
        <StatCard
          label="High"
          value={formatCount(overview.data?.summary.high)}
          tone="high"
          hint="In the newest completed scan."
          icon={ShieldAlert}
        />
        <StatCard
          label="Open findings"
          value={formatCount(overview.data?.summary.total_open)}
          hint="Across all repositories, excluding triaged items."
          icon={Activity}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle>Score history</CardTitle>
            <CardDescription>Every completed scan, oldest to newest.</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {scoreSeries.length > 1 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={scoreSeries} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                    stroke="hsl(var(--border))"
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                    stroke="hsl(var(--border))"
                  />
                  <ChartTooltip
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "hsl(var(--popover-foreground))",
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="hsl(var(--primary))"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center">
                <p className="max-w-sm text-center text-sm text-muted-foreground">
                  A trend needs at least two completed scans. Run another scan to see how the score
                  moves.
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Findings by severity</CardTitle>
            <CardDescription>Newest completed scan per repository.</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {severityData.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 8, right: 8, bottom: 0, left: -22 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                    stroke="hsl(var(--border))"
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                    stroke="hsl(var(--border))"
                  />
                  <ChartTooltip
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 12,
                      color: "hsl(var(--popover-foreground))",
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry) => (
                      <Cell key={entry.severity} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center">
                <p className="text-sm text-muted-foreground">No findings recorded yet.</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {categoryData.length ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Findings by scanner module</CardTitle>
            <CardDescription>Which analysis module produced the issues.</CardDescription>
          </CardHeader>
          <CardContent className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={categoryData} margin={{ top: 8, right: 12, bottom: 0, left: -22 }}>
                <defs>
                  <linearGradient id="moduleFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis
                  dataKey="module"
                  tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                  stroke="hsl(var(--border))"
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                  stroke="hsl(var(--border))"
                />
                <ChartTooltip
                  contentStyle={{
                    background: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "hsl(var(--popover-foreground))",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="hsl(var(--primary))"
                  strokeWidth={2}
                  fill="url(#moduleFill)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader className="pb-2">
            <CardTitle>Repository health</CardTitle>
            <CardDescription>Latest completed scan for each repository.</CardDescription>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repository</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Gate</TableHead>
                  <TableHead>Critical / High</TableHead>
                  <TableHead>Last scan</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(overview.data?.repository_health ?? []).map((row) => (
                  <TableRow key={String(row.repository_id)}>
                    <TableCell>
                      <Link
                        to={`/repositories/${row.repository_id}`}
                        className="font-medium hover:text-primary"
                      >
                        {String(row.name)}
                      </Link>
                      <p className="text-xs text-muted-foreground">
                        {row.main_language ? String(row.main_language) : "unknown language"}
                      </p>
                    </TableCell>
                    <TableCell className={cn("font-semibold tabular-nums", scoreColor(row.score as number | null))}>
                      {formatScore(row.score as number | null)}
                    </TableCell>
                    <TableCell>
                      <GateBadge gate={(row.gate as string | null) ?? null} />
                    </TableCell>
                    <TableCell className="tabular-nums">
                      <span className="text-severity-critical">{formatCount(row.critical as number)}</span>
                      <span className="px-1 text-muted-foreground">/</span>
                      <span className="text-severity-high">{formatCount(row.high as number)}</span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatRelative(row.last_scan_at as string | null)}
                    </TableCell>
                  </TableRow>
                ))}
                {!(overview.data?.repository_health ?? []).length ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                      No repositories registered yet.
                    </TableCell>
                  </TableRow>
                ) : null}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle>Recent activity</CardTitle>
            <CardDescription>Scans, findings and remediation proposals.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <DataState
              loading={activity.loading}
              error={activity.error}
              onRetry={() => void activity.reload()}
              loadingRows={4}
            >
              {(activity.data?.items ?? []).length ? (
                (activity.data?.items ?? []).map((item, index) => (
                  <div
                    key={`${item.kind}-${index}`}
                    className="flex items-start justify-between gap-3 border-b pb-3 last:border-0 last:pb-0"
                  >
                    <div className="min-w-0 space-y-0.5">
                      <p className="truncate text-sm font-medium">{item.title}</p>
                      <p className="truncate text-xs text-muted-foreground">{item.detail}</p>
                      <div className="flex items-center gap-2 pt-0.5">
                        {item.severity ? <SeverityBadge severity={item.severity} /> : null}
                        <span className="text-[11px] text-muted-foreground">
                          {formatRelative(item.at)}
                        </span>
                      </div>
                    </div>
                    {item.scan_id ? (
                      <Link
                        to={`/scans/${item.scan_id}`}
                        className="shrink-0 text-muted-foreground transition-colors hover:text-primary"
                        aria-label="Open scan"
                      >
                        <ArrowUpRight className="h-4 w-4" />
                      </Link>
                    ) : item.finding_id ? (
                      <Link
                        to={`/findings/${item.finding_id}`}
                        className="shrink-0 text-muted-foreground transition-colors hover:text-primary"
                        aria-label="Open finding"
                      >
                        <ArrowUpRight className="h-4 w-4" />
                      </Link>
                    ) : null}
                  </div>
                ))
              ) : (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  Nothing has happened yet.
                </p>
              )}
            </DataState>
          </CardContent>
        </Card>
      </div>

      {overview.data ? (
        <Card>
          <CardContent className="grid gap-4 p-5 sm:grid-cols-4">
            <MiniFact
              icon={TestTube2}
              label="Tests executed (latest)"
              value={
                overview.data.summary.tests_executed === null
                  ? "Not executed"
                  : `${formatCount(overview.data.summary.tests_passed)} / ${formatCount(overview.data.summary.tests_executed)} passed`
              }
            />
            <MiniFact
              icon={GitBranchPlus}
              label="Repositories in scope"
              value={formatCount(overview.data.summary.repository_count)}
            />
            <MiniFact
              icon={Gauge}
              label="Latest scan duration"
              value={formatDuration(overview.data.summary.latest_scan_duration_ms)}
            />
            <MiniFact
              icon={ShieldAlert}
              label="Release gate"
              value={gateLabel(overview.data.summary.gate)}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function MiniFact({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Gauge;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-md bg-muted">
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="min-w-0">
        <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
        <p className="truncate text-sm font-medium">{value}</p>
      </div>
    </div>
  );
}

function shortLabel(at: string | null, scanId: number): string {
  if (!at) return `#${scanId}`;
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return `#${scanId}`;
  return date.toLocaleDateString(undefined, { month: "short", day: "2-digit" });
}
