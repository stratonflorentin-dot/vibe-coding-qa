import { ChevronDown, ExternalLink, Search, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { FindingStatusBadge } from "@/components/common/status-badge";
import { SeverityBadge } from "@/components/common/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAsync } from "@/hooks/use-async";
import { useDebounced } from "@/hooks/use-debounced";
import { api } from "@/lib/api";
import { groupIssues } from "@/lib/finding-groups";
import { formatCount, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Finding } from "@/types/api";

const BATCH_SIZE = 10;
const PRIORITIES = ["critical", "high", "medium", "low", "info"] as const;
const PRIORITY_STYLES = {
  critical: {
    border: "border-severity-critical",
    text: "text-severity-critical",
    fill: "bg-severity-critical",
    surface: "bg-severity-critical/10",
  },
  high: {
    border: "border-severity-high",
    text: "text-severity-high",
    fill: "bg-severity-high",
    surface: "bg-severity-high/10",
  },
  medium: {
    border: "border-severity-medium",
    text: "text-severity-medium",
    fill: "bg-severity-medium",
    surface: "bg-severity-medium/10",
  },
  low: {
    border: "border-severity-low",
    text: "text-severity-low",
    fill: "bg-severity-low",
    surface: "bg-severity-low/10",
  },
  info: {
    border: "border-severity-info",
    text: "text-severity-info",
    fill: "bg-severity-info",
    surface: "bg-severity-info/10",
  },
} as const;

export function FindingsPage() {
  const { activeRepositoryId, repositories } = useApp();
  const [searchParams, setSearchParams] = useSearchParams();
  const [repositoryId, setRepositoryId] = useState("active");
  const [module, setModule] = useState("all");
  const [status, setStatus] = useState("open");
  const [search, setSearch] = useState("");
  const [visibleCount, setVisibleCount] = useState(BATCH_SIZE);
  const parsedScanId = Number(searchParams.get("scan_id"));
  const scanId =
    Number.isSafeInteger(parsedScanId) && parsedScanId > 0 ? parsedScanId : undefined;
  const priorityParam = searchParams.get("priority");
  const selectedSeverity =
    PRIORITIES.find((priority) => priority === priorityParam) ?? null;
  const debouncedSearch = useDebounced(search);
  const selectedRepositoryId =
    scanId !== undefined || repositoryId === "all"
      ? undefined
      : repositoryId === "active"
        ? activeRepositoryId ?? undefined
        : Number(repositoryId);

  function togglePriority(priority: (typeof PRIORITIES)[number]) {
    const next = new URLSearchParams(searchParams);
    if (selectedSeverity === priority) next.delete("priority");
    else next.set("priority", priority);
    setSearchParams(next, { replace: true });
  }

  function clearScanScope() {
    const next = new URLSearchParams(searchParams);
    next.delete("scan_id");
    setSearchParams(next, { replace: true });
  }

  const result = useAsync(
    async () => {
      const allFindings: Finding[] = [];
      const pageSize = 200;
      let pageOffset = 0;
      let total = 0;

      do {
        const page = await api.findings.list({
          scan_id: scanId,
          repository_id: selectedRepositoryId,
          module: module === "all" ? undefined : [module],
          status: status === "all" ? undefined : [status],
          search: debouncedSearch || undefined,
          limit: pageSize,
          offset: pageOffset,
        });
        allFindings.push(...page.items);
        total = page.total;
        if (!page.items.length) break;
        pageOffset += page.items.length;
      } while (pageOffset < total);

      return allFindings;
    },
    [scanId, selectedRepositoryId, module, status, debouncedSearch],
  );

  useEffect(() => {
    if (scanId === undefined || selectedSeverity || result.loading || result.error || !result.data) {
      return;
    }
    const firstAvailable = PRIORITIES.find((priority) =>
      result.data?.some((finding) => finding.severity === priority),
    );
    if (!firstAvailable) return;

    const next = new URLSearchParams(searchParams);
    next.set("priority", firstAvailable);
    setSearchParams(next, { replace: true });
  }, [
    scanId,
    selectedSeverity,
    result.loading,
    result.error,
    result.data,
    searchParams,
    setSearchParams,
  ]);

  useEffect(
    () => setVisibleCount(BATCH_SIZE),
    [scanId, selectedRepositoryId, selectedSeverity, module, status, debouncedSearch],
  );

  const findings = useMemo(() => result.data ?? [], [result.data]);
  const groups = useMemo(() => groupIssues(findings), [findings]);
  const prioritySummary = useMemo(
    () =>
      PRIORITIES.map((priority) => {
        const priorityGroups = groups.filter(
          (group) => group.representative.severity === priority,
        );
        return {
          priority,
          findings: findings.filter((finding) => finding.severity === priority).length,
          issues: priorityGroups.length,
        };
      }),
    [findings, groups],
  );
  const selectedGroups = selectedSeverity
    ? groups.filter((group) => group.representative.severity === selectedSeverity)
    : [];
  const visibleGroups = selectedGroups.slice(0, visibleCount);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        description="Choose a severity to review its highest-priority unique issues. Repeated findings are grouped with every affected location."
      />

      {scanId !== undefined ? (
        <Card className="border-primary/25 bg-primary/[0.03]">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
            <div>
              <p className="font-semibold">Scan #{formatCount(scanId)} findings</p>
              <p className="text-sm text-muted-foreground">
                Showing findings from this scan only. Issues remain grouped by repeated rule and
                message.
              </p>
            </div>
            <Button size="sm" variant="outline" onClick={clearScanScope}>
              Show latest findings
            </Button>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardContent className="grid gap-4 p-4 sm:grid-cols-2 xl:grid-cols-5">
          <div className="space-y-1.5 xl:col-span-2">
            <Label htmlFor="finding-search">Search</Label>
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                id="finding-search"
                className="pl-9"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Rule, file, or description"
              />
            </div>
          </div>
          {scanId === undefined ? (
            <FilterSelect
              id="finding-repository"
              label="Repository"
              value={repositoryId}
              onChange={setRepositoryId}
              options={[
                { value: "active", label: "Top bar selection" },
                { value: "all", label: "All repositories" },
                ...repositories.map((repo) => ({ value: String(repo.id), label: repo.name })),
              ]}
            />
          ) : null}
          <FilterSelect
            id="finding-module"
            label="Category"
            value={module}
            onChange={setModule}
            options={[
              { value: "all", label: "All categories" },
              ...["security", "quality", "dependencies", "database", "infrastructure", "compliance", "performance"].map(
                (value) => ({ value, label: titleCase(value) }),
              ),
            ]}
          />
          <FilterSelect
            id="finding-status"
            label="Status"
            value={status}
            onChange={setStatus}
            options={["open", "reviewed", "unverified", "dismissed", "all"].map((value) => ({
              value,
              label: value === "all" ? "All statuses" : titleCase(value),
            }))}
          />
        </CardContent>
      </Card>

      <DataState
        loading={result.loading}
        error={result.error}
        onRetry={() => void result.reload()}
        loadingRows={4}
      >
        {findings.length ? (
          <div className="space-y-5">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
              {prioritySummary.map(({ priority, findings: count, issues }) => {
                const styles = PRIORITY_STYLES[priority];
                const selected = selectedSeverity === priority;
                const maxCount = Math.max(...prioritySummary.map((item) => item.findings), 1);
                const barWidth = `${Math.max(count ? 3 : 0, (count / maxCount) * 100)}%`;

                return (
                  <button
                    key={priority}
                    type="button"
                    aria-pressed={selected}
                    disabled={!count}
                    onClick={() => togglePriority(priority)}
                    className={cn(
                      "group relative overflow-hidden rounded-lg border bg-card p-4 text-left shadow-sm transition hover:-translate-y-0.5 hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:translate-y-0",
                      selected && `${styles.border} ${styles.surface} ring-1 ring-inset`,
                    )}
                  >
                    <span className={cn("absolute inset-x-0 top-0 h-1", styles.fill)} />
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className={cn("text-sm font-semibold", styles.text)}>
                          {titleCase(priority)}
                        </p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {formatCount(issues)} unique issue{issues === 1 ? "" : "s"}
                        </p>
                      </div>
                      <span className="text-2xl font-bold tabular-nums">
                        {formatCount(count)}
                      </span>
                    </div>
                    <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-muted">
                      <span
                        className={cn("block h-full rounded-full transition-all", styles.fill)}
                        style={{ width: barWidth }}
                      />
                    </div>
                    <p className="mt-2 text-[11px] text-muted-foreground">
                      {selected ? "Click to close" : "Click to review"}
                    </p>
                  </button>
                );
              })}
            </div>

            {selectedSeverity ? (
              selectedGroups.length ? (
                <section className="space-y-3" aria-live="polite">
                  <div className="flex flex-wrap items-end justify-between gap-2">
                    <div>
                      <h2 className="text-lg font-semibold">
                        {titleCase(selectedSeverity)} issues
                      </h2>
                      <p className="text-sm text-muted-foreground">
                        Showing {formatCount(visibleGroups.length)} of{" "}
                        {formatCount(selectedGroups.length)} unique issues from{" "}
                        {formatCount(prioritySummary.find((item) => item.priority === selectedSeverity)?.findings ?? 0)} findings.
                      </p>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {visibleGroups.map((group) => {
                      const finding = group.representative;
                      const fileCount = new Set(
                        group.occurrences.map((item) => `${item.repository_id}:${item.file}`),
                      ).size;
                      const styles = PRIORITY_STYLES[selectedSeverity];

                      return (
                        <details
                          key={group.key}
                          className={cn(
                            "group rounded-lg border border-l-4 bg-card transition-colors open:bg-muted/10",
                            styles.border,
                          )}
                        >
                          <summary className="flex cursor-pointer list-none items-center gap-3 px-3 py-2.5 [&::-webkit-details-marker]:hidden">
                            <SeverityBadge severity={finding.severity} />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-sm font-semibold">
                                {finding.rule}
                                <span className="ml-2 text-xs font-normal text-muted-foreground">
                                  {titleCase(finding.module)}
                                </span>
                              </span>
                              <span className="block line-clamp-1 text-xs text-muted-foreground">
                                {finding.message || "No description was recorded."}
                              </span>
                            </span>
                            <span
                              className={cn(
                                "shrink-0 rounded-md px-2 py-1 text-xs font-semibold tabular-nums",
                                styles.surface,
                                styles.text,
                              )}
                              title={`${formatCount(group.occurrences.length)} occurrences in ${formatCount(fileCount)} files`}
                            >
                              {formatCount(group.occurrences.length)}×
                            </span>
                            <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" />
                          </summary>

                          <div className="space-y-3 border-t px-3 py-3 sm:px-4">
                            <p className="whitespace-pre-wrap text-sm leading-relaxed">
                              {finding.message || "No description was recorded."}
                            </p>
                            {finding.suggestion ? (
                              <div className="rounded-md bg-muted/60 px-3 py-2">
                                <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                                  Suggested next step
                                </p>
                                <p className="text-sm">{finding.suggestion}</p>
                              </div>
                            ) : null}
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <p className="text-xs text-muted-foreground">
                                {formatCount(group.occurrences.length)} occurrences across{" "}
                                {formatCount(fileCount)} files
                              </p>
                              <Link
                                to={`/findings/${group.occurrences[0].id}`}
                                className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                              >
                                Open finding details <ExternalLink className="h-3 w-3" />
                              </Link>
                            </div>
                            <details className="border-t pt-2">
                              <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground">
                                View affected locations
                              </summary>
                              <ul className="mt-2 grid max-h-52 gap-1.5 overflow-auto sm:grid-cols-2">
                                {group.occurrences.map((item) => (
                                  <li
                                    key={item.id}
                                    className="flex min-w-0 flex-wrap items-center gap-2 rounded bg-background px-2.5 py-2 text-xs"
                                  >
                                    <Link
                                      to={`/findings/${item.id}`}
                                      className="min-w-0 flex-1 break-all font-mono text-primary hover:underline"
                                    >
                                      {item.repository_name}: {item.file}:{item.line}
                                    </Link>
                                    <FindingStatusBadge status={item.status} />
                                  </li>
                                ))}
                              </ul>
                            </details>
                          </div>
                        </details>
                      );
                    })}
                  </div>

                  {visibleCount < selectedGroups.length ? (
                    <div className="flex justify-center pt-1">
                      <Button
                        variant="outline"
                        onClick={() =>
                          setVisibleCount((current) =>
                            Math.min(current + BATCH_SIZE, selectedGroups.length),
                          )
                        }
                      >
                        Load {Math.min(BATCH_SIZE, selectedGroups.length - visibleCount)} more{" "}
                        {titleCase(selectedSeverity)} issues
                      </Button>
                    </div>
                  ) : null}
                </section>
              ) : (
                <EmptyState
                  icon={ShieldAlert}
                  title={`No ${titleCase(selectedSeverity).toLowerCase()} issues match these filters`}
                  description="Try another priority, category, status, repository, or search term."
                />
              )
            ) : (
              <Card>
                <CardContent className="p-6 text-center">
                  <p className="font-medium">Choose a priority to review its issues</p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Each selection starts with the 10 most repeated unique issues. Load more in
                    batches when you need the rest.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        ) : (
          <EmptyState
            icon={ShieldAlert}
            title="No findings match these filters"
            description="Run a scan or adjust the category, status, search, or repository filters."
            action={<Button asChild variant="outline" size="sm"><Link to="/scans/new">Start a scan</Link></Button>}
          />
        )}
      </DataState>
    </div>
  );
}

function FilterSelect({
  id,
  label,
  value,
  onChange,
  options,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id}><SelectValue /></SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
