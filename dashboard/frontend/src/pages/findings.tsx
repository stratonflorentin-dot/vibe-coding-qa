import { Search, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAsync } from "@/hooks/use-async";
import { useDebounced } from "@/hooks/use-debounced";
import { api } from "@/lib/api";
import { formatDateTime, formatCount, titleCase } from "@/lib/format";

const PAGE_SIZE = 25;

export function FindingsPage() {
  const { activeRepositoryId, repositories } = useApp();
  const [repositoryId, setRepositoryId] = useState("active");
  const [severity, setSeverity] = useState("all");
  const [module, setModule] = useState("all");
  const [status, setStatus] = useState("open");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const debouncedSearch = useDebounced(search);
  const selectedRepositoryId =
    repositoryId === "all"
      ? undefined
      : repositoryId === "active"
        ? activeRepositoryId ?? undefined
        : Number(repositoryId);

  const result = useAsync(
    () =>
      api.findings.list({
        repository_id: selectedRepositoryId,
        severity: severity === "all" ? undefined : [severity],
        module: module === "all" ? undefined : [module],
        status: status === "all" ? undefined : [status],
        search: debouncedSearch || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    [selectedRepositoryId, severity, module, status, debouncedSearch, offset],
  );

  useEffect(() => setOffset(0), [selectedRepositoryId, severity, module, status, debouncedSearch]);

  const items = result.data?.items ?? [];
  const total = result.data?.total ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        description="Search and triage issues from actual completed scans. Review status does not mean a finding is fixed."
      />

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
          <FilterSelect
            id="finding-severity"
            label="Severity"
            value={severity}
            onChange={setSeverity}
            options={["all", "critical", "high", "medium", "low", "info"].map((value) => ({
              value,
              label: value === "all" ? "All severities" : titleCase(value),
            }))}
          />
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
        {items.length ? (
          <>
            <Card>
              <CardContent className="overflow-x-auto p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Finding</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Repository</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Detected</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((finding) => (
                      <TableRow key={finding.id}>
                        <TableCell><SeverityBadge severity={finding.severity} /></TableCell>
                        <TableCell className="min-w-56">
                          <Link to={`/findings/${finding.id}`} className="font-medium hover:text-primary">
                            {finding.rule}
                          </Link>
                          <p className="mt-1 max-w-md text-xs text-muted-foreground">{finding.message}</p>
                        </TableCell>
                        <TableCell>{titleCase(finding.module)}</TableCell>
                        <TableCell>{finding.repository_name}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {finding.file}:{finding.line}
                        </TableCell>
                        <TableCell>{titleCase(finding.confidence ?? "unknown")}</TableCell>
                        <TableCell><FindingStatusBadge status={finding.status} /></TableCell>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                          {formatDateTime(finding.created_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">
                Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {formatCount(total)}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                  Previous
                </Button>
                <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                  Next
                </Button>
              </div>
            </div>
          </>
        ) : (
          <EmptyState
            icon={ShieldAlert}
            title="No findings match these filters"
            description="Run a scan or adjust the severity, category, status, or repository filters."
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
