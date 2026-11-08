import { PackageSearch } from "lucide-react";
import { useMemo, useState } from "react";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAsync } from "@/hooks/use-async";
import { useDebounced } from "@/hooks/use-debounced";
import { api } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Dependency } from "@/types/api";

interface Advisory {
  id: string;
  aliases: string[];
  severity: string;
  summary: string;
  url: string | null;
  modified: string | null;
}

function parseAdvisories(raw: Array<Record<string, unknown>>): Advisory[] {
  return raw.map((entry) => ({
    id: typeof entry.id === "string" ? entry.id : "",
    aliases: Array.isArray(entry.aliases) ? entry.aliases.map((alias) => String(alias)) : [],
    severity: typeof entry.severity === "string" && entry.severity ? entry.severity : "info",
    summary: typeof entry.summary === "string" ? entry.summary : "",
    url: typeof entry.url === "string" ? entry.url : null,
    modified: typeof entry.modified === "string" ? entry.modified : null,
  }));
}

function statusClasses(status: string): string {
  switch (status) {
    case "ok":
      return "border-gate-pass/40 bg-gate-pass/10 text-gate-pass";
    case "advisory":
      return "border-severity-medium/40 bg-severity-medium/10 text-severity-medium";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

export function DependenciesPage() {
  const { activeRepositoryId } = useApp();
  const [osv, setOsv] = useState(false);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const debouncedSearch = useDebounced(search);

  const dependencies = useAsync(
    () => api.intel.dependencies(activeRepositoryId as number, osv),
    [activeRepositoryId, osv],
    { enabled: activeRepositoryId !== null },
  );

  const data = dependencies.data ?? null;
  const items = data?.dependencies ?? [];
  const filtered = useMemo(() => {
    const term = debouncedSearch.trim().toLowerCase();
    if (!term) return items;
    return items.filter((dependency) => dependency.name.toLowerCase().includes(term));
  }, [items, debouncedSearch]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dependencies"
        description="Direct and transitive packages found in the repository's lockfiles and manifests."
        actions={
          <>
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search packages"
              className="h-8 w-48"
              aria-label="Search dependencies"
            />
            <Button
              size="sm"
              variant="outline"
              onClick={() => setOsv(true)}
              disabled={osv || activeRepositoryId === null}
            >
              {osv ? "Advisories requested" : "Check advisories now (network)"}
            </Button>
          </>
        }
      />

      {activeRepositoryId === null ? (
        <EmptyState
          icon={PackageSearch}
          title="No repository selected"
          description="Choose a repository in the top bar to inspect its dependencies."
        />
      ) : (
        <DataState
          loading={dependencies.loading}
          error={dependencies.error}
          onRetry={() => void dependencies.reload()}
          loadingRows={4}
        >
          {data === null ? null : (
            <div className="space-y-4">
              <Card>
                <CardContent className="flex flex-wrap items-start gap-x-8 gap-y-3 p-5">
                  <Fact label="Package manager" value={data.package_manager ?? "Not detected"} />
                  <Fact
                    label="OSV advisories"
                    value={data.osv_checked ? "Checked" : "Not checked"}
                  />
                  <div className="space-y-1">
                    <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
                      Lockfiles
                    </p>
                    {data.lockfiles.length ? (
                      <div className="flex flex-wrap gap-1.5">
                        {data.lockfiles.map((lockfile) => (
                          <Badge key={lockfile} variant="secondary" className="font-mono text-[11px]">
                            {lockfile}
                          </Badge>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No lockfiles were found.</p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {data.notes.length ? (
                <ul className="list-disc space-y-1 rounded-lg border bg-card/40 py-4 pl-10 pr-6 text-sm text-muted-foreground">
                  {data.notes.map((note, index) => (
                    <li key={index}>{note}</li>
                  ))}
                </ul>
              ) : null}

              {items.length === 0 ? (
                <EmptyState
                  icon={PackageSearch}
                  title="No dependencies found"
                  description="No lockfile or package manifest was found for this repository, so there are no packages to list."
                />
              ) : (
                <Card>
                  <CardContent className="px-0 pb-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Package</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Scope</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Advisories</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filtered.map((dependency) => (
                          <DependencyRows
                            key={dependency.name}
                            dependency={dependency}
                            open={expanded === dependency.name}
                            onToggle={() =>
                              setExpanded(expanded === dependency.name ? null : dependency.name)
                            }
                          />
                        ))}
                        {filtered.length === 0 ? (
                          <TableRow>
                            <TableCell
                              colSpan={5}
                              className="py-8 text-center text-sm text-muted-foreground"
                            >
                              No dependencies match &quot;{debouncedSearch.trim()}&quot;.
                            </TableCell>
                          </TableRow>
                        ) : null}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </DataState>
      )}
    </div>
  );
}

function DependencyRows({
  dependency,
  open,
  onToggle,
}: {
  dependency: Dependency;
  open: boolean;
  onToggle: () => void;
}) {
  const advisories = parseAdvisories(dependency.advisories);
  return (
    <>
      <TableRow className="cursor-pointer" aria-expanded={open} onClick={onToggle}>
        <TableCell className="font-medium">{dependency.name}</TableCell>
        <TableCell
          className={dependency.version ? "font-mono text-xs" : "text-muted-foreground"}
        >
          {dependency.version ?? "unpinned"}
        </TableCell>
        <TableCell>
          <Badge variant={dependency.direct ? "secondary" : "muted"}>
            {dependency.direct ? "direct" : "transitive"}
          </Badge>
        </TableCell>
        <TableCell>
          <span
            className={cn(
              "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium",
              statusClasses(dependency.status),
            )}
          >
            {titleCase(dependency.status)}
          </span>
        </TableCell>
        <TableCell className="tabular-nums">
          {advisories.length ? (
            <span className="font-medium text-severity-medium">{advisories.length}</span>
          ) : (
            <span className="text-muted-foreground">0</span>
          )}
        </TableCell>
      </TableRow>
      {open ? (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={5} className="py-3">
            {advisories.length ? (
              <ul className="space-y-3">
                {advisories.map((advisory, index) => (
                  <li key={`${advisory.id}-${index}`} className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={advisory.severity} />
                      {advisory.id ? <span className="font-mono text-xs">{advisory.id}</span> : null}
                      {advisory.aliases.length ? (
                        <span className="text-xs text-muted-foreground">
                          aliases: {advisory.aliases.join(", ")}
                        </span>
                      ) : null}
                    </div>
                    {advisory.summary ? <p className="text-sm">{advisory.summary}</p> : null}
                    <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                      {advisory.url ? (
                        <a
                          href={advisory.url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="text-primary underline-offset-4 hover:underline"
                        >
                          {advisory.url}
                        </a>
                      ) : null}
                      <span>Modified {formatDateTime(advisory.modified)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">
                No advisories were recorded for this package.
              </p>
            )}
          </TableCell>
        </TableRow>
      ) : null}
    </>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="text-sm font-medium">{value}</p>
    </div>
  );
}
