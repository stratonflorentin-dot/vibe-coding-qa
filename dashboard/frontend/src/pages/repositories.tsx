import { GitBranchPlus, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { GateBadge } from "@/components/common/gate-badge";
import { PageHeader } from "@/components/common/page-header";
import { ScanStatusBadge } from "@/components/common/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import { Input } from "@/components/ui/input";
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
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api";
import { formatRelative, formatScore, scoreColor, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Repository, SourceType } from "@/types/api";

/** Surface the server's own error text instead of inventing one. */
function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "The request failed.";
}

export function RepositoriesPage() {
  const { repositories, loading, error, reload } = useApp();
  const { toast } = useToast();

  const [addOpen, setAddOpen] = useState(false);
  const [name, setName] = useState("");
  const [source, setSource] = useState("");
  const [sourceType, setSourceType] = useState<SourceType>("local");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<Repository | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [refreshingId, setRefreshingId] = useState<number | null>(null);

  function closeAdd() {
    setAddOpen(false);
    setName("");
    setSource("");
    setSourceType("local");
    setSubmitError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setSubmitError(null);
    try {
      await api.repositories.create({
        name: name.trim() ? name.trim() : undefined,
        source: source.trim(),
        source_type: sourceType,
      });
      toast({ title: "Repository added", variant: "success" });
      closeAdd();
      await reload();
    } catch (caught) {
      // The backend rejects paths outside allowed roots and embedded credentials
      // with a specific message; show exactly that.
      setSubmitError(errorMessage(caught));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRefresh(repository: Repository) {
    setRefreshingId(repository.id);
    try {
      await api.repositories.refresh(repository.id);
      toast({ title: "Metadata refreshed", description: repository.name, variant: "success" });
      await reload();
    } catch (caught) {
      toast({ title: "Refresh failed", description: errorMessage(caught), variant: "error" });
    } finally {
      setRefreshingId(null);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.repositories.remove(deleteTarget.id);
      toast({ title: "Repository deleted", description: deleteTarget.name, variant: "success" });
      setDeleteTarget(null);
      await reload();
    } catch (caught) {
      toast({ title: "Delete failed", description: errorMessage(caught), variant: "error" });
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Repositories"
        description="Register the codebases the engine is allowed to analyse."
        actions={
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus />
            Add repository
          </Button>
        }
      />

      <DataState loading={loading} error={error} onRetry={() => void reload()} loadingRows={4}>
        {repositories.length ? (
          <Card>
            <CardContent className="px-0 pb-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Repository</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Language</TableHead>
                    <TableHead>Frameworks</TableHead>
                    <TableHead>Latest scan</TableHead>
                    <TableHead>Last scan</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {repositories.map((repository) => (
                    <TableRow key={repository.id}>
                      <TableCell className="max-w-[240px]">
                        <Link
                          to={`/repositories/${repository.id}`}
                          className="font-medium hover:text-primary"
                        >
                          {repository.name}
                        </Link>
                        <p className="truncate text-xs text-muted-foreground" title={repository.source}>
                          {repository.source}
                        </p>
                      </TableCell>
                      <TableCell>
                        <Badge variant="muted">{titleCase(repository.source_type)}</Badge>
                      </TableCell>
                      <TableCell>
                        <p className="text-sm">{repository.main_language ?? "—"}</p>
                        <p className="text-xs text-muted-foreground">
                          {repository.package_manager ?? "—"}
                        </p>
                      </TableCell>
                      <TableCell>
                        <Chips values={repository.frameworks} />
                      </TableCell>
                      <TableCell>
                        {repository.latest_scan ? (
                          <div className="flex flex-col gap-1.5">
                            <span
                              className={cn(
                                "font-semibold tabular-nums",
                                scoreColor(repository.latest_scan.overall_score),
                              )}
                            >
                              {formatScore(repository.latest_scan.overall_score)}
                            </span>
                            <div className="flex flex-wrap items-center gap-1.5">
                              <GateBadge gate={repository.latest_scan.gate} />
                              <ScanStatusBadge status={repository.latest_scan.status} />
                            </div>
                          </div>
                        ) : (
                          <span className="text-sm text-muted-foreground">No scans yet</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatRelative(
                          repository.latest_scan?.completed_at ??
                            repository.latest_scan?.created_at,
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <Button asChild variant="ghost" size="sm">
                            <Link to={`/repositories/${repository.id}`}>Open</Link>
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={refreshingId === repository.id}
                            onClick={() => void handleRefresh(repository)}
                          >
                            <RefreshCw
                              className={
                                refreshingId === repository.id ? "animate-spin" : undefined
                              }
                            />
                            Refresh
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:text-destructive"
                            onClick={() => setDeleteTarget(repository)}
                          >
                            <Trash2 />
                            Delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        ) : (
          <EmptyState
            icon={GitBranchPlus}
            title="No repositories registered"
            description="Add a local path or a GitHub URL to start running scans."
            action={
              <Button size="sm" onClick={() => setAddOpen(true)}>
                <Plus />
                Add repository
              </Button>
            }
          />
        )}
      </DataState>

      <Dialog open={addOpen} onOpenChange={(open) => (open ? setAddOpen(true) : closeAdd())}>
        <DialogContent>
          <form className="space-y-4" onSubmit={handleSubmit}>
            <DialogHeader>
              <DialogTitle>Add repository</DialogTitle>
              <DialogDescription>
                The backend only accepts local paths inside its configured allowed roots.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-1.5">
              <Label htmlFor="repository-name">Name (optional)</Label>
              <Input
                id="repository-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Defaults to the folder name"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="repository-source">Source</Label>
              <Input
                id="repository-source"
                value={source}
                onChange={(event) => setSource(event.target.value)}
                placeholder={
                  sourceType === "github"
                    ? "https://github.com/org/repo"
                    : "/absolute/path/to/repo"
                }
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="repository-source-type">Source type</Label>
              <Select value={sourceType} onValueChange={(value) => setSourceType(value as SourceType)}>
                <SelectTrigger id="repository-source-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="local">Local path</SelectItem>
                  <SelectItem value="github">GitHub URL</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {submitError ? (
              <Alert variant="destructive">
                <AlertTitle>Could not add the repository</AlertTitle>
                <AlertDescription>{submitError}</AlertDescription>
              </Alert>
            ) : null}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={closeAdd}>
                Cancel
              </Button>
              <Button type="submit" disabled={submitting || !source.trim()}>
                Add repository
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete repository</DialogTitle>
            <DialogDescription>
              This removes {deleteTarget?.name} and its scan history from the dashboard. This cannot
              be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={deleting}>
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

function Chips({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-sm text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {values.map((value) => (
        <Badge key={value} variant="muted" className="text-[11px]">
          {value}
        </Badge>
      ))}
    </div>
  );
}
