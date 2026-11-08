import { RefreshCw, ShieldCheck, Sparkles, Undo2, Wrench } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { api, ApiError } from "@/lib/api";
import { formatDateTime, formatRelative, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";

/**
 * Remediation proposals.
 *
 * AI-drafted patches are never applied automatically: approving a proposal writes
 * to the real working tree and therefore requires an explicit human confirmation.
 * Every API error is shown verbatim rather than hidden.
 */
export function RemediationsPage() {
  const { activeRepositoryId, activeRepository } = useApp();
  const { toast } = useToast();

  const proposals = useAsync(() => api.ai.remediations(), []);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const detail = useAsync(() => api.ai.remediation(selectedId as number), [selectedId], {
    enabled: selectedId !== null,
  });

  const findings = useAsync(
    () =>
      api.findings.list({
        repository_id: activeRepositoryId ?? undefined,
        status: ["open"],
        limit: 100,
      }),
    [activeRepositoryId],
  );

  const [findingId, setFindingId] = useState("");
  const [proposing, setProposing] = useState(false);
  const [proposeError, setProposeError] = useState<string | null>(null);

  const [approveOpen, setApproveOpen] = useState(false);
  const [confirmChecked, setConfirmChecked] = useState(false);
  const [runTests, setRunTests] = useState(false);
  const [testPermission, setTestPermission] = useState(false);
  const [applying, setApplying] = useState(false);

  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);

  const [actionError, setActionError] = useState<string | null>(null);

  const rows = proposals.data ?? [];
  const findingItems = findings.data?.items ?? [];
  const selected = detail.data;

  function openApprove() {
    setConfirmChecked(false);
    setRunTests(false);
    setTestPermission(false);
    setActionError(null);
    setApproveOpen(true);
  }

  function selectProposal(id: number) {
    setSelectedId(id);
    setActionError(null);
  }

  async function handlePropose() {
    const id = Number.parseInt(findingId, 10);
    if (!Number.isFinite(id)) return;
    setProposing(true);
    setProposeError(null);
    try {
      const created = await api.ai.proposeRemediation(id);
      await proposals.reload(true);
      setSelectedId(created.id);
      setFindingId("");
      toast({
        title: "Proposal created",
        description: `A patch for finding #${id} is ready to review.`,
        variant: "success",
      });
    } catch (error) {
      setProposeError(
        error instanceof ApiError ? error.message : "The proposal could not be created.",
      );
    } finally {
      setProposing(false);
    }
  }

  async function handleApprove() {
    if (selectedId === null) return;
    setApplying(true);
    setActionError(null);
    const tests = runTests && testPermission;
    try {
      const updated = await api.ai.approveRemediation(selectedId, {
        confirm: true,
        run_tests: tests,
        explicit_permission: tests,
      });
      detail.setData(updated);
      setApproveOpen(false);
      await proposals.reload(true);
      if (updated.error) {
        setActionError(updated.error);
      } else {
        toast({
          title: "Patch applied",
          description: tests
            ? "The patch was written to the working tree and tests were requested."
            : "The patch was written to the working tree.",
          variant: "success",
        });
      }
    } catch (error) {
      setActionError(
        error instanceof ApiError ? error.message : "The approval could not be completed.",
      );
    } finally {
      setApplying(false);
    }
  }

  async function handleRollback() {
    if (selectedId === null) return;
    setRollingBack(true);
    setActionError(null);
    try {
      const updated = await api.ai.rollbackRemediation(selectedId);
      detail.setData(updated);
      setRollbackOpen(false);
      await proposals.reload(true);
      if (updated.error) {
        setActionError(updated.error);
      } else {
        toast({
          title: "Rolled back",
          description: "The applied patch was reverted.",
          variant: "success",
        });
      }
    } catch (error) {
      setActionError(
        error instanceof ApiError ? error.message : "The rollback could not be completed.",
      );
    } finally {
      setRollingBack(false);
    }
  }

  const approveDisabled = applying || !confirmChecked || (runTests && !testPermission);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation"
        description="AI-proposed patches that require explicit human approval before they touch the working tree."
        actions={
          <Button variant="outline" size="sm" onClick={() => void proposals.reload()}>
            <RefreshCw />
            Refresh
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Propose a remediation</CardTitle>
          <CardDescription>
            Ask the model to draft a patch for an open finding. A proposal is never applied
            automatically.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="remediation-finding">Open finding</Label>
              <Select
                value={findingId}
                onValueChange={setFindingId}
                disabled={proposing || !findingItems.length}
              >
                <SelectTrigger id="remediation-finding">
                  <SelectValue placeholder="Select an open finding" />
                </SelectTrigger>
                <SelectContent>
                  {findingItems.map((finding) => (
                    <SelectItem key={finding.id} value={String(finding.id)}>
                      #{finding.id} · {finding.severity} · {finding.rule}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={() => void handlePropose()} disabled={proposing || !findingId}>
              <Sparkles />
              {proposing ? "Proposing…" : "Propose patch"}
            </Button>
          </div>

          {findings.error ? (
            <p className="text-xs text-destructive">
              Open findings could not be loaded: {findings.error}
            </p>
          ) : null}
          {!findings.loading && !findings.error && !findingItems.length ? (
            <p className="text-xs text-muted-foreground">
              No open findings are available to propose against
              {activeRepository ? ` in ${activeRepository.name}` : ""}.
            </p>
          ) : null}

          {proposeError ? (
            <Alert variant="destructive">
              <AlertDescription>
                {proposeError}{" "}
                <Link to="/settings" className="font-medium underline underline-offset-4">
                  Open settings
                </Link>{" "}
                to configure an AI provider.
              </AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle>Proposals</CardTitle>
            <CardDescription>Every patch the model has drafted.</CardDescription>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <DataState
              loading={proposals.loading}
              error={proposals.error}
              onRetry={() => void proposals.reload()}
              loadingRows={3}
            >
              {rows.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>ID</TableHead>
                      <TableHead>Finding</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>File</TableHead>
                      <TableHead>Provider</TableHead>
                      <TableHead>Updated</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((proposal) => (
                      <TableRow
                        key={proposal.id}
                        onClick={() => selectProposal(proposal.id)}
                        className={cn("cursor-pointer", proposal.id === selectedId && "bg-muted")}
                      >
                        <TableCell className="font-medium">#{proposal.id}</TableCell>
                        <TableCell>
                          {proposal.finding_id !== null ? (
                            <Link
                              to={`/findings/${proposal.finding_id}`}
                              className="hover:text-primary"
                              onClick={(event) => event.stopPropagation()}
                            >
                              #{proposal.finding_id}
                            </Link>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant={proposalVariant(proposal.status)}>
                            {titleCase(proposal.status)}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-[180px] truncate font-mono text-xs">
                          {proposal.file ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {providerLabel(proposal.provider, proposal.model)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatRelative(proposal.updated_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="px-4 pb-4">
                  <EmptyState
                    icon={Wrench}
                    title="No remediation proposals yet"
                    description="Propose a patch from an open finding to review it here. Nothing is applied without your explicit approval."
                  />
                </div>
              )}
            </DataState>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle>Proposal detail</CardTitle>
            <CardDescription>Review the patch before applying it.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {selectedId === null ? (
              <EmptyState
                icon={Wrench}
                title="No proposal selected"
                description="Select a proposal to inspect its diff and decide whether to apply it."
              />
            ) : (
              <DataState
                loading={detail.loading}
                error={detail.error}
                onRetry={() => void detail.reload()}
                loadingRows={3}
              >
                {selected ? (
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={proposalVariant(selected.status)}>
                        {titleCase(selected.status)}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        finding{" "}
                        {selected.finding_id !== null ? `#${selected.finding_id}` : "not linked"}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {providerLabel(selected.provider, selected.model)}
                      </span>
                    </div>

                    {selected.file ? (
                      <p className="font-mono text-xs text-muted-foreground">{selected.file}</p>
                    ) : null}

                    {actionError ? (
                      <Alert variant="destructive">
                        <AlertTitle>Action failed</AlertTitle>
                        <AlertDescription>{actionError}</AlertDescription>
                      </Alert>
                    ) : null}

                    {selected.error ? (
                      <Alert variant="destructive">
                        <AlertTitle>Reported error</AlertTitle>
                        <AlertDescription>{selected.error}</AlertDescription>
                      </Alert>
                    ) : null}

                    {selected.rationale ? (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Rationale
                        </p>
                        <p className="whitespace-pre-wrap text-sm text-muted-foreground">
                          {selected.rationale}
                        </p>
                      </div>
                    ) : null}

                    {selected.diff ? (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                          Unified diff
                        </p>
                        <pre className="max-h-80 overflow-x-auto rounded-md border bg-muted/40 p-3 font-mono text-xs">
                          {selected.diff}
                        </pre>
                      </div>
                    ) : null}

                    <Tabs defaultValue="original">
                      <TabsList>
                        <TabsTrigger value="original">Original</TabsTrigger>
                        <TabsTrigger value="proposed">Proposed</TabsTrigger>
                      </TabsList>
                      <TabsContent value="original">
                        <pre className="max-h-80 overflow-x-auto rounded-md border bg-muted/40 p-3 font-mono text-xs">
                          {selected.original ?? "No original content was captured."}
                        </pre>
                      </TabsContent>
                      <TabsContent value="proposed">
                        <pre className="max-h-80 overflow-x-auto rounded-md border bg-muted/40 p-3 font-mono text-xs">
                          {selected.proposed ?? "No proposed content was captured."}
                        </pre>
                      </TabsContent>
                    </Tabs>

                    <div className="space-y-1.5">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        History
                      </p>
                      {selected.history.length ? (
                        <ol className="ml-1 space-y-2 border-l pl-4">
                          {selected.history.map((entry, index) => {
                            const item = historyEntry(entry);
                            return (
                              <li key={index} className="relative">
                                <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-border" />
                                <p className="text-sm font-medium">{titleCase(item.status)}</p>
                                <p className="text-xs text-muted-foreground">
                                  {formatDateTime(item.at)}
                                </p>
                              </li>
                            );
                          })}
                        </ol>
                      ) : (
                        <p className="text-sm text-muted-foreground">No history recorded yet.</p>
                      )}
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <Button onClick={openApprove} disabled={applying || rollingBack}>
                        <ShieldCheck />
                        Approve and apply
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => {
                          setActionError(null);
                          setRollbackOpen(true);
                        }}
                        disabled={applying || rollingBack}
                      >
                        <Undo2 />
                        Roll back
                      </Button>
                    </div>
                  </div>
                ) : null}
              </DataState>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog
        open={approveOpen}
        onOpenChange={(open) => {
          if (!open && !applying) setApproveOpen(false);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Apply this patch</DialogTitle>
            <DialogDescription>
              Approving writes the proposed change to the real working tree. This is not a preview.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 rounded border-input"
                checked={confirmChecked}
                onChange={(event) => setConfirmChecked(event.target.checked)}
              />
              <span>I understand this patch will be written to the working tree.</span>
            </label>

            <div className="flex items-start justify-between gap-4 rounded-md border p-3">
              <div className="space-y-0.5">
                <Label htmlFor="run-tests">Run the isolated test suite after applying</Label>
                <p className="text-xs text-muted-foreground">
                  Off by default. Tests run inside an isolated sandbox.
                </p>
              </div>
              <Switch
                id="run-tests"
                checked={runTests}
                onCheckedChange={(checked) => {
                  setRunTests(checked);
                  if (!checked) setTestPermission(false);
                }}
              />
            </div>

            {runTests ? (
              <div className="space-y-2 rounded-md border border-severity-medium/40 bg-severity-medium/10 p-3">
                <p className="text-xs">
                  Tests execute inside a Docker sandbox and require Docker to be installed and
                  running. They are an isolated check, not a guarantee.
                </p>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5 h-4 w-4 rounded border-input"
                    checked={testPermission}
                    onChange={(event) => setTestPermission(event.target.checked)}
                  />
                  <span>I explicitly permit executing the test suite for this patch.</span>
                </label>
              </div>
            ) : null}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setApproveOpen(false)} disabled={applying}>
              Cancel
            </Button>
            <Button onClick={() => void handleApprove()} disabled={approveDisabled}>
              {applying ? "Applying…" : "Approve and apply"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={rollbackOpen}
        onOpenChange={(open) => {
          if (!open && !rollingBack) setRollbackOpen(false);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Roll back this patch</DialogTitle>
            <DialogDescription>
              This reverts the previously applied change in the working tree. Continue only if you
              are sure.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRollbackOpen(false)} disabled={rollingBack}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void handleRollback()} disabled={rollingBack}>
              {rollingBack ? "Rolling back…" : "Roll back"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function providerLabel(provider: string | null, model: string | null): string {
  const parts = [provider, model].filter((value): value is string => Boolean(value));
  return parts.length ? parts.join(" / ") : "—";
}

function proposalVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" | "muted" {
  switch ((status || "").toLowerCase()) {
    case "applied":
    case "approved":
      return "default";
    case "failed":
    case "rejected":
    case "error":
      return "destructive";
    case "rolled_back":
    case "rolled-back":
      return "secondary";
    default:
      return "muted";
  }
}

/** Read status and timestamp from an untyped history entry without inventing values. */
function historyEntry(entry: Record<string, unknown>): { status: string; at: string | null } {
  const statusValue = entry.status ?? entry.state ?? entry.event;
  const status = typeof statusValue === "string" ? statusValue : "update";
  const atValue = entry.at ?? entry.ts ?? entry.timestamp ?? entry.created_at ?? entry.updated_at;
  return { status, at: typeof atValue === "string" ? atValue : null };
}
