import { useEffect, useState, type FormEvent } from "react";
import { Activity, Check, Clipboard, Download, LoaderCircle, Play, Plus, RefreshCw, ShieldCheck, Square, Trash2 } from "lucide-react";

import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, SEVERITY_ORDER, titleCase } from "@/lib/format";
import type { SecurityEvidence, SecurityFinding, SecurityJob, SecurityProfile, SecurityTarget, SecurityWorker, Severity } from "@/types/api";

const ACTIVE = new Set(["queued", "running"]);
const SEVERITY_CARD_CLASSES: Record<Severity, string> = {
  critical: "border-severity-critical/40 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  medium: "border-severity-medium/40 bg-severity-medium/10 text-severity-medium",
  low: "border-severity-low/40 bg-severity-low/10 text-severity-low",
  info: "border-border bg-muted/50 text-muted-foreground",
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "The request could not be completed.";
}

export function SecurityLabPage() {
  const { toast } = useToast();
  const profiles = useAsync(() => api.security.profiles(), []);
  const summary = useAsync(() => api.security.summary(), []);
  const workers = useAsync(() => api.security.workers(), []);
  const targets = useAsync(() => api.security.targets(), []);
  const jobs = useAsync(() => api.security.jobs({ limit: 100 }), []);
  const findings = useAsync(() => api.security.findings({ limit: 100 }), []);
  const evidence = useAsync(() => api.security.evidence({ limit: 50 }), []);
  const reloadJobs = jobs.reload;
  const reloadFindings = findings.reload;
  const reloadEvidence = evidence.reload;
  const reloadSummary = summary.reload;

  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedProfile, setSelectedProfile] = useState("basic");
  const [scanRate, setScanRate] = useState("");
  const [authorizedComprehensive, setAuthorizedComprehensive] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<{ target: SecurityTarget; token: string } | null>(null);
  const [evidenceContent, setEvidenceContent] = useState<SecurityEvidence | null>(null);

  const activeJobs = (jobs.data?.items ?? []).some((job) => ACTIVE.has(job.status));
  useEffect(() => {
    if (!activeJobs) return;
    const timer = window.setInterval(() => {
      void reloadJobs(true);
      void reloadFindings(true);
      void reloadEvidence(true);
      void reloadSummary(true);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activeJobs, reloadJobs, reloadFindings, reloadEvidence, reloadSummary]);

  const selectedProfileInfo = (profiles.data ?? []).find((item) => item.key === selectedProfile);
  const authorizedTargets = (targets.data ?? []).filter(
    (target) => target.ownership_confirmed && target.verify_status === "verified" && target.worker_id,
  );

  async function refreshAll() {
    setError(null);
    await Promise.all([
      profiles.reload(true),
      summary.reload(true),
      workers.reload(true),
      targets.reload(true),
      jobs.reload(true),
      findings.reload(true),
      evidence.reload(true),
    ]);
  }

  async function checkWorker(worker: SecurityWorker) {
    setBusy(`worker-${worker.id}`);
    setError(null);
    try {
      const status = await api.security.workerStatus(worker.id);
      workers.setData((current) => (current ?? []).map((item) => item.id === status.id ? status : item));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  async function startScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedTarget) return;
    setBusy("scan");
    setError(null);
    try {
      const job = await api.security.startScan({
        target_id: Number(selectedTarget),
        profile: selectedProfile,
        rate_limit: scanRate ? Number(scanRate) : undefined,
        explicit_authorization: authorizedComprehensive,
      });
      toast({ title: `Security job #${job.id} queued`, description: "The worker will report real progress and results.", variant: "success" });
      await jobs.reload(true);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  async function cancelJob(job: SecurityJob) {
    setBusy(`cancel-${job.id}`);
    try {
      await api.security.cancelJob(job.id);
      await jobs.reload(true);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  async function setFindingStatus(finding: SecurityFinding) {
    setBusy(`finding-${finding.id}`);
    try {
      await api.security.updateFinding(finding.id, finding.status === "reviewed" ? "open" : "reviewed");
      await findings.reload(true);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  async function verifyFinding(finding: SecurityFinding) {
    setBusy(`verify-${finding.id}`);
    setError(null);
    try {
      const result = await api.security.verifyFinding(finding.id);
      toast({
        title: `Verification job #${result.verification_job_id} started`,
        description: "Verification updates only when the original tool produces deterministic evidence.",
        variant: "success",
      });
      await jobs.reload(true);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  async function openEvidence(item: SecurityEvidence) {
    setBusy(`evidence-${item.id}`);
    try {
      setEvidenceContent(await api.security.evidenceItem(item.id));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  async function exportReport() {
    setBusy("report");
    try {
      const report = await api.security.report(selectedTarget ? Number(selectedTarget) : undefined);
      const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `security-report-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Lab"
        description="Authorized live-target testing through isolated customer-run security workers."
        actions={<Button size="sm" variant="outline" onClick={() => void refreshAll()}><RefreshCw />Refresh</Button>}
      />
      {error ? <Alert variant="destructive"><AlertTitle>Security Lab action failed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
      <Alert variant="warning">
        <AlertTitle>Authorized scope only</AlertTitle>
        <AlertDescription>
          Targets must be allowlisted and ownership-verified, or explicitly administrator-approved on a private worker.
          Network egress filtering is a required deployment control; worker-side DNS checks do not replace a host firewall.
        </AlertDescription>
      </Alert>

      <section id="workers" className="space-y-3">
        <div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Security workers</h2><Badge variant="muted">{workers.data?.length ?? 0} registered</Badge></div>
        <DataState loading={workers.loading} error={workers.error} onRetry={() => void workers.reload()} loadingRows={2}>
          {(workers.data?.length ?? 0) > 0 ? (
            <div className="grid gap-3 lg:grid-cols-2">
              {(workers.data ?? []).map((worker) => (
                <WorkerCard key={worker.id} worker={worker} busy={busy === `worker-${worker.id}`} onCheck={() => void checkWorker(worker)} />
              ))}
            </div>
          ) : (
            <EmptyState icon={Activity} title="No security worker connected" description="Security Lab is optional. Deploy the isolated worker and register its URL and token in Worker settings below." />
          )}
        </DataState>
      </section>

      <section id="tools" className="space-y-3">
        <h2 className="text-lg font-semibold">Tool inventory</h2>
        {workers.data?.some((worker) => worker.tools?.length) ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {(workers.data ?? []).flatMap((worker) => (worker.tools ?? []).map((tool) => (
              <Card key={`${worker.id}-${tool.key}`}>
                <CardContent className="flex items-start justify-between gap-3 p-4">
                  <div className="min-w-0">
                    <p className="font-medium">{tool.name}</p>
                    <p className="mt-1 truncate text-xs text-muted-foreground">{worker.name} · {tool.version ?? tool.detail ?? "Version not reported"}</p>
                  </div>
                  <Badge variant={tool.installed ? "default" : "muted"}>{tool.installed ? "Available" : "Unavailable"}</Badge>
                </CardContent>
              </Card>
            )))}
          </div>
        ) : <p className="rounded-md border p-4 text-sm text-muted-foreground">Tool versions appear after an authenticated worker health check. No tool status is assumed.</p>}
      </section>

      <section id="profiles" className="space-y-3">
        <h2 className="text-lg font-semibold">Scan profiles</h2>
        <DataState loading={profiles.loading} error={profiles.error} onRetry={() => void profiles.reload()} loadingRows={2}>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {(profiles.data ?? []).map((profile) => <ProfileCard key={profile.key} profile={profile} />)}
          </div>
        </DataState>
      </section>

      <div className="grid gap-4 xl:grid-cols-2">
        <TargetPanel
          workers={workers.data ?? []}
          profiles={profiles.data ?? []}
          busy={busy}
          onCreated={async (target, token) => {
            setChallenge(token ? { target, token } : null);
            await Promise.all([targets.reload(true), workers.reload(true)]);
          }}
          onError={setError}
          onBusy={setBusy}
        />
        <Card id="new-scan">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Play className="h-4 w-4" />New scan</CardTitle>
            <CardDescription>Only verified targets assigned to an enabled worker can be selected.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={(event) => void startScan(event)}>
              <div className="space-y-2">
                <Label htmlFor="security-target">Authorized target</Label>
                <Select value={selectedTarget} onValueChange={setSelectedTarget}>
                  <SelectTrigger id="security-target"><SelectValue placeholder="Select a verified target" /></SelectTrigger>
                  <SelectContent>{authorizedTargets.map((target) => <SelectItem key={target.id} value={String(target.id)}>{target.value} · {target.environment}</SelectItem>)}</SelectContent>
                </Select>
                {!authorizedTargets.length ? <p className="text-xs text-muted-foreground">Register and verify a target before starting a scan.</p> : null}
              </div>
              <div className="space-y-2">
                <Label htmlFor="security-profile">Profile</Label>
                <Select value={selectedProfile} onValueChange={setSelectedProfile}>
                  <SelectTrigger id="security-profile"><SelectValue /></SelectTrigger>
                  <SelectContent>{(profiles.data ?? []).map((profile) => <SelectItem key={profile.key} value={profile.key}>{profile.name}</SelectItem>)}</SelectContent>
                </Select>
              </div>
              {selectedProfileInfo ? (
                <div className="rounded-md border bg-muted/20 p-3 text-sm">
                  <p>{selectedProfileInfo.description}</p>
                  <p className="mt-2 text-xs text-muted-foreground">
                    Tools: {selectedProfileInfo.activities.map((item) => `${item.tool} (${item.activity})`).join(", ")} · Rate {selectedProfileInfo.default_rate}/{selectedProfileInfo.max_rate} max
                  </p>
                </div>
              ) : null}
              <div className="space-y-2">
                <Label htmlFor="security-rate">Rate limit (requests/second or Nmap max rate)</Label>
                <Input id="security-rate" type="number" min="1" max={selectedProfileInfo?.max_rate ?? 1000} value={scanRate} onChange={(event) => setScanRate(event.target.value)} placeholder={`Profile default: ${selectedProfileInfo?.default_rate ?? "—"}`} />
              </div>
              {selectedProfileInfo?.requires_explicit_authorization ? (
                <label className="flex items-start gap-2 rounded-md border p-3 text-sm">
                  <input type="checkbox" checked={authorizedComprehensive} onChange={(event) => setAuthorizedComprehensive(event.target.checked)} className="mt-1" />
                  <span>I explicitly authorize this comprehensive, non-destructive scan against the selected target.</span>
                </label>
              ) : null}
              <Button type="submit" disabled={!selectedTarget || busy !== "" || (selectedProfileInfo?.requires_explicit_authorization === true && !authorizedComprehensive)}>
                {busy === "scan" ? <LoaderCircle className="animate-spin" /> : <Play />}Start authorized scan
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>

      {challenge ? (
        <Alert variant="info">
          <AlertTitle>Publish the ownership challenge</AlertTitle>
          <AlertDescription>
            {challenge.target.verify_method === "dns"
              ? `Create TXT record _vcqa-verification.${new URL(challenge.target.value).hostname} with this value: `
              : "Serve this exact token as plain text at /.well-known/vcqa-verification: "}
            <code className="break-all rounded bg-muted px-1">
              {challenge.target.verify_method === "dns" ? `vcqa-verification=${challenge.token}` : challenge.token}
            </code>
            <Button className="ml-2 h-7" size="sm" variant="outline" onClick={() => void navigator.clipboard.writeText(challenge.token)}>Copy token</Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <section id="jobs" className="space-y-3">
        <div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Running jobs and scan history</h2><Badge variant="muted">{jobs.data?.total ?? 0} jobs</Badge></div>
        <DataState loading={jobs.loading} error={jobs.error} onRetry={() => void jobs.reload()} loadingRows={3}>
          {(jobs.data?.items.length ?? 0) > 0 ? (
            <div className="space-y-2">
              {(jobs.data?.items ?? []).map((job) => (
                <JobRow key={job.id} job={job} target={targets.data?.find((item) => item.id === job.target_id)} busy={busy === `cancel-${job.id}`} onCancel={() => void cancelJob(job)} />
              ))}
            </div>
          ) : <EmptyState icon={Activity} title="No scans yet" description="Completed jobs and real worker status will appear here." />}
        </DataState>
      </section>

      <section id="findings" className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Vulnerability findings</h2>
          <Button size="sm" variant="outline" onClick={() => void exportReport()} disabled={busy !== ""}><Download />{busy === "report" ? "Preparing…" : "Export report"}</Button>
        </div>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-5" aria-label="Findings by severity">
          {SEVERITY_ORDER.map((severity) => (
            <Card key={severity} className={`border ${SEVERITY_CARD_CLASSES[severity]}`}>
              <CardContent className="flex items-center justify-between p-3">
                <span className="text-sm font-medium">{titleCase(severity)}</span>
                <span className="text-2xl font-semibold tabular-nums">{summary.data?.[severity] ?? 0}</span>
              </CardContent>
            </Card>
          ))}
        </div>
        <DataState loading={findings.loading} error={findings.error} onRetry={() => void findings.reload()} loadingRows={3}>
          {(findings.data?.items.length ?? 0) > 0 ? (
            <div className="space-y-2">
              {(findings.data?.items ?? []).map((finding) => (
                <FindingRow key={finding.id} finding={finding} busy={busy} onStatus={() => void setFindingStatus(finding)} onVerify={() => void verifyFinding(finding)} />
              ))}
            </div>
          ) : <EmptyState icon={ShieldCheck} title="No vulnerability findings recorded" description="Findings are created only from actual worker output." />}
        </DataState>
      </section>

      <section id="evidence" className="space-y-3">
        <h2 className="text-lg font-semibold">Evidence</h2>
        <DataState loading={evidence.loading} error={evidence.error} onRetry={() => void evidence.reload()} loadingRows={2}>
          {(evidence.data?.length ?? 0) > 0 ? (
            <div className="space-y-2">
              {(evidence.data ?? []).map((item) => (
                <button key={item.id} type="button" onClick={() => void openEvidence(item)} className="flex w-full items-center justify-between gap-3 rounded-md border px-3 py-2 text-left hover:bg-muted/40">
                  <span className="min-w-0"><span className="font-medium">{item.tool}</span><span className="ml-2 text-sm text-muted-foreground">Job #{item.job_id} · {item.byte_size.toLocaleString()} bytes · SHA-256 {item.content_sha256.slice(0, 12)}…</span></span>
                  {busy === `evidence-${item.id}` ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Clipboard className="h-4 w-4" />}
                </button>
              ))}
            </div>
          ) : <p className="rounded-md border p-4 text-sm text-muted-foreground">Raw output artifacts appear after an actual worker job completes. They are access-controlled and are not treated as instructions.</p>}
        </DataState>
      </section>

      {evidenceContent ? (
        <Card>
          <CardHeader className="flex-row items-start justify-between">
            <div><CardTitle>Raw evidence · {evidenceContent.tool}</CardTitle><CardDescription>Job #{evidenceContent.job_id} · SHA-256 {evidenceContent.content_sha256}</CardDescription></div>
            <Button size="sm" variant="outline" onClick={() => setEvidenceContent(null)}>Close</Button>
          </CardHeader>
          <CardContent><pre className="max-h-[480px] overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/30 p-3 font-mono text-xs">{evidenceContent.content}</pre></CardContent>
        </Card>
      ) : null}

      <WorkerSettings workers={workers.data ?? []} busy={busy} onCreated={async () => { await workers.reload(true); }} onError={setError} onBusy={setBusy} />
      <TargetList targets={targets.data ?? []} workers={workers.data ?? []} onRefresh={async () => { await targets.reload(true); }} onError={setError} onBusy={setBusy} busy={busy} />
    </div>
  );
}

function WorkerCard({ worker, busy, onCheck }: { worker: SecurityWorker; busy: boolean; onCheck: () => void }) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div><CardTitle className="text-base">{worker.name}</CardTitle><CardDescription>{worker.placement.replaceAll("_", " ")} · {worker.base_url}</CardDescription></div>
          <Badge variant={worker.reachable || worker.last_status === "healthy" ? "default" : "muted"}>{worker.reachable ? "Healthy" : worker.last_status ?? "Not checked"}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Worker {worker.worker_version ?? "version not reported"} · Last checked {worker.last_seen_at ? formatDateTime(worker.last_seen_at) : "never"}
        </p>
        {worker.detail ? <p className="text-xs text-muted-foreground">{worker.detail}</p> : null}
        <Button size="sm" variant="outline" disabled={busy || !worker.enabled} onClick={onCheck}>
          {busy ? <LoaderCircle className="animate-spin" /> : <RefreshCw />}Check health and tools
        </Button>
      </CardContent>
    </Card>
  );
}

function ProfileCard({ profile }: { profile: SecurityProfile }) {
  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle className="text-base">{profile.name}</CardTitle><CardDescription>{profile.description}</CardDescription></CardHeader>
      <CardContent className="space-y-2">
        <div className="flex flex-wrap gap-1">{profile.activities.map((activity) => <Badge key={activity.tool} variant={activity.activity === "active" ? "secondary" : "muted"}>{activity.tool} · {activity.activity}</Badge>)}</div>
        <p className="text-xs text-muted-foreground">Rate {profile.default_rate} default / {profile.max_rate} max per second{profile.requires_explicit_authorization ? " · explicit authorization required" : ""}</p>
      </CardContent>
    </Card>
  );
}

function JobRow({ job, target, busy, onCancel }: { job: SecurityJob; target?: SecurityTarget; busy: boolean; onCancel: () => void }) {
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center justify-between gap-3 p-3">
        <div className="min-w-0">
          <p className="font-medium">Job #{job.id} · {titleCase(job.profile)} <Badge variant={ACTIVE.has(job.status) ? "secondary" : "muted"}>{job.status}</Badge></p>
          <p className="truncate text-sm text-muted-foreground">{target?.value ?? `Target #${job.target_id}`} · {job.findings_count} findings · {formatDateTime(job.created_at)}</p>
          {job.error ? <p className="mt-1 text-xs text-destructive">{job.error}</p> : null}
        </div>
        {ACTIVE.has(job.status) ? <Button size="sm" variant="outline" disabled={busy} onClick={onCancel}><Square />Cancel</Button> : null}
      </CardContent>
    </Card>
  );
}

function FindingRow({ finding, busy, onStatus, onVerify }: { finding: SecurityFinding; busy: string; onStatus: () => void; onVerify: () => void }) {
  return (
    <Card>
      <CardContent className="flex flex-wrap items-start justify-between gap-3 p-3">
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="font-medium">{finding.title}</span><Badge variant="muted">{finding.verification_status}</Badge></div>
          <p className="text-sm text-muted-foreground">{finding.endpoint ?? finding.target} · {finding.tools.join(", ")} · {finding.confidence ?? "confidence unavailable"}</p>
          {finding.description ? <p className="line-clamp-2 text-sm">{finding.description}</p> : null}
          {finding.references.length ? <p className="text-xs text-muted-foreground">References: {finding.references.join(", ")}</p> : null}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" disabled={busy !== ""} onClick={onStatus}>{finding.status === "reviewed" ? "Reopen" : "Mark reviewed"}</Button>
          <Button size="sm" disabled={busy !== "" || finding.verification_status === "pending"} onClick={onVerify}>{busy === `verify-${finding.id}` ? <LoaderCircle className="animate-spin" /> : <Check />}Verify fix</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function WorkerSettings({ workers, busy, onCreated, onError, onBusy }: {
  workers: SecurityWorker[];
  busy: string;
  onCreated: () => Promise<void>;
  onError: (message: string | null) => void;
  onBusy: (value: string) => void;
}) {
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [token, setToken] = useState("");
  const [placement, setPlacement] = useState<SecurityWorker["placement"]>("same_vps");
  const [cidrs, setCidrs] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onBusy("worker-create");
    onError(null);
    try {
      await api.security.createWorker({
        name: name.trim(),
        base_url: baseUrl.trim(),
        token,
        placement,
        allowed_networks: cidrs.split(",").map((item) => item.trim()).filter(Boolean),
      });
      setName("");
      setBaseUrl("");
      setToken("");
      setCidrs("");
      await onCreated();
    } catch (caught) {
      onError(errorMessage(caught));
    } finally {
      onBusy("");
    }
  }

  async function revoke(worker: SecurityWorker) {
    onBusy(`revoke-${worker.id}`);
    try {
      await api.security.revokeWorker(worker.id);
      await onCreated();
    } catch (caught) {
      onError(errorMessage(caught));
    } finally {
      onBusy("");
    }
  }

  return (
    <details id="worker-settings" className="rounded-lg border bg-card p-4">
      <summary className="cursor-pointer font-semibold">Worker settings</summary>
      <div className="mt-4 grid gap-6 lg:grid-cols-2">
        <form className="space-y-3" onSubmit={(event) => void submit(event)}>
          <p className="text-sm text-muted-foreground">Register an independently deployed worker. The token is stored server-side and never returned to the browser after creation.</p>
          <div className="space-y-1"><Label htmlFor="worker-name">Worker name</Label><Input id="worker-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={120} /></div>
          <div className="space-y-1"><Label htmlFor="worker-url">Worker base URL</Label><Input id="worker-url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://worker.example.com" required /></div>
          <div className="space-y-1"><Label htmlFor="worker-token">Bearer token</Label><Input id="worker-token" type="password" autoComplete="new-password" value={token} onChange={(event) => setToken(event.target.value)} minLength={32} required /></div>
          <div className="space-y-1">
            <Label>Placement</Label>
            <Select value={placement} onValueChange={(value) => setPlacement(value as SecurityWorker["placement"])}>
              <SelectTrigger><SelectValue /></SelectTrigger><SelectContent>
                <SelectItem value="same_vps">Same VPS</SelectItem><SelectItem value="remote_vps">Remote VPS</SelectItem><SelectItem value="private_network">Authorized private network</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {placement === "private_network" ? <div className="space-y-1"><Label htmlFor="worker-cidrs">Administrator-approved CIDRs</Label><Input id="worker-cidrs" value={cidrs} onChange={(event) => setCidrs(event.target.value)} placeholder="10.20.0.0/16, 192.168.10.0/24" /></div> : null}
          <Button type="submit" disabled={busy !== ""}>{busy === "worker-create" ? <LoaderCircle className="animate-spin" /> : <Plus />}Register worker</Button>
        </form>
        <div className="space-y-2">
          <p className="text-sm font-medium">Credential management</p>
          {workers.map((worker) => (
            <div key={worker.id} className="flex items-center justify-between gap-2 rounded-md border p-2 text-sm">
              <span>{worker.name} · {worker.enabled ? "enabled" : "disabled"}</span>
              {worker.enabled ? <Button size="sm" variant="destructive" disabled={busy !== ""} onClick={() => void revoke(worker)}>{busy === `revoke-${worker.id}` ? <LoaderCircle className="animate-spin" /> : <Trash2 />}Revoke</Button> : null}
            </div>
          ))}
          {!workers.length ? <p className="text-sm text-muted-foreground">No workers registered.</p> : null}
        </div>
      </div>
    </details>
  );
}

function TargetPanel({ workers, profiles, busy, onCreated, onError, onBusy }: {
  workers: SecurityWorker[];
  profiles: SecurityProfile[];
  busy: string;
  onCreated: (target: SecurityTarget, token: string | null) => Promise<void>;
  onError: (message: string | null) => void;
  onBusy: (value: string) => void;
}) {
  const [value, setValue] = useState("");
  const [environment, setEnvironment] = useState<SecurityTarget["environment"]>("staging");
  const [workerId, setWorkerId] = useState("");
  const [profile, setProfile] = useState("basic");
  const [verifyMethod, setVerifyMethod] = useState<"dns" | "http">("http");
  const [cidrs, setCidrs] = useState("");
  const [scope, setScope] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onBusy("target-create");
    onError(null);
    try {
      const result = await api.security.createTarget({
        value: value.trim(),
        environment,
        ownership_confirmed: confirmed,
        profile,
        worker_id: workerId ? Number(workerId) : undefined,
        allowed_cidrs: cidrs.split(",").map((item) => item.trim()).filter(Boolean),
        scope: scope.trim() || undefined,
        verify_method: value.includes("://") ? verifyMethod : undefined,
      });
      setValue("");
      setScope("");
      setCidrs("");
      setConfirmed(false);
      await onCreated(result.target, result.verification_token);
    } catch (caught) {
      onError(errorMessage(caught));
    } finally {
      onBusy("");
    }
  }

  return (
    <Card id="targets">
      <CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" />Authorized targets</CardTitle><CardDescription>Registration is an allowlist entry, not proof of ownership. Public domains need DNS/HTTP verification; private targets need administrator approval.</CardDescription></CardHeader>
      <CardContent>
        <form className="space-y-3" onSubmit={(event) => void submit(event)}>
          <div className="space-y-1"><Label htmlFor="target-value">Target URL or IP</Label><Input id="target-value" value={value} onChange={(event) => setValue(event.target.value)} placeholder="https://app.example.com or approved IP" required /></div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1"><Label>Environment</Label><Select value={environment} onValueChange={(choice) => setEnvironment(choice as SecurityTarget["environment"])}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="development">Development</SelectItem><SelectItem value="staging">Staging</SelectItem><SelectItem value="production">Production</SelectItem></SelectContent></Select></div>
            <div className="space-y-1"><Label>Assigned worker</Label><Select value={workerId} onValueChange={setWorkerId}><SelectTrigger><SelectValue placeholder="Select worker" /></SelectTrigger><SelectContent>{workers.filter((worker) => worker.enabled).map((worker) => <SelectItem key={worker.id} value={String(worker.id)}>{worker.name} · {worker.placement.replaceAll("_", " ")}</SelectItem>)}</SelectContent></Select></div>
            <div className="space-y-1"><Label>Default profile</Label><Select value={profile} onValueChange={setProfile}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{profiles.map((item) => <SelectItem key={item.key} value={item.key}>{item.name}</SelectItem>)}</SelectContent></Select></div>
            {value.includes("://") ? <div className="space-y-1"><Label>Ownership verification</Label><Select value={verifyMethod} onValueChange={(choice) => setVerifyMethod(choice as "dns" | "http")}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="http">HTTP challenge</SelectItem><SelectItem value="dns">DNS TXT challenge</SelectItem></SelectContent></Select></div> : null}
          </div>
          <div className="space-y-1"><Label htmlFor="target-scope">Approved scope (optional description)</Label><Input id="target-scope" value={scope} onChange={(event) => setScope(event.target.value)} placeholder="Application and explicitly approved paths" /></div>
          <div className="space-y-1"><Label htmlFor="target-cidrs">Private CIDRs (administrator-approved only)</Label><Input id="target-cidrs" value={cidrs} onChange={(event) => setCidrs(event.target.value)} placeholder="10.20.1.0/24" /></div>
          <label className="flex items-start gap-2 rounded-md border p-3 text-sm">
            <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-1" />
            <span>I own this target or have written authorization for this exact scope. I understand that entering an IP is not proof of authorization.</span>
          </label>
          <Button type="submit" disabled={!confirmed || busy !== ""}>{busy === "target-create" ? <LoaderCircle className="animate-spin" /> : <Plus />}Add authorized target</Button>
        </form>
      </CardContent>
    </Card>
  );
}

function TargetList({ targets, workers, onRefresh, onError, onBusy, busy }: {
  targets: SecurityTarget[];
  workers: SecurityWorker[];
  onRefresh: () => Promise<void>;
  onError: (message: string | null) => void;
  onBusy: (value: string) => void;
  busy: string;
}) {
  async function verify(target: SecurityTarget) {
    onBusy(`verify-target-${target.id}`);
    try {
      const result = await api.security.verifyTarget(target.id);
      if (result.verify_status !== "verified") onError(result.verify_detail || "The ownership challenge has not been found yet.");
      await onRefresh();
    } catch (caught) {
      onError(errorMessage(caught));
    } finally {
      onBusy("");
    }
  }

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Target allowlist</h2><Badge variant="muted">{targets.length}</Badge></div>
      {targets.length ? targets.map((target) => {
        const worker = workers.find((item) => item.id === target.worker_id);
        return (
          <Card key={target.id}>
            <CardContent className="flex flex-wrap items-center justify-between gap-3 p-3">
              <div className="min-w-0">
                <p className="truncate font-medium">{target.value}</p>
                <p className="text-xs text-muted-foreground">{target.environment} · {worker?.name ?? "No worker"} · {target.verify_method ?? "admin-approved"} · {target.allowed_cidrs ?? "public scope"}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={target.verify_status === "verified" ? "default" : "secondary"}>{target.verify_status}</Badge>
                {target.verify_status !== "verified" ? <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void verify(target)}>{busy === `verify-target-${target.id}` ? <LoaderCircle className="animate-spin" /> : <Check />}Verify</Button> : null}
              </div>
            </CardContent>
          </Card>
        );
      }) : <p className="rounded-md border p-4 text-sm text-muted-foreground">No authorized targets are registered.</p>}
    </section>
  );
}
