import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FolderPlus } from "lucide-react";

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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { api, ApiError } from "@/lib/api";
import { formatScore } from "@/lib/format";
import type { ScanOptions } from "@/types/api";

function parseOptionalNumber(raw: string): number | null {
  const value = raw.trim();
  if (!value) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function NewScanPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { repositories, activeRepositoryId } = useApp();

  const profiles = useAsync(() => api.system.profiles(), []);
  const settings = useAsync(() => api.system.scanSettings(), []);

  const [repositoryId, setRepositoryId] = useState<string>(() =>
    activeRepositoryId !== null ? String(activeRepositoryId) : "",
  );
  const [profileKey, setProfileKey] = useState("");
  const [osv, setOsv] = useState(false);
  const [aiReview, setAiReview] = useState(false);
  const [staticOnly, setStaticOnly] = useState(false);
  const [explicitPermission, setExplicitPermission] = useState(false);
  const [testTimeoutRaw, setTestTimeoutRaw] = useState("");
  const [testImageRaw, setTestImageRaw] = useState("");
  const [maxMemoryRaw, setMaxMemoryRaw] = useState("");
  const [maxCpuRaw, setMaxCpuRaw] = useState("");
  const [maxSnapshotRaw, setMaxSnapshotRaw] = useState("");
  const [maxWriteRaw, setMaxWriteRaw] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmAcknowledged, setConfirmAcknowledged] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const prefilled = useRef(false);
  useEffect(() => {
    const data = settings.data;
    if (!data || prefilled.current) return;
    prefilled.current = true;
    setProfileKey(data.default_scan_profile);
    setOsv(data.osv_enabled);
    setTestTimeoutRaw(String(data.test_timeout));
    setTestImageRaw(data.test_image);
    setMaxMemoryRaw(String(data.max_memory_mb));
    setMaxCpuRaw(String(data.max_cpu_seconds));
    setMaxSnapshotRaw(String(data.max_snapshot_mb));
    setMaxWriteRaw(String(data.max_write_mb));
  }, [settings.data]);

  const selectedProfile = useMemo(
    () => (profiles.data ?? []).find((profile) => profile.key === profileKey) ?? null,
    [profiles.data, profileKey],
  );
  const selectedRepository = useMemo(
    () => repositories.find((repository) => String(repository.id) === repositoryId) ?? null,
    [repositories, repositoryId],
  );
  const allowTestExecution = settings.data?.allow_test_execution ?? false;

  const options = useMemo<ScanOptions>(() => {
    const built: ScanOptions = { osv, ai_review: aiReview, static_only: staticOnly };
    if (explicitPermission) built.explicit_permission = true;
    const data = settings.data;
    if (data && !staticOnly) {
      if (testTimeoutRaw.trim() !== String(data.test_timeout)) {
        const value = parseOptionalNumber(testTimeoutRaw);
        if (value !== null) built.test_timeout = value;
      }
      if (testImageRaw.trim() !== data.test_image) {
        built.test_image = testImageRaw.trim() || null;
      }
      if (maxMemoryRaw.trim() !== String(data.max_memory_mb)) {
        const value = parseOptionalNumber(maxMemoryRaw);
        if (value !== null) built.max_memory_mb = value;
      }
      if (maxCpuRaw.trim() !== String(data.max_cpu_seconds)) {
        const value = parseOptionalNumber(maxCpuRaw);
        if (value !== null) built.max_cpu_seconds = value;
      }
      if (maxSnapshotRaw.trim() !== String(data.max_snapshot_mb)) {
        const value = parseOptionalNumber(maxSnapshotRaw);
        if (value !== null) built.max_snapshot_mb = value;
      }
      if (maxWriteRaw.trim() !== String(data.max_write_mb)) {
        const value = parseOptionalNumber(maxWriteRaw);
        if (value !== null) built.max_write_mb = value;
      }
    }
    return built;
  }, [
    osv,
    aiReview,
    staticOnly,
    explicitPermission,
    testTimeoutRaw,
    testImageRaw,
    maxMemoryRaw,
    maxCpuRaw,
    maxSnapshotRaw,
    maxWriteRaw,
    settings.data,
  ]);

  function handleStaticOnly(next: boolean) {
    setStaticOnly(next);
    if (next) {
      setExplicitPermission(false);
      setTestTimeoutRaw("");
      setTestImageRaw("");
      setMaxMemoryRaw("");
      setMaxCpuRaw("");
      setMaxSnapshotRaw("");
      setMaxWriteRaw("");
    }
  }

  async function handleSubmit() {
    if (!repositoryId) {
      toast({ title: "Select a repository", variant: "error" });
      return;
    }
    if (!profileKey) {
      toast({ title: "Select a scan profile", variant: "error" });
      return;
    }
    setSubmitting(true);
    try {
      const scan = await api.scans.create({
        repository_id: Number(repositoryId),
        profile: profileKey,
        options,
      });
      toast({
        title: "Scan queued",
        description: `Scan #${scan.id} was accepted by the engine.`,
        variant: "success",
      });
      navigate(`/scans/${scan.id}`);
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "The scan could not be started.";
      toast({ title: "Scan could not be started", description: message, variant: "error" });
    } finally {
      setSubmitting(false);
    }
  }

  if (repositories.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="New scan"
          description="Choose a repository and a profile, then start a scan."
        />
        <EmptyState
          icon={FolderPlus}
          title="No repositories yet"
          description="Register a repository before starting a scan. Tests only ever run inside an isolated sandbox, and only when you allow it."
          action={
            <Button asChild size="sm" variant="outline">
              <Link to="/repositories">Add a repository</Link>
            </Button>
          }
        />
      </div>
    );
  }

  const testsWillRun = explicitPermission && !staticOnly;

  return (
    <div className="space-y-6">
      <PageHeader
        title="New scan"
        description="Choose a repository and a profile, then start a scan."
      />

      <DataState
        loading={profiles.loading || settings.loading}
        error={profiles.error ?? settings.error}
        onRetry={() => {
          void profiles.reload();
          void settings.reload();
        }}
        loadingRows={2}
      >
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle>Target</CardTitle>
                <CardDescription>
                  The repository to scan and the profile that decides what actually runs.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="repository">Repository</Label>
                  <Select value={repositoryId || undefined} onValueChange={setRepositoryId}>
                    <SelectTrigger id="repository">
                      <SelectValue placeholder="Select a repository" />
                    </SelectTrigger>
                    <SelectContent>
                      {repositories.map((repository) => (
                        <SelectItem key={repository.id} value={String(repository.id)}>
                          {repository.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="profile">Profile</Label>
                  <Select value={profileKey || undefined} onValueChange={setProfileKey}>
                    <SelectTrigger id="profile">
                      <SelectValue placeholder="Select a profile" />
                    </SelectTrigger>
                    <SelectContent>
                      {(profiles.data ?? []).map((profile) => (
                        <SelectItem key={profile.key} value={profile.key}>
                          {profile.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {selectedProfile ? (
                  <div className="space-y-3 rounded-md border bg-muted/30 p-4">
                    <p className="text-sm text-muted-foreground">{selectedProfile.description}</p>
                    {selectedProfile.modules.length ? (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedProfile.modules.map((module) => (
                          <Badge key={module} variant="muted">
                            {module}
                          </Badge>
                        ))}
                      </div>
                    ) : null}
                    <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
                      <ProfileFact
                        label="Minimum score"
                        value={formatScore(selectedProfile.minimum_score)}
                      />
                      <ProfileFact label="Runs tests" value={selectedProfile.run_tests ? "Yes" : "No"} />
                      <ProfileFact label="OSV" value={selectedProfile.osv ? "Yes" : "No"} />
                      <ProfileFact label="AI review" value={selectedProfile.ai_review ? "Yes" : "No"} />
                    </dl>
                    {selectedProfile.notes.length ? (
                      <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                        {selectedProfile.notes.map((note, index) => (
                          <li key={index}>{note}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                ) : null}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Options</CardTitle>
                <CardDescription>These map directly onto the engine's scan options.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <OptionRow
                  id="osv"
                  label="Check dependencies against OSV advisories"
                  checked={osv}
                  onChange={setOsv}
                />
                <OptionRow
                  id="ai-review"
                  label="Request AI review of critical and high findings"
                  description="Requires a configured AI provider."
                  checked={aiReview}
                  onChange={setAiReview}
                />
                <OptionRow
                  id="static-only"
                  label="Static analysis only"
                  description="Skips the isolated test suite and clears its sandbox controls."
                  checked={staticOnly}
                  onChange={handleStaticOnly}
                />

                <Separator />

                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-4">
                    <div className="space-y-1">
                      <Label htmlFor="explicit-permission">
                        Allow the isolated test suite to run inside Docker
                      </Label>
                      <p className="text-xs text-muted-foreground">
                        Off by default. The test suite never runs unless you grant explicit
                        permission.
                      </p>
                    </div>
                    <Switch
                      id="explicit-permission"
                      checked={explicitPermission}
                      disabled={staticOnly || !allowTestExecution}
                      onCheckedChange={(next) => {
                        if (next) setConfirmOpen(true);
                        else setExplicitPermission(false);
                      }}
                    />
                  </div>
                  {!allowTestExecution ? (
                    <p className="text-xs text-muted-foreground">
                      Test execution is disabled by the operator in scan settings.
                    </p>
                  ) : null}
                </div>

                <Alert variant="warning">
                  <AlertTitle>Tests run in an isolated Docker sandbox</AlertTitle>
                  <AlertDescription>
                    Enabling test execution runs the repository's test suite inside a Docker sandbox
                    with memory, CPU, snapshot and write limits. Docker must be available on the
                    host for this to succeed.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Advanced limits</CardTitle>
                <CardDescription>
                  Sandbox limits and overrides. Leave a field untouched to use the operator default.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <details className="group">
                  <summary className="cursor-pointer text-sm font-medium text-muted-foreground hover:text-foreground">
                    Show advanced options
                  </summary>
                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <SettingsField
                      id="test-timeout"
                      label="Test timeout (seconds)"
                      type="number"
                      value={testTimeoutRaw}
                      onChange={setTestTimeoutRaw}
                      disabled={staticOnly}
                    />
                    <SettingsField
                      id="test-image"
                      label="Test image"
                      type="text"
                      value={testImageRaw}
                      onChange={setTestImageRaw}
                      disabled={staticOnly}
                    />
                    <SettingsField
                      id="max-memory"
                      label="Max memory (MB)"
                      type="number"
                      value={maxMemoryRaw}
                      onChange={setMaxMemoryRaw}
                      disabled={staticOnly}
                    />
                    <SettingsField
                      id="max-cpu"
                      label="Max CPU (seconds)"
                      type="number"
                      value={maxCpuRaw}
                      onChange={setMaxCpuRaw}
                      disabled={staticOnly}
                    />
                    <SettingsField
                      id="max-snapshot"
                      label="Max snapshot (MB)"
                      type="number"
                      value={maxSnapshotRaw}
                      onChange={setMaxSnapshotRaw}
                      disabled={staticOnly}
                    />
                    <SettingsField
                      id="max-write"
                      label="Max write (MB)"
                      type="number"
                      value={maxWriteRaw}
                      onChange={setMaxWriteRaw}
                      disabled={staticOnly}
                    />
                  </div>
                  {staticOnly ? (
                    <p className="mt-3 text-xs text-muted-foreground">
                      These controls are cleared and disabled while static analysis only is enabled.
                    </p>
                  ) : null}
                </details>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-4 lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle>Operator defaults</CardTitle>
                <CardDescription>Values configured in scan settings.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <FactRow label="Default profile" value={settings.data?.default_scan_profile ?? "—"} />
                <FactRow label="Allow test execution" value={allowTestExecution ? "Yes" : "No"} />
                <FactRow label="Test image" value={settings.data?.test_image ?? "—"} />
                <FactRow
                  label="Test timeout"
                  value={settings.data ? `${settings.data.test_timeout} s` : "—"}
                />
                <FactRow
                  label="Max memory"
                  value={settings.data ? `${settings.data.max_memory_mb} MB` : "—"}
                />
                <FactRow
                  label="Max CPU"
                  value={settings.data ? `${settings.data.max_cpu_seconds} s` : "—"}
                />
                <FactRow
                  label="Max snapshot"
                  value={settings.data ? `${settings.data.max_snapshot_mb} MB` : "—"}
                />
                <FactRow
                  label="Max write"
                  value={settings.data ? `${settings.data.max_write_mb} MB` : "—"}
                />
                <FactRow
                  label="OSV advisories"
                  value={settings.data?.osv_enabled ? "Enabled" : "Disabled"}
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Summary</CardTitle>
                <CardDescription>What this scan will do.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <FactRow label="Repository" value={selectedRepository?.name ?? "Not selected"} />
                <FactRow
                  label="Profile"
                  value={selectedProfile?.name ?? (profileKey || "Not selected")}
                />
                <FactRow label="Static analysis" value="Enabled" />
                <FactRow label="OSV advisories" value={osv ? "Enabled" : "Disabled"} />
                <FactRow label="AI review" value={aiReview ? "Requested" : "Not requested"} />
                <FactRow label="Test suite" value={testsWillRun ? "Runs in a Docker sandbox" : "Does not run"} />
                <p className="text-xs text-muted-foreground">
                  Static analysis always runs.{" "}
                  {testsWillRun
                    ? "The isolated test suite will run in a Docker sandbox."
                    : "No tests will be executed."}{" "}
                  {osv ? "Dependency advisories are checked via OSV." : null}
                </p>
                <Button
                  className="w-full"
                  disabled={submitting || !repositoryId || !profileKey}
                  onClick={() => void handleSubmit()}
                >
                  {submitting ? "Starting..." : "Start scan"}
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </DataState>

      <Dialog
        open={confirmOpen}
        onOpenChange={(open) => {
          setConfirmOpen(open);
          if (!open) setConfirmAcknowledged(false);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Run the test suite in a sandbox?</DialogTitle>
            <DialogDescription>
              Tests execute inside an isolated Docker sandbox. Only enable this when you intend to
              run the repository's test suite.
            </DialogDescription>
          </DialogHeader>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 rounded border-input"
              checked={confirmAcknowledged}
              onChange={(event) => setConfirmAcknowledged(event.target.checked)}
            />
            <span>I understand tests will execute in an isolated sandbox.</span>
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!confirmAcknowledged}
              onClick={() => {
                setExplicitPermission(true);
                setConfirmOpen(false);
                setConfirmAcknowledged(false);
              }}
            >
              Enable test execution
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ProfileFact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="font-medium tabular-nums">{value}</dd>
    </div>
  );
}

function FactRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  );
}

function OptionRow({
  id,
  label,
  description,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  description?: string;
  checked: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="space-y-1">
        <Label htmlFor={id}>{label}</Label>
        {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

function SettingsField({
  id,
  label,
  value,
  onChange,
  type = "number",
  disabled,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (next: string) => void;
  type?: string;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type={type}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}
