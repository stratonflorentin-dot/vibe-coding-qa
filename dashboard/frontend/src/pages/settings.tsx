import { ShieldCheck } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { api, ApiError } from "@/lib/api";
import { formatCount } from "@/lib/format";
import type { AIConnectionTest, AISettings, AISettingsIn, ScanSettings } from "@/types/api";

const SAFETY_GUARANTEES = [
  "The Python engine is the single source of truth; the dashboard only displays what it produced.",
  "The AI never decides the release gate. Verdicts come from deterministic checks.",
  "Proposed patches are never applied without explicit human confirmation.",
  "The test suite only runs with explicit permission, inside a Docker sandbox with no network access.",
  "Secrets are redacted before anything is sent to an AI provider.",
];

const SOURCE_LABELS: Record<AISettings["source"], string> = {
  environment: "Environment variable",
  settings: "Saved in settings",
  none: "None",
};

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Scan defaults, the optional AI provider and the product's safety guarantees."
      />

      <Tabs defaultValue="scan">
        <TabsList>
          <TabsTrigger value="scan">Scan</TabsTrigger>
          <TabsTrigger value="ai">AI provider</TabsTrigger>
          <TabsTrigger value="safety">About / safety</TabsTrigger>
        </TabsList>
        <TabsContent value="scan">
          <ScanTab />
        </TabsContent>
        <TabsContent value="ai">
          <AiTab />
        </TabsContent>
        <TabsContent value="safety">
          <SafetyTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ScanTab() {
  const { toast } = useToast();
  const settings = useAsync(() => api.system.scanSettings(), []);
  const profiles = useAsync(() => api.system.profiles(), []);
  const [form, setForm] = useState<ScanSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (settings.data) setForm(settings.data);
  }, [settings.data]);

  const current = form ?? settings.data;

  async function save() {
    if (!current) return;
    setSaving(true);
    setSaveError(null);
    try {
      const saved = await api.system.updateScanSettings(current);
      setForm(saved);
      toast({ title: "Scan settings saved", variant: "success" });
    } catch (caught) {
      const message =
        caught instanceof ApiError ? caught.message : "The scan settings could not be saved.";
      setSaveError(message);
      toast({ title: "Could not save scan settings", description: message, variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <DataState
      loading={settings.loading || profiles.loading}
      error={settings.error ?? profiles.error}
      onRetry={() => {
        void settings.reload();
        void profiles.reload();
      }}
      loadingRows={4}
    >
      {current ? (
        <Card>
          <CardHeader>
            <CardTitle>Default scan settings</CardTitle>
            <CardDescription>
              Applied when a scan is created without explicit overrides.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-1.5">
              <Label htmlFor="default-scan-profile">Default scan profile</Label>
              <Select
                value={current.default_scan_profile}
                onValueChange={(value) => setForm({ ...current, default_scan_profile: value })}
              >
                <SelectTrigger id="default-scan-profile">
                  <SelectValue placeholder="Choose a profile" />
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

            <SwitchRow
              id="allow-test-execution"
              label="Allow test execution"
              description="Tests run only in an isolated Docker sandbox with no network access. Enabling this lets future scans request test execution; every scan still needs explicit permission."
              checked={current.allow_test_execution}
              onCheckedChange={(checked) => setForm({ ...current, allow_test_execution: checked })}
            />

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Test image" htmlFor="test-image">
                <Input
                  id="test-image"
                  value={current.test_image}
                  onChange={(event) => setForm({ ...current, test_image: event.target.value })}
                />
              </Field>
              <NumberField
                label="Test timeout (seconds)"
                htmlFor="test-timeout"
                value={current.test_timeout}
                onChange={(value) => setForm({ ...current, test_timeout: value })}
              />
              <NumberField
                label="Max memory (MB)"
                htmlFor="max-memory"
                value={current.max_memory_mb}
                onChange={(value) => setForm({ ...current, max_memory_mb: value })}
              />
              <NumberField
                label="Max CPU seconds"
                htmlFor="max-cpu"
                value={current.max_cpu_seconds}
                onChange={(value) => setForm({ ...current, max_cpu_seconds: value })}
              />
              <NumberField
                label="Max snapshot (MB)"
                htmlFor="max-snapshot"
                value={current.max_snapshot_mb}
                onChange={(value) => setForm({ ...current, max_snapshot_mb: value })}
              />
              <NumberField
                label="Max write (MB)"
                htmlFor="max-write"
                value={current.max_write_mb}
                onChange={(value) => setForm({ ...current, max_write_mb: value })}
              />
            </div>

            <SwitchRow
              id="osv-enabled"
              label="Check OSV advisories"
              description="When enabled, scans may look up known vulnerabilities for dependencies. This uses the network."
              checked={current.osv_enabled}
              onCheckedChange={(checked) => setForm({ ...current, osv_enabled: checked })}
            />

            {saveError ? (
              <Alert variant="destructive">
                <AlertTitle>Save failed</AlertTitle>
                <AlertDescription>{saveError}</AlertDescription>
              </Alert>
            ) : null}

            <div className="flex justify-end">
              <Button onClick={() => void save()} disabled={saving}>
                {saving ? "Saving…" : "Save scan settings"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </DataState>
  );
}

function toAiForm(settings: AISettings): AISettingsIn {
  return {
    enabled: settings.enabled,
    provider: settings.provider,
    base_url: settings.base_url,
    model: settings.model,
    timeout: settings.timeout,
    max_output_tokens: settings.max_output_tokens,
    share_source_context: settings.share_source_context,
  };
}

function AiTab() {
  const { toast } = useToast();
  const settings = useAsync(() => api.system.aiSettings(), []);
  const [form, setForm] = useState<AISettingsIn | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<AIConnectionTest | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  useEffect(() => {
    if (settings.data) setForm(toAiForm(settings.data));
  }, [settings.data]);

  const current = form ?? (settings.data ? toAiForm(settings.data) : null);

  async function save() {
    if (!current) return;
    setSaving(true);
    setSaveError(null);
    try {
      const saved = await api.system.updateAiSettings(current);
      setForm(toAiForm(saved));
      settings.setData(saved);
      toast({ title: "AI settings saved", variant: "success" });
    } catch (caught) {
      const message =
        caught instanceof ApiError ? caught.message : "The AI settings could not be saved.";
      setSaveError(message);
      toast({ title: "Could not save AI settings", description: message, variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  async function testConnection() {
    setTesting(true);
    setTestError(null);
    setTestResult(null);
    try {
      setTestResult(await api.system.testAiConnection());
    } catch (caught) {
      setTestError(
        caught instanceof ApiError ? caught.message : "The connection test could not be completed.",
      );
    } finally {
      setTesting(false);
    }
  }

  return (
    <DataState
      loading={settings.loading}
      error={settings.error}
      onRetry={() => void settings.reload()}
      loadingRows={4}
    >
      {current && settings.data ? (
        <div className="space-y-4">
          <Alert variant="info">
            <AlertTitle>AI features are optional</AlertTitle>
            <AlertDescription>
              The scanner and the release gate work without any AI provider. AI assistance is layered
              on top of real scan results and never decides the verdict.
            </AlertDescription>
          </Alert>

          <Card>
            <CardHeader>
              <CardTitle>AI provider</CardTitle>
              <CardDescription>Used only for the optional AI features.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <SwitchRow
                id="ai-enabled"
                label="Enable AI features"
                description="Turn AI assistance on or off across the dashboard."
                checked={current.enabled}
                onCheckedChange={(checked) => setForm({ ...current, enabled: checked })}
              />

              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Provider" htmlFor="ai-provider">
                  <Input
                    id="ai-provider"
                    value={current.provider}
                    onChange={(event) => setForm({ ...current, provider: event.target.value })}
                  />
                </Field>
                <Field label="Model" htmlFor="ai-model">
                  <Input
                    id="ai-model"
                    value={current.model}
                    onChange={(event) => setForm({ ...current, model: event.target.value })}
                  />
                </Field>
                <Field label="Base URL" htmlFor="ai-base-url">
                  <Input
                    id="ai-base-url"
                    value={current.base_url}
                    onChange={(event) => setForm({ ...current, base_url: event.target.value })}
                  />
                </Field>
                <NumberField
                  label="Timeout (seconds)"
                  htmlFor="ai-timeout"
                  value={current.timeout}
                  onChange={(value) => setForm({ ...current, timeout: value })}
                />
                <NumberField
                  label="Max output tokens"
                  htmlFor="ai-max-output"
                  value={current.max_output_tokens}
                  onChange={(value) => setForm({ ...current, max_output_tokens: value })}
                />
              </div>

              <SwitchRow
                id="ai-share-context"
                label="Share source context"
                description="When enabled, the dashboard sends selected source context to the configured provider so it can answer with real code. Leave this off to keep source on the server."
                checked={current.share_source_context}
                onCheckedChange={(checked) =>
                  setForm({ ...current, share_source_context: checked })
                }
              />

              <div className="space-y-1.5 rounded-md border bg-muted/30 p-3">
                <p className="text-sm font-medium">Server-side credentials</p>
                <p className="text-xs text-muted-foreground">
                  {settings.data.api_key_configured ? "A key is configured" : "No key configured"} ·
                  source: {SOURCE_LABELS[settings.data.source]}
                </p>
                <p className="text-xs text-muted-foreground">
                  Set <code>VCQA_AI_API_KEY</code> in the backend process environment. Keys are
                  never sent through the browser or stored in SQLite.
                </p>
              </div>

              {saveError ? (
                <Alert variant="destructive">
                  <AlertTitle>Save failed</AlertTitle>
                  <AlertDescription>{saveError}</AlertDescription>
                </Alert>
              ) : null}

              <div className="flex flex-wrap justify-end gap-2">
                <Button variant="outline" onClick={() => void testConnection()} disabled={testing}>
                  {testing ? "Testing…" : "Test connection"}
                </Button>
                <Button onClick={() => void save()} disabled={saving}>
                  {saving ? "Saving…" : "Save AI settings"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {testError ? (
            <Alert variant="destructive">
              <AlertTitle>Connection test failed</AlertTitle>
              <AlertDescription>{testError}</AlertDescription>
            </Alert>
          ) : null}

          {testResult ? (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>Connection test</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex flex-wrap gap-2">
                  <Badge variant={testResult.ok ? "default" : "destructive"}>
                    {testResult.ok ? "ok" : "not ok"}
                  </Badge>
                  <Badge variant="muted">
                    {testResult.configured ? "configured" : "not configured"}
                  </Badge>
                  {testResult.provider ? (
                    <Badge variant="secondary">{testResult.provider}</Badge>
                  ) : null}
                  {testResult.model ? <Badge variant="secondary">{testResult.model}</Badge> : null}
                </div>
                <p className="text-sm text-muted-foreground">{testResult.detail}</p>
              </CardContent>
            </Card>
          ) : null}
        </div>
      ) : null}
    </DataState>
  );
}

function SafetyTab() {
  const { health, healthError, loading } = useApp();

  return (
    <div className="space-y-4">
      <DataState loading={loading} error={healthError} loadingRows={2}>
        {health ? (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle>Backend</CardTitle>
              <CardDescription>Reported by the running engine.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 p-5 pt-0 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Version" value={health.version} />
              <Fact label="Database" value={health.database} />
              <Fact label="Repositories" value={formatCount(health.repositories)} />
              <Fact label="Scans" value={formatCount(health.scans)} />
              <Fact label="AI configured" value={health.ai_configured ? "Yes" : "No"} />
            </CardContent>
          </Card>
        ) : null}
      </DataState>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" />
            Safety guarantees
          </CardTitle>
          <CardDescription>How the product keeps analysis honest and safe.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
            {SAFETY_GUARANTEES.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

function SwitchRow({
  id,
  label,
  description,
  checked,
  onCheckedChange,
}: {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-md border p-3">
      <div className="space-y-1">
        <Label htmlFor={id}>{label}</Label>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

function Field({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
    </div>
  );
}

function NumberField({
  label,
  htmlFor,
  value,
  onChange,
}: {
  label: string;
  htmlFor: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <Field label={label} htmlFor={htmlFor}>
      <Input
        id={htmlFor}
        type="number"
        value={Number.isFinite(value) ? value : 0}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </Field>
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
