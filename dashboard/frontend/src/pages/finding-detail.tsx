import { ArrowLeft, Bot, Check, Copy, FileDown, Sparkles, Wrench } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { FindingStatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import { Markdown } from "@/components/common/markdown";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { useToast } from "@/components/ui/toast";
import { useAsync } from "@/hooks/use-async";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/format";
import type { FindingStatus } from "@/types/api";

export function FindingDetailPage() {
  const { health } = useApp();
  const { findingId: rawId } = useParams();
  const id = Number.parseInt(rawId ?? "", 10);
  const valid = Number.isInteger(id) && id > 0;
  const navigate = useNavigate();
  const { toast } = useToast();
  const finding = useAsync(() => api.findings.get(id), [id], { enabled: valid });
  const [busy, setBusy] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [aiUnavailable, setAiUnavailable] = useState(false);
  const [aiAnswer, setAiAnswer] = useState<string | null>(null);
  const [proposalId, setProposalId] = useState<number | null>(null);
  const aiDisabled = aiUnavailable || health?.ai_configured !== true;
  const showAiUnavailable = aiUnavailable || health?.ai_configured === false;

  if (!valid) {
    return <EmptyState icon={ArrowLeft} title="Finding not found" description="The finding id must be a positive number." action={<Button asChild variant="outline"><Link to="/findings">Back to findings</Link></Button>} />;
  }

  const data = finding.data;

  async function updateStatus(status: FindingStatus) {
    setBusy("status");
    setError(null);
    try {
      await api.findings.setStatus(id, status);
      await finding.reload(true);
      toast({ title: status === "reviewed" ? "Marked as reviewed" : `Status set to ${titleCase(status)}`, variant: "success" });
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The status could not be updated.");
    } finally {
      setBusy("");
    }
  }

  async function askAssistant() {
    if (!data) return;
    setBusy("assistant");
    setError(null);
    try {
      const response = await api.ai.chat({
        repository_id: data.repository_id,
        message: `Explain finding ${data.rule} at ${data.file}:${data.line}. Use the stored scan evidence and distinguish confirmed facts from hypotheses.`,
      });
      if (!response.configured) {
        setAiUnavailable(true);
      } else {
        setAiAnswer(response.message.content);
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The assistant request failed.");
    } finally {
      setBusy("");
    }
  }

  async function explainFinding() {
    setBusy("review");
    setError(null);
    try {
      const response = await api.ai.reviewFinding(id, "analyst");
      if (!response.configured) {
        setAiUnavailable(true);
      } else if (response.error) {
        setError(response.error);
      } else {
        const text = response.content.text;
        setAiAnswer(typeof text === "string" ? text : JSON.stringify(response.content, null, 2));
        await finding.reload(true);
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The finding review failed.");
    } finally {
      setBusy("");
    }
  }

  async function generateFix() {
    setBusy("fix");
    setError(null);
    try {
      const proposal = await api.ai.proposeRemediation(id);
      setProposalId(proposal.id);
      toast({ title: "Patch proposal is ready", description: "Review it before applying any change.", variant: "success" });
    } catch (caught) {
      const message = caught instanceof ApiError ? caught.message : "";
      if (/AI is not configured/i.test(message)) {
        setAiUnavailable(true);
      } else {
        setError(message || "A patch proposal could not be generated.");
      }
    } finally {
      setBusy("");
    }
  }

  function exportFinding() {
    if (!data) return;
    const markdown = [
      `# ${data.rule}`,
      "",
      `- Severity: ${data.severity}`,
      `- Category: ${data.module}`,
      `- Repository: ${data.repository_name}`,
      `- Location: ${data.file}:${data.line}`,
      `- Confidence: ${data.confidence ?? "unknown"}`,
      `- Status: ${data.status}`,
      "",
      "## Finding",
      data.message ?? "",
      "",
      "## Remediation",
      data.suggestion ?? "No remediation guidance was recorded.",
      "",
      "## Evidence",
      "```text",
      ...(data.evidence ?? []),
      "```",
    ].join("\n");
    const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `finding-${data.id}.md`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={data?.rule ?? `Finding #${id}`}
        description={data ? `${data.repository_name} · ${data.file}:${data.line}` : "Finding details and source evidence."}
        actions={
          <>
            <Button asChild size="sm" variant="outline"><Link to="/findings"><ArrowLeft />Findings</Link></Button>
            {data?.status === "open" ? (
              <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void updateStatus("reviewed")}><Check />Mark reviewed</Button>
            ) : data?.status === "reviewed" ? (
              <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => void updateStatus("open")}>Reopen</Button>
            ) : null}
            <Button size="sm" variant="outline" onClick={exportFinding} disabled={!data}><FileDown />Export</Button>
          </>
        }
      />

      <DataState loading={finding.loading} error={finding.error} onRetry={() => void finding.reload()} loadingRows={4}>
        {data ? (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={data.severity} />
              <Badge variant="muted">{titleCase(data.module)}</Badge>
              <FindingStatusBadge status={data.status} />
              <span className="text-sm text-muted-foreground">Confidence: {titleCase(data.confidence ?? "unknown")}</span>
            </div>

            {showAiUnavailable ? (
              <Alert variant="warning">
                <AlertTitle>AI assistance is unavailable</AlertTitle>
                <AlertDescription>
                  Configure an AI provider in{" "}
                  <Link to="/settings" className="font-medium underline underline-offset-4">
                    Settings
                  </Link>{" "}
                  to explain this finding or generate a fix. The deterministic finding, evidence,
                  status actions, and export remain available.
                </AlertDescription>
              </Alert>
            ) : null}
            {error ? <Alert variant="destructive"><AlertTitle>Action could not be completed</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}

            <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
              <div className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Finding</CardTitle>
                    <CardDescription>Reported by {titleCase(data.module)} in scan #{data.scan_id}.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm leading-relaxed">{data.message || "No description was recorded."}</p>
                    <div className="rounded-md border bg-muted/30 p-3">
                      <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Suggested remediation</p>
                      <p className="text-sm">{data.suggestion || "No remediation advice was recorded."}</p>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Source evidence</CardTitle>
                    <CardDescription>Redacted lines from the current repository working tree. This view is not a syntax-highlighting editor.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {data.evidence.length ? (
                      <pre className="max-h-[520px] overflow-auto rounded-md border bg-muted/40 p-4 font-mono text-xs leading-6"><code>{data.evidence.join("\n")}</code></pre>
                    ) : (
                      <p className="text-sm text-muted-foreground">Source is unavailable or the referenced file no longer exists.</p>
                    )}
                  </CardContent>
                </Card>

                {aiAnswer ? (
                  <Card>
                    <CardHeader><CardTitle className="flex items-center gap-2"><Bot className="h-4 w-4" />AI analysis</CardTitle><CardDescription>Advisory model output. It does not change severity or the release gate.</CardDescription></CardHeader>
                    <CardContent><Markdown text={aiAnswer} /></CardContent>
                  </Card>
                ) : data.latest_ai_review?.content ? (
                  <Card>
                    <CardHeader><CardTitle>Latest AI review</CardTitle><CardDescription>Stored advisory output for this finding.</CardDescription></CardHeader>
                    <CardContent><Markdown text={String(data.latest_ai_review.content.text ?? "")} /></CardContent>
                  </Card>
                ) : null}

                <Card>
                  <CardHeader><CardTitle>Related findings</CardTitle><CardDescription>Other findings in this file from the latest completed scan.</CardDescription></CardHeader>
                  <CardContent>
                    {data.related.length ? (
                      <ul className="space-y-2">
                        {data.related.map((item, index) => (
                          <li key={String(item.id ?? index)} className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm">
                            <SeverityBadge severity={String(item.severity ?? "info")} />
                            <Link to={`/findings/${item.id}`} className="font-medium hover:text-primary">{String(item.rule)}</Link>
                            <span className="font-mono text-xs text-muted-foreground">{data.file}:{String(item.line ?? "—")}</span>
                          </li>
                        ))}
                      </ul>
                    ) : <p className="text-sm text-muted-foreground">No related findings were recorded.</p>}
                  </CardContent>
                </Card>
              </div>

              <div className="space-y-4">
                <Card>
                  <CardHeader><CardTitle>Actions</CardTitle><CardDescription>AI assistance is optional and never authoritative.</CardDescription></CardHeader>
                  <CardContent className="space-y-2">
                    <Button className="w-full" variant="outline" disabled={busy !== "" || aiDisabled} onClick={() => void askAssistant()}><Bot />{busy === "assistant" ? "Asking…" : "Ask AI"}</Button>
                    <Button className="w-full" variant="outline" disabled={busy !== "" || aiDisabled} onClick={() => void explainFinding()}><Sparkles />{busy === "review" ? "Analyzing…" : "Explain vulnerability"}</Button>
                    <Button className="w-full" disabled={busy !== "" || aiDisabled} onClick={() => void generateFix()}><Wrench />{busy === "fix" ? "Generating…" : "Generate fix"}</Button>
                    {proposalId !== null ? <Button className="w-full" variant="secondary" onClick={() => navigate("/remediations")}><Copy />View patch proposal #{proposalId}</Button> : null}
                    <p className="pt-2 text-xs text-muted-foreground">A reviewed or dismissed finding is not technically fixed. The release gate remains controlled by a fresh engine scan.</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader><CardTitle>Detection history</CardTitle><CardDescription>Scans where this finding fingerprint was recorded.</CardDescription></CardHeader>
                  <CardContent>
                    {data.history.length ? (
                      <ol className="space-y-3">
                        {data.history.map((item, index) => (
                          <li key={`${item.scan_id}-${index}`} className="flex items-start justify-between gap-2 border-l pl-3">
                            <div>
                              <Link to={`/scans/${item.scan_id}`} className="text-sm font-medium hover:text-primary">Scan #{String(item.scan_id)}</Link>
                              <p className="text-xs text-muted-foreground">{formatDateTime(String(item.completed_at ?? item.created_at ?? ""))}</p>
                            </div>
                            <FindingStatusBadge status={String(item.status ?? "open")} />
                          </li>
                        ))}
                      </ol>
                    ) : <p className="text-sm text-muted-foreground">No prior detection records.</p>}
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        ) : null}
      </DataState>
    </div>
  );
}
