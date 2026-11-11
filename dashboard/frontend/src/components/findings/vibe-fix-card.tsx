import { Check, Code, Copy, ExternalLink, FileCode, Lightbulb, LoaderCircle, ShieldAlert, Sparkles, Terminal } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { formatCount } from "@/lib/format";
import { getVibeFixGuide } from "@/lib/vibe-remediations";
import type { Finding } from "@/types/api";

interface VibeFixCardProps {
  finding: Finding;
  occurrences: Finding[];
  onStatusChange?: (findingId: number, newStatus: Finding["status"]) => Promise<void>;
}

export function VibeFixCard({ finding, occurrences, onStatusChange }: VibeFixCardProps) {
  const { toast } = useToast();
  const guide = getVibeFixGuide(finding);
  const [copiedCode, setCopiedCode] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [evidenceLines, setEvidenceLines] = useState<string[] | null>(null);
  const [statusBusy, setStatusBusy] = useState(false);

  const fileCount = new Set(occurrences.map((item) => `${item.repository_id}:${item.file}`)).size;

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(guide.codeSnippet);
      setCopiedCode(true);
      toast({
        title: "Code snippet copied",
        description: "Paste it into your SQL editor, terminal, or code file.",
        variant: "success",
      });
      setTimeout(() => setCopiedCode(false), 2000);
    } catch {
      toast({
        title: "Could not copy snippet",
        description: "Select the text manually to copy.",
        variant: "error",
      });
    }
  }

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(guide.aiPrompt);
      setCopiedPrompt(true);
      toast({
        title: "AI fix prompt copied!",
        description: "Paste this directly into Cursor, Windsurf, Claude, or Copilot.",
        variant: "success",
      });
      setTimeout(() => setCopiedPrompt(false), 2500);
    } catch {
      toast({
        title: "Could not copy prompt",
        description: "Select the prompt text manually to copy.",
        variant: "error",
      });
    }
  }

  async function toggleEvidence() {
    if (evidenceLines !== null) {
      setEvidenceLines(null);
      return;
    }
    setLoadingEvidence(true);
    try {
      const detail = await api.findings.get(finding.id);
      setEvidenceLines(detail.evidence && detail.evidence.length ? detail.evidence : ["// No raw source lines recorded."]);
    } catch {
      setEvidenceLines(["// Could not load evidence lines from the server."]);
    } finally {
      setLoadingEvidence(false);
    }
  }

  async function handleToggleStatus() {
    if (!onStatusChange) return;
    setStatusBusy(true);
    try {
      const targetStatus = finding.status === "reviewed" ? "open" : "reviewed";
      await onStatusChange(finding.id, targetStatus);
      toast({
        title: targetStatus === "reviewed" ? "Issue marked as reviewed" : "Issue reopened",
        variant: "success",
      });
    } catch {
      toast({
        title: "Failed to update status",
        variant: "error",
      });
    } finally {
      setStatusBusy(false);
    }
  }

  return (
    <div className="space-y-4 border-t px-3 py-4 sm:px-5">
      {/* 1. Header with Primary Call to Action buttons */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-muted/40 p-3">
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="font-mono text-xs">
            {finding.file}:{finding.line}
          </Badge>
          <span className="text-xs text-muted-foreground">
            {formatCount(occurrences.length)} occurrence{occurrences.length === 1 ? "" : "s"} across {formatCount(fileCount)} file{fileCount === 1 ? "" : "s"}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="default"
            onClick={copyPrompt}
            className="gap-1.5 shadow-sm"
          >
            {copiedPrompt ? <Check className="h-3.5 w-3.5 text-green-300" /> : <Sparkles className="h-3.5 w-3.5" />}
            {copiedPrompt ? "Prompt Copied!" : "Copy Prompt for AI / Cursor"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={copyCode}
            className="gap-1.5"
          >
            {copiedCode ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedCode ? "Copied" : "Copy Fix Code"}
          </Button>
          {onStatusChange ? (
            <Button
              size="sm"
              variant="ghost"
              disabled={statusBusy}
              onClick={handleToggleStatus}
              className="text-xs"
            >
              {statusBusy ? (
                <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
              ) : finding.status === "reviewed" ? (
                "Reopen"
              ) : (
                "Mark Reviewed"
              )}
            </Button>
          ) : null}
        </div>
      </div>

      {/* 2. Plain-English Impact & Why It Happens */}
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-3.5">
          <div className="flex items-center gap-2 text-destructive">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <h4 className="text-xs font-semibold uppercase tracking-wider">The Risk (Plain English)</h4>
          </div>
          <p className="mt-2 text-sm leading-relaxed text-foreground/90">
            {guide.riskSummary}
          </p>
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3.5">
          <div className="flex items-center gap-2 text-amber-500">
            <Lightbulb className="h-4 w-4 shrink-0" />
            <h4 className="text-xs font-semibold uppercase tracking-wider">Why This Happens in Vibe Coding</h4>
          </div>
          <p className="mt-2 text-sm leading-relaxed text-foreground/90">
            {guide.whyItHappens}
          </p>
        </div>
      </div>

      {/* 3. The Exact Fix Code Snippet */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code className="h-4 w-4 text-primary" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
              {guide.fixTitle}
            </h4>
            <Badge variant="muted" className="text-[10px] uppercase">
              {guide.fixLanguage}
            </Badge>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={copyCode}
            className="h-7 text-xs text-muted-foreground hover:text-foreground"
          >
            {copiedCode ? <Check className="mr-1 h-3 w-3 text-green-500" /> : <Copy className="mr-1 h-3 w-3" />}
            {copiedCode ? "Copied" : "Copy"}
          </Button>
        </div>
        <pre className="max-h-64 overflow-x-auto rounded-lg border bg-muted/60 p-3.5 font-mono text-xs leading-relaxed text-foreground">
          <code>{guide.codeSnippet}</code>
        </pre>
      </div>

      {/* 4. Action Steps Checklist */}
      <div className="rounded-lg border bg-card/60 p-3.5">
        <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          <Terminal className="h-3.5 w-3.5" />
          Step-by-Step Fix Instructions
        </h4>
        <ol className="mt-2.5 list-decimal space-y-1.5 pl-4 text-xs leading-relaxed text-foreground/90">
          {guide.actionSteps.map((step, idx) => (
            <li key={idx} className="pl-1">
              {step}
            </li>
          ))}
        </ol>
      </div>

      {/* 5. Evidence & Affected Locations Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-xs">
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            variant="outline"
            onClick={toggleEvidence}
            disabled={loadingEvidence}
            className="h-7 gap-1.5 text-xs"
          >
            {loadingEvidence ? (
              <LoaderCircle className="h-3 w-3 animate-spin" />
            ) : (
              <FileCode className="h-3 w-3" />
            )}
            {evidenceLines !== null ? "Hide Source Lines" : "Inspect Source Lines"}
          </Button>

          <Link
            to={`/findings/${finding.id}`}
            className="inline-flex items-center gap-1 text-primary hover:underline"
          >
            Full finding audit page <ExternalLink className="h-3 w-3" />
          </Link>
        </div>
      </div>

      {/* 6. Raw Evidence Lines Drawer if Toggled */}
      {evidenceLines !== null ? (
        <div className="rounded-lg border bg-zinc-950 p-3.5 text-zinc-100">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-mono text-zinc-400">
              Source extract: {finding.file}:{finding.line}
            </span>
          </div>
          <pre className="max-h-56 overflow-auto font-mono text-xs leading-5">
            <code>{evidenceLines.join("\n")}</code>
          </pre>
        </div>
      ) : null}

      {/* 7. Other occurrences if repeated */}
      {occurrences.length > 1 ? (
        <details className="rounded-md border bg-muted/20 px-3 py-2 text-xs">
          <summary className="cursor-pointer font-medium text-muted-foreground hover:text-foreground">
            View all {occurrences.length} affected locations ({fileCount} files)
          </summary>
          <ul className="mt-2.5 grid max-h-48 gap-1.5 overflow-auto sm:grid-cols-2">
            {occurrences.map((item) => (
              <li
                key={item.id}
                className="flex min-w-0 items-center justify-between gap-2 rounded border bg-background px-2.5 py-1.5 text-xs"
              >
                <Link
                  to={`/findings/${item.id}`}
                  className="min-w-0 flex-1 truncate font-mono text-primary hover:underline"
                  title={`${item.repository_name}: ${item.file}:${item.line}`}
                >
                  {item.file}:{item.line}
                </Link>
                <Badge variant={item.status === "reviewed" ? "secondary" : "muted"} className="shrink-0 text-[10px]">
                  {item.status}
                </Badge>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}
