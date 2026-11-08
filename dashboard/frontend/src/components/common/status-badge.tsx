import { Loader2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { titleCase } from "@/lib/format";
import type { ScanStatus } from "@/types/api";

const STYLES: Record<string, string> = {
  queued: "border-border bg-muted text-muted-foreground",
  running: "border-severity-low/40 bg-severity-low/10 text-severity-low",
  completed: "border-gate-pass/40 bg-gate-pass/10 text-gate-pass",
  failed: "border-gate-fail/40 bg-gate-fail/10 text-gate-fail",
  cancelled: "border-border bg-muted text-muted-foreground",
};

export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus | string;
  className?: string;
}) {
  const key = (status || "").toLowerCase();
  const running = key === "running" || key === "queued";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        STYLES[key] ?? STYLES.queued,
        className,
      )}
    >
      {running ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
      {titleCase(key || "unknown")}
    </span>
  );
}

const FINDING_STYLES: Record<string, string> = {
  open: "border-severity-high/40 bg-severity-high/10 text-severity-high",
  reviewed: "border-severity-low/40 bg-severity-low/10 text-severity-low",
  resolved: "border-gate-pass/40 bg-gate-pass/10 text-gate-pass",
  dismissed: "border-border bg-muted text-muted-foreground",
  unverified: "border-severity-medium/40 bg-severity-medium/10 text-severity-medium",
};

export function FindingStatusBadge({ status, className }: { status: string; className?: string }) {
  const key = (status || "open").toLowerCase();
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        FINDING_STYLES[key] ?? FINDING_STYLES.open,
        className,
      )}
    >
      {titleCase(key)}
    </span>
  );
}
