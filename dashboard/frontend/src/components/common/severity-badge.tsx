import { cn } from "@/lib/utils";
import { SEVERITY_LABEL, severityClasses } from "@/lib/format";
import type { Severity } from "@/types/api";

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity | string;
  className?: string;
}) {
  const key = (severity || "info").toLowerCase() as Severity;
  const label = SEVERITY_LABEL[key] ?? severity;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        severityClasses(key),
        className,
      )}
    >
      {label}
    </span>
  );
}

export function SeverityDot({ severity, className }: { severity: string; className?: string }) {
  return (
    <span
      className={cn("inline-block h-2 w-2 shrink-0 rounded-full", className)}
      style={{ backgroundColor: `hsl(var(--severity-${severity}))` }}
    />
  );
}
