import type { Gate, Severity } from "@/types/api";

/** Format an ISO timestamp for display; returns an em dash when absent. */
export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  const table: Array<[number, Intl.RelativeTimeFormatUnit]> = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [7, "day"],
    [4.35, "week"],
    [12, "month"],
  ];
  let amount = seconds;
  let unit: Intl.RelativeTimeFormatUnit = "second";
  for (const [step, nextUnit] of table) {
    if (Math.abs(amount) < step) break;
    amount /= step;
    unit = nextUnit;
  }
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  return formatter.format(-Math.round(amount), unit);
}

export function formatDuration(ms?: number | null): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

export function formatScore(score?: number | null): string {
  if (score === null || score === undefined) return "—";
  return score.toFixed(1);
}

export function formatCount(value?: number | null): string {
  if (value === null || value === undefined) return "—";
  return value.toLocaleString();
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Tailwind classes for a severity chip. Uses the theme's severity tokens. */
export function severityClasses(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-severity-critical/40 bg-severity-critical/10 text-severity-critical";
    case "high":
      return "border-severity-high/40 bg-severity-high/10 text-severity-high";
    case "medium":
      return "border-severity-medium/40 bg-severity-medium/10 text-severity-medium";
    case "low":
      return "border-severity-low/40 bg-severity-low/10 text-severity-low";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

export function severityHex(severity: string): string {
  switch (severity) {
    case "critical":
      return "hsl(var(--severity-critical))";
    case "high":
      return "hsl(var(--severity-high))";
    case "medium":
      return "hsl(var(--severity-medium))";
    case "low":
      return "hsl(var(--severity-low))";
    default:
      return "hsl(var(--severity-info))";
  }
}

export function gateClasses(gate: Gate): string {
  switch ((gate ?? "").toLowerCase()) {
    case "pass":
      return "border-gate-pass/40 bg-gate-pass/10 text-gate-pass";
    case "fail":
      return "border-gate-fail/40 bg-gate-fail/10 text-gate-fail";
    case "block":
      return "border-gate-block/40 bg-gate-block/10 text-gate-block";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

export function gateLabel(gate: Gate): string {
  const value = (gate ?? "").toLowerCase();
  if (!value) return "Not verified";
  if (value === "not_verified") return "Not verified";
  return value.toUpperCase();
}

/** Gate verdicts are the release decision and must not be softened. */
export function gateDescription(gate: Gate): string {
  switch ((gate ?? "").toLowerCase()) {
    case "pass":
      return "Every enforced check passed.";
    case "fail":
      return "One or more enforced checks failed.";
    case "block":
      return "Blocking issues were found; the release is not allowed.";
    case "not_verified":
      return "The gate could not be verified because required checks did not run.";
    default:
      return "No scan has produced a verdict yet.";
  }
}

export function scoreColor(score?: number | null): string {
  if (score === null || score === undefined) return "text-muted-foreground";
  if (score >= 80) return "text-gate-pass";
  if (score >= 60) return "text-severity-medium";
  return "text-gate-fail";
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
