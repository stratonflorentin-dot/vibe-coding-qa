import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: LucideIcon;
  tone?: "default" | "critical" | "high" | "medium" | "low" | "pass" | "fail";
  className?: string;
}

const TONES: Record<string, string> = {
  default: "text-foreground",
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  pass: "text-gate-pass",
  fail: "text-gate-fail",
};

const TONE_CHIP: Record<string, string> = {
  default: "bg-primary/10 text-primary",
  critical: "bg-severity-critical/10 text-severity-critical",
  high: "bg-severity-high/10 text-severity-high",
  medium: "bg-severity-medium/10 text-severity-medium",
  low: "bg-severity-low/10 text-severity-low",
  pass: "bg-gate-pass/10 text-gate-pass",
  fail: "bg-gate-fail/10 text-gate-fail",
};

/** A single metric tile. Values are always supplied from real persisted data. */
export function StatCard({ label, value, hint, icon: Icon, tone = "default", className }: StatCardProps) {
  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardContent className="flex items-start justify-between gap-3 p-5">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className={cn("text-3xl font-semibold tabular-nums tracking-tight", TONES[tone])}>{value}</p>
          {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
        </div>
        {Icon ? (
          <div className={cn("flex h-9 w-9 items-center justify-center rounded-lg", TONE_CHIP[tone])}>
            <Icon className="h-4 w-4" />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
