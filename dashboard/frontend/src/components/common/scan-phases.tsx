import { Check, Loader2, Minus, X } from "lucide-react";
import { useMemo } from "react";

import { cn } from "@/lib/utils";
import type { ScanEvent } from "@/types/api";

/**
 * The ordered, human-readable phases of a scan.
 *
 * These are derived strictly from the events the engine actually emits
 * (see `_emit` in `vibe_coding_qa/engine.py`). Nothing here is fabricated:
 * a phase is pending until the engine reports a real event for it.
 */
const PHASES = [
  {
    key: "preparation",
    label: "Preparation",
    stages: ["preparation"],
    description: "Clone or load the repository snapshot.",
  },
  {
    key: "analysis",
    label: "Analysis",
    stages: ["scanner", "technology"],
    description: "Run every configured scanner and detect the tech stack.",
  },
  {
    key: "ai",
    label: "AI review",
    stages: ["ai"],
    description: "Optional AI review of findings.",
  },
  {
    key: "tests",
    label: "Tests",
    stages: ["tests"],
    description: "Run the test suite in the isolated sandbox.",
  },
  {
    key: "gate",
    label: "Release gate",
    stages: ["gate"],
    description: "Compute the deterministic release verdict.",
  },
  {
    key: "report",
    label: "Report",
    stages: ["report"],
    description: "Persist results and write reports.",
  },
] as const;

type PhaseStatus = "pending" | "running" | "completed" | "skipped" | "failed";

interface PhaseState {
  key: string;
  label: string;
  description: string;
  status: PhaseStatus;
  message: string | null;
}

function phaseStatus(events: ScanEvent[], phaseStages: readonly string[], laterStarted: boolean): PhaseStatus {
  const phaseEvents = events.filter((event) => phaseStages.includes(event.stage));
  const statuses = new Set(phaseEvents.map((event) => event.status));
  if (statuses.has("failed")) return "failed";
  if (statuses.has("completed")) return "completed";
  if (statuses.has("running")) return "running";
  if (statuses.has("skipped")) return "skipped";
  // The engine moved past this phase without an explicit event for it (for
  // example, a phase that was not requested). Treat it as completed rather
  // than leaving it pending forever.
  if (laterStarted) return "completed";
  return "pending";
}

function phaseMessage(events: ScanEvent[], phaseStages: readonly string[], status: PhaseStatus): string | null {
  const phaseEvents = events.filter((event) => phaseStages.includes(event.stage));
  if (!phaseEvents.length) return null;
  // For the "running" state, show the most recent running event's message so
  // the user sees which scanner is currently active.
  const ordered = [...phaseEvents].sort((a, b) => b.id - a.id);
  if (status === "running") {
    const running = ordered.find((event) => event.status === "running");
    return running?.message ?? null;
  }
  return ordered[0]?.message ?? null;
}

function derivePhases(events: ScanEvent[]): PhaseState[] {
  return PHASES.map((phase, index) => {
    const laterStages: readonly string[] = PHASES.slice(index + 1).flatMap((p) => p.stages);
    const laterStarted = events.some((event) => laterStages.includes(event.stage));
    const status = phaseStatus(events, phase.stages, laterStarted);
    return {
      key: phase.key,
      label: phase.label,
      description: phase.description,
      status,
      message: phaseMessage(events, phase.stages, status),
    };
  });
}

function PhaseIcon({ status }: { status: PhaseStatus }) {
  const base = "flex h-7 w-7 shrink-0 items-center justify-center rounded-full border transition-colors";
  if (status === "completed") {
    return (
      <span className={cn(base, "border-gate-pass bg-gate-pass text-white")}>
        <Check className="h-4 w-4" />
      </span>
    );
  }
  if (status === "running") {
    return (
      <span className={cn(base, "border-primary bg-primary text-primary-foreground")}>
        <Loader2 className="h-4 w-4 animate-spin" />
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className={cn(base, "border-gate-fail bg-gate-fail text-white")}>
        <X className="h-4 w-4" />
      </span>
    );
  }
  if (status === "skipped") {
    return (
      <span className={cn(base, "border-muted-foreground/30 text-muted-foreground")}>
        <Minus className="h-4 w-4" />
      </span>
    );
  }
  return (
    <span className={cn(base, "border-muted-foreground/30 text-muted-foreground/60")}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
    </span>
  );
}

function PhaseConnector({ active }: { active: boolean }) {
  return (
    <div className="hidden h-px flex-1 self-center bg-muted-foreground/20 sm:block">
      <div
        className={cn(
          "h-full bg-primary transition-[width] duration-500",
          active ? "w-full" : "w-0",
        )}
      />
    </div>
  );
}

export function ScanPhases({ events }: { events: ScanEvent[] }) {
  const phases = useMemo(() => derivePhases(events), [events]);
  const activeIndex = phases.findIndex((phase) => phase.status === "running");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-stretch gap-3 sm:flex-nowrap sm:gap-2">
        {phases.map((phase, index) => {
          const isActive = phase.status === "running";
          const showConnector = index < phases.length - 1;
          return (
            <div key={phase.key} className="flex min-w-[160px] flex-1 items-start gap-2">
              <div
                className={cn(
                  "flex w-full items-start gap-2 rounded-md border p-2 transition-colors",
                  isActive ? "border-primary/60 bg-primary/5" : "border-transparent",
                )}
              >
                <PhaseIcon status={phase.status} />
                <div className="min-w-0 space-y-0.5">
                  <p
                    className={cn(
                      "text-xs font-semibold",
                      phase.status === "pending" && "text-muted-foreground",
                    )}
                  >
                    {phase.label}
                  </p>
                  {phase.message ? (
                    <p className="truncate text-[11px] text-muted-foreground" title={phase.message}>
                      {phase.message}
                    </p>
                  ) : (
                    <p className="text-[11px] text-muted-foreground/70">{phase.description}</p>
                  )}
                </div>
              </div>
              {showConnector ? (
                <PhaseConnector active={phase.status === "completed" || phase.status === "skipped"} />
              ) : null}
            </div>
          );
        })}
      </div>
      {activeIndex >= 0 ? (
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="h-3 w-3 animate-spin text-primary" />
          Currently in <span className="font-medium text-foreground">{phases[activeIndex].label}</span>
          {phases[activeIndex].message ? ` — ${phases[activeIndex].message}` : ""}
        </p>
      ) : null}
    </div>
  );
}
