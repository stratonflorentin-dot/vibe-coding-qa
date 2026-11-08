import { ShieldCheck, ShieldX, ShieldAlert, ShieldQuestion } from "lucide-react";

import { gateClasses, gateDescription, gateLabel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Gate } from "@/types/api";

const ICONS: Record<string, typeof ShieldCheck> = {
  pass: ShieldCheck,
  fail: ShieldX,
  block: ShieldAlert,
  not_verified: ShieldQuestion,
};

/**
 * The release-gate verdict.
 *
 * The gate is decided by the Python engine from real checks — the dashboard only
 * renders it. Its wording is never softened.
 */
export function GateBadge({ gate, className }: { gate: Gate; className?: string }) {
  const key = (gate ?? "not_verified").toLowerCase();
  const Icon = ICONS[key] ?? ShieldQuestion;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            "inline-flex cursor-help items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
            gateClasses(gate),
            className,
          )}
        >
          <Icon className="h-3.5 w-3.5" />
          {gateLabel(gate)}
        </span>
      </TooltipTrigger>
      <TooltipContent>{gateDescription(gate)}</TooltipContent>
    </Tooltip>
  );
}
