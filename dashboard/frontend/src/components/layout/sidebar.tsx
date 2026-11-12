import { GitBranch } from "lucide-react";
import { NavLink } from "react-router-dom";

import { NAV_GROUPS, SETTINGS_ITEM, type NavItem } from "@/app/navigation";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useApp } from "@/app/app-context";

function NavRow({ item }: { item: NavItem }) {
  const Icon = item.icon;
  return (
    <NavLink
      to={item.to}
      end={item.end}
      title={item.description}
      className={({ isActive }) =>
        cn(
          "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-150",
          "text-sidebar-foreground/70 hover:bg-sidebar-accent/70 hover:text-sidebar-foreground",
          isActive
            ? "bg-primary/10 font-semibold text-primary shadow-sm ring-1 ring-inset ring-primary/20 hover:bg-primary/15 hover:text-primary"
            : "",
        )
      }
    >
      {({ isActive }) => (
        <>
          {isActive ? (
            <span
              className="absolute inset-y-1.5 left-0 w-1 rounded-r-full bg-primary"
              aria-hidden="true"
            />
          ) : null}
          <Icon
            className={cn(
              "h-4 w-4 shrink-0 transition-colors",
              isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
            )}
          />
          <span className="truncate">{item.label}</span>
        </>
      )}
    </NavLink>
  );
}

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { health, repositories } = useApp();

  return (
    <div className="flex h-full flex-col bg-sidebar text-sidebar-foreground">
      {/* Brand Header */}
      <div className="flex h-14 items-center justify-between border-b border-sidebar-border px-4">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="vcqa-logo-badge shrink-0" aria-hidden="true">
            <img src="/pet-badge.svg" alt="" draggable={false} className="h-6 w-6 object-contain" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-sm font-bold tracking-tight text-foreground">
                Vibe Coding QA
              </span>
            </div>
            <p className="truncate text-[11px] font-mono text-muted-foreground">
              {health ? `v${health.version}` : "Connecting…"}
            </p>
          </div>
        </div>
        <Badge variant="muted" className="hidden shrink-0 text-[10px] font-mono sm:inline-flex">
          local
        </Badge>
      </div>

      {/* Navigation Groups */}
      <ScrollArea className="flex-1 px-3 py-3">
        <nav className="space-y-5" onClick={onNavigate}>
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="space-y-1">
              <p className="px-2 pb-1 text-[10px] font-bold uppercase tracking-widest text-muted-foreground/60">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <NavRow key={item.to} item={item} />
                ))}
              </div>
            </div>
          ))}
        </nav>
      </ScrollArea>

      {/* Footer / Meta */}
      <div className="space-y-2 border-t border-sidebar-border p-3">
        <div className="flex items-center justify-between rounded-md bg-muted/40 px-2.5 py-1.5 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5 truncate">
            <GitBranch className="h-3.5 w-3.5 shrink-0 text-primary" />
            <span className="truncate">Repositories</span>
          </span>
          <Badge variant="outline" className="font-mono text-[11px]">
            {repositories.length}
          </Badge>
        </div>
        <nav onClick={onNavigate}>
          <NavRow item={SETTINGS_ITEM} />
        </nav>
      </div>
    </div>
  );
}
