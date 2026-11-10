import { ScanSearch } from "lucide-react";
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
          "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
          "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
          isActive &&
            "bg-primary/10 font-semibold text-primary ring-1 ring-inset ring-primary/15 hover:bg-primary/10 hover:text-primary",
        )
      }
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span className="truncate">{item.label}</span>
    </NavLink>
  );
}

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { health, repositories } = useApp();

  return (
    <div className="flex h-full flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-14 items-center gap-2.5 border-b border-sidebar-border px-4">
        <span className="vcqa-logo-badge" aria-hidden="true">
          <img src="/phone-mascots.gif" alt="" draggable={false} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold leading-tight">Vibe Coding QA</p>
          <p className="truncate text-[11px] text-muted-foreground">
            {health ? `v${health.version}` : "Connecting…"}
          </p>
        </div>
      </div>

      <ScrollArea className="flex-1 px-2 py-3">
        <nav className="space-y-5" onClick={onNavigate}>
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="space-y-1">
              <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                {group.label}
              </p>
              {group.items.map((item) => (
                <NavRow key={item.to} item={item} />
              ))}
            </div>
          ))}
        </nav>
      </ScrollArea>

      <div className="space-y-2 border-t border-sidebar-border p-3">
        <div className="flex items-center justify-between px-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <ScanSearch className="h-3.5 w-3.5" />
            Repositories
          </span>
          <Badge variant="muted">{repositories.length}</Badge>
        </div>
        <nav onClick={onNavigate}>
          <NavRow item={SETTINGS_ITEM} />
        </nav>
      </div>
    </div>
  );
}
