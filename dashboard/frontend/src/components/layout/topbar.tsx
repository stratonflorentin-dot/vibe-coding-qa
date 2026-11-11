import { Database, FolderGit2, Menu, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { UserMenu } from "@/components/layout/user-menu";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export function Topbar({ onOpenMenu }: { onOpenMenu: () => void }) {
  const {
    health,
    healthError,
    repositories,
    reload,
    loading,
    activeRepositoryId,
    setActiveRepositoryId,
  } = useApp();

  const healthy = Boolean(health) && !healthError;

  return (
    <header className="flex h-14 items-center justify-between gap-3 border-b border-border/80 bg-background/80 px-4 backdrop-blur-md">
      <div className="flex items-center gap-3 min-w-0">
        <Button variant="ghost" size="icon" className="lg:hidden shrink-0" onClick={onOpenMenu} aria-label="Open navigation">
          <Menu className="h-5 w-5" />
        </Button>

        {/* Repository Scope Selector */}
        <div className="flex items-center gap-2 min-w-0">
          <div className="flex items-center gap-2 rounded-lg border border-border/70 bg-card px-2.5 py-1 shadow-sm">
            <FolderGit2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <span className="hidden text-xs font-medium text-muted-foreground sm:inline">Workspace:</span>
            <Select
              value={activeRepositoryId === null ? "all" : String(activeRepositoryId)}
              onValueChange={(value) =>
                setActiveRepositoryId(value === "all" ? null : Number.parseInt(value, 10))
              }
            >
              <SelectTrigger className="h-7 border-0 bg-transparent p-0 text-xs font-semibold shadow-none focus:ring-0 focus:ring-offset-0 w-[11rem] sm:w-[13rem]" aria-label="Active repository">
                <SelectValue placeholder="All repositories" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All repositories</SelectItem>
                {repositories.map((repository) => (
                  <SelectItem key={repository.id} value={String(repository.id)} className="text-xs">
                    {repository.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {repositories.length === 0 && !loading ? (
            <Button asChild variant="link" size="sm" className="h-7 px-1 text-xs">
              <Link to="/repositories">+ Add repository</Link>
            </Button>
          ) : null}
        </div>
      </div>

      {/* Status & Actions */}
      <div className="flex items-center gap-2 shrink-0">
        <Tooltip>
          <TooltipTrigger asChild>
            <div
              className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${
                healthy
                  ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "border-destructive/30 bg-destructive/10 text-destructive"
              }`}
            >
              <span className="relative flex h-2 w-2">
                {healthy ? (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                ) : null}
                <span
                  className={`relative inline-flex h-2 w-2 rounded-full ${
                    healthy ? "bg-emerald-500" : "bg-destructive"
                  }`}
                />
              </span>
              <span className="hidden sm:inline">{healthy ? "Backend online" : "Backend offline"}</span>
            </div>
          </TooltipTrigger>
          <TooltipContent>
            {healthy
              ? `${health?.database ?? "database"} · ${health?.repositories ?? 0} repositories · ${health?.scans ?? 0} scans · AI ${health?.ai_configured ? "configured" : "not configured"}`
              : (healthError ?? "The dashboard API did not respond.")}
          </TooltipContent>
        </Tooltip>

        {health ? (
          <Badge variant="outline" className="hidden gap-1.5 font-mono text-[11px] sm:inline-flex">
            <Database className="h-3 w-3 text-muted-foreground" />
            {health.scans} scans
          </Badge>
        ) : null}

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-muted-foreground hover:text-foreground"
              onClick={() => void reload()}
              disabled={loading}
              aria-label="Refresh application data"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Refresh workspace</TooltipContent>
        </Tooltip>

        <ThemeToggle />
        <UserMenu />
      </div>
    </header>
  );
}
