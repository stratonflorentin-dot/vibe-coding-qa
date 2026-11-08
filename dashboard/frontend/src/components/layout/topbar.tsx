import { CheckCircle2, Database, Menu, RefreshCw, TriangleAlert } from "lucide-react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { ThemeToggle } from "@/components/layout/theme-toggle";
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
    <header className="flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onOpenMenu} aria-label="Open navigation">
        <Menu />
      </Button>

      <div className="flex min-w-0 items-center gap-2">
        <Select
          value={activeRepositoryId === null ? "all" : String(activeRepositoryId)}
          onValueChange={(value) =>
            setActiveRepositoryId(value === "all" ? null : Number.parseInt(value, 10))
          }
        >
          <SelectTrigger className="h-8 w-[15rem] text-sm" aria-label="Active repository">
            <SelectValue placeholder="All repositories" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All repositories</SelectItem>
            {repositories.map((repository) => (
              <SelectItem key={repository.id} value={String(repository.id)}>
                {repository.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {repositories.length === 0 && !loading ? (
          <Button asChild variant="link" size="sm" className="h-8 px-1">
            <Link to="/repositories">Add one</Link>
          </Button>
        ) : null}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant="outline"
              className={
                healthy
                  ? "gap-1.5 border-gate-pass/40 text-gate-pass"
                  : "gap-1.5 border-destructive/40 text-destructive"
              }
            >
              {healthy ? <CheckCircle2 className="h-3 w-3" /> : <TriangleAlert className="h-3 w-3" />}
              {healthy ? "Backend online" : "Backend offline"}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            {healthy
              ? `${health?.database ?? "database"} · ${health?.repositories ?? 0} repositories · ${health?.scans ?? 0} scans · AI ${health?.ai_configured ? "configured" : "not configured"}`
              : (healthError ?? "The dashboard API did not respond.")}
          </TooltipContent>
        </Tooltip>

        {health ? (
          <Badge variant="muted" className="hidden gap-1.5 sm:inline-flex">
            <Database className="h-3 w-3" />
            {health.scans} scans
          </Badge>
        ) : null}

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => void reload()}
              disabled={loading}
              aria-label="Refresh application data"
            >
              <RefreshCw className={loading ? "animate-spin" : undefined} />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Refresh</TooltipContent>
        </Tooltip>

        <ThemeToggle />
      </div>
    </header>
  );
}
