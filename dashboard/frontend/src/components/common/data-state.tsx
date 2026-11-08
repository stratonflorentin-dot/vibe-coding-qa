import { AlertTriangle, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export function LoadingBlock({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-3", className)} aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }).map((_, index) => (
        <Skeleton key={index} className="h-20 w-full" />
      ))}
    </div>
  );
}

export function ErrorBlock({
  message,
  onRetry,
  className,
}: {
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-6 py-8 text-center",
        className,
      )}
    >
      <AlertTriangle className="h-5 w-5 text-destructive" />
      <div className="space-y-1">
        <p className="text-sm font-medium">Request failed</p>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">{message}</p>
      </div>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw />
          Try again
        </Button>
      ) : null}
    </div>
  );
}

/**
 * Render exactly one of loading / error / content. Keeps every page honest:
 * an error is always surfaced instead of being silently swallowed.
 */
export function DataState({
  loading,
  error,
  onRetry,
  loadingRows = 3,
  children,
}: {
  loading: boolean;
  error: string | null;
  onRetry?: () => void;
  loadingRows?: number;
  children: ReactNode;
}) {
  if (loading) return <LoadingBlock rows={loadingRows} />;
  if (error) return <ErrorBlock message={error} onRetry={onRetry} />;
  return <>{children}</>;
}
