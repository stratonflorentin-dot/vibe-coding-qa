import { Component, type ComponentType, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Custom fallback. Receives the error and a `reset` to clear the boundary. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
  /** Optional label used in the default fallback (e.g. the page name). */
  label?: string;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Catches render/runtime errors in its subtree so a single component crash
 * cannot take the whole dashboard down. Wrap the app root and each routed page
 * with it; the fallback offers a retry (reset) and a full reload.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Keep a trace in the console; the UI stays usable via the fallback below.
    console.error("ErrorBoundary caught an error:", error, info.componentStack);
  }

  reset = (): void => {
    this.setState({ error: null });
  };

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    if (this.props.fallback) return this.props.fallback(error, this.reset);

    const where = this.props.label ? ` in ${this.props.label}` : "";
    return (
      <div
        role="alert"
        className="mx-auto my-10 max-w-md rounded-xl border border-destructive/30 bg-card p-6 text-center shadow-sm"
      >
        <h2 className="text-lg font-semibold text-foreground">Something went wrong{where}.</h2>
        <p className="mt-2 break-words text-sm text-muted-foreground">
          {error.message || "An unexpected error occurred while rendering this view."}
        </p>
        <div className="mt-5 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={this.reset}
            className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:opacity-90"
          >
            Try again
          </button>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground transition hover:bg-accent"
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}

/** HOC form: wrap a component so its own crashes are isolated. */
export function withErrorBoundary<P extends object>(
  Wrapped: ComponentType<P>,
  label?: string,
): ComponentType<P> {
  const Wrapper = (props: P) => (
    <ErrorBoundary label={label ?? Wrapped.displayName ?? Wrapped.name}>
      <Wrapped {...props} />
    </ErrorBoundary>
  );
  Wrapper.displayName = `withErrorBoundary(${Wrapped.displayName ?? Wrapped.name ?? "Component"})`;
  return Wrapper;
}
