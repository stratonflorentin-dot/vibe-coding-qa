import { Component, type ErrorInfo, type ReactNode } from "react";

import { ErrorBlock } from "@/components/common/data-state";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/** Prevents a rendering bug in one page from blanking the whole dashboard. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surfaced in the browser console; never silently swallowed.
    console.error("Dashboard render error", error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <ErrorBlock
          className="m-6"
          message={this.state.error.message || "An unexpected rendering error occurred."}
          onRetry={() => this.setState({ error: null })}
        />
      );
    }
    return this.props.children;
  }
}
