import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "@/lib/api";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Re-run the request. Pass ``silent`` to refresh without a loading state. */
  reload: (silent?: boolean) => Promise<void>;
  setData: (updater: T | ((previous: T | null) => T | null)) => void;
}

function messageOf(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}

/**
 * Run an async request and track loading/error state.
 *
 * ``deps`` behaves like a ``useEffect`` dependency list: the request re-runs
 * whenever they change, and results from a superseded request are discarded so
 * a slow response can never overwrite a newer one.
 */
export function useAsync<T>(
  factory: () => Promise<T>,
  deps: ReadonlyArray<unknown> = [],
  options: { enabled?: boolean } = {},
): AsyncState<T> {
  const enabled = options.enabled ?? true;
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(enabled);

  const requestId = useRef(0);
  const factoryRef = useRef(factory);
  factoryRef.current = factory;

  const run = useCallback(
    async (silent = false) => {
      const id = ++requestId.current;
      if (!silent) setLoading(true);
      try {
        const result = await factoryRef.current();
        if (requestId.current === id) {
          setData(result);
          setError(null);
        }
      } catch (caught) {
        if (requestId.current === id) setError(messageOf(caught));
      } finally {
        if (requestId.current === id) setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    void run();
    return () => {
      // Invalidate the in-flight request when dependencies change or on unmount.
      requestId.current += 1;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps]);

  const update = useCallback((updater: T | ((previous: T | null) => T | null)) => {
    setData((previous) =>
      typeof updater === "function" ? (updater as (p: T | null) => T | null)(previous) : updater,
    );
  }, []);

  return { data, error, loading, reload: run, setData: update };
}
