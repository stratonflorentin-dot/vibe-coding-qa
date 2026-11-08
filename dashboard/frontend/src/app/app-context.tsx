import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { api, ApiError } from "@/lib/api";
import type { HealthOut, Repository } from "@/types/api";

const ACTIVE_KEY = "vcqa-active-repository";

interface AppContextValue {
  health: HealthOut | null;
  healthError: string | null;
  repositories: Repository[];
  loading: boolean;
  error: string | null;
  reload: (silent?: boolean) => Promise<void>;
  activeRepositoryId: number | null;
  setActiveRepositoryId: (id: number | null) => void;
  activeRepository: Repository | null;
}

const AppContext = createContext<AppContextValue | null>(null);

function readStoredId(): number | null {
  try {
    const raw = window.localStorage.getItem(ACTIVE_KEY);
    if (!raw) return null;
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Global application state: backend health and the repository list.
 *
 * Every page reads repositories from here instead of refetching, so the sidebar
 * count, the overview and the filters always agree. A missing backend is
 * reported as an error rather than hidden.
 */
export function AppProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthOut | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeRepositoryId, setActiveId] = useState<number | null>(readStoredId);

  const reload = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    const [healthResult, repoResult] = await Promise.allSettled([
      api.system.health(),
      api.repositories.list(),
    ]);

    if (healthResult.status === "fulfilled") {
      setHealth(healthResult.value);
      setHealthError(null);
    } else {
      setHealth(null);
      setHealthError(
        healthResult.reason instanceof ApiError
          ? healthResult.reason.message
          : "The backend health check failed.",
      );
    }

    if (repoResult.status === "fulfilled") {
      setRepositories(repoResult.value);
      setError(null);
    } else {
      setError(
        repoResult.reason instanceof ApiError
          ? repoResult.reason.message
          : "The repository list could not be loaded.",
      );
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const setActiveRepositoryId = useCallback((id: number | null) => {
    setActiveId(id);
    try {
      if (id === null) window.localStorage.removeItem(ACTIVE_KEY);
      else window.localStorage.setItem(ACTIVE_KEY, String(id));
    } catch {
      /* Persistence is best-effort. */
    }
  }, []);

  // Drop a stored selection that no longer exists.
  useEffect(() => {
    if (loading || activeRepositoryId === null) return;
    if (!repositories.some((repository) => repository.id === activeRepositoryId)) {
      setActiveRepositoryId(null);
    }
  }, [loading, repositories, activeRepositoryId, setActiveRepositoryId]);

  const activeRepository = useMemo(
    () => repositories.find((repository) => repository.id === activeRepositoryId) ?? null,
    [repositories, activeRepositoryId],
  );

  const value = useMemo(
    () => ({
      health,
      healthError,
      repositories,
      loading,
      error,
      reload,
      activeRepositoryId,
      setActiveRepositoryId,
      activeRepository,
    }),
    [
      health,
      healthError,
      repositories,
      loading,
      error,
      reload,
      activeRepositoryId,
      setActiveRepositoryId,
      activeRepository,
    ],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const context = useContext(AppContext);
  if (!context) throw new Error("useApp must be used inside an AppProvider.");
  return context;
}
