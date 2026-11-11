import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { api, type AuthMode, type AuthUser } from "@/lib/api";

interface SessionValue {
  loading: boolean;
  mode: AuthMode | undefined;
  user: AuthUser | null;
  needsSetup: boolean;
  authRequired: boolean;
  authenticated: boolean;
  /** True when the current principal may administer users (incl. the operator). */
  isAdmin: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

const ADMIN_ROLES = new Set(["owner", "administrator"]);

/**
 * Loads /api/auth/status once and exposes the account mode, the signed-in user
 * and their role to the whole app. It also re-checks on the "vcqa-auth-required"
 * event the API client fires on any 401, so an expired session is reflected
 * everywhere (and the AuthGate drops back to the login screen).
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Awaited<ReturnType<typeof api.auth.status>> | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.auth.status());
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch {
      /* best effort - clear local state regardless */
    }
    await refresh();
  }, [refresh]);

  useEffect(() => {
    void refresh();
    const onAuthRequired = () => void refresh();
    window.addEventListener("vcqa-auth-required", onAuthRequired);
    return () => window.removeEventListener("vcqa-auth-required", onAuthRequired);
  }, [refresh]);

  const value = useMemo<SessionValue>(() => {
    const user = status?.user ?? null;
    const mode = status?.mode;
    return {
      loading,
      mode,
      user,
      needsSetup: Boolean(status?.needs_setup),
      authRequired: Boolean(status?.auth_required),
      authenticated: Boolean(status?.authenticated),
      // In open / legacy-credential mode the single operator has full authority.
      isAdmin: user ? ADMIN_ROLES.has(user.role) : mode !== "accounts",
      refresh,
      logout,
    };
  }, [status, loading, refresh, logout]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within a SessionProvider");
  return ctx;
}

export const ROLE_LABELS: Record<string, string> = {
  owner: "Owner",
  administrator: "Administrator",
  security_analyst: "Security Analyst",
  viewer: "Viewer",
};
