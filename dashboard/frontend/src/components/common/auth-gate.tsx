import { useCallback, useEffect, useState, type ReactNode } from "react";

import { LoginScreen } from "@/components/layout/login-screen";
import { api } from "@/lib/api";

/**
 * Decides whether a login is needed before rendering the dashboard.
 *
 * Calls /api/auth/status (always 200). When auth is required and no valid
 * session exists, it shows the in-app LoginScreen instead of the app - so the
 * browser's native Basic-Auth popup never appears. It also listens for the
 * "vcqa-auth-required" event the API client fires on any 401, so an expired
 * session mid-use drops the user back to the login screen. When no credential
 * is configured (pure localhost), auth_required is false and the app renders
 * straight through with no login.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "authed" | "login">("checking");

  const check = useCallback(async () => {
    try {
      const status = await api.auth.status();
      setState(!status.auth_required || status.authenticated ? "authed" : "login");
    } catch {
      // If status itself is unreachable, let the app render and surface its own error.
      setState("authed");
    }
  }, []);

  useEffect(() => {
    void check();
    const onAuthRequired = () => setState("login");
    window.addEventListener("vcqa-auth-required", onAuthRequired);
    return () => window.removeEventListener("vcqa-auth-required", onAuthRequired);
  }, [check]);

  if (state === "checking") return null;
  if (state === "login") return <LoginScreen onAuthenticated={() => setState("authed")} />;
  return <>{children}</>;
}
