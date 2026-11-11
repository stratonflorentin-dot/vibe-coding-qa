import { type ReactNode } from "react";

import { SessionProvider, useSession } from "@/app/session-context";
import { LoginScreen } from "@/components/layout/login-screen";

/**
 * Decides whether a login is needed before rendering the dashboard, and makes
 * the session (mode, user, role) available to the whole app via SessionProvider.
 *
 * When authentication is required (account mode, or the legacy single
 * credential) and no valid session exists, it shows the in-app LoginScreen
 * instead of the app - so the browser's native Basic-Auth popup never appears.
 * When no auth is configured (pure localhost "open" mode) the app renders
 * straight through.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <Gate>{children}</Gate>
    </SessionProvider>
  );
}

function Gate({ children }: { children: ReactNode }) {
  const { loading, authRequired, authenticated, refresh } = useSession();
  if (loading) return null;
  if (authRequired && !authenticated) {
    return <LoginScreen onAuthenticated={() => void refresh()} />;
  }
  return <>{children}</>;
}
