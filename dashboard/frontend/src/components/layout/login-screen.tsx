import { useState, type FormEvent } from "react";

import { api, ApiError } from "@/lib/api";

/**
 * In-app login that replaces the browser's native Basic-Auth popup. It posts to
 * /api/auth/login, which sets a signed session cookie on success; the AuthGate
 * then renders the dashboard.
 */
export function LoginScreen({ onAuthenticated }: { onAuthenticated: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const status = await api.auth.login({ username, password });
      if (status.authenticated) {
        onAuthenticated();
      } else {
        setError("Invalid username or password.");
      }
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.status === 401
          ? "Invalid username or password."
          : "Could not sign in. Is the backend running?",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="vcqa-login">
      <form className="vcqa-login-card" onSubmit={submit}>
        <span className="vcqa-login-badge" aria-hidden="true">
          <img src="/pet-badge.svg" alt="" draggable={false} />
        </span>
        <h1 className="vcqa-login-title">Vibe Coding QA</h1>
        <p className="vcqa-login-sub">Sign in to your dashboard</p>

        <label className="vcqa-login-field">
          <span>Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </label>
        <label className="vcqa-login-field">
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        {error ? (
          <p className="vcqa-login-error" role="alert">
            {error}
          </p>
        ) : null}

        <button type="submit" className="vcqa-login-btn" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="vcqa-login-foot">Loopback-only · your data stays on this machine</p>
    </div>
  );
}
