/**
 * Typed client for the dashboard API.
 *
 * Everything goes through ``/api`` on the same origin: Vite proxies the path to
 * the FastAPI backend in development. No credential ever lives in the browser —
 * the AI key is only ever sent *to* the server from the settings form and is
 * never returned.
 */

import type {
  AIChatResponse,
  AIConversation,
  AIConversationDetail,
  AIConnectionTest,
  AIReviewResponse,
  AISettings,
  AISettingsIn,
  Architecture,
  Dependencies,
  Finding,
  FindingDetail,
  FindingStatus,
  HealthOut,
  Overview,
  Paged,
  Remediation,
  Repository,
  RepositoryCreate,
  Scan,
  ScanComparison,
  ScanEvent,
  ScanOptions,
  ScanProfile,
  ScanSettings,
  SummaryResponse,
  TestGenerateResponse,
  ThreatModelResponse,
  ActivityItem,
} from "@/types/api";

export const API_BASE = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type QueryValue = string | number | boolean | null | undefined | Array<string | number>;

function buildQuery(params?: Record<string, QueryValue>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, String(item));
    } else {
      search.append(key, String(value));
    }
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
      },
      ...init,
    });
  } catch {
    throw new ApiError(
      "The dashboard API is unreachable. Is the backend running on 127.0.0.1:8756?",
      0,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    if (response.status === 401) {
      // Let the auth gate drop back to the login screen on an expired session.
      try {
        window.dispatchEvent(new CustomEvent("vcqa-auth-required"));
      } catch {
        /* non-browser environment */
      }
    }
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? formatDetail((payload as { detail: unknown }).detail)
        : typeof payload === "string" && payload
          ? payload
          : `Request failed with status ${response.status}.`;
    throw new ApiError(detail, response.status);
  }

  return payload as T;
}

/** FastAPI validation errors arrive as a list of {loc, msg}. */
function formatDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (item && typeof item === "object" && "msg" in item) {
          const record = item as { msg?: string; loc?: unknown[] };
          const location = Array.isArray(record.loc) ? record.loc.slice(-1).join("") : "";
          return location ? `${location}: ${record.msg}` : String(record.msg);
        }
        return JSON.stringify(item);
      })
      .join("; ");
  }
  return "The request could not be completed.";
}

function json(method: string, body: unknown): RequestInit {
  return { method, body: JSON.stringify(body) };
}

// --------------------------------------------------------------------- system
export const system = {
  health: () => request<HealthOut>("/api/health"),
  profiles: () => request<ScanProfile[]>("/api/profiles"),
  scanSettings: () => request<ScanSettings>("/api/settings/scan"),
  updateScanSettings: (payload: ScanSettings) =>
    request<ScanSettings>("/api/settings/scan", json("PUT", payload)),
  aiSettings: () => request<AISettings>("/api/settings/ai"),
  updateAiSettings: (payload: AISettingsIn) =>
    request<AISettings>("/api/settings/ai", json("PUT", payload)),
  testAiConnection: () => request<AIConnectionTest>("/api/settings/ai/test", { method: "POST" }),
};

// ---------------------------------------------------------------- repositories
export const repositories = {
  list: () => request<Repository[]>("/api/repositories"),
  get: (id: number) => request<Repository>(`/api/repositories/${id}`),
  create: (payload: RepositoryCreate) =>
    request<Repository>("/api/repositories", json("POST", payload)),
  refresh: (id: number) => request<Repository>(`/api/repositories/${id}/refresh`, { method: "POST" }),
  remove: (id: number) =>
    request<{ detail: string }>(`/api/repositories/${id}`, { method: "DELETE" }),
  scans: (id: number, params?: { limit?: number; offset?: number }) =>
    request<Paged<Scan>>(`/api/repositories/${id}/scans${buildQuery(params)}`),
};

// -------------------------------------------------------------------- scans
export const scans = {
  list: (params?: {
    repository_id?: number;
    status?: string;
    limit?: number;
    offset?: number;
  }) => request<Paged<Scan>>(`/api/scans${buildQuery(params)}`),
  get: (id: number) => request<Scan>(`/api/scans/${id}`),
  create: (payload: { repository_id: number; profile: string; options?: ScanOptions }) =>
    request<Scan>("/api/scans", json("POST", payload)),
  cancel: (id: number) => request<Scan>(`/api/scans/${id}/cancel`, { method: "POST" }),
  events: (id: number, after = 0) =>
    request<ScanEvent[]>(`/api/scans/${id}/events.json${buildQuery({ after })}`),
  compare: (base: number, head: number) =>
    request<ScanComparison>(`/api/scans/compare${buildQuery({ base, head })}`),
};

/**
 * Subscribe to a scan's Server-Sent Events stream.
 *
 * Returns a disposer. Events are exactly the ones the engine emitted — the
 * dashboard never fabricates progress.
 */
export function streamScanEvents(
  scanId: number,
  handlers: {
    onOpen?: () => void;
    onEvent?: (event: ScanEvent) => void;
    onEnd?: (payload: { status: string; reason?: string }) => void;
    onError?: (error: Event) => void;
  },
  after = 0,
): () => void {
  const source = new EventSource(`${API_BASE}/api/scans/${scanId}/events${buildQuery({ after })}`);

  source.addEventListener("open", () => handlers.onOpen?.());
  source.addEventListener("scan-event", (raw) => {
    try {
      handlers.onEvent?.(JSON.parse((raw as MessageEvent).data) as ScanEvent);
    } catch {
      /* A malformed frame is ignored rather than breaking the stream. */
    }
  });
  source.addEventListener("end", (raw) => {
    try {
      handlers.onEnd?.(JSON.parse((raw as MessageEvent).data));
    } catch {
      handlers.onEnd?.({ status: "unknown" });
    }
    source.close();
  });
  source.onerror = (error) => {
    handlers.onError?.(error);
    source.close();
  };

  return () => source.close();
}

// ------------------------------------------------------------------ findings
export interface FindingFilters {
  repository_id?: number;
  scan_id?: number;
  severity?: string[];
  module?: string[];
  status?: string[];
  search?: string;
  limit?: number;
  offset?: number;
}

export const findings = {
  list: (filters?: FindingFilters) =>
    request<Paged<Finding>>(`/api/findings${buildQuery(filters as Record<string, QueryValue>)}`),
  get: (id: number) => request<FindingDetail>(`/api/findings/${id}`),
  setStatus: (id: number, status: FindingStatus) =>
    request<Finding>(`/api/findings/${id}`, json("PATCH", { status })),
};

// ----------------------------------------------------------------- dashboard
export const dashboard = {
  overview: (repositoryId?: number) =>
    request<Overview>(`/api/dashboard/overview${buildQuery({ repository_id: repositoryId })}`),
  activity: (limit = 30) =>
    request<{ items: ActivityItem[] }>(`/api/dashboard/activity${buildQuery({ limit })}`),
};

// ------------------------------------------------------------------------ AI
export const ai = {
  chat: (payload: { message: string; repository_id?: number | null; conversation_id?: number | null }) =>
    request<AIChatResponse>("/api/ai/chat", json("POST", payload)),
  conversations: () => request<AIConversation[]>("/api/ai/conversations"),
  conversation: (id: number) => request<AIConversationDetail>(`/api/ai/conversations/${id}`),
  deleteConversation: (id: number) =>
    request<{ detail: string }>(`/api/ai/conversations/${id}`, { method: "DELETE" }),
  reviewFinding: (id: number, kind: "analyst" | "explain" | "impact" = "analyst") =>
    request<AIReviewResponse>(`/api/ai/findings/${id}/review`, json("POST", { kind })),
  generateTest: (id: number) =>
    request<TestGenerateResponse>(`/api/ai/findings/${id}/test`, json("POST", { finding_id: id })),
  remediations: () => request<Remediation[]>("/api/ai/remediations"),
  remediation: (id: number) => request<Remediation>(`/api/ai/remediations/${id}`),
  proposeRemediation: (findingId: number) =>
    request<Remediation>("/api/ai/remediations", json("POST", { finding_id: findingId })),
  approveRemediation: (
    id: number,
    payload: { confirm: boolean; run_tests?: boolean; explicit_permission?: boolean },
  ) => request<Remediation>(`/api/ai/remediations/${id}/approve`, json("POST", payload)),
  rollbackRemediation: (id: number) =>
    request<Remediation>(`/api/ai/remediations/${id}/rollback`, { method: "POST" }),
  summary: (payload: { repository_id?: number | null; scan_id?: number | null }) =>
    request<SummaryResponse>("/api/ai/summary", json("POST", payload)),
  threatModel: (repositoryId: number) =>
    request<ThreatModelResponse>("/api/ai/threat-model", json("POST", { repository_id: repositoryId })),
};

// --------------------------------------------------------------------- intel
export const intel = {
  architecture: (repositoryId: number) =>
    request<Architecture>(`/api/architecture/${repositoryId}`),
  dependencies: (repositoryId: number, osv = false) =>
    request<Dependencies>(`/api/dependencies/${repositoryId}${buildQuery({ osv })}`),
};

// --------------------------------------------------------------------- auth
export interface AuthStatus {
  auth_required: boolean;
  authenticated: boolean;
}

export const auth = {
  status: () => request<AuthStatus>("/api/auth/status"),
  login: (payload: { username: string; password: string }) =>
    request<AuthStatus>("/api/auth/login", json("POST", payload)),
  logout: () => request<AuthStatus>("/api/auth/logout", { method: "POST" }),
};

export const api = {
  system,
  auth,
  repositories,
  scans,
  findings,
  dashboard,
  ai,
  intel,
};
