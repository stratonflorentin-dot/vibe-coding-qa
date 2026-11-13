/** Shared response/request types. These mirror the FastAPI schemas exactly. */

export type SourceType = "local" | "github" | "url";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type FindingStatus = "open" | "reviewed" | "resolved" | "dismissed" | "unverified";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Gate = "pass" | "fail" | "block" | "not_verified" | string | null;

export interface HealthOut {
  status: string;
  version: string;
  database: string;
  ai_configured: boolean;
  repositories: number;
  scans: number;
}

export interface SecurityProfile {
  key: string;
  name: string;
  description: string;
  tools: string[];
  default_rate: number;
  max_rate: number;
  requires_explicit_authorization: boolean;
  activities: Array<{ tool: string; activity: string; intrusive: boolean }>;
}

export interface SecuritySeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SecurityTool {
  key: string;
  name: string;
  installed: boolean;
  status: "available" | "unavailable" | string;
  version: string | null;
  detail?: string | null;
  activity?: string;
  license?: string;
}

export interface SecurityWorker {
  id: number;
  name: string;
  base_url: string;
  placement: "same_vps" | "remote_vps" | "private_network";
  allowed_networks: string | null;
  enabled: boolean;
  last_seen_at: string | null;
  last_status: string | null;
  worker_version: string | null;
  tools: SecurityTool[];
  reachable?: boolean;
  status?: string;
  detail?: string;
  profiles?: SecurityProfile[];
}

export interface SecurityTarget {
  id: number;
  value: string;
  kind: "url" | "ip";
  environment: "development" | "staging" | "production";
  ownership_confirmed: boolean;
  scope: string | null;
  profile: string;
  rate_limit: number | null;
  verify_method: string | null;
  verify_status: string;
  verify_detail: string | null;
  allowed_cidrs: string | null;
  worker_id: number | null;
  notes: string | null;
  created_at: string;
  verified_at: string | null;
}

export interface SecurityJob {
  id: number;
  target_id: number;
  worker_id: number | null;
  profile: string;
  tools: unknown;
  status: string;
  intrusive: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  cancel_requested: boolean;
  findings_count: number;
  message: string | null;
  error: string | null;
  remote_job_id: string | null;
}

export interface SecurityFinding {
  id: number;
  job_id: number;
  target_id: number;
  fingerprint: string;
  dedupe_key: string;
  tool: string;
  tools: string[];
  tool_version: string | null;
  target: string;
  endpoint: string | null;
  title: string;
  category: string | null;
  description: string | null;
  severity: Severity;
  confidence: string | null;
  evidence: string | null;
  remediation: string | null;
  references: string[];
  detected_at: string;
  verification_status: string;
  verification_checked_at: string | null;
  verified_at: string | null;
  status: FindingStatus;
  occurrences: number;
}

export interface SecurityEvidence {
  id: number;
  job_id: number;
  finding_id: number | null;
  tool: string;
  kind: string;
  content_sha256: string;
  byte_size: number;
  created_at: string;
  content?: string;
}

export interface ScanProfile {
  key: string;
  name: string;
  description: string;
  modules: string[];
  run_tests: boolean;
  osv: boolean;
  ai_review: boolean;
  minimum_score: number;
  notes: string[];
}

export interface LatestScanSummary {
  id: number;
  status: ScanStatus;
  overall_score: number | null;
  gate: Gate;
  critical_count: number | null;
  high_count: number | null;
  completed_at: string | null;
  created_at: string | null;
  test_status: string | null;
}

export interface Repository {
  id: number;
  name: string;
  source: string;
  source_type: string;
  created_at: string;
  updated_at: string;
  main_language: string | null;
  frameworks: string[];
  package_manager: string | null;
  database_tech: string[];
  auth_tech: string[];
  deployment: string[];
  default_branch: string | null;
  last_commit_sha: string | null;
  last_scan_id: number | null;
  latest_scan: LatestScanSummary | null;
}

export interface RepositoryCreate {
  name?: string | null;
  source: string;
  source_type: SourceType;
}

export interface ScanOptions {
  static_only?: boolean;
  explicit_permission?: boolean;
  test_timeout?: number | null;
  test_image?: string | null;
  test_command?: string | null;
  max_memory_mb?: number | null;
  max_cpu_seconds?: number | null;
  max_snapshot_mb?: number | null;
  max_write_mb?: number | null;
  osv?: boolean | null;
  ai_review?: boolean | null;
  pentagi?: boolean;
  share_source_context?: boolean;
}

export interface Scan {
  id: number;
  repository_id: number;
  repository_name: string | null;
  repository_source: string | null;
  status: ScanStatus;
  profile: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  commit_sha: string | null;
  overall_score: number | null;
  gate: Gate;
  critical_count: number | null;
  high_count: number | null;
  total_findings: number | null;
  test_status: string | null;
  tests_executed: number | null;
  tests_passed: number | null;
  tests_failed: number | null;
  tests_skipped: number | null;
  duration_ms: number | null;
  scanner_versions: Record<string, unknown>;
  coverage_gaps: string[];
  ai_review_status: string | null;
  error: string | null;
  options: Record<string, unknown>;
}

export interface ScanEvent {
  id: number;
  scan_id: number;
  ts: string;
  stage: string;
  status: string | null;
  message: string | null;
  data: Record<string, unknown>;
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Finding {
  id: number;
  scan_id: number;
  repository_id: number;
  repository_name: string | null;
  fingerprint: string;
  rule: string;
  module: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  message: string | null;
  suggestion: string | null;
  confidence: string | null;
  fixable: number;
  status: FindingStatus;
  first_seen_scan_id: number | null;
  created_at: string;
}

export interface AiReview {
  content: Record<string, unknown>;
  provider?: string | null;
  model?: string | null;
  created_at?: string | null;
  [key: string]: unknown;
}

export interface FindingDetail extends Finding {
  scan_profile: string | null;
  scan_completed_at: string | null;
  evidence: string[];
  history: Array<Record<string, unknown>>;
  related: Array<Record<string, unknown>>;
  latest_ai_review: AiReview | null;
}

export interface SummaryCards {
  overall_score: number | null;
  critical: number;
  high: number;
  total_open: number;
  tests_executed: number | null;
  tests_passed: number | null;
  gate: Gate;
  repository_count: number;
  latest_scan_duration_ms: number | null;
}

export interface Overview {
  summary: SummaryCards;
  severity_breakdown: Record<string, number>;
  category_breakdown: Record<string, number>;
  score_history: Array<Record<string, unknown>>;
  findings_trend: Array<Record<string, unknown>>;
  test_history: Array<Record<string, unknown>>;
  repository_health: Array<Record<string, unknown>>;
  has_data: boolean;
}

export interface ActivityItem {
  kind: string;
  title: string;
  detail: string;
  at: string | null;
  repository_id: number | null;
  scan_id: number | null;
  finding_id: number | null;
  severity: string | null;
}

export interface AISettings {
  enabled: boolean;
  provider: string;
  base_url: string;
  model: string;
  timeout: number;
  max_output_tokens: number;
  share_source_context: boolean;
  api_key_configured: boolean;
  source: "environment" | "settings" | "none";
}

export interface AISettingsIn {
  enabled: boolean;
  provider: string;
  base_url: string;
  model: string;
  timeout: number;
  max_output_tokens: number;
  share_source_context: boolean;
  api_key?: string;
  clear_api_key?: boolean;
}

export interface AIConnectionTest {
  ok: boolean;
  configured: boolean;
  provider: string | null;
  model: string | null;
  detail: string;
}

export interface ScanSettings {
  default_scan_profile: string;
  allow_test_execution: boolean;
  test_image: string;
  test_timeout: number;
  max_memory_mb: number;
  max_cpu_seconds: number;
  max_snapshot_mb: number;
  max_write_mb: number;
  osv_enabled: boolean;
}

export interface AIMessage {
  id: number;
  role: string;
  content: string;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface AIChatResponse {
  conversation_id: number;
  message: AIMessage;
  configured: boolean;
  sources: Array<Record<string, unknown>>;
  task_id?: number | null;
  confidence?: string;
  limitations?: string[];
  status?: string;
  execution?: string;
  provider?: string | null;
  model?: string | null;
  latency_ms?: number | null;
  fallback_used?: boolean;
}

export interface AIConversation {
  id: number;
  repository_id: number | null;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
}

export interface AIConversationDetail {
  id: number;
  repository_id: number | null;
  title: string;
  created_at: string;
  updated_at: string;
  messages: AIMessage[];
}

export interface AIReviewResponse {
  finding_id: number;
  configured: boolean;
  provider: string | null;
  model: string | null;
  error: string | null;
  content: Record<string, unknown>;
  task_id?: number | null;
  confidence?: string;
  evidence?: Array<Record<string, unknown>>;
  limitations?: string[];
  status?: string;
  execution?: string;
  latency_ms?: number | null;
}

export interface IntelligenceTask {
  id: number;
  user_id: number | null;
  project_id: number | null;
  operation: string;
  status: string;
  error_code: string | null;
  created_at: string;
  completed_at: string | null;
  executions: Array<{
    id: number; provider_id: string | null; model_id: string | null;
    execution_status: string; latency_ms: number | null; token_usage: number | null;
    estimated_cost: number | null; fallback_used: number; created_at: string;
  }>;
  tool_calls: Array<{ id: number; tool_name: string; argument_names: string; status: string; created_at: string }>;
}

export interface Remediation {
  id: number;
  finding_id: number | null;
  repository_id: number;
  status: string;
  created_at: string;
  updated_at: string;
  provider: string | null;
  model: string | null;
  file: string | null;
  original: string | null;
  proposed: string | null;
  diff: string | null;
  rationale: string | null;
  error: string | null;
  history: Array<Record<string, unknown>>;
}

export interface TestGenerateResponse {
  finding_id: number;
  configured: boolean;
  file_path: string | null;
  content: string | null;
  error: string | null;
  note: string;
}

export interface SummaryResponse {
  configured: boolean;
  provider: string | null;
  model: string | null;
  error: string | null;
  text: string;
}

export interface ThreatModelResponse {
  repository_id: number;
  configured: boolean;
  provider: string | null;
  model: string | null;
  error: string | null;
  text: string;
  note: string;
}

export interface ArchitectureNode {
  id: string;
  kind: string;
  label: string;
  files: string[];
  confidence: string;
  details: Record<string, unknown>;
}

export interface ArchitectureEdge {
  source: string;
  target: string;
  kind: string;
}

export interface Architecture {
  repository_id: number;
  nodes: ArchitectureNode[];
  edges: ArchitectureEdge[];
  findings_by_node: Record<string, Array<Record<string, unknown>>>;
  notes: string[];
}

export interface Dependency {
  name: string;
  version: string | null;
  direct: boolean;
  license: string | null;
  advisories: Array<Record<string, unknown>>;
  status: string;
}

export interface Dependencies {
  repository_id: number;
  package_manager: string | null;
  lockfiles: string[];
  dependencies: Dependency[];
  notes: string[];
  osv_checked: boolean;
}

export interface ComparedFinding {
  rule: string;
  severity: Severity;
  file: string;
  line: number;
  message: string | null;
}

export interface ScanComparison {
  base_scan_id: number;
  head_scan_id: number;
  base_score: number | null;
  head_score: number | null;
  score_delta: number | null;
  /** Findings present in the newer scan but not the baseline. */
  added: ComparedFinding[];
  /** Findings present in the baseline but no longer reported. */
  resolved: ComparedFinding[];
  unchanged_count: number;
}

export interface RemediationProposal extends Remediation {
  history: Array<Record<string, unknown>>;
}
