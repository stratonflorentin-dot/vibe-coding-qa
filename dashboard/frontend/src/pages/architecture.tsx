import { Boxes, ChevronDown, Maximize2, Minimize2, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/use-async";
import { api } from "@/lib/api";
import { groupIssues } from "@/lib/finding-groups";
import { formatCount, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ArchitectureNode, Severity } from "@/types/api";

const NODE_HEIGHT = 82;
const GRAPH_PADDING = 24;
const NODE_COLUMN_GAP = 16;
const NODE_ROW_GAP = 18;

/** A fixed palette so the same kind always gets the same colour. */
const KIND_PALETTE = [
  "hsl(var(--primary))",
  "hsl(var(--severity-low))",
  "hsl(var(--gate-pass))",
  "hsl(var(--severity-medium))",
  "hsl(var(--severity-high))",
];

function kindColor(kind: string): string {
  let hash = 0;
  for (let index = 0; index < kind.length; index += 1) {
    hash = (hash * 31 + kind.charCodeAt(index)) >>> 0;
  }
  return KIND_PALETTE[hash % KIND_PALETTE.length];
}

function truncate(value: string, max = 27): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

interface NodeFinding {
  id: number | null;
  rule: string;
  module: string;
  severity: string;
  file: string;
  line: number | null;
  message: string;
}

function parseFindings(entries: Array<Record<string, unknown>> | undefined): NodeFinding[] {
  return (entries ?? []).map((entry) => ({
    id: typeof entry.id === "number" ? entry.id : null,
    rule: typeof entry.rule === "string" ? entry.rule : "Finding",
    module: typeof entry.module === "string" ? entry.module : "other",
    severity: typeof entry.severity === "string" ? entry.severity : "info",
    file: typeof entry.file === "string" ? entry.file : "",
    line: typeof entry.line === "number" ? entry.line : null,
    message: typeof entry.message === "string" ? entry.message : "",
  }));
}

interface LayoutPoint {
  node: ArchitectureNode;
  x: number;
  y: number;
}

interface LayoutEdge {
  source: string;
  target: string;
  path: string;
}

interface GraphLayout {
  points: LayoutPoint[];
  edges: LayoutEdge[];
  width: number;
  height: number;
  cardWidth: number;
  appWidth: number;
  rootId: string | null;
}

function createGraphLayout(
  nodes: ArchitectureNode[],
  edges: Array<{ source: string; target: string }>,
  viewportWidth: number,
): GraphLayout {
  const root = nodes.find((node) => node.kind === "application") ?? nodes[0];
  const width = Math.max(360, viewportWidth);
  const columnCount = width >= 1280 ? 4 : width >= 850 ? 3 : width >= 520 ? 2 : 1;
  const cardWidth =
    (width - GRAPH_PADDING * 2 - NODE_COLUMN_GAP * (columnCount - 1)) / columnCount;
  const appWidth = Math.min(480, width - GRAPH_PADDING * 2);
  const children = nodes
    .filter((node) => node.id !== root?.id)
    .slice()
    .sort((left, right) => left.kind.localeCompare(right.kind) || left.label.localeCompare(right.label));
  const rowCount = Math.ceil(children.length / columnCount);
  const firstRowY = 150;
  const height = Math.max(240, firstRowY + rowCount * (NODE_HEIGHT + NODE_ROW_GAP) + GRAPH_PADDING);
  const points: LayoutPoint[] = [];
  if (root) points.push({ node: root, x: width / 2, y: 66 });
  children.forEach((node, index) => {
    const column = index % columnCount;
    const row = Math.floor(index / columnCount);
    points.push({
      node,
      x: GRAPH_PADDING + cardWidth / 2 + column * (cardWidth + NODE_COLUMN_GAP),
      y: firstRowY + NODE_HEIGHT / 2 + row * (NODE_HEIGHT + NODE_ROW_GAP),
    });
  });

  const byId = new Map(points.map((point) => [point.node.id, point]));
  const graphEdges = edges.flatMap((edge) => {
    const source = byId.get(edge.source);
    const target = byId.get(edge.target);
    if (!source || !target) return [];
    const startY = source.y + NODE_HEIGHT / 2;
    const endY = target.y - NODE_HEIGHT / 2;
    const curve = Math.max(36, (endY - startY) * 0.48);
    return [{
      source: edge.source,
      target: edge.target,
      path: `M ${source.x} ${startY} C ${source.x} ${startY + curve}, ${target.x} ${endY - curve}, ${target.x} ${endY}`,
    }];
  });

  return {
    points,
    edges: graphEdges,
    width,
    height,
    cardWidth,
    appWidth,
    rootId: root?.id ?? null,
  };
}

export function ArchitecturePage() {
  const { activeRepositoryId } = useApp();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [expandedNodeKind, setExpandedNodeKind] = useState<string | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [animationKey, setAnimationKey] = useState(0);
  const [graphWidth, setGraphWidth] = useState(900);
  const graphViewportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = graphViewportRef.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => {
      setGraphWidth(Math.round(entry.contentRect.width));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const architecture = useAsync(
    () => api.intel.architecture(activeRepositoryId as number),
    [activeRepositoryId],
    { enabled: activeRepositoryId !== null },
  );

  const data = architecture.data ?? null;
  const nodes = useMemo(() => data?.nodes ?? [], [data?.nodes]);
  const selected =
    selectedId && data ? data.nodes.find((node) => node.id === selectedId) ?? null : null;

  const kinds = useMemo(() => Array.from(new Set(nodes.map((node) => node.kind))), [nodes]);
  const nodeGroups = useMemo(() => {
    const grouped = new Map<string, ArchitectureNode[]>();
    for (const node of nodes) {
      const group = grouped.get(node.kind) ?? [];
      group.push(node);
      grouped.set(node.kind, group);
    }
    return [...grouped.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [nodes]);
  const layout = useMemo(
    () => createGraphLayout(nodes, data?.edges ?? [], graphWidth),
    [nodes, data?.edges, graphWidth],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Architecture"
        description="How the codebase is put together. This view is derived from static analysis of source, not from a runtime call graph."
      />

      {activeRepositoryId === null ? (
        <EmptyState
          icon={Boxes}
          title="No repository selected"
          description="Choose a repository in the top bar to see its derived architecture."
        />
      ) : (
        <DataState
          loading={architecture.loading}
          error={architecture.error}
          onRetry={() => void architecture.reload()}
          loadingRows={4}
        >
          {data === null ? null : nodes.length === 0 ? (
            <EmptyState
              icon={Boxes}
              title="No architecture could be derived"
              description="Static analysis did not produce any nodes for this repository. Run a scan, or check that the source is reachable."
            />
          ) : (
            <div className="space-y-6">
              <Card
                className={cn(
                  fullscreen && "fixed inset-3 z-50 flex flex-col overflow-hidden bg-background shadow-2xl",
                )}
              >
                <CardHeader className="flex-col items-start justify-between gap-4 pb-3 sm:flex-row">
                  <div className="space-y-1.5">
                    <CardTitle>Component graph</CardTitle>
                    <CardDescription>
                      Select a feature to animate its connections. Nodes are grouped into readable
                      lanes by type; this is static analysis, not a runtime call graph.
                    </CardDescription>
                  </div>
                  <div className="flex shrink-0 flex-wrap justify-end gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setAnimationKey((current) => current + 1)}
                    >
                      <RefreshCw />
                      Replay movement
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setFullscreen((current) => !current)}
                      aria-label={fullscreen ? "Exit expanded graph" : "Expand graph"}
                    >
                      {fullscreen ? <Minimize2 /> : <Maximize2 />}
                      {fullscreen ? "Exit expanded view" : "Expand graph"}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className={cn("min-h-0", fullscreen && "flex flex-1 flex-col")}>
                  <div
                    ref={graphViewportRef}
                    className="w-full overflow-auto rounded-lg border bg-muted/20"
                    style={{ maxHeight: fullscreen ? "calc(100vh - 190px)" : undefined }}
                  >
                      <svg
                        viewBox={`0 0 ${layout.width} ${layout.height}`}
                        width={layout.width}
                        height={layout.height}
                        className="block w-full"
                        role="group"
                        aria-label="Interactive architecture component graph"
                      >
                        <defs>
                          <marker
                            id="architecture-arrow"
                            markerWidth="10"
                            markerHeight="10"
                            refX="9"
                            refY="3"
                            orient="auto"
                            markerUnits="strokeWidth"
                          >
                            <path d="M0,0 L9,3 L0,6 z" fill="hsl(var(--muted-foreground))" />
                          </marker>
                          <pattern
                            id="architecture-grid"
                            width="32"
                            height="32"
                            patternUnits="userSpaceOnUse"
                          >
                            <circle cx="1" cy="1" r="1" fill="hsl(var(--border))" opacity="0.55" />
                          </pattern>
                        </defs>
                        <rect
                          width={layout.width}
                          height={layout.height}
                          fill="url(#architecture-grid)"
                        />
                        {layout.edges.map((edge, index) => {
                          const activeNodeId = hoveredId ?? selectedId;
                          const isActive =
                            activeNodeId !== null &&
                            (edge.source === activeNodeId || edge.target === activeNodeId);
                          const flowInterval = Math.max(1, Math.ceil(layout.edges.length / 8));
                          const isFlowing =
                            isActive &&
                            (activeNodeId !== layout.rootId || index % flowInterval === 0);
                          const pathId = `architecture-edge-${index}`;
                          return (
                            <g key={pathId}>
                              <path
                                id={pathId}
                                d={edge.path}
                                fill="none"
                                stroke={isActive ? "hsl(var(--primary))" : "hsl(var(--muted-foreground))"}
                                strokeOpacity={activeNodeId ? (isActive ? 0.9 : 0.08) : 0.22}
                                strokeWidth={isActive ? 2.5 : 1.25}
                                markerEnd="url(#architecture-arrow)"
                                className={isFlowing ? "architecture-edge-active" : undefined}
                              />
                              {isFlowing ? (
                                <circle r="4" className="architecture-flow-dot">
                                  <animateMotion
                                    dur={`${1.4 + (index % 4) * 0.2}s`}
                                    repeatCount="indefinite"
                                  >
                                    <mpath href={`#${pathId}`} />
                                  </animateMotion>
                                </circle>
                              ) : null}
                            </g>
                          );
                        })}
                        {layout.points.map((point, index) => {
                          const isSelected = point.node.id === selectedId;
                          const isHovered = point.node.id === hoveredId;
                          const nodeWidth =
                            point.node.id === layout.rootId ? layout.appWidth : layout.cardWidth;
                          const labelLength = Math.max(18, Math.floor((nodeWidth - 54) / 7.2));
                          return (
                            <g
                              key={point.node.id}
                              transform={`translate(${point.x - nodeWidth / 2} ${point.y - NODE_HEIGHT / 2})`}
                              className="cursor-pointer outline-none"
                              role="button"
                              tabIndex={0}
                              aria-label={`Select ${point.node.label}`}
                              onClick={() => setSelectedId(point.node.id)}
                              onMouseEnter={() => setHoveredId(point.node.id)}
                              onMouseLeave={() => setHoveredId(null)}
                              onFocus={() => setHoveredId(point.node.id)}
                              onBlur={() => setHoveredId(null)}
                              onKeyDown={(event) => {
                                if (event.key === "Enter" || event.key === " ") {
                                  event.preventDefault();
                                  setSelectedId(point.node.id);
                                }
                              }}
                            >
                              <g
                                key={`${animationKey}-${point.node.id}`}
                                className="architecture-node-enter"
                                style={{ animationDelay: `${Math.min(index, 24) * 22}ms` }}
                              >
                                <title>{point.node.label}</title>
                                <rect
                                  width={nodeWidth}
                                  height={NODE_HEIGHT}
                                  rx="12"
                                  fill="hsl(var(--card))"
                                  stroke={
                                    isSelected || isHovered
                                      ? "hsl(var(--primary))"
                                      : "hsl(var(--border))"
                                  }
                                  strokeWidth={isSelected ? 3 : isHovered ? 2 : 1}
                                  className="architecture-node-card"
                                />
                                <circle
                                  cx="22"
                                  cy="25"
                                  r="6"
                                  fill={kindColor(point.node.kind)}
                                />
                                <text
                                  x="38"
                                  y="30"
                                  fill="hsl(var(--card-foreground))"
                                  fontSize="14"
                                  fontWeight="600"
                                >
                                  {truncate(point.node.label, labelLength)}
                                </text>
                                <text
                                  x="38"
                                  y="56"
                                  fill="hsl(var(--muted-foreground))"
                                  fontSize="11"
                                >
                                  {titleCase(point.node.kind)} · {formatCount(point.node.files.length)} files
                                </text>
                              </g>
                            </g>
                          );
                        })}
                  </svg>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2">
                    {kinds.map((kind) => (
                      <span
                        key={kind}
                        className="flex items-center gap-1.5 text-xs text-muted-foreground"
                      >
                        <span
                          className="inline-block h-2.5 w-2.5 rounded-full"
                          style={{ backgroundColor: kindColor(kind) }}
                        />
                        {titleCase(kind)}
                      </span>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <div className="grid gap-4 lg:grid-cols-3">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>{selected ? selected.label : "Node details"}</CardTitle>
                    <CardDescription>
                      {selected
                        ? `${titleCase(selected.kind)} · confidence ${titleCase(selected.confidence)}`
                        : "Select a node in the graph or the table to inspect it."}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {selected ? (
                      <NodePanel
                        node={selected}
                        findings={parseFindings(data.findings_by_node[selected.id])}
                      />
                    ) : (
                      <p className="text-sm text-muted-foreground">No node selected yet.</p>
                    )}
                  </CardContent>
                </Card>

              <Card className="lg:col-span-2">
                <CardHeader className="pb-3">
                  <CardTitle>Architecture nodes</CardTitle>
                  <CardDescription>
                    Grouped by type to keep the feature list compact. Expand a type to show or hide
                    its nodes.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {nodeGroups.map(([kind, groupedNodes]) => {
                    const isExpanded = expandedNodeKind === kind;
                    const groupLabel =
                      kind === "endpoint" ? "Endpoints" : `${titleCase(kind)} nodes`;
                    return (
                      <section key={kind} className="overflow-hidden rounded-lg border">
                        <button
                          type="button"
                          aria-expanded={isExpanded}
                          onClick={() =>
                            setExpandedNodeKind((current) => (current === kind ? null : kind))
                          }
                          className={cn(
                            "flex w-full items-center gap-3 px-3 py-3 text-left transition-colors hover:bg-muted/60",
                            isExpanded && "bg-muted/40",
                          )}
                        >
                          <span
                            className="h-3 w-3 shrink-0 rounded-full ring-4 ring-background"
                            style={{ backgroundColor: kindColor(kind) }}
                          />
                          <span className="min-w-0 flex-1">
                            <span className="block font-medium">{groupLabel}</span>
                            <span className="text-xs text-muted-foreground">
                              {formatCount(groupedNodes.length)} feature
                              {groupedNodes.length === 1 ? "" : "s"}
                            </span>
                          </span>
                          <ChevronDown
                            className={cn(
                              "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
                              isExpanded && "rotate-180",
                            )}
                          />
                        </button>
                        {isExpanded ? (
                          <div className="grid gap-2 border-t bg-muted/20 p-3 sm:grid-cols-2 xl:grid-cols-3">
                            {groupedNodes.map((node) => (
                              <button
                                key={node.id}
                                type="button"
                                aria-pressed={selected?.id === node.id}
                                onClick={() => setSelectedId(node.id)}
                                className={cn(
                                  "flex min-w-0 items-center gap-2 rounded-md border bg-card px-3 py-2 text-left transition-colors hover:border-primary/60 hover:bg-accent/50",
                                  selected?.id === node.id && "border-primary bg-primary/10",
                                )}
                              >
                                <span
                                  className="h-2.5 w-2.5 shrink-0 rounded-full"
                                  style={{ backgroundColor: kindColor(node.kind) }}
                                />
                                <span className="min-w-0 flex-1 truncate text-sm font-medium">
                                  {node.label}
                                </span>
                                <span className="shrink-0 text-[11px] text-muted-foreground">
                                  {formatCount(node.files.length)} files
                                </span>
                              </button>
                            ))}
                          </div>
                        ) : null}
                      </section>
                    );
                  })}
                </CardContent>
              </Card>
              </div>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>Notes</CardTitle>
                  <CardDescription>Reported verbatim by the analysis engine.</CardDescription>
                </CardHeader>
                <CardContent>
                  {data.notes.length ? (
                    <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                      {data.notes.map((note, index) => (
                        <li key={index}>{note}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      The engine did not provide any notes for this graph.
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </DataState>
      )}
    </div>
  );
}

function NodePanel({ node, findings }: { node: ArchitectureNode; findings: NodeFinding[] }) {
  const [severity, setSeverity] = useState("all");
  const severityCounts = useMemo(
    () =>
      findings.reduce<Record<string, number>>((counts, finding) => {
        counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
        return counts;
      }, {}),
    [findings],
  );
  const filteredFindings =
    severity === "all" ? findings : findings.filter((finding) => finding.severity === severity);
  const groups = useMemo(() => groupIssues(filteredFindings), [filteredFindings]);

  return (
    <div className="space-y-4">
      <div>
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Files
        </p>
        {node.files.length ? (
          <ul className="space-y-1">
            {node.files.map((file, index) => (
              <li key={index} className="truncate font-mono text-xs">
                {file}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No files were attached to this node.</p>
        )}
      </div>

      <div>
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Details
        </p>
        <DetailsList details={node.details} />
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Findings ({formatCount(filteredFindings.length)})
          </p>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger aria-label="Filter node findings by severity" className="h-8 w-[132px] text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["all", "critical", "high", "medium", "low", "info"].map((value) => (
                <SelectItem key={value} value={value}>
                  {value === "all"
                    ? `All (${formatCount(findings.length)})`
                    : `${titleCase(value)} (${formatCount(severityCounts[value] ?? 0)})`}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {groups.length ? (
          <ul className="space-y-2">
            {groups.map((group) => {
              const finding = group.representative;
              const fileCount = new Set(group.occurrences.map((item) => item.file)).size;
              return (
                <li key={group.key} className="rounded-md border p-2">
                  <details>
                    <summary className="cursor-pointer list-none space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={finding.severity as Severity} />
                        <span className="min-w-0 truncate font-mono text-[11px] text-muted-foreground">
                          {finding.rule}
                        </span>
                        <span className="ml-auto shrink-0 text-xs font-medium">
                          {formatCount(group.occurrences.length)}×
                        </span>
                      </div>
                      {finding.message ? (
                        <p className="text-sm">{finding.message}</p>
                      ) : null}
                      <p className="text-xs text-muted-foreground">
                        {formatCount(group.occurrences.length)} occurrence
                        {group.occurrences.length === 1 ? "" : "s"} across {formatCount(fileCount)} file
                        {fileCount === 1 ? "" : "s"} · show locations
                      </p>
                    </summary>
                    <ul className="mt-2 max-h-48 space-y-1 overflow-auto border-t pt-2">
                      {group.occurrences.map((item, index) => (
                        <li key={item.id ?? `${item.file}:${item.line}:${index}`} className="text-xs">
                          {item.id !== null ? (
                            <Link
                              to={`/findings/${item.id}`}
                              className="break-all font-mono text-primary hover:underline"
                            >
                              {item.file}:{item.line ?? "—"}
                            </Link>
                          ) : (
                            <span className="break-all font-mono">
                              {item.file}:{item.line ?? "—"}
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </details>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            {findings.length ? "No findings match this severity." : "No findings are attached to this node."}
          </p>
        )}
      </div>
    </div>
  );
}

function DetailsList({ details }: { details: Record<string, unknown> }) {
  const entries = Object.entries(details);
  if (!entries.length) {
    return <p className="text-sm text-muted-foreground">No additional details were recorded.</p>;
  }
  return (
    <dl className="space-y-1 text-sm">
      {entries.map(([key, value]) => (
        <div key={key} className="flex gap-2">
          <dt className="shrink-0 text-muted-foreground">{titleCase(key)}</dt>
          <dd className="min-w-0 break-words">{formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  );
}
