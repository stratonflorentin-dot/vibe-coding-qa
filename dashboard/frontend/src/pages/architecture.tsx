import { Boxes } from "lucide-react";
import { useMemo, useState } from "react";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { PageHeader } from "@/components/common/page-header";
import { SeverityBadge } from "@/components/common/severity-badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAsync } from "@/hooks/use-async";
import { api } from "@/lib/api";
import { formatCount, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ArchitectureNode } from "@/types/api";

const NODE_RADIUS = 26;
const LAYOUT_PADDING = 110;

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

function truncate(value: string, max = 18): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

interface NodeFinding {
  severity: string;
  file: string;
  line: number | null;
  message: string;
}

function parseFindings(entries: Array<Record<string, unknown>> | undefined): NodeFinding[] {
  return (entries ?? []).map((entry) => ({
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
  sourcePoint: LayoutPoint;
  targetPoint: LayoutPoint;
}

export function ArchitecturePage() {
  const { activeRepositoryId } = useApp();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const architecture = useAsync(
    () => api.intel.architecture(activeRepositoryId as number),
    [activeRepositoryId],
    { enabled: activeRepositoryId !== null },
  );

  const data = architecture.data ?? null;
  const nodes = data?.nodes ?? [];
  const selected =
    selectedId && data ? data.nodes.find((node) => node.id === selectedId) ?? null : null;

  const kinds = useMemo(() => Array.from(new Set(nodes.map((node) => node.kind))), [nodes]);

  // Nodes are placed on a circle from their index only — deterministic and
  // dependency-free. Edges reference node ids and are skipped when unresolved.
  const layout = useMemo(() => {
    const list = data?.nodes ?? [];
    const count = Math.max(list.length, 1);
    const radius = Math.max(150, count * 26);
    const size = (radius + LAYOUT_PADDING) * 2;
    const center = size / 2;
    const points: LayoutPoint[] = list.map((node, index) => {
      const angle = (2 * Math.PI * index) / count - Math.PI / 2;
      return {
        node,
        x: center + radius * Math.cos(angle),
        y: center + radius * Math.sin(angle),
      };
    });
    const byId = new Map<string, LayoutPoint>();
    for (const point of points) byId.set(point.node.id, point);
    const edges: LayoutEdge[] = [];
    for (const edge of data?.edges ?? []) {
      const sourcePoint = byId.get(edge.source);
      const targetPoint = byId.get(edge.target);
      if (sourcePoint && targetPoint) {
        edges.push({ source: edge.source, target: edge.target, sourcePoint, targetPoint });
      }
    }
    return { points, edges, size };
  }, [data]);

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
              <div className="grid gap-4 lg:grid-cols-3">
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle>Component graph</CardTitle>
                    <CardDescription>
                      Nodes come straight from the analysis output; edges are the dependencies static
                      analysis reported. This is not a runtime call graph.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="h-[480px] w-full">
                      <svg
                        viewBox={`0 0 ${layout.size} ${layout.size}`}
                        className="h-full w-full"
                        role="img"
                        aria-label="Architecture component graph"
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
                        </defs>
                        {layout.edges.map((edge, index) => (
                          <line
                            key={`${edge.source}-${edge.target}-${index}`}
                            x1={edge.sourcePoint.x}
                            y1={edge.sourcePoint.y}
                            x2={edge.targetPoint.x}
                            y2={edge.targetPoint.y}
                            stroke="hsl(var(--muted-foreground))"
                            strokeOpacity={0.5}
                            strokeWidth={1.5}
                            markerEnd="url(#architecture-arrow)"
                          />
                        ))}
                        {layout.points.map((point) => {
                          const isSelected = point.node.id === selectedId;
                          return (
                            <g
                              key={point.node.id}
                              className="cursor-pointer"
                              role="button"
                              tabIndex={0}
                              aria-label={`Select ${point.node.label}`}
                              onClick={() => setSelectedId(point.node.id)}
                              onKeyDown={(event) => {
                                if (event.key === "Enter" || event.key === " ") {
                                  event.preventDefault();
                                  setSelectedId(point.node.id);
                                }
                              }}
                            >
                              <circle
                                cx={point.x}
                                cy={point.y}
                                r={NODE_RADIUS}
                                fill={kindColor(point.node.kind)}
                                stroke={isSelected ? "hsl(var(--foreground))" : "hsl(var(--border))"}
                                strokeWidth={isSelected ? 3 : 1.5}
                              />
                              <text
                                x={point.x}
                                y={point.y + NODE_RADIUS + 15}
                                textAnchor="middle"
                                fontSize={11}
                                fill="hsl(var(--muted-foreground))"
                              >
                                {truncate(point.node.label)}
                              </text>
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
              </div>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>Nodes</CardTitle>
                  <CardDescription>The same graph as a plain table.</CardDescription>
                </CardHeader>
                <CardContent className="px-0 pb-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Kind</TableHead>
                        <TableHead>Label</TableHead>
                        <TableHead>Files</TableHead>
                        <TableHead>Confidence</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {nodes.map((node) => (
                        <TableRow
                          key={node.id}
                          className={cn(
                            "cursor-pointer",
                            selected?.id === node.id && "bg-muted/60",
                          )}
                          onClick={() => setSelectedId(node.id)}
                        >
                          <TableCell>
                            <span className="flex items-center gap-2">
                              <span
                                className="inline-block h-2.5 w-2.5 rounded-full"
                                style={{ backgroundColor: kindColor(node.kind) }}
                              />
                              {titleCase(node.kind)}
                            </span>
                          </TableCell>
                          <TableCell className="font-medium">{node.label}</TableCell>
                          <TableCell className="tabular-nums">
                            {formatCount(node.files.length)}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {titleCase(node.confidence)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>

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

      <div>
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Findings ({findings.length})
        </p>
        {findings.length ? (
          <ul className="space-y-2">
            {findings.map((finding, index) => (
              <li key={index} className="space-y-1 rounded-md border p-2">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <span className="truncate font-mono text-[11px] text-muted-foreground">
                    {finding.file}
                    {finding.line !== null ? `:${finding.line}` : ""}
                  </span>
                </div>
                {finding.message ? <p className="text-sm">{finding.message}</p> : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No findings are attached to this node.</p>
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
