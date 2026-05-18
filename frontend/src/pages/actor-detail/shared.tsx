/**
 * Shared helpers, types, and primitive components for the ActorDetail page.
 * Extracted from ActorDetail.tsx to enable sub-component files.
 */
import React, { useState } from "react";
import {
  Sparkles, Pencil, X, Play, Pause, Square, Shuffle,
  Activity, ChevronDown, ChevronUp, Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { getCapabilityConfig } from "@/lib/capabilityConfig";
import { relativeTime } from "@/lib/formatTime";
import {
  graphqlRequest,
  type ActorActionLogEntry,
} from "@/lib/graphqlClient";

// Re-export so callers can import relativeTime from one place within this feature.
export { relativeTime };

// ── Tab type ──────────────────────────────────────────────────────────────────

export type Tab =
  | "summary"
  | "workflows"
  | "memory"
  | "budget"
  | "policies"
  | "log"
  | "handoffs";

// ── Pure helpers ──────────────────────────────────────────────────────────────

export function statusColors(status: string) {
  switch (status) {
    case "active":
      return {
        badge: "bg-success/10 text-success border-success/20 shadow-[0_0_8px_hsla(var(--success),0.2)]",
        dot: "bg-success",
        border: "border-l-success",
      };
    case "suspended":
      return {
        badge: "bg-warning/10 text-warning border-warning/20 shadow-[0_0_8px_hsla(var(--warning),0.2)]",
        dot: "bg-warning",
        border: "border-l-warning",
      };
    case "terminated":
      return {
        badge: "bg-destructive/10 text-destructive border-destructive/20 shadow-[0_0_8px_hsla(var(--destructive),0.2)]",
        dot: "bg-destructive",
        border: "border-l-destructive",
      };
    default:
      return { badge: "bg-muted-foreground/10 text-muted-foreground", dot: "bg-muted-foreground", border: "border-l-muted-foreground" };
  }
}

export function workflowStatusColor(status: string | null) {
  switch (status) {
    case "published": return "text-emerald-400";
    case "draft":     return "text-amber-400";
    case "archived":  return "text-muted-foreground/40";
    default:          return "text-muted-foreground";
  }
}

export function humanizeLogEntry(
  entry: ActorActionLogEntry,
  wfName?: string,
): string {
  const type = entry.actionType.toLowerCase();
  const wf = wfName || (entry.workflowId ? `wf:${entry.workflowId.slice(0, 8)}` : null);
  if (type === "created") return "Actor created";
  if (type === "workflow_executed") return wf ? `Ran ${wf}` : "Ran a workflow";
  if (type.includes("handoff_received")) return `Received handoff — ${entry.summary}`;
  if (type.includes("handoff")) return `Handoff — ${entry.summary}`;
  if (type === "suspended") return "Actor suspended";
  if (type === "activated") return "Actor activated";
  if (type === "archived") return "Actor archived";
  if (type === "terminated") return "Actor terminated";
  return entry.summary;
}

export function downloadLogCsv(entries: ActorActionLogEntry[]) {
  const header = "id,action_type,summary,timestamp,workflow_id,execution_id";
  const rows = entries.map((e) =>
    [
      e.id,
      e.actionType,
      `"${e.summary.replace(/"/g, '""')}"`,
      e.timestamp,
      e.workflowId ?? "",
      e.executionId ?? "",
    ].join(","),
  );
  const csv = [header, ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `actor-log-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export const ACTION_ICONS: Record<string, React.ReactNode> = {
  create:           <Sparkles className="w-3.5 h-3.5" />,
  created:          <Sparkles className="w-3.5 h-3.5" />,
  update:           <Pencil className="w-3.5 h-3.5" />,
  delete:           <X className="w-3.5 h-3.5" />,
  execute:          <Play className="w-3.5 h-3.5" />,
  workflow_executed:<Play className="w-3.5 h-3.5" />,
  suspend:          <Pause className="w-3.5 h-3.5" />,
  suspended:        <Pause className="w-3.5 h-3.5" />,
  activate:         <Play className="w-3.5 h-3.5" />,
  activated:        <Play className="w-3.5 h-3.5" />,
  terminate:        <Square className="w-3.5 h-3.5" />,
  terminated:       <Square className="w-3.5 h-3.5" />,
  handoff:          <Shuffle className="w-3.5 h-3.5" />,
};

// ── Shared primitive components ───────────────────────────────────────────────

export function CapabilityBadge({ world }: { world: string }) {
  const cfg = getCapabilityConfig(world);
  return (
    <span
      title={cfg.tooltipDetail}
      className={cn(
        "inline-flex items-center gap-1 rounded-full border text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 whitespace-nowrap",
        cfg.textColor,
        cfg.bgColor,
        cfg.borderColor,
      )}
    >
      {cfg.label}
    </span>
  );
}

export function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="bg-surface-4/40 border border-white/5 rounded-[2rem] p-6 glass transition-premium hover:border-white/10">
      <div className={cn("text-3xl font-black tabular-nums tracking-tight", accent ?? "text-white")}>
        {value}
      </div>
      <div className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mt-1.5">{label}</div>
      {sub && <div className="text-[10px] text-muted-foreground/40 font-bold mt-1 uppercase">{sub}</div>}
    </div>
  );
}

/** Local EmptyState for ActorDetail panels — distinct from the global ui/EmptyState. */
export function LocalEmptyState({
  icon,
  message,
}: {
  icon: React.ReactNode;
  message: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <div className="text-violet-500/30">{icon}</div>
      <p className="text-muted-foreground text-sm">{message}</p>
    </div>
  );
}

export function ManagedViaMcp({ tools }: { tools: string[] }) {
  return (
    <div className="mt-4 bg-background border border-white/5 rounded-xl px-4 py-3">
      <p className="text-muted-foreground/40 text-xs font-medium uppercase tracking-wider mb-1.5">
        Managed via MCP
      </p>
      <p className="text-muted-foreground text-sm">
        Use{" "}
        {tools.map((t, i) => (
          <React.Fragment key={t}>
            <code className="text-violet-300 text-xs font-mono bg-violet-500/10 px-1 py-0.5 rounded">
              {t}
            </code>
            {i < tools.length - 1 ? ", " : ""}
          </React.Fragment>
        ))}{" "}
        from your MCP client.
      </p>
    </div>
  );
}

// ── TabBar ────────────────────────────────────────────────────────────────────

export function TabBar({
  active,
  onChange,
  counts,
  showHandoffs,
}: {
  active: Tab;
  onChange: (t: Tab) => void;
  counts: { workflows: number; log: number; handoffs: number };
  showHandoffs: boolean;
}) {
  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "summary", label: "Overview" },
    { id: "workflows", label: "Logic", count: counts.workflows },
    { id: "memory", label: "State" },
    { id: "budget", label: "Resources" },
    { id: "policies", label: "Rules" },
    { id: "log", label: "Telemetry", count: counts.log },
    ...(showHandoffs
      ? [{ id: "handoffs" as Tab, label: "Handoffs", count: counts.handoffs }]
      : []),
  ];

  return (
    <div className="flex items-center gap-2 p-1.5 bg-surface-3/40 border-b border-white/5 shrink-0 flex-wrap glass sticky top-0 z-20 px-8">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            "px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-premium flex items-center gap-2",
            active === t.id
              ? "bg-primary text-primary-foreground shadow-lg shadow-primary/20"
              : "text-muted-foreground hover:text-foreground hover:bg-white/5",
          )}
        >
          {t.label}
          {t.count !== undefined && t.count > 0 && (
            <span className={cn(
              "text-[9px] px-1.5 py-0.5 rounded-full font-black",
              active === t.id ? "bg-white/20 text-white" : "bg-surface-4 text-muted-foreground"
            )}>
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ── LogEntryRow ───────────────────────────────────────────────────────────────

export function LogEntryRow({ entry }: { entry: ActorActionLogEntry }) {
  const [expanded, setExpanded] = useState(false);
  const [output, setOutput] = useState<string | null>(null);
  const [loadingOutput, setLoadingOutput] = useState(false);

  const isExecutionEntry =
    entry.actionType.toLowerCase() === "workflow_executed" && entry.executionId;

  const handleExpand = async () => {
    if (expanded) { setExpanded(false); return; }
    setExpanded(true);
    if (output !== null || !entry.workflowId || !entry.executionId) return;
    setLoadingOutput(true);
    try {
      const res = await graphqlRequest<{
        workflowExecutionHistory: Array<{
          id: string;
          status: string;
          outputData: string | null;
          errorMessage: string | null;
          durationMs: number | null;
        }>;
      }>(
        `query ($wfId: UUID!, $p: PaginationInput) {
          workflowExecutionHistory(workflowId: $wfId, pagination: $p) {
            id status outputData errorMessage durationMs
          }
        }`,
        { wfId: entry.workflowId, p: { limit: 100 } },
      );
      const match = res.workflowExecutionHistory.find((e) => e.id === entry.executionId);
      if (match) {
        const text =
          match.outputData != null
            ? typeof match.outputData === "string"
              ? match.outputData
              : JSON.stringify(match.outputData, null, 2)
            : match.errorMessage
              ? `Error: ${match.errorMessage}`
              : "(no output)";
        setOutput(text);
      } else {
        setOutput("(execution not found)");
      }
    } catch {
      setOutput("(failed to load output)");
    } finally {
      setLoadingOutput(false);
    }
  };

  const icon = ACTION_ICONS[entry.actionType.toLowerCase()] ?? (
    <Activity className="w-3.5 h-3.5" />
  );

  return (
    <div className="flex items-start gap-4 px-5 py-3 hover:bg-[rgba(255,255,255,0.02)] transition-premium">
      <div className="w-7 h-7 rounded-lg bg-violet-500/10 flex items-center justify-center text-violet-400 text-xs shrink-0 mt-0.5">
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-white text-sm leading-snug">{humanizeLogEntry(entry)}</p>
        <div className="flex items-center gap-2 mt-0.5 flex-wrap">
          {entry.workflowId && (
            <span className="text-[10px] text-violet-400 font-mono">
              wf:{entry.workflowId.slice(0, 8)}
            </span>
          )}
          {entry.executionId && (
            <span className="text-[10px] text-sky-400 font-mono">
              ex:{entry.executionId.slice(0, 8)}
            </span>
          )}
          {isExecutionEntry && (
            <button
              onClick={handleExpand}
              className="text-[10px] text-muted-foreground/40 hover:text-violet-300 transition-premium flex items-center gap-0.5"
            >
              {expanded ? (
                <><ChevronUp className="w-3 h-3" />hide output</>
              ) : (
                <><ChevronDown className="w-3 h-3" />view output</>
              )}
            </button>
          )}
        </div>
        {expanded && (
          <div className="mt-2">
            {loadingOutput ? (
              <div className="flex items-center gap-2 text-muted-foreground/40 text-xs py-2">
                <Loader2 className="w-3 h-3 animate-spin" />
                Loading output…
              </div>
            ) : (
              <pre className="text-xs text-foreground bg-background border border-white/5 rounded-xl p-3 overflow-auto max-h-64 whitespace-pre-wrap break-words font-mono leading-relaxed">
                {(() => {
                  if (!output) return "(no output)";
                  try { return JSON.stringify(JSON.parse(output), null, 2); }
                  catch { return output; }
                })()}
              </pre>
            )}
          </div>
        )}
      </div>
      <time className="text-muted-foreground/40 text-[11px] shrink-0 mt-0.5">
        {relativeTime(entry.timestamp)}
      </time>
    </div>
  );
}
