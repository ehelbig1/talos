import {
  Bot,
  Activity,
  Share2,
  Calendar,
  Play,
  History,
  GitBranch,
  ArrowRightCircle,
  Trash2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { relativeTime } from "@/lib/formatTime";
import { getFixSuggestion } from "@/lib/fixSuggestions";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import type { WorkflowRunStatus } from "@/store/executionStore";

export interface Workflow {
  id: string;
  name: string;
  graphJson: string;
  actorId?: string | null;
}

export interface WorkflowSchedule {
  cronExpression: string;
  isEnabled: boolean;
  nextTriggerAt?: string | null;
}

export interface WorkflowCardProps {
  workflow: Workflow;
  runStatus: WorkflowRunStatus | undefined;
  onEdit: () => void;
  onRun: () => void;
  onHistory: () => void;
  onVersions: () => void;
  onDelete: () => void;
  schedule?: WorkflowSchedule;
  actorName?: string;
}

function parseNodeCount(graphJson: string): { nodes: number; edges: number } {
  try {
    const g = JSON.parse(graphJson);
    return {
      nodes: g.nodes?.length ?? 0,
      edges: g.edges?.length ?? 0,
    };
  } catch {
    return { nodes: 0, edges: 0 };
  }
}

export default function WorkflowCard({
  workflow,
  runStatus,
  onEdit,
  onRun,
  onHistory,
  onVersions,
  onDelete,
  schedule,
  actorName,
}: WorkflowCardProps) {
  const { nodes, edges } = parseNodeCount(workflow.graphJson);
  const isRunning = runStatus?.status === "running";

  const statusLabel = !runStatus
    ? "Idle"
    : runStatus.status === "success"
      ? "Operational"
      : runStatus.status === "failed"
        ? "Failure"
        : "Executing";

  const statusColorClass = !runStatus
    ? "bg-white/5 text-muted-foreground/40 border-white/5"
    : runStatus.status === "success"
      ? "bg-success/5 text-success border-success/20 shadow-[0_0_15px_hsla(var(--success),0.1)]"
      : runStatus.status === "failed"
        ? "bg-destructive/5 text-destructive border-destructive/20 shadow-[0_0_15px_hsla(var(--destructive),0.1)]"
        : "bg-primary/5 text-primary border-primary/20 animate-status-pulse shadow-[0_0_15px_hsla(var(--primary),0.1)]";

  const fixSuggestion = runStatus?.error
    ? getFixSuggestion(runStatus.error)
    : undefined;

  return (
    <div
      className={cn(
        "group relative flex flex-col gap-6 p-7 rounded-[2.5rem] bg-surface-3/40 border border-white/10 backdrop-blur-3xl transition-premium hover:border-primary/20 hover:scale-[1.02] active:scale-[0.98] shadow-2xl overflow-hidden glass gpu",
        isRunning && "ring-1 ring-primary/30"
      )}
    >
      {/* Decorative background glow */}
      <div className="absolute -top-16 -right-16 w-32 h-32 bg-primary/5 blur-[50px] group-hover:bg-primary/10 transition-premium" />

      {/* Header & Status */}
      <div className="flex items-start justify-between gap-5 relative z-10">
        <div className="space-y-2 flex-1 min-w-0">
          <div className="flex items-center gap-3">
            {isRunning && (
              <div className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary shadow-[0_0_10px_hsla(var(--primary),0.8)]" />
              </div>
            )}
            <h3 className="text-xl font-black text-white tracking-tighter truncate leading-tight font-outfit uppercase">
              {workflow.name}
            </h3>
          </div>
          
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn(
              "px-3 py-1 text-[9px] font-black uppercase tracking-[0.2em] rounded-lg border transition-premium",
              statusColorClass
            )}>
              {statusLabel}
            </span>
            
            {actorName && (
              <div className="flex items-center gap-2 px-3 py-1 text-[9px] font-black uppercase tracking-[0.2em] text-primary/60 bg-primary/5 rounded-lg border border-primary/10 shadow-sm transition-premium hover:border-primary/30">
                <Bot className="w-3 h-3" />
                <span>{actorName}</span>
              </div>
            )}
          </div>
        </div>

        <button
          onClick={(e) => { e.stopPropagation(); onRun(); }}
          className={cn(
            "w-12 h-12 flex items-center justify-center rounded-2xl transition-premium shadow-2xl active:scale-90 relative group/run overflow-hidden",
            isRunning 
              ? "bg-surface-4/60 text-primary cursor-not-allowed border border-primary/20" 
              : "bg-primary text-white hover:bg-primary/90 hover:scale-110 border border-white/10"
          )}
          disabled={isRunning}
          title="Manual Trigger"
        >
          <div className="absolute inset-0 bg-white/20 opacity-0 group-hover/run:opacity-100 transition-premium pointer-events-none" />
          <Play className={cn("w-5 h-5 relative z-10", isRunning && "animate-spin-slow")} fill="currentColor" />
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 gap-4 relative z-10">
        <div className="flex items-center gap-3 px-4 py-3 rounded-2xl bg-surface-2/40 border border-white/5 shadow-sm group/metric hover:border-success/30 transition-premium glass-light">
          <div className="p-1.5 rounded-lg bg-success/5 border border-success/10 group-hover/metric:bg-success/20 transition-premium">
            <Activity className="w-4 h-4 text-success/60 group-hover/metric:text-success" />
          </div>
          <div className="flex flex-col">
            <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest leading-none mb-1">Nodes</span>
            <span className="text-sm font-black text-white font-outfit leading-none">{nodes}</span>
          </div>
        </div>
        <div className="flex items-center gap-3 px-4 py-3 rounded-2xl bg-surface-2/40 border border-white/5 shadow-sm group/metric hover:border-primary/30 transition-premium glass-light">
          <div className="p-1.5 rounded-lg bg-primary/5 border border-primary/10 group-hover/metric:bg-primary/20 transition-premium">
            <Share2 className="w-4 h-4 text-primary/60 group-hover/metric:text-primary" />
          </div>
          <div className="flex flex-col">
            <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest leading-none mb-1">Edges</span>
            <span className="text-sm font-black text-white font-outfit leading-none">{edges}</span>
          </div>
        </div>
      </div>

      {/* Operational State */}
      <div className="space-y-4 relative z-10">
        {schedule && (
          <div className={cn(
            "flex items-center gap-4 p-4 rounded-2xl border transition-premium glass-light",
            schedule.isEnabled 
              ? "bg-warning/5 border-warning/20 text-warning/80 shadow-lg shadow-warning/5" 
              : "bg-white/5 border-white/5 text-muted-foreground/30"
          )}>
            <div className="p-2 rounded-xl bg-white/5 border border-white/10">
                <Calendar className="w-4 h-4 shrink-0" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-[9px] font-black uppercase tracking-[0.2em] leading-tight mb-1 opacity-60">
                Scheduled Trigger
              </span>
              <div className="flex items-center gap-3 truncate">
                <span className="text-[11px] font-mono font-black text-white/80">{schedule.cronExpression}</span>
                {schedule.isEnabled && schedule.nextTriggerAt && (
                  <span className="text-[9px] font-bold text-muted-foreground/40 uppercase tracking-widest">
                    Next {relativeTime(schedule.nextTriggerAt)}
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between text-[10px] font-black text-muted-foreground/20 uppercase tracking-[0.2em] px-1">
          <div className="flex items-center gap-3">
            <div className={cn("w-2 h-2 rounded-full", runStatus ? "bg-primary/40 shadow-[0_0_8px_hsla(var(--primary),0.3)]" : "bg-white/5")} />
            {runStatus ? (
              <span className="text-muted-foreground/40">Last active <span className="text-white/40">{relativeTime(runStatus.runAt)}</span></span>
            ) : (
              <span>No operational telemetry</span>
            )}
          </div>
        </div>
      </div>

      {/* Failure Diagnostics */}
      {runStatus?.status === "failed" && runStatus.error && (
        <div className="p-4 rounded-2xl bg-destructive/5 border border-destructive/10 animate-in fade-in zoom-in-95 glass-dark relative z-10">
          <p className="text-[11px] text-destructive/80 font-bold leading-relaxed line-clamp-2 uppercase tracking-wide mb-2">
            {sanitizeErrorMessage(runStatus.error)}
          </p>
          {fixSuggestion && (
            <div className="flex items-center gap-2 text-[9px] text-warning font-black uppercase tracking-[0.2em]">
              <ArrowRightCircle className="w-3 h-3" />
              <span>{fixSuggestion}</span>
            </div>
          )}
        </div>
      )}

      {/* Quick Actions Footer */}
      <div className="flex items-center gap-3 mt-auto pt-6 border-t border-white/5 relative z-10">
        <button
          onClick={(e) => { e.stopPropagation(); onHistory(); }}
          className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl bg-surface-4/40 border border-white/5 text-muted-foreground/60 hover:text-white hover:bg-surface-4 hover:border-white/20 transition-premium shadow-xl glass-light group/log active:scale-95"
          title="Telemetry History"
        >
          <History className="w-4 h-4 transition-transform group-hover/log:rotate-12" />
          <span className="text-[10px] font-black uppercase tracking-[0.2em]">Logs</span>
        </button>
        
        <button
          onClick={(e) => { e.stopPropagation(); onVersions(); }}
          className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl bg-surface-4/40 border border-white/5 text-muted-foreground/60 hover:text-white hover:bg-surface-4 hover:border-white/20 transition-premium shadow-xl glass-light group/ver active:scale-95"
          title="Snapshot Registry"
        >
          <GitBranch className="w-4 h-4 transition-transform group-hover/ver:scale-110" />
          <span className="text-[10px] font-black uppercase tracking-[0.2em]">Snap</span>
        </button>

        <div className="flex gap-2">
          <button
            onClick={onEdit}
            className="w-10 h-10 flex items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 hover:border-primary/40 transition-premium shadow-xl active:scale-90"
            title="Configure Architecture"
          >
            <Activity className="w-4.5 h-4.5" />
          </button>
          
          <button
            onClick={(e) => { e.stopPropagation(); onDelete(); }}
            className="w-10 h-10 flex items-center justify-center rounded-xl text-muted-foreground/40 hover:text-destructive hover:bg-destructive/10 hover:border-destructive/20 border border-transparent transition-premium active:scale-90"
            title="Decommission"
          >
            <Trash2 className="w-4.5 h-4.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
