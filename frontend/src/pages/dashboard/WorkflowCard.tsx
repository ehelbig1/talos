import {
  Bot,
  Calendar,
  Play,
  History,
  GitBranch,
  ArrowRightCircle,
  Trash2,
  Pencil,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { relativeTime } from "@/lib/formatTime";
import { getFixSuggestion } from "@/lib/fixSuggestions";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import type { WorkflowRunStatus } from "@/store/executionStore";

export interface Workflow {
  id: string;
  name: string;
  actorId?: string | null;
  /** Counted by the server; null when the stored graph could not be read. */
  nodeCount: number | null;
  edgeCount: number | null;
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

/**
 * One workflow on the dashboard. The card answers three questions in order:
 * what is it, how did it last go, when does it run next. Everything else is
 * an action in the footer.
 */
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
  const nodes = workflow.nodeCount ?? "—";
  const edges = workflow.edgeCount ?? "—";
  const isRunning = runStatus?.status === "running";

  const statusLabel = !runStatus
    ? "Never run"
    : runStatus.status === "success"
      ? "Succeeded"
      : runStatus.status === "failed"
        ? "Failed"
        : "Running";

  const statusColorClass = !runStatus
    ? "bg-white/5 text-muted-foreground border-white/5"
    : runStatus.status === "success"
      ? "bg-success/10 text-success border-success/20"
      : runStatus.status === "failed"
        ? "bg-destructive/10 text-destructive border-destructive/20"
        : "bg-primary/10 text-primary border-primary/20";

  const fixSuggestion = runStatus?.error
    ? getFixSuggestion(runStatus.error)
    : undefined;

  const actionButton =
    "flex items-center justify-center gap-2 h-9 rounded-lg text-xs font-medium transition-premium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30";

  return (
    <div
      className={cn(
        "group relative flex flex-col gap-5 p-6 rounded-2xl bg-surface-3/60 border border-white/10 transition-premium hover:border-white/20",
        isRunning && "ring-1 ring-primary/30",
      )}
    >
      {/* Name, status, run */}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1 space-y-2">
          <h3
            className="text-base font-semibold text-white truncate leading-tight font-outfit"
            title={workflow.name}
          >
            {workflow.name}
          </h3>

          <div className="flex items-center gap-2 flex-wrap">
            <span
              className={cn(
                "inline-flex items-center gap-1.5 px-2 py-0.5 text-2xs font-medium rounded-md border",
                statusColorClass,
              )}
            >
              {isRunning && <Loader2 className="w-3 h-3 animate-spin" />}
              {statusLabel}
            </span>

            {actorName && (
              <span
                className="inline-flex items-center gap-1.5 px-2 py-0.5 text-2xs font-medium text-primary bg-primary/10 rounded-md border border-primary/15"
                title="Runs as this actor"
              >
                <Bot className="w-3 h-3" />
                {actorName}
              </span>
            )}
          </div>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onRun();
          }}
          className={cn(
            "w-10 h-10 shrink-0 flex items-center justify-center rounded-xl transition-premium active:scale-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30",
            isRunning
              ? "bg-surface-4/60 text-muted-foreground cursor-not-allowed border border-white/5"
              : "bg-primary text-white hover:bg-primary/90",
          )}
          disabled={isRunning}
          title={isRunning ? "Running" : "Run now"}
          aria-label={isRunning ? "Running" : "Run now"}
        >
          <Play className="w-4 h-4" fill="currentColor" />
        </button>
      </div>

      {/* Facts */}
      <dl className="space-y-1.5 text-xs text-muted-foreground">
        <div className="flex items-center gap-2">
          <dt className="sr-only">Last run</dt>
          <dd>
            {runStatus ? (
              <>
                Last run{" "}
                <span className="text-foreground/80">
                  {relativeTime(runStatus.runAt)}
                </span>
              </>
            ) : (
              "Not run yet"
            )}
          </dd>
          <span aria-hidden="true">·</span>
          <dt className="sr-only">Size</dt>
          <dd className="tabular-nums">
            {nodes} nodes, {edges} edges
          </dd>
        </div>

        {schedule && (
          <div
            className={cn(
              "flex items-center gap-2",
              !schedule.isEnabled && "text-muted-foreground/60",
            )}
          >
            <Calendar className="w-3.5 h-3.5 shrink-0" />
            <dt className="sr-only">Schedule</dt>
            <dd className="flex items-center gap-2 min-w-0">
              <code className="font-mono text-foreground/80 truncate">
                {schedule.cronExpression}
              </code>
              {schedule.isEnabled ? (
                schedule.nextTriggerAt && (
                  <span className="truncate">
                    next {relativeTime(schedule.nextTriggerAt)}
                  </span>
                )
              ) : (
                <span>paused</span>
              )}
            </dd>
          </div>
        )}
      </dl>

      {/* Last failure */}
      {runStatus?.status === "failed" && runStatus.error && (
        <div className="p-3 rounded-xl bg-destructive/5 border border-destructive/15 space-y-1.5">
          <p className="text-xs text-destructive leading-relaxed line-clamp-2 break-words">
            {sanitizeErrorMessage(runStatus.error)}
          </p>
          {fixSuggestion && (
            <p className="flex items-start gap-1.5 text-xs text-warning">
              <ArrowRightCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
              <span>{fixSuggestion}</span>
            </p>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 mt-auto pt-4 border-t border-white/5">
        <button
          onClick={(e) => {
            e.stopPropagation();
            onHistory();
          }}
          className={cn(
            actionButton,
            "flex-1 px-3 bg-white/5 border border-white/5 text-muted-foreground hover:text-white hover:bg-white/10",
          )}
          title="Run history"
        >
          <History className="w-4 h-4" />
          Runs
        </button>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onVersions();
          }}
          className={cn(
            actionButton,
            "flex-1 px-3 bg-white/5 border border-white/5 text-muted-foreground hover:text-white hover:bg-white/10",
          )}
          title="Versions"
        >
          <GitBranch className="w-4 h-4" />
          Versions
        </button>

        <button
          onClick={onEdit}
          className={cn(
            actionButton,
            "w-9 bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20",
          )}
          title="Open in editor"
          aria-label="Open in editor"
        >
          <Pencil className="w-4 h-4" />
        </button>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          className={cn(
            actionButton,
            "w-9 text-muted-foreground hover:text-destructive hover:bg-destructive/10 border border-transparent hover:border-destructive/20",
          )}
          title="Delete workflow"
          aria-label="Delete workflow"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
