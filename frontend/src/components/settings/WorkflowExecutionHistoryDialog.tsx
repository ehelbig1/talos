import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  History,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  RotateCcw,
  Play,
  Zap,
  Timer,
  Clock,
  Terminal,
  Webhook,
  CalendarClock,
  User,
  AlertCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { WorkflowExecution } from "@/generated/graphql";
import {
  useWorkflowExecutionHistoryQuery,
  useRetryExecutionMutation,
  useResumeWorkflowMutation,
} from "@/generated/graphql";
import { Dialog } from "@/components/ui/dialog";

interface WorkflowExecutionHistoryProps {
  workflowId: string;
  workflowName: string;
  onClose: () => void;
}

function formatRelativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.floor((ms % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}

function TriggerIcon({ type }: { type: string | null | undefined }) {
  const t = (type ?? "").toLowerCase();
  if (t === "webhook") return <Webhook className="w-3.5 h-3.5" />;
  if (t === "scheduled" || t === "cron")
    return <CalendarClock className="w-3.5 h-3.5" />;
  if (t === "manual" || t === "user") return <User className="w-3.5 h-3.5" />;
  if (t === "mcp") return <Terminal className="w-3.5 h-3.5" />;
  return <Zap className="w-3.5 h-3.5" />;
}

const STATUS_STYLES: Record<
  string,
  { badge: string; dot: string; label: string }
> = {
  completed: {
    badge: "bg-emerald-500/10 border-emerald-500/25 text-emerald-400",
    dot: "bg-emerald-400",
    label: "Completed",
  },
  failed: {
    badge: "bg-red-500/10 border-red-500/25 text-red-400",
    dot: "bg-red-400",
    label: "Failed",
  },
  running: {
    badge: "bg-indigo-500/10 border-indigo-500/25 text-indigo-400",
    dot: "bg-indigo-400",
    label: "Running",
  },
  paused: {
    badge: "bg-amber-500/10 border-amber-500/25 text-amber-400",
    dot: "bg-amber-400",
    label: "Paused",
  },
  cancelled: {
    badge: "bg-white/5 border-white/10 text-muted-foreground",
    dot: "bg-muted-foreground",
    label: "Cancelled",
  },
};

function statusStyle(status: string) {
  return STATUS_STYLES[status.toLowerCase()] ?? STATUS_STYLES["cancelled"];
}

export default function WorkflowExecutionHistoryDialog({
  workflowId,
  workflowName,
  onClose,
}: WorkflowExecutionHistoryProps) {
  const queryClient = useQueryClient();
  const [limit, setLimit] = useState(50);
  const [expandedErrors, setExpandedErrors] = useState<Set<string>>(new Set());
  const [confirmAction, setConfirmAction] = useState<{
    executionId: string;
    type: "retry" | "resume";
  } | null>(null);

  const { data, isLoading, refetch, isFetching } =
    useWorkflowExecutionHistoryQuery({ workflowId, limit });

  const executions = data?.workflowExecutionHistory ?? [];

  const invalidateKeys = () => {
    queryClient.invalidateQueries({
      queryKey: ["WorkflowExecutionHistory", { workflowId }],
    });
    queryClient.invalidateQueries({ queryKey: ["LatestWorkflowExecutions"] });
  };

  const retryMutation = useRetryExecutionMutation({
    onSuccess: () => {
      invalidateKeys();
      toast.success("Execution queued for retry");
      setConfirmAction(null);
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to retry execution"),
      );
    },
  });

  const resumeMutation = useResumeWorkflowMutation({
    onSuccess: () => {
      invalidateKeys();
      toast.success("Execution resumed");
      setConfirmAction(null);
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to resume execution"),
      );
    },
  });

  const handleConfirm = () => {
    if (!confirmAction) return;
    if (confirmAction.type === "retry") {
      retryMutation.mutate({ executionId: confirmAction.executionId });
    } else {
      resumeMutation.mutate({ executionId: confirmAction.executionId });
    }
  };

  const toggleError = (id: string) => {
    setExpandedErrors((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const actionPending = retryMutation.isPending || resumeMutation.isPending;

  return (
    <Dialog
      open={true}
      onClose={onClose}
      title="Execution History"
      className="max-w-3xl"
    >
      <div className="space-y-6 relative z-10 p-2 -mt-4">
        <div className="flex items-center justify-between mb-2">
          <p className="text-xs text-muted-foreground/60 font-medium truncate max-w-[360px]">
            {workflowName}
          </p>
          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className={cn(
              "w-8 h-8 flex items-center justify-center rounded-lg border border-white/5 text-muted-foreground hover:text-primary hover:border-primary/30 hover:bg-primary/5 transition-ui",
              isFetching && "animate-spin text-primary",
            )}
            title="Refresh"
            aria-label="Refresh execution history"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="max-h-[520px] overflow-y-auto custom-scrollbar border border-white/5 rounded-2xl bg-surface-4/20">
          {isLoading ? (
            <div className="p-20 flex flex-col items-center justify-center gap-4">
              <LoadingSpinner className="w-8 h-8 text-primary" />
              <p className="text-xs text-muted-foreground/60 font-semibold">
                Loading History...
              </p>
            </div>
          ) : executions.length === 0 ? (
            <div className="p-20 flex flex-col items-center justify-center gap-4 opacity-20">
              <div className="w-14 h-14 rounded-full bg-surface-3/60 border border-white/5 flex items-center justify-center text-muted-foreground">
                <History size={28} />
              </div>
              <p className="text-xs font-semibold">No executions recorded</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-white/[0.02] border-b border-white/5">
                    <th className="px-6 py-4 text-2xs font-semibold text-muted-foreground/70">
                      Status
                    </th>
                    <th className="px-6 py-4 text-2xs font-semibold text-muted-foreground/70">
                      Trigger
                    </th>
                    <th className="px-6 py-4 text-2xs font-semibold text-muted-foreground/70">
                      Timestamp
                    </th>
                    <th className="px-6 py-4 text-2xs font-semibold text-muted-foreground/70">
                      Duration
                    </th>
                    <th className="px-6 py-4 text-right text-2xs font-semibold text-muted-foreground/70">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {executions.map((exec: WorkflowExecution) => {
                    const style = statusStyle(exec.status);
                    const statusLower = exec.status.toLowerCase();
                    const isErrorExpanded = expandedErrors.has(exec.id);
                    const canRetry =
                      statusLower === "failed" || statusLower === "cancelled";
                    const canResume = statusLower === "paused";

                    return (
                      <React.Fragment key={exec.id}>
                        <tr className="group hover:bg-primary/[0.015] transition-ui">
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-2">
                              <span
                                className={cn(
                                  "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-2xs font-semibold uppercase tracking-wider",
                                  style.badge,
                                )}
                              >
                                <span
                                  className={cn(
                                    "w-1 h-1 rounded-full shrink-0",
                                    style.dot,
                                  )}
                                />
                                {style.label}
                              </span>
                              {exec.errorMessage && (
                                <button
                                  type="button"
                                  onClick={() => toggleError(exec.id)}
                                  className="text-muted-foreground/70 hover:text-destructive transition-ui"
                                  title="Toggle error details"
                                >
                                  {isErrorExpanded ? (
                                    <ChevronDown className="w-3 h-3" />
                                  ) : (
                                    <ChevronRight className="w-3 h-3" />
                                  )}
                                </button>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-1.5 text-xs font-bold text-muted-foreground/60">
                              <TriggerIcon type={exec.triggerType} />
                              <span>{exec.triggerType ?? "unknown"}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-1.5 text-xs font-bold text-muted-foreground/60 whitespace-nowrap">
                              <Clock className="w-3 h-3 text-muted-foreground/50" />
                              {formatRelativeTime(exec.startedAt)}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-1.5 text-xs font-bold text-muted-foreground/60">
                              <Timer className="w-3 h-3 text-muted-foreground/50" />
                              {formatDuration(exec.durationMs)}
                            </div>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {canRetry && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() =>
                                    setConfirmAction({
                                      executionId: exec.id,
                                      type: "retry",
                                    })
                                  }
                                  className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-primary hover:bg-primary/10 h-7 px-3 font-semibold transition-ui text-2xs gap-1.5"
                                >
                                  <RotateCcw className="w-3 h-3" />
                                  Retry
                                </Button>
                              )}
                              {canResume && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() =>
                                    setConfirmAction({
                                      executionId: exec.id,
                                      type: "resume",
                                    })
                                  }
                                  className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-warning hover:bg-warning/10 h-7 px-3 font-semibold transition-ui text-2xs gap-1.5"
                                >
                                  <Play className="w-3 h-3" />
                                  Resume
                                </Button>
                              )}
                            </div>
                          </td>
                        </tr>
                        {exec.errorMessage && isErrorExpanded && (
                          <tr>
                            <td
                              colSpan={5}
                              className="px-6 pb-4 bg-destructive/[0.02]"
                            >
                              <div className="flex items-start gap-2.5 px-6 py-4 bg-destructive/5 border border-destructive/15 rounded-2xl">
                                <AlertCircle className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
                                <pre className="text-xs text-destructive/80 font-mono whitespace-pre-wrap break-all leading-relaxed font-bold">
                                  {sanitizeErrorMessage(
                                    exec.errorMessage || "",
                                  )}
                                </pre>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {executions.length >= limit && (
          <div className="flex justify-center">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setLimit((prev) => prev + 50)}
              className="text-muted-foreground/70 hover:text-primary hover:bg-primary/5 font-semibold text-2xs gap-1.5 h-10 px-8 rounded-2xl border border-white/5 transition-ui"
            >
              <ChevronDown className="w-3 h-3" />
              Load more
            </Button>
          </div>
        )}
      </div>

      {confirmAction && (
        <Dialog
          open={true}
          onClose={() => setConfirmAction(null)}
          title={
            confirmAction.type === "retry"
              ? "Initialize Retry"
              : "Initialize Resume"
          }
          className="max-w-sm"
        >
          <div className="p-2 text-center space-y-6">
            <div
              className={cn(
                "w-16 h-16 rounded-2xl flex items-center justify-center mx-auto border",
                confirmAction.type === "retry"
                  ? "bg-primary/10 border-primary/20 text-primary"
                  : "bg-warning/10 border-warning/20 text-warning",
              )}
            >
              {confirmAction.type === "retry" ? (
                <RotateCcw size={28} />
              ) : (
                <Play size={28} />
              )}
            </div>
            <div>
              <p className="text-sm text-muted-foreground/60 leading-relaxed">
                {confirmAction.type === "retry"
                  ? "A new run will start with the original trigger input."
                  : "The paused run will continue from its last checkpoint."}
              </p>
            </div>
            <div className="flex items-center gap-4 pt-4">
              <Button
                variant="ghost"
                onClick={() => setConfirmAction(null)}
                className="flex-1 text-sm font-semibold h-12 rounded-2xl"
              >
                Cancel
              </Button>
              <Button
                onClick={handleConfirm}
                disabled={actionPending}
                className={cn(
                  "flex-1 text-sm font-semibold h-12 rounded-2xl transition-ui border border-white/10",
                  confirmAction.type === "retry"
                    ? "bg-primary hover:bg-primary/90"
                    : "bg-warning hover:bg-warning/90 text-background",
                )}
              >
                {actionPending ? (
                  <div className="flex items-center gap-2">
                    <LoadingSpinner className="w-4 h-4" />
                    <span>Working…</span>
                  </div>
                ) : (
                  "Confirm"
                )}
              </Button>
            </div>
          </div>
        </Dialog>
      )}
    </Dialog>
  );
}
