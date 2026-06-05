import React, { useState, useCallback, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getWorkflowExecutionHistory,
  listActors,
  WorkflowExecution,
  subscribeWorkflowExecutions,
} from "../lib/graphqlClient";
import { useEffect } from "react";
import {
  useRetryExecutionMutation,
  useResumeWorkflowMutation,
} from "@/generated/graphql";
import { toast } from "sonner";
import { Dialog } from "@/components/ui/dialog";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { formatDistanceToNow } from "date-fns";
import {
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  ChevronRight,
  RefreshCw,
  Activity,
  Bot,
  Webhook,
  CalendarClock,
  RotateCcw,
  PlayCircle,
  Copy,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button, Badge } from "@/components/ui";

interface WorkflowExecutionHistoryProps {
  workflowId: string;
  workflowName?: string;
  onClose?: () => void;
}

function formatDuration(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60_000);
  const secs = Math.round((ms % 60_000) / 1000);
  return `${mins}m ${secs}s`;
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="w-4 h-4 text-success shrink-0" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-destructive shrink-0" />;
    case "running":
      return <Loader2 className="w-4 h-4 text-primary shrink-0 animate-spin" />;
    case "awaiting_approval":
      return <Clock className="w-4 h-4 text-warning shrink-0" />;
    default:
      return <Clock className="w-4 h-4 text-muted-foreground/40 shrink-0" />;
  }
}

function StatusPill({ status }: { status: string }) {
  const cls =
    {
      completed:
        "bg-success/10 text-success border-success/20 shadow-[0_0_15px_hsla(var(--success),0.15)]",
      failed:
        "bg-destructive/10 text-destructive border-destructive/20 shadow-[0_0_15px_hsla(var(--destructive),0.15)]",
      running:
        "bg-primary/10 text-primary border-primary/20 shadow-[0_0_15px_hsla(var(--primary),0.15)]",
      awaiting_approval:
        "bg-warning/10 text-warning border-warning/20 shadow-[0_0_15px_hsla(var(--warning),0.15)]",
      pending: "bg-warning/10 text-warning border-warning/20",
      timeout: "bg-warning/10 text-warning border-warning/20",
    }[status] ?? "bg-surface-4 text-muted-foreground/40 border-white/5";

  return (
    <span
      className={cn(
        "px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-[0.2em] border transition-premium",
        cls,
      )}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

function TriggerBadge({ triggerType }: { triggerType: string | null }) {
  if (!triggerType || triggerType === "manual") return null;
  const configs: Record<
    string,
    {
      label: string;
      cls: string;
      Icon: React.ComponentType<{ className?: string }>;
    }
  > = {
    actor_dispatch: {
      label: "ACTOR_LINK",
      cls: "text-violet-400 bg-violet-400/10 border-violet-400/20",
      Icon: Bot,
    },
    scheduled: {
      label: "SCHEDULED",
      cls: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
      Icon: CalendarClock,
    },
    webhook: {
      label: "WEBHOOK",
      cls: "text-blue-400 bg-blue-400/10 border-blue-400/20",
      Icon: Webhook,
    },
  };
  const cfg = configs[triggerType];
  if (!cfg)
    return (
      <span className="px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-[0.2em] border bg-surface-4 text-muted-foreground/40 border-white/5">
        {triggerType.replace(/_/g, " ")}
      </span>
    );
  const { label, cls, Icon } = cfg;
  return (
    <span
      className={cn(
        "flex items-center gap-2 px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-[0.2em] border transition-premium",
        cls,
      )}
    >
      <Icon className="w-3 h-3" />
      {label}
    </span>
  );
}

function ExecutionRow({
  exec,
  isExpanded,
  onToggle,
  agentName,
  onRetry,
  onResume,
  isRetrying,
  isResuming,
}: {
  exec: WorkflowExecution;
  isExpanded: boolean;
  onToggle: () => void;
  agentName?: string;
  onRetry?: (id: string) => void;
  onResume?: (id: string) => void;
  isRetrying?: boolean;
  isResuming?: boolean;
}) {
  const outputText = useMemo(() => {
    if (!exec.outputData) return null;
    try {
      return typeof exec.outputData === "string"
        ? JSON.stringify(JSON.parse(exec.outputData), null, 2)
        : JSON.stringify(exec.outputData, null, 2);
    } catch {
      return String(exec.outputData);
    }
  }, [exec.outputData]);

  return (
    <div
      className={cn(
        "group border border-white/5 bg-surface-3/30 rounded-[2rem] overflow-hidden backdrop-blur-3xl transition-premium shadow-2xl relative",
        isExpanded
          ? "border-primary/30 bg-surface-3/60"
          : "hover:bg-surface-3/50 hover:border-white/10",
      )}
    >
      {isExpanded && (
        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
      )}
      {/* Row header */}
      <button
        className="w-full flex items-center gap-6 text-xs p-6 transition-premium text-left focus:outline-none relative z-10"
        onClick={onToggle}
        aria-expanded={isExpanded}
      >
        <div className="shrink-0 flex items-center justify-center w-12 h-12 rounded-2xl bg-black/20 border border-white/5 group-hover:scale-110 transition-premium shadow-xl relative overflow-hidden">
          <div
            className={cn(
              "absolute inset-0 opacity-10 blur-xl",
              exec.status === "failed" ? "bg-destructive" : "bg-primary",
            )}
          />
          <StatusIcon status={exec.status} />
        </div>

        <div className="flex flex-col min-w-0 flex-1 gap-2">
          <div className="flex items-center gap-3">
            <StatusPill status={exec.status} />
            <TriggerBadge triggerType={exec.triggerType} />
          </div>
          <div className="flex items-center gap-4 text-muted-foreground/30 text-[10px] font-black uppercase tracking-widest truncate">
            <span className="flex items-center gap-2">
              <Clock size={12} />
              {formatDistanceToNow(new Date(exec.startedAt), {
                addSuffix: true,
              })}
            </span>
            {agentName && exec.triggerType === "actor_dispatch" && (
              <span className="flex items-center gap-2 text-violet-400/60">
                <Bot size={12} />
                {agentName}
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0 pr-2">
          <span className="text-[11px] text-white/60 font-black uppercase tracking-widest font-outfit">
            {formatDuration(exec.durationMs)}
          </span>
          <ChevronRight
            className={cn(
              "w-5 h-5 text-muted-foreground/20 shrink-0 transition-transform duration-500",
              isExpanded && "rotate-90 text-primary",
            )}
          />
        </div>
      </button>

      {/* Expand panel */}
      <div
        className={cn(
          "overflow-hidden transition-all duration-700 ease-in-out relative z-10",
          isExpanded ? "max-h-[800px] opacity-100" : "max-h-0 opacity-0",
        )}
      >
        <div className="px-8 pb-8 space-y-8 animate-in slide-in-from-top-4 duration-500">
          <div className="h-px bg-white/5 mx-[-2rem]" />

          {/* Action buttons */}
          {(onRetry || onResume) && (
            <div className="flex items-center gap-4">
              {onRetry &&
                (exec.status === "failed" || exec.status === "completed") && (
                  <Button
                    onClick={(e) => {
                      e.stopPropagation();
                      onRetry(exec.id);
                    }}
                    disabled={isRetrying}
                    className="h-11 px-6 text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl bg-violet-500/10 border border-violet-500/20 text-violet-400 hover:bg-violet-500/20 active:scale-95 transition-premium shadow-xl"
                  >
                    {isRetrying ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <RotateCcw className="w-4 h-4" />
                    )}
                    RETRY_EXECUTION
                  </Button>
                )}
              {onResume && exec.status === "awaiting_approval" && (
                <Button
                  onClick={(e) => {
                    e.stopPropagation();
                    onResume(exec.id);
                  }}
                  disabled={isResuming}
                  className="h-11 px-6 text-[10px] font-black uppercase tracking-[0.2em] rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 active:scale-95 transition-premium shadow-xl"
                >
                  {isResuming ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <PlayCircle className="w-4 h-4" />
                  )}
                  RESUME_PROTOCOL
                </Button>
              )}
            </div>
          )}

          {exec.errorMessage && (
            <div className="space-y-4">
              <label className="text-[10px] text-destructive uppercase tracking-[0.3em] font-black ml-1">
                Operational Fault
              </label>
              <div className="relative group/error">
                <div className="absolute -inset-1 bg-destructive/10 rounded-3xl blur opacity-30 group-hover/error:opacity-50 transition-premium" />
                <div className="relative p-6 bg-destructive/5 rounded-[2rem] border border-destructive/20 text-[12px] font-bold text-destructive shadow-2xl leading-relaxed">
                  <div className="flex items-center gap-3 mb-4 opacity-60">
                    <XCircle className="w-4 h-4" />
                    <span className="font-black uppercase tracking-widest text-[9px]">
                      CRITICAL_EXCEPTION
                    </span>
                  </div>
                  <div className="bg-black/40 p-4 rounded-2xl border border-destructive/10 font-mono">
                    {sanitizeErrorMessage(exec.errorMessage)}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <div className="flex items-center justify-between px-2">
              <p className="text-muted-foreground/30 text-[10px] font-black uppercase tracking-[0.3em] flex items-center gap-3">
                <Activity className="w-4 h-4 text-primary" />
                Telemetric Stream
              </p>
              {outputText && (
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(outputText);
                    toast.success("Output copied to clipboard");
                  }}
                  className="w-10 h-10 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-muted-foreground/40 hover:text-white transition-premium shadow-lg"
                  title="Copy Output"
                >
                  <Copy className="w-4 h-4" />
                </button>
              )}
            </div>
            {outputText ? (
              <div className="relative">
                <div className="absolute inset-0 bg-primary/5 rounded-[2rem] blur-3xl opacity-20 pointer-events-none" />
                <div className="relative p-6 bg-black/40 rounded-[2rem] border border-white/5 shadow-2xl group overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-20 pointer-events-none" />
                  <pre className="relative z-10 overflow-x-auto whitespace-pre-wrap max-h-96 text-[11px] font-mono text-foreground/70 custom-scrollbar selection:bg-primary/20 leading-relaxed p-2">
                    {outputText}
                  </pre>
                  <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.02),rgba(0,255,0,0.01),rgba(0,0,255,0.02))] bg-[length:100%_4px,3px_100%]" />
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 px-6 bg-black/20 rounded-[2rem] border border-white/5 border-dashed">
                <p className="text-muted-foreground/10 text-[10px] font-black uppercase tracking-[0.4em] italic">
                  NULL_TELEMETRY_RECORD
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export const WorkflowExecutionHistory = React.memo(
  function WorkflowExecutionHistory({
    workflowId,
    workflowName,
    onClose,
  }: WorkflowExecutionHistoryProps) {
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const [pendingId, setPendingId] = useState<string | null>(null);
    const queryClient = useQueryClient();

    const toggleExpanded = useCallback((id: string) => {
      setExpandedId((prev) => (prev === id ? null : id));
    }, []);

    const retryMutation = useRetryExecutionMutation({
      onMutate: ({ executionId }) => setPendingId(executionId),
      onSuccess: () => {
        toast.success("Execution retried");
        queryClient.invalidateQueries({
          queryKey: ["workflow-execution-history", workflowId],
        });
      },
      onError: () => toast.error("Failed to retry execution"),
      onSettled: () => setPendingId(null),
    });

    const resumeMutation = useResumeWorkflowMutation({
      onMutate: ({ executionId }) => setPendingId(executionId),
      onSuccess: () => {
        toast.success("Execution resumed");
        queryClient.invalidateQueries({
          queryKey: ["workflow-execution-history", workflowId],
        });
      },
      onError: () => toast.error("Failed to resume execution"),
      onSettled: () => setPendingId(null),
    });

    const { data: agentsData } = useQuery({
      queryKey: ["dashboard-agents"],
      queryFn: listActors,
      staleTime: 30_000,
    });

    const agentIdToName = useMemo(() => {
      const map: Record<string, string> = {};
      for (const a of agentsData ?? []) {
        map[a.id] = a.name;
      }
      return map;
    }, [agentsData]);

    const {
      data: history = [],
      isLoading,
      refetch,
      isFetching,
    } = useQuery({
      queryKey: ["workflow-execution-history", workflowId],
      queryFn: () => getWorkflowExecutionHistory(workflowId, 20),
      enabled: !!workflowId,
      staleTime: 0,
      // Polling removed in favor of real-time WebSocket subscriptions
    });

    const hasRunning = history.some((e) => e.status === "running");

    // ── Real-time Subscriptions ──────────────────────────────────────────────────

    useEffect(() => {
      if (!workflowId) return;

      const unsubscribe = subscribeWorkflowExecutions((event) => {
        // Only invalidate if the event pertains to this specific workflow context
        if (event.workflowId === workflowId) {
          queryClient.invalidateQueries({
            queryKey: ["workflow-execution-history", workflowId],
          });
        }
      });

      return unsubscribe;
    }, [workflowId, queryClient]);

    const content = (
      <div
        className={cn(
          "space-y-8 animate-in fade-in duration-700",
          onClose && "mt-0 p-2",
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4">
          <div className="flex items-center gap-6">
            <div
              className={cn(
                "flex items-center justify-center w-12 h-12 rounded-[1.25rem] bg-surface-3/60 border border-white/5 shadow-2xl transition-premium relative overflow-hidden",
                hasRunning &&
                  "border-primary/40 shadow-[0_0_25px_hsla(var(--primary),0.2)]",
              )}
            >
              <div
                className={cn(
                  "absolute inset-0 opacity-10 blur-xl",
                  hasRunning ? "bg-primary" : "bg-white/10",
                )}
              />
              {hasRunning ? (
                <Activity className="w-6 h-6 text-primary relative z-10" />
              ) : (
                <Clock className="w-6 h-6 text-muted-foreground/40 relative z-10" />
              )}
            </div>
            <div className="flex flex-col gap-1">
              <h4 className="text-md font-black text-white tracking-tight font-outfit uppercase">
                {onClose ? "Execution Registry" : "Execution Log"}
              </h4>
              <div className="flex items-center gap-3">
                <span className="text-[10px] text-muted-foreground/30 font-black uppercase tracking-[0.3em]">
                  {onClose ? workflowName : "Historical Telemetry"}
                </span>
                {hasRunning && (
                  <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full shadow-[0_0_15px_hsla(var(--primary),0.1)]">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                    <span className="text-[9px] font-black text-primary tracking-[0.2em] uppercase">
                      Capture_Active
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
          <Button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-3 text-[10px] font-black uppercase tracking-[0.2em] text-white/40 hover:text-white bg-white/5 hover:bg-white/10 px-6 h-12 rounded-2xl transition-premium active:scale-95 disabled:opacity-50 border border-white/5 shadow-2xl"
          >
            <RefreshCw
              className={cn("w-4 h-4", isFetching && "animate-spin")}
            />
            REFRESH_STREAM
          </Button>
        </div>

        {/* Content */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-24 gap-6 text-muted-foreground/20 animate-in fade-in duration-1000">
            <div className="relative">
              <Loader2 className="w-12 h-12 animate-spin text-primary/40" />
              <div className="absolute inset-0 blur-xl bg-primary/20 animate-pulse" />
            </div>
            <p className="text-[11px] font-black uppercase tracking-[0.4em]">
              Synchronizing Registry...
            </p>
          </div>
        ) : history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 px-10 text-center bg-white/[0.02] rounded-[3rem] border border-white/5 border-dashed">
            <div className="w-20 h-20 rounded-full bg-white/5 border border-white/5 flex items-center justify-center mb-6 opacity-40">
              <Clock className="w-8 h-8 text-muted-foreground/20" />
            </div>
            <p className="text-[11px] font-black text-muted-foreground/10 uppercase tracking-[0.4em]">
              NO_EXECUTION_RECORDS_FOUND
            </p>
          </div>
        ) : (
          <div className="grid gap-4 animate-in fade-in slide-in-from-bottom-6 duration-1000">
            {history.map((exec) => (
              <ExecutionRow
                key={exec.id}
                exec={exec}
                isExpanded={expandedId === exec.id}
                onToggle={() => toggleExpanded(exec.id)}
                agentName={
                  exec.actorId ? agentIdToName[exec.actorId] : undefined
                }
                onRetry={(id) => retryMutation.mutate({ executionId: id })}
                onResume={(id) => resumeMutation.mutate({ executionId: id })}
                isRetrying={retryMutation.isPending && pendingId === exec.id}
                isResuming={resumeMutation.isPending && pendingId === exec.id}
              />
            ))}
          </div>
        )}
      </div>
    );

    if (onClose) {
      return (
        <Dialog
          open={true}
          onClose={onClose}
          title="Telemetry Feed"
          className="max-w-2xl"
        >
          {content}
        </Dialog>
      );
    }

    return content;
  },
);
