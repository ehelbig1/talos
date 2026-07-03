import React from "react";
import { sanitizeErrorMessage } from "../lib/sanitize";
import { gql } from "../lib/graphqlClient";
import type {
  GetModuleExecutionHistoryQuery,
  GetModuleExecutionLogsQuery,
} from "../generated/graphql";
import {
  useGetModuleExecutionHistoryQuery,
  useGetModuleExecutionLogsQuery,
} from "../generated/graphql";
import { formatDistanceToNow } from "date-fns";
import {
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  ChevronRight,
  History as HistoryIcon,
  RefreshCw,
  Activity,
  AlertTriangle,
} from "lucide-react";
import { cn, formatDuration } from "@/lib/utils";
import { Button } from "@/components/ui";

// Define queries for codegen to pick up
const _GET_MODULE_EXECUTION_HISTORY = gql`
  query GetModuleExecutionHistory(
    $moduleId: UUID!
    $pagination: PaginationInput
  ) {
    moduleExecutionHistory(moduleId: $moduleId, pagination: $pagination) {
      id
      status
      durationMs
      startedAt
      errorMessage
      outputData
    }
  }
`;

const _GET_MODULE_EXECUTION_LOGS = gql`
  query GetModuleExecutionLogs($executionId: UUID!) {
    moduleExecutionLogs(executionId: $executionId) {
      id
      level
      message
      createdAt
      metadata
    }
  }
`;

type GqlModuleExecution = NonNullable<
  GetModuleExecutionHistoryQuery["moduleExecutionHistory"]
>[number];
type GqlModuleExecutionLog = NonNullable<
  GetModuleExecutionLogsQuery["moduleExecutionLogs"]
>[number];

interface ExecutionHistoryProps {
  moduleId: string;
}

interface ModuleExecution extends GqlModuleExecution {
  retryCount?: number;
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="w-4 h-4 text-success" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-destructive" />;
    case "running":
      return <Loader2 className="w-4 h-4 text-primary animate-spin" />;
    case "awaiting_approval":
      return <Clock className="w-4 h-4 text-warning" />;
    case "timeout":
      return <AlertTriangle className="w-4 h-4 text-warning" />;
    default:
      return <Clock className="w-4 h-4 text-muted-foreground/20" />;
  }
}

function StatusPill({ status }: { status: string }) {
  const configs: Record<string, string> = {
    completed:
      "bg-success/5 text-success border-success/10 shadow-[0_0_10px_hsla(var(--success),0.1)]",
    failed:
      "bg-destructive/5 text-destructive border-destructive/10 shadow-[0_0_10px_hsla(var(--destructive),0.1)]",
    running:
      "bg-primary/5 text-primary border-primary/10 shadow-[0_0_10px_hsla(var(--primary),0.1)]",
    awaiting_approval:
      "bg-warning/5 text-warning border-warning/10 shadow-[0_0_10px_hsla(var(--warning),0.1)]",
    pending: "bg-warning/5 text-warning border-warning/10",
    timeout: "bg-warning/5 text-warning border-warning/10",
  };

  const cls =
    configs[status] ?? "bg-surface-4 text-muted-foreground/20 border-white/5";

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

const LogItem = React.memo(({ log }: { log: GqlModuleExecutionLog }) => (
  <div className="flex gap-4 group/log py-1">
    <span className="text-[10px] font-black font-mono text-muted-foreground/20 group-hover/log:text-primary transition-premium shrink-0 pt-0.5">
      {new Date(log.createdAt).toLocaleTimeString([], {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })}
    </span>
    <span
      className={cn(
        "break-words text-[11px] font-mono leading-relaxed selection:bg-primary/20",
        log.level === "error"
          ? "text-destructive/80"
          : log.level === "warn"
            ? "text-warning/80"
            : "text-white/60 group-hover/log:text-white/90 transition-colors",
      )}
    >
      {log.message}
    </span>
  </div>
));
LogItem.displayName = "LogItem";

/** Per-row component — owns its own log query so logs never bleed across rows */
const ExecutionItem = React.memo(
  ({
    exec,
    isExpanded,
    onToggle,
  }: {
    exec: ModuleExecution;
    isExpanded: boolean;
    onToggle: (id: string) => void;
  }) => {
    const handleToggle = React.useCallback(
      () => onToggle(exec.id),
      [onToggle, exec.id],
    );

    // Only fetch logs when this row is expanded
    const { data: logsData, isLoading: loadingLogs } =
      useGetModuleExecutionLogsQuery(
        {
          executionId: exec.id,
        },
        {
          enabled: isExpanded,
          staleTime: 30_000,
        },
      );
    const logs = logsData?.moduleExecutionLogs ?? [];

    const outputText = React.useMemo(() => {
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
          "group border border-white/5 bg-surface-1/40 rounded-2xl overflow-hidden backdrop-blur-3xl transition-premium shadow-xl",
          isExpanded
            ? "border-primary/20 ring-1 ring-primary/10 bg-surface-2/60"
            : "hover:bg-surface-2/40 hover:border-white/10",
        )}
      >
        {/* Row header */}
        <button
          className="w-full flex items-center gap-5 p-4 text-xs transition-premium text-left focus:outline-none"
          onClick={handleToggle}
          aria-expanded={isExpanded}
        >
          <ChevronRight
            className={cn(
              "w-4 h-4 text-muted-foreground/20 shrink-0 transition-transform duration-500",
              isExpanded && "rotate-90 text-primary",
            )}
          />

          <div className="shrink-0 flex items-center justify-center w-10 h-10 rounded-2xl bg-surface-4 border border-white/5 group-hover:scale-110 transition-premium shadow-lg relative">
            <div className="absolute inset-0 bg-primary/5 rounded-full blur-xl opacity-0 group-hover:opacity-50 transition-premium" />
            <StatusIcon status={exec.status} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-1">
              <StatusPill status={exec.status} />
              {(exec.retryCount ?? 0) > 0 && (
                <span className="text-[9px] font-black uppercase tracking-widest text-warning px-2 py-0.5 rounded-lg bg-warning/5 border border-warning/10">
                  RETRY_SEQUENCE: {exec.retryCount}
                </span>
              )}
            </div>
            <div className="flex items-center gap-4 text-[10px] font-bold text-white/20 tracking-tight">
              <span className="truncate max-w-[200px] group-hover:text-white/40 transition-premium">
                {formatDistanceToNow(new Date(exec.startedAt), {
                  addSuffix: true,
                })}
              </span>
              <div className="w-1 h-1 rounded-full bg-white/5" />
              <span className="font-mono uppercase tracking-[0.2em] group-hover:text-primary/40 transition-premium">
                {formatDuration(exec.durationMs ?? null)}
              </span>
            </div>
          </div>

          <div className="shrink-0 opacity-0 group-hover:opacity-100 transition-premium translate-x-4 group-hover:translate-x-0">
            <Activity className="w-4 h-4 text-primary/40" />
          </div>
        </button>

        {/* Expand panel */}
        <div
          className={cn(
            "overflow-hidden transition-premium duration-700 ease-in-out",
            isExpanded ? "max-h-[800px] opacity-100" : "max-h-0 opacity-0",
          )}
        >
          <div className="p-8 border-t border-white/5 bg-surface-3/40 backdrop-blur-3xl space-y-8">
            {exec.errorMessage && (
              <div className="relative group/error">
                <div className="absolute -inset-1 bg-destructive/10 rounded-2xl blur opacity-0 group-hover/error:opacity-100 transition-premium" />
                <div className="relative p-5 bg-destructive/5 rounded-2xl border border-destructive/20 text-[11px] font-bold text-destructive shadow-inner leading-relaxed animate-in fade-in slide-in-from-top-2">
                  <div className="flex items-center gap-3 mb-2">
                    <XCircle className="w-4 h-4" />
                    <span className="font-black uppercase tracking-[0.3em] text-[9px]">
                      CRITICAL_FAULT_TRACE
                    </span>
                  </div>
                  {sanitizeErrorMessage(exec.errorMessage ?? "")}
                </div>
              </div>
            )}

            {/* Output */}
            <div className="space-y-4">
              <h5 className="text-muted-foreground/30 text-[10px] font-black uppercase tracking-[0.3em] flex items-center gap-3 ml-1">
                <div className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_10px_hsla(var(--primary),0.5)]" />
                Diagnostic Payload
              </h5>
              <div className="relative group/output">
                <div className="absolute -inset-0.5 bg-primary/5 rounded-2xl opacity-0 group-hover/output:opacity-100 transition-premium pointer-events-none" />
                {outputText ? (
                  <pre
                    tabIndex={0}
                    className="p-6 bg-surface-4/60 rounded-2xl border border-white/5 overflow-x-auto whitespace-pre-wrap max-h-64 text-[11px] font-mono text-white/80 focus:outline-none focus:ring-2 focus:ring-primary/20 shadow-inner custom-scrollbar relative z-10 leading-relaxed selection:bg-primary/30"
                  >
                    {outputText}
                  </pre>
                ) : (
                  <div className="p-8 bg-surface-4/40 rounded-2xl border border-white/5 border-dashed flex items-center justify-center">
                    <p className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/20 italic">
                      Null Response Buffer
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Logs */}
            <div className="space-y-4">
              <h5 className="text-muted-foreground/30 text-[10px] font-black uppercase tracking-[0.3em] flex items-center gap-3 ml-1">
                <div className="w-1.5 h-1.5 rounded-full bg-primary/40 shadow-[0_0_10px_hsla(var(--primary),0.2)]" />
                Telemetry Stream
              </h5>
              <div
                tabIndex={0}
                className="p-6 bg-surface-4/60 rounded-2xl border border-white/5 font-mono space-y-2 max-h-64 overflow-y-auto focus:outline-none focus:ring-2 focus:ring-primary/20 shadow-inner custom-scrollbar relative z-10 animate-in fade-in slide-in-from-bottom-2"
              >
                {loadingLogs ? (
                  <div className="flex items-center gap-4 text-muted-foreground/20 py-4">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span className="text-[10px] font-black uppercase tracking-widest">
                      Synchronizing Logs...
                    </span>
                  </div>
                ) : logs.length === 0 ? (
                  <div className="py-8 flex flex-col items-center justify-center opacity-20 grayscale">
                    <Activity className="w-8 h-8 mb-4 stroke-[1px]" />
                    <p className="text-[10px] font-black uppercase tracking-widest">
                      No Events Captured
                    </p>
                  </div>
                ) : (
                  logs.map((log: GqlModuleExecutionLog) => (
                    <LogItem key={log.id} log={log} />
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  },
);
ExecutionItem.displayName = "ExecutionItem";

export const ExecutionHistory = React.memo(function ExecutionHistory({
  moduleId,
}: ExecutionHistoryProps) {
  const [expandedId, setExpandedId] = React.useState<string | null>(null);

  const handleToggle = React.useCallback((id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  }, []);

  // MCP-890 (2026-05-14): cap the 3-second running-execution poll at
  // 30 minutes per mount. Pre-fix `refetchInterval` returned 3000 as
  // long as ANY execution had status === "running", so a stuck-running
  // execution (worker crash mid-run, dropped terminal event, or a
  // legitimate long-running approval-gated workflow) caused the tab
  // to hammer the backend at ~28,800 queries/day for as long as the
  // user left the page open. Same idle-timeout-fallback pattern as
  // MCP-888/889; after the cap fires, the user can manually click
  // "Refresh History" to force a fresh fetch.
  // Mount timestamp for the poll-duration cap. A lazy useState initializer
  // runs exactly once and keeps render idempotent — calling Date.now()
  // directly in render is impure (react-hooks/purity).
  const [mountedAt] = React.useState(() => Date.now());
  const POLL_CAP_MS = 30 * 60 * 1000;

  const {
    data: historyData,
    isLoading,
    refetch,
    isFetching,
  } = useGetModuleExecutionHistoryQuery(
    {
      moduleId,
      pagination: { limit: 20 },
    },
    {
      enabled: !!moduleId,
      staleTime: 0,
      refetchInterval: (query: {
        state: { data?: GetModuleExecutionHistoryQuery };
      }) => {
        if (Date.now() - mountedAt > POLL_CAP_MS) {
          return false;
        }
        const execs = query.state.data?.moduleExecutionHistory;
        return execs?.some((e) => e.status === "running") ? 3000 : false;
      },
    },
  );
  const history = historyData?.moduleExecutionHistory ?? [];

  const hasRunning = history.some((e) => e.status === "running");

  return (
    <div className="mt-12 space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-1000">
      {/* Header */}
      <div className="flex items-center justify-between px-2">
        <div className="flex items-center gap-5">
          <div
            className={cn(
              "w-12 h-12 rounded-2xl flex items-center justify-center bg-surface-3 border border-white/5 shadow-2xl transition-premium",
              hasRunning &&
                "border-primary/40 shadow-[0_0_20px_hsla(var(--primary),0.2)] animate-status-pulse",
            )}
          >
            {hasRunning ? (
              <Activity className="w-6 h-6 text-primary" />
            ) : (
              <HistoryIcon className="w-6 h-6 text-muted-foreground/30" />
            )}
          </div>
          <div>
            <h4 className="text-sm font-black text-white tracking-tight font-outfit uppercase leading-none mb-1.5">
              Protocol Execution Archive
            </h4>
            <div className="flex items-center gap-3">
              <span className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-[0.3em]">
                {hasRunning
                  ? "Synchronizing Telemetry..."
                  : "Historical Trace Log"}
              </span>
              {hasRunning && (
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-status-pulse shadow-[0_0_10px_hsla(var(--primary),0.5)]" />
              )}
            </div>
          </div>
        </div>
        <Button
          onClick={() => refetch()}
          disabled={isFetching}
          variant="ghost"
          className="h-11 px-5 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white bg-surface-3 border border-white/5 rounded-xl transition-premium active:scale-95 shadow-xl disabled:opacity-50"
        >
          <RefreshCw
            className={cn("w-4 h-4 mr-2.5", isFetching && "animate-spin")}
          />
          Rescan Archive
        </Button>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-32 gap-6 opacity-20 grayscale">
          <Loader2 className="w-12 h-12 animate-spin text-primary" />
          <p className="text-[10px] font-black uppercase tracking-[0.4em]">
            Decoding Sequence Trace...
          </p>
        </div>
      ) : history.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-32 bg-surface-2/20 border border-white/5 border-dashed rounded-[3rem] animate-in zoom-in-95 duration-1000">
          <HistoryIcon className="w-16 h-16 text-muted-foreground/5 mb-6" />
          <p className="text-[10px] font-black text-muted-foreground/20 uppercase tracking-[0.4em]">
            Zero Execution Cycles Logged
          </p>
        </div>
      ) : (
        <div className="grid gap-3">
          {history.map((exec: GqlModuleExecution) => (
            <ExecutionItem
              key={exec.id}
              exec={exec}
              isExpanded={expandedId === exec.id}
              onToggle={handleToggle}
            />
          ))}
        </div>
      )}
    </div>
  );
});
