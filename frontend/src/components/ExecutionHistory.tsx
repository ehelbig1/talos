import React from "react";
import { Spinner } from "@/components/ui/spinner";
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
      return <Spinner className="w-4 h-4 text-primary" />;
    case "awaiting_approval":
      return <Clock className="w-4 h-4 text-warning" />;
    case "timeout":
      return <AlertTriangle className="w-4 h-4 text-warning" />;
    default:
      return <Clock className="w-4 h-4 text-muted-foreground/50" />;
  }
}

function StatusPill({ status }: { status: string }) {
  const configs: Record<string, string> = {
    completed: "bg-success/5 text-success border-success/10",
    failed: "bg-destructive/5 text-destructive border-destructive/10",
    running: "bg-primary/5 text-primary border-primary/10",
    awaiting_approval: "bg-warning/5 text-warning border-warning/10",
    pending: "bg-warning/5 text-warning border-warning/10",
    timeout: "bg-warning/5 text-warning border-warning/10",
  };

  const cls =
    configs[status] ?? "bg-surface-4 text-muted-foreground/50 border-white/5";

  return (
    <span
      className={cn(
        "px-3 py-1 rounded-full text-2xs font-semibold uppercase tracking-wider border transition-ui",
        cls,
      )}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

const LogItem = React.memo(({ log }: { log: GqlModuleExecutionLog }) => (
  <div className="flex gap-4 group/log py-1">
    <span className="text-xs font-semibold font-mono text-muted-foreground/50 group-hover/log:text-primary transition-ui shrink-0 pt-0.5">
      {new Date(log.createdAt).toLocaleTimeString([], {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })}
    </span>
    <span
      className={cn(
        "break-words text-xs font-mono leading-relaxed selection:bg-primary/20",
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
          "group border border-white/5 bg-surface-1/40 rounded-2xl overflow-hidden transition-ui",
          isExpanded
            ? "border-primary/20 ring-1 ring-primary/10 bg-surface-2/60"
            : "hover:bg-surface-2/40 hover:border-white/10",
        )}
      >
        {/* Row header */}
        <button
          className="w-full flex items-center gap-5 p-4 text-xs transition-ui text-left focus:outline-none"
          onClick={handleToggle}
          aria-expanded={isExpanded}
        >
          <ChevronRight
            className={cn(
              "w-4 h-4 text-muted-foreground/50 shrink-0 transition-transform",
              isExpanded && "rotate-90 text-primary",
            )}
          />

          <div className="shrink-0 flex items-center justify-center w-10 h-10 rounded-2xl bg-surface-4 border border-white/5 transition-ui relative">
            <StatusIcon status={exec.status} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-1">
              <StatusPill status={exec.status} />
              {(exec.retryCount ?? 0) > 0 && (
                <span className="text-xs font-medium text-warning px-2 py-0.5 rounded-lg bg-warning/5 border border-warning/10">
                  Retries: {exec.retryCount}
                </span>
              )}
            </div>
            <div className="flex items-center gap-4 text-xs font-bold text-white/50 tracking-tight">
              <span className="truncate max-w-[200px] group-hover:text-white/70 transition-ui">
                {formatDistanceToNow(new Date(exec.startedAt), {
                  addSuffix: true,
                })}
              </span>
              <div className="w-1 h-1 rounded-full bg-white/5" />
              <span className="font-mono group-hover:text-primary/70 transition-ui">
                {formatDuration(exec.durationMs ?? null)}
              </span>
            </div>
          </div>

          <div className="shrink-0 opacity-0 group-hover:opacity-100 transition-ui">
            <Activity className="w-4 h-4 text-primary/70" />
          </div>
        </button>

        {/* Expand panel */}
        <div
          className={cn(
            "overflow-hidden transition-ui ease-in-out",
            isExpanded ? "max-h-[800px] opacity-100" : "max-h-0 opacity-0",
          )}
        >
          <div className="p-8 border-t border-white/5 bg-surface-3/40 space-y-8">
            {exec.errorMessage && (
              <div className="relative group/error">
                <div className="relative p-5 bg-destructive/5 rounded-2xl border border-destructive/20 text-xs font-bold text-destructive leading-relaxed">
                  <div className="flex items-center gap-3 mb-2">
                    <XCircle className="w-4 h-4" />
                    <span className="font-semibold uppercase tracking-wider text-2xs">
                      Error
                    </span>
                  </div>
                  {sanitizeErrorMessage(exec.errorMessage ?? "")}
                </div>
              </div>
            )}

            {/* Output */}
            <div className="space-y-4">
              <h5 className="text-muted-foreground/60 text-xs font-semibold flex items-center gap-3 ml-1">
                <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                Diagnostic Payload
              </h5>
              <div className="relative group/output">
                <div className="absolute -inset-0.5 bg-primary/5 rounded-2xl opacity-0 group-hover/output:opacity-100 transition-ui pointer-events-none" />
                {outputText ? (
                  <pre
                    tabIndex={0}
                    className="p-6 bg-surface-4/60 rounded-2xl border border-white/5 overflow-x-auto whitespace-pre-wrap max-h-64 text-xs font-mono text-white/80 focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar relative z-10 leading-relaxed selection:bg-primary/30"
                  >
                    {outputText}
                  </pre>
                ) : (
                  <div className="p-8 bg-surface-4/40 rounded-2xl border border-white/5 border-dashed flex items-center justify-center">
                    <p className="text-xs font-semibold text-muted-foreground/50 italic">
                      Null Response Buffer
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Logs */}
            <div className="space-y-4">
              <h5 className="text-muted-foreground/60 text-xs font-semibold flex items-center gap-3 ml-1">
                <div className="w-1.5 h-1.5 rounded-full bg-primary/40" />
                Output
              </h5>
              <div
                tabIndex={0}
                className="p-6 bg-surface-4/60 rounded-2xl border border-white/5 font-mono space-y-2 max-h-64 overflow-y-auto focus:outline-none focus:ring-2 focus:ring-primary/20 custom-scrollbar relative z-10"
              >
                {loadingLogs ? (
                  <div className="flex items-center gap-4 text-muted-foreground/50 py-4">
                    <Spinner className="w-4 h-4" />
                    <span className="text-xs font-semibold">
                      Synchronizing Logs...
                    </span>
                  </div>
                ) : logs.length === 0 ? (
                  <div className="py-8 flex flex-col items-center justify-center opacity-20 grayscale">
                    <Activity className="w-8 h-8 mb-4 stroke-[1px]" />
                    <p className="text-xs font-semibold">No Events Captured</p>
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
    <div className="mt-12 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between px-2">
        <div className="flex items-center gap-5">
          <div
            className={cn(
              "w-12 h-12 rounded-2xl flex items-center justify-center bg-surface-3 border border-white/5 transition-ui",
              hasRunning && "border-primary/40 animate-status-pulse",
            )}
          >
            {hasRunning ? (
              <Activity className="w-6 h-6 text-primary" />
            ) : (
              <HistoryIcon className="w-6 h-6 text-muted-foreground/60" />
            )}
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white tracking-tight font-outfit leading-none mb-1.5">
              Run history
            </h4>
            <div className="flex items-center gap-3">
              <span className="text-xs font-medium text-muted-foreground/50">
                {hasRunning ? "A run is in progress…" : "Past runs"}
              </span>
              {hasRunning && (
                <div className="w-1.5 h-1.5 rounded-full bg-primary" />
              )}
            </div>
          </div>
        </div>
        <Button
          onClick={() => refetch()}
          disabled={isFetching}
          variant="ghost"
          className="h-11 px-5 text-sm font-semibold text-muted-foreground/70 hover:text-white bg-surface-3 border border-white/5 rounded-xl transition-ui disabled:opacity-50"
        >
          <RefreshCw
            className={cn("w-4 h-4 mr-2.5", isFetching && "animate-spin")}
          />
          Rescan Archive
        </Button>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-32 gap-6 opacity-20 grayscale">
          <Spinner className="w-12 h-12 text-primary" />
          <p className="text-xs font-semibold">Loading…</p>
        </div>
      ) : history.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-32 bg-surface-2/20 border border-white/5 border-dashed rounded-2xl">
          <HistoryIcon className="w-16 h-16 text-muted-foreground/5 mb-6" />
          <p className="text-xs font-semibold text-muted-foreground/50">
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
