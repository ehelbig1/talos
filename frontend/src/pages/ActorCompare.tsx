import React, { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  listActors,
  graphqlRequest,
  subscribeExecution,
  type ActorSummary,
  type ExecutionUpdate,
} from "@/lib/graphqlClient";
import { cn } from "@/lib/utils";
import {
  ChevronLeft,
  Play,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Bot,
  GitCompare,
  AlertTriangle,
} from "lucide-react";

// ── types ─────────────────────────────────────────────────────────────────────

interface WorkflowOption {
  id: string;
  name: string;
}

type ExecStatus =
  | "idle"
  | "triggering"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

interface LaneState {
  actor: ActorSummary;
  executionId: string | null;
  status: ExecStatus;
  logs: string[];
  output: string | null;
  errorMessage: string | null;
  durationMs: number | null;
  startedAt: number | null;
}

// ── helpers ───────────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: ExecStatus }) {
  const map: Record<
    ExecStatus,
    { label: string; className: string; icon: React.ReactNode; glow: string }
  > = {
    idle: {
      label: "IDLE",
      className: "text-muted-foreground/40 bg-white/5",
      icon: <Clock className="w-3 h-3" />,
      glow: "",
    },
    triggering: {
      label: "UPLINKING...",
      className: "text-primary bg-primary/10",
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
      glow: "shadow-[0_0_10px_hsla(var(--primary),0.2)]",
    },
    queued: {
      label: "QUEUED",
      className: "text-warning bg-warning/10",
      icon: <Clock className="w-3 h-3" />,
      glow: "shadow-[0_0_10px_hsla(var(--warning),0.2)]",
    },
    running: {
      label: "EXECUTING",
      className: "text-primary bg-primary/10",
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
      glow: "shadow-[0_0_10px_hsla(var(--primary),0.3)]",
    },
    completed: {
      label: "RESOLVED",
      className: "text-success bg-success/10",
      icon: <CheckCircle2 className="w-3 h-3" />,
      glow: "shadow-[0_0_10px_hsla(var(--success),0.2)]",
    },
    failed: {
      label: "FAULT",
      className: "text-destructive bg-destructive/10",
      icon: <XCircle className="w-3 h-3" />,
      glow: "shadow-[0_0_10px_hsla(var(--destructive),0.2)]",
    },
    cancelled: {
      label: "ABORTED",
      className: "text-muted-foreground/60 bg-white/5",
      icon: <XCircle className="w-3 h-3" />,
      glow: "",
    },
  };
  const { label, className, icon, glow } = map[status] ?? map.idle;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 text-[10px] font-black px-3 py-1 rounded-full border border-white/5 transition-premium uppercase tracking-widest",
        className,
        glow,
      )}
    >
      {icon}
      {label}
    </span>
  );
}

function formatDuration(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms}MS`;
  return `${(ms / 1000).toFixed(1)}S`;
}

function tryPrettyJson(raw: string | null): string {
  if (!raw) return "—";
  try {
    const parsed = JSON.parse(raw);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return raw;
  }
}

// ── CompareLane ───────────────────────────────────────────────────────────────

function CompareLane({ lane }: { lane: LaneState }) {
  const [showLogs, setShowLogs] = useState(false);
  const logsRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (showLogs && logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [lane.logs, showLogs]);

  const isActive = lane.status === "running" || lane.status === "queued";

  return (
    <div
      className={cn(
        "flex flex-col gap-6 rounded-[2.5rem] border p-8 transition-premium relative overflow-hidden glass-dark shadow-2xl",
        isActive
          ? "border-primary/30 bg-primary/5 ring-1 ring-primary/20"
          : lane.status === "completed"
            ? "border-success/20 bg-success/[0.02]"
            : lane.status === "failed"
              ? "border-destructive/20 bg-destructive/[0.02]"
              : "border-white/5 bg-surface-1/40",
      )}
    >
      <div className="absolute inset-0 bg-gradient-to-b from-white/[0.02] to-transparent pointer-events-none" />

      {/* Actor header */}
      <div className="flex items-start justify-between gap-4 relative z-10">
        <div className="flex items-center gap-4 min-w-0">
          <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0 shadow-xl transition-premium hover:scale-110">
            <Bot className="w-6 h-6 text-primary" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-black text-white truncate font-outfit uppercase tracking-tight">
              {lane.actor.name}
            </p>
            {lane.actor.description && (
              <p className="text-[10px] text-muted-foreground/40 font-bold truncate uppercase tracking-widest mt-1">
                {lane.actor.description}
              </p>
            )}
          </div>
        </div>
        <StatusBadge status={lane.status} />
      </div>

      <div className="space-y-6 relative z-10">
        {/* Execution Meta */}
        <div className="flex items-center justify-between px-1">
          {lane.executionId && (
            <div className="flex flex-col gap-1">
              <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em]">
                PROTOCOL_ID
              </span>
              <span className="text-[10px] text-white font-mono opacity-60">
                {lane.executionId.slice(0, 12)}...
              </span>
            </div>
          )}
          {(lane.status === "completed" || lane.status === "failed") && (
            <div className="flex flex-col gap-1 items-end">
              <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em]">
                DURATION
              </span>
              <span className="text-[10px] text-white font-black uppercase tracking-widest">
                {formatDuration(lane.durationMs)}
              </span>
            </div>
          )}
        </div>

        {/* Error */}
        {lane.status === "failed" && lane.errorMessage && (
          <div className="flex items-start gap-3 bg-destructive/10 border border-destructive/20 rounded-[1.5rem] px-5 py-4 shadow-xl animate-in fade-in slide-in-from-top-2">
            <AlertTriangle className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
            <p className="text-[11px] text-destructive/80 font-bold uppercase tracking-wide leading-relaxed">
              {lane.errorMessage}
            </p>
          </div>
        )}

        {/* Output */}
        {lane.output && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 ml-1">
              <div className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
              <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.2em]">
                DATA_PAYLOAD
              </p>
            </div>
            <div className="relative group">
              <div className="absolute -inset-px bg-gradient-to-b from-white/10 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition-premium" />
              <pre className="text-[11px] text-white/80 bg-surface-4/60 border border-white/5 rounded-2xl p-5 overflow-auto max-h-80 whitespace-pre-wrap break-words font-mono leading-relaxed shadow-inner selection:bg-primary/30 shadow-2xl">
                {tryPrettyJson(lane.output)}
              </pre>
            </div>
          </div>
        )}

        {/* Logs toggle */}
        {lane.logs.length > 0 && (
          <div className="space-y-3 pt-2">
            <button
              onClick={() => setShowLogs((v) => !v)}
              className="flex items-center gap-3 px-4 py-2 rounded-xl bg-white/5 border border-white/5 text-[10px] text-muted-foreground/60 font-black uppercase tracking-[0.2em] hover:text-white hover:bg-white/10 transition-premium"
            >
              <Clock className="w-3 h-3" />
              {showLogs
                ? "DISMISS LOGS"
                : `REVEAL TELEMETRY (${lane.logs.length})`}
            </button>
            {showLogs && (
              <div
                ref={logsRef}
                className="text-[10px] font-mono text-muted-foreground/40 bg-surface-4/60 border border-white/5 rounded-2xl p-5 max-h-48 overflow-y-auto space-y-1 custom-scrollbar shadow-inner animate-in fade-in zoom-in-95"
              >
                {lane.logs.map((line, i) => (
                  <div
                    key={i}
                    className="leading-relaxed selection:bg-primary/20"
                  >
                    <span className="opacity-20 mr-3">
                      [{i.toString().padStart(3, "0")}]
                    </span>
                    {line}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Idle placeholder */}
        {lane.status === "idle" && (
          <div className="flex flex-col items-center justify-center py-10 opacity-20 gap-3 grayscale">
            <div className="p-4 rounded-2xl bg-white/5 border border-white/10">
              <Bot className="w-8 h-8 text-muted-foreground/30" />
            </div>
            <p className="text-[10px] text-muted-foreground/60 font-black uppercase tracking-[0.2em]">
              AWAITING_COMMAND
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── ActorCompare page ─────────────────────────────────────────────────────────

export default function ActorCompare() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Pre-select actors from URL (?actors=id1,id2)
  const preselectedActorIds =
    searchParams.get("actors")?.split(",").filter(Boolean) ?? [];

  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string>("");
  const [selectedActorIds, setSelectedActorIds] = useState<Set<string>>(
    new Set(preselectedActorIds),
  );
  const [lanes, setLanes] = useState<LaneState[]>([]);
  const [running, setRunning] = useState(false);

  // Subscriptions cleanup refs
  const unsubscribesRef = useRef<Array<() => void>>([]);
  // MCP-892 (2026-05-14): track the output-polling interval and safety-
  // stop timeout so unmount can cancel them. Pre-fix navigating away
  // mid-comparison left the 3s interval AND the 10min setTimeout
  // running until the safety stop fired naturally — the interval
  // then fired `setLanes` setState on an unmounted component (React
  // warning + leaked closure references).
  const outputPollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(
    null,
  );
  const outputPollTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  const { data: actors = [], isLoading: loadingActors } = useQuery<
    ActorSummary[]
  >({
    queryKey: ["actors"],
    queryFn: listActors,
  });

  const { data: workflows = [], isLoading: loadingWorkflows } = useQuery<
    WorkflowOption[]
  >({
    queryKey: ["workflows-for-compare"],
    queryFn: async () => {
      const result = await graphqlRequest<{
        workflows: { id: string; name: string }[];
      }>(`query { workflows { id name } }`);
      return result.workflows;
    },
  });

  const activeActors = actors.filter((a) => a.status === "active");

  const toggleActor = (id: string) => {
    setSelectedActorIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Cleanup subscriptions on unmount
  useEffect(() => {
    return () => {
      unsubscribesRef.current.forEach((fn) => fn());
      // MCP-892: also cancel any pending output-poll interval +
      // safety-stop timeout so unmount fully tears down side effects.
      if (outputPollIntervalRef.current) {
        clearInterval(outputPollIntervalRef.current);
        outputPollIntervalRef.current = null;
      }
      if (outputPollTimeoutRef.current) {
        clearTimeout(outputPollTimeoutRef.current);
        outputPollTimeoutRef.current = null;
      }
    };
  }, []);

  const updateLane = useCallback(
    (actorId: string, patch: Partial<LaneState>) => {
      setLanes((prev) =>
        prev.map((l) => (l.actor.id === actorId ? { ...l, ...patch } : l)),
      );
    },
    [],
  );

  const handleRun = async () => {
    if (!selectedWorkflowId) {
      toast.error("Select a workflow first");
      return;
    }
    if (selectedActorIds.size < 2) {
      toast.error("Select at least 2 actors to compare");
      return;
    }

    // Cancel existing subscriptions
    unsubscribesRef.current.forEach((fn) => fn());
    unsubscribesRef.current = [];

    const chosenActors = activeActors.filter((a) => selectedActorIds.has(a.id));

    // Initialise lanes
    setLanes(
      chosenActors.map((actor) => ({
        actor,
        executionId: null,
        status: "triggering",
        logs: [],
        output: null,
        errorMessage: null,
        durationMs: null,
        startedAt: null,
      })),
    );
    setRunning(true);

    // Trigger one execution per actor (sequentially to avoid rate-limiting)
    for (const actor of chosenActors) {
      try {
        const data = await graphqlRequest<{ triggerWorkflow: { id: string } }>(
          `mutation ($workflowId: UUID!, $actorId: UUID) {
            triggerWorkflow(workflowId: $workflowId, actorId: $actorId) { id }
          }`,
          { workflowId: selectedWorkflowId, actorId: actor.id },
        );
        const execId = data.triggerWorkflow.id;

        // Capture the queued-at timestamp inside the state updater (as the
        // live-update handler below does) so Date.now() isn't called in
        // render-reachable scope (react-hooks/purity).
        setLanes((prev) =>
          prev.map((l) =>
            l.actor.id === actor.id
              ? {
                  ...l,
                  executionId: execId,
                  status: "queued",
                  startedAt: Date.now(),
                }
              : l,
          ),
        );

        // Subscribe to live updates for this execution
        const unsub = subscribeExecution(execId, (event: ExecutionUpdate) => {
          setLanes((prev) =>
            prev.map((l) => {
              if (l.actor.id !== actor.id) return l;
              const newLogs = event.logMessage
                ? [...l.logs, event.logMessage]
                : l.logs;
              let newStatus: ExecStatus = l.status;
              if (event.status === "running") newStatus = "running";
              else if (event.status === "completed") newStatus = "completed";
              else if (event.status === "failed") newStatus = "failed";
              else if (event.status === "cancelled") newStatus = "cancelled";

              const now = Date.now();
              const durationMs =
                newStatus === "completed" || newStatus === "failed"
                  ? l.startedAt
                    ? now - l.startedAt
                    : null
                  : l.durationMs;

              return {
                ...l,
                status: newStatus,
                logs: newLogs,
                durationMs,
                errorMessage:
                  newStatus === "failed"
                    ? (event.logMessage ?? l.errorMessage)
                    : l.errorMessage,
              };
            }),
          );
        });
        unsubscribesRef.current.push(unsub);
      } catch (err) {
        updateLane(actor.id, {
          status: "failed",
          errorMessage: sanitizeErrorMessage(String(err)),
        });
      }
    }

    // Poll for final output once each execution completes
    startOutputPolling(chosenActors.map((a) => a.id));
  };

  const startOutputPolling = (actorIds: string[]) => {
    // MCP-892: cancel any prior interval/timeout before starting a
    // new comparison run (handleReset doesn't fire when user just
    // clicks Run again).
    if (outputPollIntervalRef.current) {
      clearInterval(outputPollIntervalRef.current);
    }
    if (outputPollTimeoutRef.current) {
      clearTimeout(outputPollTimeoutRef.current);
    }
    const interval = setInterval(async () => {
      setLanes((current) => {
        // Check if all lanes are terminal
        const allDone = current.every(
          (l) =>
            l.status === "completed" ||
            l.status === "failed" ||
            l.status === "cancelled" ||
            l.status === "idle",
        );
        if (allDone) {
          clearInterval(interval);
          setRunning(false);
        }
        return current;
      });

      // Fetch output for completed lanes that still lack output
      setLanes((current) =>
        current.map((l) => {
          if (
            (l.status === "completed" || l.status === "failed") &&
            l.executionId &&
            l.output === null &&
            actorIds.includes(l.actor.id)
          ) {
            // Fire-and-forget fetch
            graphqlRequest<{
              workflowExecutionHistory: Array<{
                id: string;
                outputData: string | null;
                errorMessage: string | null;
                durationMs: number | null;
              }>;
            }>(
              `query ($wfId: UUID!, $p: PaginationInput) {
                workflowExecutionHistory(workflowId: $wfId, pagination: $p) {
                  id outputData errorMessage durationMs
                }
              }`,
              {
                wfId: selectedWorkflowId,
                p: { limit: 50 },
              },
            )
              .then((res) => {
                const match = res.workflowExecutionHistory.find(
                  (e) => e.id === l.executionId,
                );
                if (match) {
                  setLanes((prev) =>
                    prev.map((lane) =>
                      lane.executionId === l.executionId
                        ? {
                            ...lane,
                            output:
                              match.outputData != null
                                ? typeof match.outputData === "string"
                                  ? match.outputData
                                  : JSON.stringify(match.outputData)
                                : lane.output,
                            errorMessage:
                              match.errorMessage ?? lane.errorMessage,
                            durationMs: match.durationMs ?? lane.durationMs,
                          }
                        : lane,
                    ),
                  );
                }
              })
              .catch((err: unknown) => {
                if (import.meta.env.DEV)
                  console.warn("Failed to load execution history:", err);
              });
          }
          return l;
        }),
      );
    }, 3000);
    outputPollIntervalRef.current = interval;

    // Safety stop after 10 minutes
    outputPollTimeoutRef.current = setTimeout(() => {
      clearInterval(interval);
      outputPollIntervalRef.current = null;
      outputPollTimeoutRef.current = null;
      setRunning(false);
    }, 600_000);
  };

  const handleReset = () => {
    unsubscribesRef.current.forEach((fn) => fn());
    unsubscribesRef.current = [];
    setLanes([]);
    setRunning(false);
  };

  const allDone =
    lanes.length > 0 &&
    lanes.every(
      (l) =>
        l.status === "completed" ||
        l.status === "failed" ||
        l.status === "cancelled",
    );

  const canRun = !running && selectedWorkflowId && selectedActorIds.size >= 2;

  return (
    <div className="min-h-screen bg-background text-white relative overflow-hidden font-inter">
      {/* Ambient background glows */}
      <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] bg-primary/5 rounded-full blur-[120px] animate-pulse" />
      <div className="absolute bottom-[-5%] left-[-5%] w-[40%] h-[40%] bg-violet-500/5 rounded-full blur-[100px] animate-pulse delay-700" />

      <div className="max-w-7xl mx-auto px-8 py-10 space-y-12 relative z-10">
        {/* Page header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-6">
            <button
              onClick={() => navigate("/actors")}
              className="p-3 rounded-2xl bg-white/5 border border-white/10 text-muted-foreground/60 hover:text-white hover:bg-white/10 transition-premium shadow-xl"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-5">
              <div className="p-3.5 rounded-2xl bg-primary/10 border border-primary/20 shadow-[0_0_20px_hsla(var(--primary),0.15)]">
                <GitCompare className="w-7 h-7 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-black tracking-tight font-outfit uppercase">
                  Actor Strategic Compare
                </h1>
                <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em] mt-1">
                  Simultaneous multi-actor protocol evaluation
                </p>
              </div>
            </div>
          </div>

          {/* Global Actions */}
          <div className="flex items-center gap-4">
            {lanes.length > 0 && allDone && (
              <button
                onClick={handleReset}
                className="flex items-center gap-3 px-6 py-3 rounded-2xl bg-surface-2/40 border border-white/5 text-[11px] font-black uppercase tracking-widest text-muted-foreground/60 hover:text-white hover:bg-surface-2/60 transition-premium shadow-2xl active:scale-95"
              >
                <RefreshCw className="w-4 h-4" />
                New Analysis
              </button>
            )}
            <button
              onClick={handleRun}
              disabled={!canRun}
              className="flex items-center gap-3 px-8 py-3.5 rounded-2xl bg-primary hover:bg-primary/90 disabled:opacity-40 disabled:grayscale disabled:cursor-not-allowed text-white text-[11px] font-black uppercase tracking-[0.2em] transition-premium shadow-[0_0_30px_hsla(var(--primary),0.2)] active:scale-95"
            >
              {running ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              {running ? "ANALYZING..." : "INITIATE PROTOCOL"}
            </button>
          </div>
        </div>

        {/* Setup panel (hidden after run starts) */}
        {lanes.length === 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Workflow selector */}
            <div className="bg-surface-1/40 border border-white/5 rounded-[2.5rem] p-10 space-y-6 glass-dark shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 p-8 opacity-5">
                <Clock size={120} />
              </div>
              <h2 className="text-[10px] font-black text-primary uppercase tracking-[0.3em] flex items-center gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-status-pulse" />
                01. SELECT TARGET WORKFLOW
              </h2>
              {loadingWorkflows ? (
                <div className="flex items-center gap-3 text-muted-foreground/30 animate-pulse py-4">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-xs font-bold uppercase tracking-widest">
                    Accessing Registry...
                  </span>
                </div>
              ) : workflows.length === 0 ? (
                <p className="text-muted-foreground/40 text-xs font-bold uppercase tracking-widest py-4">
                  No active protocols detected.
                </p>
              ) : (
                <div className="relative group">
                  <div className="absolute -inset-px bg-gradient-to-r from-primary/20 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition-premium" />
                  <select
                    value={selectedWorkflowId}
                    onChange={(e) => setSelectedWorkflowId(e.target.value)}
                    className="w-full bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-4 text-xs font-bold text-white uppercase tracking-widest focus:outline-none focus:ring-2 focus:ring-primary/40 transition-premium appearance-none cursor-pointer relative z-10 shadow-inner"
                  >
                    <option value="" className="bg-surface-4">
                      — SELECT PROTOCOL —
                    </option>
                    {workflows.map((w) => (
                      <option key={w.id} value={w.id} className="bg-surface-4">
                        {w.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <p className="text-[10px] text-muted-foreground/20 font-bold uppercase tracking-widest leading-relaxed">
                Choose the shared operational sequence to evaluate across
                multiple actor profiles.
              </p>
            </div>

            {/* Actor selector */}
            <div className="bg-surface-1/40 border border-white/5 rounded-[2.5rem] p-10 space-y-6 glass-dark shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 p-8 opacity-5">
                <Bot size={120} />
              </div>
              <h2 className="text-[10px] font-black text-primary uppercase tracking-[0.3em] flex items-center gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-status-pulse" />
                02. IDENTIFY ACTOR COHORT
                <span className="text-muted-foreground/40 normal-case font-bold tracking-widest ml-auto">
                  (MIN_REQ: 2)
                </span>
              </h2>
              {loadingActors ? (
                <div className="flex items-center gap-3 text-muted-foreground/30 animate-pulse py-4">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-xs font-bold uppercase tracking-widest">
                    Scanning Identities...
                  </span>
                </div>
              ) : activeActors.length === 0 ? (
                <p className="text-muted-foreground/40 text-xs font-bold uppercase tracking-widest py-4">
                  No active identities.{" "}
                  <button
                    onClick={() => navigate("/actors")}
                    className="text-primary hover:text-white transition-premium underline"
                  >
                    REGISTER_NEW →
                  </button>
                </p>
              ) : (
                <div className="space-y-3 max-h-72 overflow-y-auto pr-3 custom-scrollbar">
                  {activeActors.map((actor) => {
                    const selected = selectedActorIds.has(actor.id);
                    return (
                      <label
                        key={actor.id}
                        className={cn(
                          "flex items-center gap-4 p-4 rounded-2xl cursor-pointer transition-premium group relative overflow-hidden",
                          selected
                            ? "bg-primary/5 border-primary/20 shadow-xl"
                            : "bg-surface-3/40 border border-white/5 hover:border-white/20",
                        )}
                      >
                        <div
                          className={cn(
                            "w-5 h-5 rounded-md border transition-premium flex items-center justify-center shrink-0",
                            selected
                              ? "bg-primary border-primary shadow-[0_0_10px_hsla(var(--primary),0.5)]"
                              : "border-white/10 group-hover:border-white/30",
                          )}
                        >
                          {selected && (
                            <CheckCircle2 className="w-3 h-3 text-white" />
                          )}
                        </div>
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={() => toggleActor(actor.id)}
                          className="hidden"
                        />
                        <div className="min-w-0 flex-1">
                          <p className="text-[11px] font-black text-white uppercase tracking-widest truncate">
                            {actor.name}
                          </p>
                          {actor.description && (
                            <p className="text-[9px] text-muted-foreground/40 font-bold uppercase tracking-tight truncate mt-1">
                              {actor.description}
                            </p>
                          )}
                        </div>
                        <span className="text-[9px] text-primary/40 font-black tracking-widest uppercase shrink-0">
                          {actor.maxCapabilityWorld}
                        </span>
                      </label>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Status ticker when running */}
        {running && (
          <div className="flex items-center gap-6 px-8 py-4 bg-primary/5 border border-primary/10 rounded-2xl shadow-2xl animate-in slide-in-from-top-4">
            <div className="flex -space-x-3">
              {lanes.map((l, i) => (
                <div
                  key={l.actor.id}
                  className="w-8 h-8 rounded-full border-2 border-background bg-surface-4 flex items-center justify-center shadow-xl"
                  style={{ zIndex: 10 - i }}
                >
                  <Bot
                    className={cn(
                      "w-4 h-4",
                      l.status === "running"
                        ? "text-primary animate-pulse"
                        : "text-muted-foreground/20",
                    )}
                  />
                </div>
              ))}
            </div>
            <div className="flex-1 flex items-center gap-4 text-[10px] font-black uppercase tracking-[0.2em] text-primary">
              <Loader2 className="w-4 h-4 animate-spin" />
              SYSTEM_BROADCAST: SYNCHRONIZED EXECUTION IN PROGRESS...
              <div className="ml-auto flex gap-6">
                <span className="text-white/40">
                  PENDING:{" "}
                  {
                    lanes.filter(
                      (l) => l.status === "queued" || l.status === "triggering",
                    ).length
                  }
                </span>
                <span className="animate-pulse">
                  ACTIVE: {lanes.filter((l) => l.status === "running").length}
                </span>
                <span className="text-success">
                  COMPLETE:{" "}
                  {lanes.filter((l) => l.status === "completed").length}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Comparison grid */}
        {lanes.length > 0 && (
          <div
            className={cn(
              "grid gap-8 animate-in fade-in zoom-in-95 duration-700",
              lanes.length === 2
                ? "grid-cols-1 lg:grid-cols-2"
                : lanes.length === 3
                  ? "grid-cols-1 lg:grid-cols-3"
                  : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4",
            )}
          >
            {lanes.map((lane) => (
              <CompareLane key={lane.actor.id} lane={lane} />
            ))}
          </div>
        )}

        {/* Empty prompt */}
        {lanes.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 gap-8 text-center animate-in fade-in duration-1000">
            <div className="relative">
              <div className="absolute -inset-10 bg-primary/5 rounded-full blur-3xl animate-pulse" />
              <GitCompare className="w-24 h-24 text-white/5 relative z-10" />
            </div>
            <div className="space-y-3 relative z-10">
              <p className="text-sm font-black text-white/40 uppercase tracking-[0.3em] font-outfit">
                Strategic Analysis Engine Offline
              </p>
              <p className="text-[10px] text-muted-foreground/20 font-bold uppercase tracking-widest max-w-sm leading-relaxed">
                Awaiting protocol designation and actor cohort assignment to
                begin comparative telemetry collection.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
