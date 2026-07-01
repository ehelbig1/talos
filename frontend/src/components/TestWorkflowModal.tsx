import React, { useState, useMemo, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  Zap,
  CheckCircle2,
  XCircle,
  SkipForward,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Clock,
  Play,
  Terminal,
  Activity,
  PauseCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useTestWorkflowMutation } from "@/generated/graphql";
import { subscribeExecution, type ExecutionUpdate } from "@/lib/graphqlClient";
import { useWorkflowStore } from "@/store/workflowStore";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";

/** Terminal phases of a detached test run (driven by executionUpdates). */
type RunPhase = "idle" | "running" | "completed" | "failed" | "waiting";

/** Per-node display status derived from the `ExecutionStatus` wire enum. */
type NodeStatus =
  | "completed"
  | "failed"
  | "running"
  | "skipped"
  | "waiting"
  | "pending";

/**
 * A per-node view folded from the live `executionUpdates` stream. The subscription
 * carries status + logMessage + durationMs per node (not the full output JSON — that
 * matches how the rest of the app renders live executions).
 */
interface NodeTrace {
  nodeId: string;
  status: NodeStatus;
  logMessage?: string | null;
  durationMs?: number | null;
  /** Final node output JSON, from the terminal event's aggregated output. */
  output?: string | null;
}

function formatJson(raw: unknown): string {
  if (typeof raw === "string") {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }
  return JSON.stringify(raw, null, 2);
}

function normalizeStatus(wire: string): NodeStatus {
  switch (wire) {
    case "COMPLETED":
      return "completed";
    case "FAILED":
      return "failed";
    case "RUNNING":
      return "running";
    case "SKIPPED":
      return "skipped";
    case "WAITING":
      return "waiting";
    default:
      return "pending";
  }
}

function NodeTraceCard({
  trace,
  index,
  nodeLabel,
}: {
  trace: NodeTrace;
  index: number;
  nodeLabel?: string;
}) {
  const [expanded, setExpanded] = useState(trace.status === "failed");

  const statusConfig = {
    completed: {
      icon: <CheckCircle2 className="w-3 h-3" />,
      color: "text-success bg-success/10 border-success/20",
    },
    failed: {
      icon: <XCircle className="w-3 h-3" />,
      color: "text-destructive bg-destructive/10 border-destructive/20",
    },
    running: {
      icon: <LoadingSpinner className="w-3 h-3" />,
      color: "text-primary bg-primary/10 border-primary/20",
    },
    skipped: {
      icon: <SkipForward className="w-3 h-3" />,
      color: "text-muted-foreground bg-white/5 border-white/10",
    },
    waiting: {
      icon: <PauseCircle className="w-3 h-3" />,
      color: "text-warning bg-warning/10 border-warning/20",
    },
    pending: {
      icon: <Zap className="w-3 h-3" />,
      color: "text-muted-foreground bg-white/5 border-white/10",
    },
  }[trace.status];

  const hasDetail = !!trace.logMessage || !!trace.output;

  return (
    <div
      className={cn(
        "rounded-2xl border overflow-hidden transition-premium",
        trace.status === "failed"
          ? "border-destructive/30 bg-destructive/5"
          : "border-white/5 bg-white/[0.02]",
      )}
    >
      <button
        className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-white/5 transition-premium"
        onClick={() => setExpanded((v) => !v)}
        disabled={!hasDetail}
      >
        <span className="text-[10px] font-black text-muted-foreground/30 w-5 shrink-0 tabular-nums">
          {String(index + 1).padStart(2, "0")}
        </span>
        <div
          className={cn(
            "flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[9px] font-black border shrink-0 uppercase tracking-widest",
            statusConfig.color,
          )}
        >
          {statusConfig.icon}
          {trace.status}
        </div>
        <span className="text-xs font-bold text-foreground/80 flex-1 truncate uppercase tracking-tight">
          {nodeLabel ?? (
            <code className="font-mono text-muted-foreground/40">
              {trace.nodeId.slice(0, 8)}
            </code>
          )}
        </span>
        {trace.durationMs != null && (
          <span className="text-[9px] font-black text-muted-foreground/40 tabular-nums shrink-0">
            {trace.durationMs}ms
          </span>
        )}
        {hasDetail && (
          <div className="w-6 h-6 rounded-lg bg-white/5 flex items-center justify-center transition-premium group-hover:bg-white/10">
            {expanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/50" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/50" />
            )}
          </div>
        )}
      </button>

      {expanded && hasDetail && (
        <div className="border-t border-white/5 px-6 pb-6 space-y-5 pt-5 animate-in slide-in-from-top-2 duration-300">
          {trace.logMessage && (
            <div className="space-y-3">
              <p className="text-[9px] font-black text-muted-foreground/30 uppercase tracking-[0.2em] ml-1">
                {trace.status === "failed" ? "Diagnostic Fault" : "Node Log"}
              </p>
              <pre
                className={cn(
                  "text-[10px] font-mono border rounded-[1.25rem] p-5 overflow-x-auto max-h-48 whitespace-pre-wrap shadow-inner leading-relaxed",
                  trace.status === "failed"
                    ? "text-destructive/80 bg-destructive/10 border-destructive/20 font-bold"
                    : "text-foreground/60 bg-surface-4/60 border-white/5",
                )}
              >
                {sanitizeErrorMessage(trace.logMessage)}
              </pre>
            </div>
          )}
          {trace.output && (
            <div className="space-y-3">
              <p className="text-[9px] font-black text-muted-foreground/30 uppercase tracking-[0.2em] ml-1">
                Egress Result
              </p>
              <pre className="text-[10px] font-mono text-primary/60 bg-primary/5 border border-primary/10 rounded-[1.25rem] p-5 overflow-x-auto max-h-64 whitespace-pre-wrap shadow-inner leading-relaxed">
                {trace.output}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface Props {
  workflowId: string;
  workflowName: string;
  onClose: () => void;
}

export function TestWorkflowModal({
  workflowId,
  workflowName,
  onClose,
}: Props) {
  const [mockInputs, setMockInputs] = useState("{}");
  const [jsonError, setJsonError] = useState<string | null>(null);

  // Detached-run state. The mutation now returns immediately with an
  // executionId; progress + final result arrive over the executionUpdates
  // subscription, so a slow local-Ollama test is no longer capped by any
  // HTTP-request timeout (the bug that left rows stuck `running`).
  const [executionId, setExecutionId] = useState<string | null>(null);
  const [phase, setPhase] = useState<RunPhase>("idle");
  const [events, setEvents] = useState<ExecutionUpdate[]>([]);
  const [elapsedMs, setElapsedMs] = useState<number | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  // Aggregated per-node output, delivered on the terminal event.
  const [finalOutput, setFinalOutput] = useState<Record<
    string,
    unknown
  > | null>(null);
  const startRef = useRef<number>(0);

  const nodes = useWorkflowStore((s) => s.nodes);
  const nodeLabelMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const n of nodes) {
      map[n.id] = n.data.label ?? n.data.moduleName ?? n.id.slice(0, 8);
    }
    return map;
  }, [nodes]);

  const testMutation = useTestWorkflowMutation({
    onSuccess: (data) => {
      setExecutionId(data.testWorkflow.executionId);
      setPhase("running");
    },
    onError: (err) => {
      setPhase("failed");
      setRunError(sanitizeErrorMessage(String(err)));
      toast.error("Test run failed to start");
    },
  });

  // Subscribe to live execution events for the detached run. Folds terminal
  // execution-level events (nodeId == null) into the run phase; per-node
  // events accumulate for the trace list.
  useEffect(() => {
    if (!executionId) return;
    const unsub = subscribeExecution(executionId, (ev) => {
      setEvents((prev) => [...prev, ev]);
      if (ev.output && typeof ev.output === "object") {
        setFinalOutput(ev.output);
      }
      if (!ev.nodeId) {
        if (ev.status === "COMPLETED") {
          setPhase("completed");
          setElapsedMs(Date.now() - startRef.current);
        } else if (ev.status === "FAILED") {
          setPhase("failed");
          setRunError(ev.logMessage ?? "Test run failed");
          setElapsedMs(Date.now() - startRef.current);
        } else if (ev.status === "WAITING") {
          setPhase("waiting");
          setElapsedMs(Date.now() - startRef.current);
        }
      }
    });
    return () => unsub();
  }, [executionId]);

  const handleMockInputChange = (v: string) => {
    setMockInputs(v);
    try {
      JSON.parse(v);
      setJsonError(null);
    } catch {
      setJsonError("Invalid JSON Protocol");
    }
  };

  const handleRun = () => {
    if (jsonError) return;
    setEvents([]);
    setExecutionId(null);
    setElapsedMs(null);
    setRunError(null);
    setFinalOutput(null);
    setPhase("idle");
    startRef.current = Date.now();
    testMutation.mutate({
      workflowId,
      mockInputs: mockInputs !== "{}" ? mockInputs : undefined,
    });
  };

  // Fold per-node events into the latest-status-per-node trace list.
  //
  // Per-node events on the live channel are LOG frames (status RUNNING, keyed by
  // node_id) plus start/terminal execution-level frames — the engine's
  // node-completion events are written to the DB but not broadcast. So once the
  // run reaches terminal `completed`, promote any node still showing `running`
  // to `completed` (its logs streamed, then the whole run succeeded). A failed /
  // waiting run leaves nodes in their last live state; the global banner carries
  // the authoritative outcome.
  const nodeTraces = useMemo<NodeTrace[]>(() => {
    const byNode = new Map<string, NodeTrace>();
    for (const ev of events) {
      if (!ev.nodeId) continue;
      const prev = byNode.get(ev.nodeId);
      byNode.set(ev.nodeId, {
        nodeId: ev.nodeId,
        status: normalizeStatus(ev.status),
        logMessage: ev.logMessage ?? prev?.logMessage,
        durationMs: ev.durationMs ?? prev?.durationMs,
      });
    }
    const traces = Array.from(byNode.values());
    if (phase === "completed") {
      for (const t of traces) {
        if (t.status === "running" || t.status === "pending") {
          t.status = "completed";
        }
      }
    }
    // Attach the terminal aggregated output (keyed by node id) so each card
    // can show the node's actual result, not just its live log.
    if (finalOutput) {
      for (const t of traces) {
        const out = finalOutput[t.nodeId];
        if (out !== undefined) t.output = formatJson(out);
      }
      // A node that produced output but never emitted a live status frame
      // (fast short-circuit) won't be in `byNode` — surface it too.
      for (const nodeId of Object.keys(finalOutput)) {
        if (!byNode.has(nodeId)) {
          traces.push({
            nodeId,
            status: phase === "completed" ? "completed" : "pending",
            output: formatJson(finalOutput[nodeId]),
          });
        }
      }
    }
    return traces;
  }, [events, phase, finalOutput]);

  const { succeeded, failed, skipped } = useMemo(() => {
    return nodeTraces.reduce(
      (acc, t) => {
        if (t.status === "completed") acc.succeeded++;
        else if (t.status === "failed") acc.failed++;
        else if (t.status === "skipped") acc.skipped++;
        return acc;
      },
      { succeeded: 0, failed: 0, skipped: 0 },
    );
  }, [nodeTraces]);

  const isRunning = phase === "running";
  const isTerminal =
    phase === "completed" || phase === "failed" || phase === "waiting";
  const traceTotal = nodeTraces.length || 1;

  return (
    <Dialog
      open={true}
      onClose={onClose}
      title="Dry Run Diagnostics"
      className="max-w-3xl"
    >
      <div className="space-y-8 relative z-10 p-2 -mt-4">
        <div className="flex items-center justify-between mb-2">
          <p className="text-[11px] text-muted-foreground/60 font-medium truncate max-w-[400px] uppercase tracking-widest leading-none">
            {workflowName}
          </p>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_hsla(var(--success),0.5)] animate-pulse" />
            <span className="text-[9px] font-black text-emerald-500/60 uppercase tracking-[0.2em]">
              Sandboxed Protocol
            </span>
          </div>
        </div>

        {/* Mock inputs */}
        <div className="bg-surface-4/40 border border-white/5 rounded-[2rem] p-8 space-y-6 shadow-inner glass-light">
          <div className="flex items-center justify-between">
            <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 ml-1">
              Synthetic Trigger Ingress (JSON)
            </label>
            {jsonError && (
              <span className="text-[9px] font-black text-destructive uppercase tracking-widest animate-pulse">
                {jsonError}
              </span>
            )}
          </div>
          <textarea
            value={mockInputs}
            onChange={(e) => handleMockInputChange(e.target.value)}
            rows={4}
            spellCheck={false}
            className={cn(
              "w-full bg-surface-3/40 border focus:outline-none focus:ring-1 rounded-2xl px-6 py-5 text-[11px] font-mono text-foreground placeholder:text-muted-foreground/10 resize-none transition-premium shadow-inner uppercase tracking-wider",
              jsonError
                ? "border-destructive/40 focus:border-destructive focus:ring-destructive/20"
                : "border-white/5 focus:border-primary/40 focus:ring-primary/20",
            )}
          />
          <div className="flex items-center justify-between gap-6">
            <div className="flex items-start gap-3 flex-1">
              <AlertTriangle className="w-4 h-4 text-warning/40 shrink-0 mt-0.5" />
              <p className="text-[10px] text-muted-foreground/30 font-bold uppercase tracking-widest leading-relaxed">
                Executes the current DAG in a transient sandbox. Streams live
                telemetry until the run resolves.
              </p>
            </div>
            <Button
              onClick={handleRun}
              disabled={!!jsonError || testMutation.isPending || isRunning}
              className="bg-primary hover:bg-primary/90 text-white font-black px-10 h-14 rounded-2xl shadow-2xl shadow-primary/20 transition-premium flex items-center gap-3 uppercase tracking-widest text-[10px] border border-white/10 shrink-0"
            >
              {testMutation.isPending || isRunning ? (
                <>
                  <LoadingSpinner className="w-4 h-4" />
                  <span>{isRunning ? "EXECUTING..." : "DISPATCHING..."}</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  INITIATE RUN
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Results */}
        <div className="max-h-[460px] overflow-y-auto custom-scrollbar border border-white/5 rounded-[2rem] bg-surface-4/20 shadow-inner">
          {phase === "idle" && !testMutation.isPending && (
            <div className="flex flex-col items-center justify-center py-24 text-center px-6 opacity-20">
              <div className="w-16 h-16 rounded-[1.5rem] bg-surface-3 border border-white/5 flex items-center justify-center mb-6 shadow-2xl">
                <Terminal size={32} className="text-muted-foreground" />
              </div>
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-[0.4em]">
                Awaiting Diagnostic Initiation
              </p>
            </div>
          )}

          {(testMutation.isPending || isRunning || isTerminal) && (
            <div className="p-8 space-y-10">
              {/* Summary bar */}
              <div className="flex items-center gap-4 flex-wrap">
                <div
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-xl border text-[10px] font-black uppercase tracking-widest shadow-lg",
                    phase === "completed"
                      ? "bg-success/10 text-success border-success/20"
                      : phase === "failed"
                        ? "bg-destructive/10 text-destructive border-destructive/20"
                        : phase === "waiting"
                          ? "bg-warning/10 text-warning border-warning/20"
                          : "bg-primary/10 text-primary border-primary/20",
                  )}
                >
                  {phase === "completed" ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : phase === "failed" ? (
                    <XCircle className="w-3.5 h-3.5" />
                  ) : phase === "waiting" ? (
                    <PauseCircle className="w-3.5 h-3.5" />
                  ) : (
                    <LoadingSpinner className="w-3.5 h-3.5" />
                  )}
                  {isTerminal ? phase : "running"}
                </div>
                {elapsedMs != null && (
                  <div className="flex items-center gap-2 px-4 py-2 rounded-xl border border-white/5 bg-white/[0.02] text-[10px] text-muted-foreground font-black uppercase tracking-widest shadow-lg">
                    <Clock className="w-3.5 h-3.5 opacity-40" />
                    {elapsedMs}ms
                  </div>
                )}
                <div className="flex items-center gap-4 ml-auto">
                  <div className="flex flex-col items-end gap-1">
                    <div className="flex items-center gap-3">
                      {succeeded > 0 && (
                        <span className="text-success text-[10px] font-black uppercase tracking-widest">
                          {succeeded} SUCCESS
                        </span>
                      )}
                      {failed > 0 && (
                        <span className="text-destructive text-[10px] font-black uppercase tracking-widest">
                          {failed} FAILURE
                        </span>
                      )}
                      {skipped > 0 && (
                        <span className="text-muted-foreground/40 text-[10px] font-black uppercase tracking-widest">
                          {skipped} SKIPPED
                        </span>
                      )}
                    </div>
                    <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden flex shadow-inner">
                      <div
                        className="bg-success h-full transition-premium"
                        style={{ width: `${(succeeded / traceTotal) * 100}%` }}
                      />
                      <div
                        className="bg-destructive h-full transition-premium"
                        style={{ width: `${(failed / traceTotal) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Global error */}
              {runError && (
                <div className="bg-destructive/5 border border-destructive/20 rounded-[2rem] p-6 flex items-start gap-4 shadow-2xl glass-light">
                  <Activity className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                  <div className="space-y-2">
                    <p className="text-[10px] font-black text-destructive uppercase tracking-[0.2em]">
                      Orchestration Failure
                    </p>
                    <p className="text-[11px] text-destructive/80 leading-relaxed font-mono font-bold">
                      {sanitizeErrorMessage(runError)}
                    </p>
                  </div>
                </div>
              )}

              {/* Live / final node traces */}
              {nodeTraces.length > 0 ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 px-1 mb-6">
                    <div className="h-px flex-1 bg-white/5" />
                    <p className="text-[10px] font-black text-muted-foreground/20 uppercase tracking-[0.4em]">
                      Telemetry Trace Sequence ({nodeTraces.length})
                    </p>
                    <div className="h-px flex-1 bg-white/5" />
                  </div>
                  <div className="space-y-3">
                    {nodeTraces.map((trace, i) => (
                      <NodeTraceCard
                        key={trace.nodeId + i}
                        trace={trace}
                        index={i}
                        nodeLabel={nodeLabelMap[trace.nodeId]}
                      />
                    ))}
                  </div>
                </div>
              ) : (
                !isTerminal && (
                  <div className="flex flex-col items-center justify-center py-16 gap-6">
                    <LoadingSpinner className="w-10 h-10 text-primary" />
                    <p className="text-[10px] font-black text-primary/40 uppercase tracking-[0.4em] animate-pulse">
                      Awaiting First Telemetry Frame...
                    </p>
                  </div>
                )
              )}
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
