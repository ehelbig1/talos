import React, { useState, useMemo } from "react";
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
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  useTestWorkflowMutation,
  TestWorkflowMutation,
} from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";

type NodeTrace = TestWorkflowMutation["testWorkflow"]["nodeTraces"][0];
type TestResult = TestWorkflowMutation["testWorkflow"];

function formatJson(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
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
    skipped: {
      icon: <SkipForward className="w-3 h-3" />,
      color: "text-muted-foreground bg-white/5 border-white/10",
    },
  }[trace.status] ?? {
    icon: <Zap className="w-3 h-3" />,
    color: "text-muted-foreground bg-white/5 border-white/10",
  };

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
        <div className="w-6 h-6 rounded-lg bg-white/5 flex items-center justify-center transition-premium group-hover:bg-white/10">
          {expanded ? (
            <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/50" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/50" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-white/5 px-6 pb-6 space-y-5 pt-5 animate-in slide-in-from-top-2 duration-300">
          {trace.error && (
            <div className="bg-destructive/10 border border-destructive/20 rounded-[1.25rem] px-5 py-4 shadow-inner">
              <p className="text-[9px] font-black text-destructive uppercase tracking-[0.2em] mb-2">
                Diagnostic Fault
              </p>
              <p className="text-[11px] text-destructive/80 font-mono leading-relaxed font-bold">
                {sanitizeErrorMessage(trace.error)}
              </p>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3">
              <p className="text-[9px] font-black text-muted-foreground/30 uppercase tracking-[0.2em] ml-1">
                Ingress Context
              </p>
              <pre className="text-[10px] font-mono text-foreground/60 bg-surface-4/60 border border-white/5 rounded-[1.25rem] p-5 overflow-x-auto max-h-48 whitespace-pre-wrap shadow-inner leading-relaxed">
                {formatJson(trace.input)}
              </pre>
            </div>
            <div className="space-y-3">
              <p className="text-[9px] font-black text-muted-foreground/30 uppercase tracking-[0.2em] ml-1">
                Egress result
              </p>
              {trace.output ? (
                <pre className="text-[10px] font-mono text-primary/60 bg-primary/5 border border-primary/10 rounded-[1.25rem] p-5 overflow-x-auto max-h-48 whitespace-pre-wrap shadow-inner leading-relaxed">
                  {formatJson(trace.output)}
                </pre>
              ) : (
                <div className="h-full flex items-center justify-center border border-white/5 bg-white/[0.02] rounded-[1.25rem] opacity-20">
                  <p className="text-[10px] font-black uppercase tracking-widest italic">
                    No Output Protocol
                  </p>
                </div>
              )}
            </div>
          </div>
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
  const [result, setResult] = useState<TestResult | null>(null);
  const [jsonError, setJsonError] = useState<string | null>(null);

  const nodes = useWorkflowStore((s) => s.nodes);
  const nodeLabelMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const n of nodes) {
      map[n.id] = n.data.label ?? n.data.moduleName ?? n.id.slice(0, 8);
    }
    return map;
  }, [nodes]);

  const testMutation = useTestWorkflowMutation({
    onSuccess: (data) => setResult(data.testWorkflow),
    onError: () => toast.error("Test run failed"),
  });

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
    setResult(null);
    testMutation.mutate({
      workflowId,
      mockInputs: mockInputs !== "{}" ? mockInputs : undefined,
    });
  };

  const { succeeded, failed, skipped } = useMemo(() => {
    if (!result?.nodeTraces) return { succeeded: 0, failed: 0, skipped: 0 };
    return result.nodeTraces.reduce(
      (acc, t) => {
        if (t.status === "completed") acc.succeeded++;
        else if (t.status === "failed") acc.failed++;
        else if (t.status === "skipped") acc.skipped++;
        return acc;
      },
      { succeeded: 0, failed: 0, skipped: 0 },
    );
    // Depend on `result` (not the narrower `result?.nodeTraces`): the body
    // reads `result`, so the narrower manual dep could go stale if `result` is
    // replaced while its `nodeTraces` reference compares equal. Matches the
    // compiler-inferred dependency (react-hooks/preserve-manual-memoization).
  }, [result]);

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
                Executes the current DAG in a transient sandbox. Zero
                persistence, zero external side-effects.
              </p>
            </div>
            <Button
              onClick={handleRun}
              disabled={!!jsonError || testMutation.isPending}
              className="bg-primary hover:bg-primary/90 text-white font-black px-10 h-14 rounded-2xl shadow-2xl shadow-primary/20 transition-premium flex items-center gap-3 uppercase tracking-widest text-[10px] border border-white/10 shrink-0"
            >
              {testMutation.isPending ? (
                <>
                  <LoadingSpinner className="w-4 h-4" />
                  <span>SYNCHRONIZING...</span>
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
          {!result && !testMutation.isPending && (
            <div className="flex flex-col items-center justify-center py-24 text-center px-6 opacity-20">
              <div className="w-16 h-16 rounded-[1.5rem] bg-surface-3 border border-white/5 flex items-center justify-center mb-6 shadow-2xl">
                <Terminal size={32} className="text-muted-foreground" />
              </div>
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-[0.4em]">
                Awaiting Diagnostic Initiation
              </p>
            </div>
          )}

          {testMutation.isPending && (
            <div className="flex flex-col items-center justify-center py-24 gap-6">
              <LoadingSpinner className="w-10 h-10 text-primary" />
              <p className="text-[10px] font-black text-primary/40 uppercase tracking-[0.4em] animate-pulse">
                Processing Execution Trace...
              </p>
            </div>
          )}

          {result && (
            <div className="p-8 space-y-10">
              {/* Summary bar */}
              <div className="flex items-center gap-4 flex-wrap">
                <div
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-xl border text-[10px] font-black uppercase tracking-widest shadow-lg",
                    result.status === "completed"
                      ? "bg-success/10 text-success border-success/20"
                      : "bg-destructive/10 text-destructive border-destructive/20",
                  )}
                >
                  {result.status === "completed" ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5" />
                  )}
                  {result.status}
                </div>
                <div className="flex items-center gap-2 px-4 py-2 rounded-xl border border-white/5 bg-white/[0.02] text-[10px] text-muted-foreground font-black uppercase tracking-widest shadow-lg">
                  <Clock className="w-3.5 h-3.5 opacity-40" />
                  {result.durationMs}ms
                </div>
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
                        style={{
                          width: `${(succeeded / result.nodeTraces.length) * 100}%`,
                        }}
                      />
                      <div
                        className="bg-destructive h-full transition-premium"
                        style={{
                          width: `${(failed / result.nodeTraces.length) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Global error */}
              {result.error && (
                <div className="bg-destructive/5 border border-destructive/20 rounded-[2rem] p-6 flex items-start gap-4 shadow-2xl glass-light">
                  <Activity className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                  <div className="space-y-2">
                    <p className="text-[10px] font-black text-destructive uppercase tracking-[0.2em]">
                      Orchestration Failure
                    </p>
                    <p className="text-[11px] text-destructive/80 leading-relaxed font-mono font-bold">
                      {sanitizeErrorMessage(result.error)}
                    </p>
                  </div>
                </div>
              )}

              {/* Schema warnings */}
              {result.schemaWarnings.length > 0 && (
                <div className="bg-warning/5 border border-warning/15 rounded-[2rem] p-6 space-y-4 shadow-2xl glass-light">
                  <p className="text-[10px] font-black text-warning uppercase tracking-[0.2em] ml-1">
                    Protocol Schema Warnings
                  </p>
                  <div className="space-y-2">
                    {result.schemaWarnings.map((w) => (
                      <p
                        key={w}
                        className="text-[11px] text-warning/60 leading-relaxed font-bold"
                      >
                        • {w}
                      </p>
                    ))}
                  </div>
                </div>
              )}

              {/* Node traces */}
              <div className="space-y-4">
                <div className="flex items-center gap-3 px-1 mb-6">
                  <div className="h-px flex-1 bg-white/5" />
                  <p className="text-[10px] font-black text-muted-foreground/20 uppercase tracking-[0.4em]">
                    Telemetry Trace Sequence ({result.nodeTraces.length})
                  </p>
                  <div className="h-px flex-1 bg-white/5" />
                </div>
                <div className="space-y-3">
                  {result.nodeTraces.map((trace, i) => (
                    <NodeTraceCard
                      key={trace.nodeId + i}
                      trace={trace}
                      index={i}
                      nodeLabel={nodeLabelMap[trace.nodeId]}
                    />
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
