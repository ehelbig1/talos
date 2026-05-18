import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
} from "react";
import { useQuery } from "@tanstack/react-query";
import { Button, ConfirmDialog } from "@/components/ui";
import { graphqlRequest, listActors, type ActorSummary } from "@/lib/graphqlClient";
import { loadWorkflowById } from "@/lib/workflowLoader";
import { useWorkflowStore } from "@/store/workflowStore";
import { useShallow } from "zustand/react/shallow";
import {
  useEphemeralExecutionStore,
} from "@/store/executionStore";

import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  AlertCircle,
  Clock,
  Activity,
  Copy,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ExecutionWaterfall } from "./ExecutionWaterfall";
import { TimelineEvent } from "./execution/TimelineEvent";
import { ExecutionHeader } from "./execution/ExecutionHeader";
import { useActiveExecutionSync } from "@/hooks/useActiveExecutionSync";

interface Workflow {
  id: string;
  name: string;
}


export default function ExecutionPanel() {
  const [workflowId, setWorkflowId] = useState("");
  const [selectedActorId, setSelectedActorId] = useState<string>("");
  const [executionId, setExecutionId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [confirmPending, setConfirmPending] = useState<null | {
    title: string;
    message: string;
    confirmLabel: string;
    onConfirm: () => void;
  }>(null);

  const { workflowId: storeWorkflowId, nodes, clearWorkflow } = useWorkflowStore(
    useShallow((s) => ({
      workflowId: s.workflowId,
      nodes: s.nodes,
      clearWorkflow: s.clearWorkflow,
    }))
  );
  const events = useEphemeralExecutionStore((s) => s.events);
  const clearCurrentExecution = useEphemeralExecutionStore((s) => s.clearCurrentExecution);
  const isRunning = useEphemeralExecutionStore((s) => s.isRunning);
  const { copy: copyId } = useCopyToClipboard();
  const [showTimeline, setShowTimeline] = useState(false);
  const [viewMode, setViewMode] = useState<"timeline" | "waterfall">("timeline");

  // React Query for fetching workflows
  const {
    data: workflows = [],
    isLoading: loadingWorkflows,
    refetch: refetchWorkflows,
  } = useQuery<Workflow[]>({
    queryKey: ["workflows"],
    queryFn: async () => {
      const data = await graphqlRequest<{ workflows: Workflow[] }>(
        `query { workflows { id name } }`,
        {},
      );
      return data?.workflows || [];
    },
  });

  // Fetch active actors for the actor selector
  const { data: actors = [] } = useQuery<ActorSummary[]>({
    queryKey: ["actors"],
    queryFn: listActors,
    select: (data) => data.filter((a) => a.status === "active"),
  });

  // Sync with workflow currently loaded in editor
  useEffect(() => {
    setWorkflowId(storeWorkflowId || "new");
  }, [storeWorkflowId]);

  useEffect(() => {
    const handleWorkflowSaved = () => refetchWorkflows();
    window.addEventListener("workflowSaved", handleWorkflowSaved);
    return () =>
      window.removeEventListener("workflowSaved", handleWorkflowSaved);
  }, [refetchWorkflows]);

  // Centralized telemetry synchronization
  useActiveExecutionSync(workflowId);

  const startExecution = useCallback(async () => {
    setLoading(true);
    setError("");
    setShowTimeline(true);

    try {
      const hasActor = selectedActorId && selectedActorId !== "";
      const data = await graphqlRequest<{ triggerWorkflow: { id: string } }>(
        hasActor
          ? `mutation ($workflowId: UUID!, $actorId: UUID) { triggerWorkflow(workflowId: $workflowId, actorId: $actorId) { id } }`
          : `mutation ($workflowId: UUID!) { triggerWorkflow(workflowId: $workflowId) { id } }`,
        hasActor
          ? { workflowId, actorId: selectedActorId }
          : { workflowId },
      );

      const execId = data.triggerWorkflow.id;
      setExecutionId(execId);
      
      // The useActiveExecutionSync hook will pick up this new execution automatically
      // via the global workflow_execution_updates stream and start the detail subscription.
      
    } catch (e: unknown) {
      setError(
        sanitizeErrorMessage(
          e instanceof Error ? e.message : "Execution failed",
        ),
      );
      clearCurrentExecution();
    } finally {
      setLoading(false);
    }
  }, [
    workflowId,
    selectedActorId,
    clearCurrentExecution,
  ]);

  const handleWorkflowSelect = useCallback(
    async (selectedWorkflowId: string) => {
      if (
        !selectedWorkflowId ||
        selectedWorkflowId === storeWorkflowId ||
        selectedWorkflowId.includes("Loading") ||
        selectedWorkflowId.includes("found")
      ) {
        return;
      }

      if (selectedWorkflowId === "new") {
        if (nodes.length > 0 && storeWorkflowId) {
          setConfirmPending({
            title: "New Workflow",
            message:
              "Clear the current workflow? Unsaved changes will be lost.",
            confirmLabel: "Clear",
            onConfirm: () => {
              setConfirmPending(null);
              clearWorkflow();
            },
          });
        } else {
          clearWorkflow();
        }
        return;
      }

      setWorkflowId(selectedWorkflowId);
      if (selectedWorkflowId) {
        try {
          await loadWorkflowById(selectedWorkflowId);
        } catch (err: unknown) {
          if (import.meta.env.DEV)
            console.error("loadWorkflowById error:", err);
          setError(
            "Failed to load workflow: " +
              sanitizeErrorMessage(
                err instanceof Error ? err.message : String(err),
              ),
          );
          setWorkflowId(storeWorkflowId || "new");
        }
      }
    },
    [nodes.length, storeWorkflowId, clearWorkflow],
  );


  const nodeNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const n of nodes) {
      map.set(n.id, n.data.moduleName ?? n.data.label ?? n.id.slice(0, 8) + "…");
    }
    return map;
  }, [nodes]);

  const resolveNodeName = useCallback(
    (nodeId: string | undefined): string | undefined =>
      nodeId ? nodeNameMap.get(nodeId) ?? nodeId.slice(0, 8) + "…" : undefined,
    [nodeNameMap],
  );

  return (
    <div className="flex flex-col bg-surface-1/60 backdrop-blur-3xl border-l border-white/5 text-foreground shadow-2xl relative overflow-hidden transition-premium">
      <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
      
      <ConfirmDialog
        open={confirmPending !== null}
        title={confirmPending?.title ?? "Confirm"}
        message={confirmPending?.message ?? ""}
        confirmLabel={confirmPending?.confirmLabel ?? "Confirm"}
        destructive
        onConfirm={() => confirmPending?.onConfirm()}
        onCancel={() => setConfirmPending(null)}
      />

      {/* Header / Workflow Selector */}
      <ExecutionHeader
        workflowId={workflowId}
        workflows={workflows}
        loadingWorkflows={loadingWorkflows}
        onWorkflowSelect={handleWorkflowSelect}
        onRefresh={() => refetchWorkflows()}
        actors={actors}
        selectedActorId={selectedActorId}
        onActorSelect={setSelectedActorId}
        isRunning={isRunning}
        loading={loading}
        onRun={startExecution}
        showTimeline={showTimeline}
        onToggleTimeline={() => setShowTimeline(!showTimeline)}
        eventCount={events.length}
      />

      {/* Main Content Area — Only visible when telemetry is toggled */}
      {showTimeline && (
        <div className="border-t border-white/5 overflow-hidden flex flex-col bg-surface-2/60 backdrop-blur-3xl animate-in slide-in-from-top-4 duration-500 relative z-20">
          {executionId && (
            <div className="px-6 py-2 bg-white/5 border-b border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <span className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/30">
                  Active Session
                </span>
                <div className="flex items-center gap-2 group">
                  <code className="text-[10px] text-primary font-mono bg-primary/10 px-2 py-1 rounded-lg border border-primary/20 shadow-[0_0_10px_hsla(var(--primary),0.1)]">
                    {executionId.slice(0, 16)}...
                  </code>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => copyId(executionId)}
                    className="h-7 w-7 text-muted-foreground/40 hover:text-primary hover:bg-primary/10 transition-premium rounded-lg"
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              {error && (
                <div className="flex items-center gap-3 px-3 py-1 bg-destructive/10 border border-destructive/20 rounded-full">
                  <AlertCircle className="h-3.5 w-3.5 text-destructive" />
                  <span className="text-[10px] text-destructive font-black uppercase tracking-tight truncate max-w-[250px]">
                    {error}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Controls bar */}
          <div className="px-6 py-2 flex gap-4 items-center border-b border-white/[0.03]">
            {events.length > 1 && (
              <div className="flex items-center gap-4 mr-4">
                <Clock className="h-4 w-4 text-muted-foreground/30" />
                <input
                  type="range"
                  min={0}
                  max={events.length - 1}
                  defaultValue={events.length - 1}
                  className="w-32 h-1 bg-white/5 rounded-full accent-primary cursor-pointer transition-premium hover:accent-primary-foreground"
                  onChange={(e) => {
                    const idx = Number(e.target.value);
                    const container = document.querySelector('.custom-scrollbar');
                    if (container) {
                      const children = container.querySelectorAll('[data-event-idx]');
                      children[idx]?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                  }}
                />
                <span className="text-[10px] font-black text-muted-foreground/30 tabular-nums min-w-[3ch]">
                  {events.length} EVENTS
                </span>
              </div>
            )}
            <div className="flex p-1 bg-surface-3/40 rounded-xl border border-white/5">
              {(["timeline", "waterfall"] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setViewMode(mode)}
                  className={cn(
                    "px-4 py-1.5 text-[9px] font-black uppercase tracking-widest rounded-lg transition-premium",
                    viewMode === mode
                      ? "bg-primary text-primary-foreground shadow-lg shadow-primary/20"
                      : "text-muted-foreground/40 hover:text-white"
                  )}
                >
                  {mode.charAt(0).toUpperCase() + mode.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Feed area */}
          <div className="max-h-[40vh] overflow-y-auto px-6 py-8 custom-scrollbar relative z-10">
            {events.length === 0 ? (
              <div className="py-20 flex flex-col items-center justify-center text-center">
                <div className="relative mb-8 group">
                    <div className="absolute -inset-10 bg-primary/5 rounded-full blur-[60px] opacity-0 group-hover:opacity-100 transition-premium animate-pulse" />
                    <div className="relative p-8 rounded-[3.5rem] bg-surface-2/40 border border-white/5 shadow-2xl transition-premium group-hover:scale-105 group-hover:border-primary/20">
                        <Activity className="h-16 w-16 text-muted-foreground/20 group-hover:text-primary transition-premium stroke-[1px]" />
                    </div>
                </div>
                <div className="space-y-3 max-w-[280px]">
                    <h3 className="text-xl font-black tracking-tighter text-white font-outfit uppercase opacity-40">
                      Telemetry Core
                    </h3>
                    <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em] leading-relaxed">
                      Initialize protocol to synchronize data streams.
                    </p>
                </div>
              </div>
            ) : viewMode === "waterfall" ? (
              <ExecutionWaterfall
                events={events}
                nodeNames={Object.fromEntries(
                  events
                    .filter((e) => e.nodeId)
                    .map((e) => [e.nodeId!, resolveNodeName(e.nodeId) ?? e.nodeId!.slice(0, 8)])
                )}
              />
            ) : (
              <div className="space-y-4 relative">
                <div className="absolute left-[47px] top-8 bottom-8 w-[1px] bg-white/[0.03]" />
                {events.map((ev, idx) => (
                  <TimelineEvent
                    key={`${ev.nodeId || "global"}-${ev.status}-${idx}`}
                    ev={ev}
                    idx={idx}
                    nodeName={resolveNodeName(ev.nodeId)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
