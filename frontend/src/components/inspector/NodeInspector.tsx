import React, { useState, useMemo, useRef, useEffect } from "react";
import type { Node } from "@xyflow/react";
import { toast } from "sonner";
import {
  Puzzle,
  Settings,
  Activity,
  ChevronDown,
  AlertCircle,
  Clock,
  CheckCircle2,
  FileText,
  Copy,
  Zap,
  X,
} from "lucide-react";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
  FormField,
  Textarea,
  Input,
} from "@/components/ui";
import { useShallow } from "zustand/react/shallow";
import { cn } from "@/lib/utils";
import type { WorkflowNodeData } from "@/store/workflowStore";
import {
  CapabilityBadge,
  LlmConfigSection,
  RetryPolicySection,
  SystemInternalsSection,
} from "./InspectorSections";
import {
  useEphemeralExecutionStore,
  type NodeStatusType,
  type TimedEvent,
  type EphemeralSlice,
} from "@/store/executionStore";
import { getFixSuggestion } from "@/lib/fixSuggestions";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { ExecutionHistory } from "../ExecutionHistory";
import { NodeConfigForm } from "../NodeConfigForm";

const STATUS_DOT: Record<NodeStatusType, string> = {
  idle: "bg-muted-foreground/20",
  running:
    "bg-primary animate-status-pulse shadow-[0_0_10px_hsla(var(--primary),0.5)]",
  success: "bg-success shadow-[0_0_10px_hsla(var(--success),0.5)]",
  failed: "bg-destructive shadow-[0_0_10px_hsla(var(--destructive),0.5)]",
  awaiting_approval:
    "bg-warning animate-pulse shadow-[0_0_10px_hsla(var(--warning),0.5)]",
};

const STATUS_LABEL: Record<NodeStatusType, string> = {
  idle: "STATUS_IDLE",
  running: "EXECUTING_LOGIC",
  success: "SEQUENCE_COMPLETE",
  failed: "EXECUTION_FAILURE",
  awaiting_approval: "PENDING_AUTHORIZATION",
};

interface NodeInspectorProps {
  node: Node<WorkflowNodeData>;
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => void;
  deleteNode: (id: string) => void;
  onClose: () => void;
}

export const NodeInspector: React.FC<NodeInspectorProps> = ({
  node,
  updateNodeData,
  deleteNode,
  onClose,
}) => {
  const [copiedNodeId, setCopiedNodeId] = useState(false);
  const [copiedModuleId, setCopiedModuleId] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [internalsOpen, setInternalsOpen] = useState(false);
  const copyNodeIdTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );
  const copyModuleIdTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  useEffect(() => {
    return () => {
      if (copyNodeIdTimeoutRef.current)
        clearTimeout(copyNodeIdTimeoutRef.current);
      if (copyModuleIdTimeoutRef.current)
        clearTimeout(copyModuleIdTimeoutRef.current);
    };
  }, []);

  // Execution Store Data
  const nodeStatus = useEphemeralExecutionStore(
    (state: EphemeralSlice) => state.nodeStatuses[node.id],
  );
  const nodeEvents = useEphemeralExecutionStore(
    useShallow((state: EphemeralSlice) =>
      state.events.filter((e: TimedEvent) => e.nodeId === node.id),
    ),
  );
  const nodeResult = useEphemeralExecutionStore(
    (state: EphemeralSlice) => state.nodeResults[node.id],
  );

  const status: NodeStatusType = nodeStatus?.status ?? "idle";
  const fixSuggestion =
    status === "failed" && nodeStatus?.error
      ? getFixSuggestion(nodeStatus.error)
      : undefined;

  const handleCopyNodeId = async () => {
    try {
      await navigator.clipboard.writeText(node.id);
      setCopiedNodeId(true);
      if (copyNodeIdTimeoutRef.current)
        clearTimeout(copyNodeIdTimeoutRef.current);
      copyNodeIdTimeoutRef.current = setTimeout(
        () => setCopiedNodeId(false),
        2000,
      );
      toast.success("Node ID copied");
    } catch {
      // Clipboard API unavailable
    }
  };

  const handleCopyModuleId = async () => {
    if (node.data.moduleId) {
      try {
        await navigator.clipboard.writeText(node.data.moduleId as string);
        setCopiedModuleId(true);
        if (copyModuleIdTimeoutRef.current)
          clearTimeout(copyModuleIdTimeoutRef.current);
        copyModuleIdTimeoutRef.current = setTimeout(
          () => setCopiedModuleId(false),
          2000,
        );
        toast.success("Module ID copied");
      } catch {
        // Clipboard API unavailable
      }
    }
  };

  return (
    <div className="flex flex-col h-full bg-surface-2/80 backdrop-blur-3xl relative border-l border-white/5 shadow-[-20px_0_50px_rgba(0,0,0,0.4)] animate-in slide-in-from-right duration-500">
      <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent opacity-20 pointer-events-none" />

      {/* Header */}
      <div className="flex items-center justify-between px-8 py-6 border-b border-white/5 bg-white/[0.02] relative z-10">
        <div className="flex items-center gap-5">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_20px_hsla(var(--primary),0.15)] relative group overflow-hidden">
            <div className="absolute inset-0 bg-primary/20 opacity-0 group-hover:opacity-100 transition-premium blur-xl" />
            <Puzzle className="w-6 h-6 text-primary relative z-10" />
          </div>
          <div>
            <h3 className="text-lg font-black text-white tracking-tight font-outfit uppercase">
              {node.data.label as string}
            </h3>
            <div className="flex items-center gap-2 mt-1">
              <div
                className={cn("w-1.5 h-1.5 rounded-full", STATUS_DOT[status])}
              />
              <p className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.2em]">
                {STATUS_LABEL[status]}
              </p>
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="w-10 h-10 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-muted-foreground/40 hover:text-white hover:bg-white/10 transition-premium active:scale-95 shadow-xl"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      <Tabs
        defaultValue="config"
        className="flex-1 flex flex-col overflow-hidden relative z-10"
      >
        <div className="px-8 pt-6 pb-2 border-b border-white/5 bg-white/[0.01]">
          <TabsList className="w-full justify-start rounded-2xl border border-white/5 bg-black/20 p-1.5 gap-1 shrink-0 h-auto">
            <TabsTrigger
              value="config"
              className="flex-1 text-[10px] font-black uppercase tracking-[0.2em] data-[state=active]:text-white data-[state=active]:bg-primary/20 data-[state=active]:border-primary/20 border border-transparent text-muted-foreground/40 rounded-xl py-3 px-5 transition-premium"
            >
              <Settings className="w-3.5 h-3.5 mr-2 opacity-40" />
              Configuration
            </TabsTrigger>
            <TabsTrigger
              value="logs"
              className="flex-1 text-[10px] font-black uppercase tracking-[0.2em] data-[state=active]:text-white data-[state=active]:bg-primary/20 data-[state=active]:border-primary/20 border border-transparent text-muted-foreground/40 rounded-xl py-3 px-5 transition-premium"
            >
              <Activity className="w-3.5 h-3.5 mr-2 opacity-40" />
              Diagnostics
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent
          value="config"
          className="flex-1 overflow-auto p-8 space-y-10 custom-scrollbar focus:outline-none"
        >
          <div className="flex flex-wrap gap-2.5">
            {node.data.capabilityWorld && (
              <CapabilityBadge
                capability={node.data.capabilityWorld as string}
                importedInterfaces={node.data.importedInterfaces as string[]}
              />
            )}
          </div>

          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-500">
            <div className="space-y-4">
              <label className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] ml-1">
                Node Parameters
              </label>
              <div className="bg-surface-3/40 border border-white/5 rounded-[2rem] p-6 glass-dark shadow-2xl">
                <NodeConfigForm
                  type={node.data.systemNodeKind || node.data.moduleId}
                  config={node.data.config || {}}
                  onChange={(newConfig) =>
                    updateNodeData(node.id, { config: newConfig })
                  }
                />
              </div>
            </div>

            <LlmConfigSection
              nodeId={node.id}
              data={node.data}
              updateNodeData={updateNodeData}
            />

            {/* Advanced Section */}
            <div className="space-y-4">
              <Collapsible
                open={advancedOpen}
                onOpenChange={setAdvancedOpen}
                className="border border-white/5 rounded-[2rem] bg-white/[0.02] overflow-hidden transition-premium hover:bg-white/[0.03]"
              >
                <CollapsibleTrigger className="flex items-center gap-4 w-full px-8 py-5 text-[10px] font-black text-muted-foreground/60 uppercase tracking-[0.3em] hover:text-white transition-premium group">
                  <Zap className="w-4 h-4 text-primary opacity-40 group-hover:opacity-100 transition-premium" />
                  <span>Execution Controls</span>
                  <div className="flex-1 h-px bg-white/5" />
                  <ChevronDown
                    className={cn(
                      "w-4 h-4 transition-premium",
                      advancedOpen && "rotate-180",
                    )}
                  />
                </CollapsibleTrigger>
                <CollapsibleContent className="px-8 pb-8 space-y-8 animate-in slide-in-from-top-4 duration-300">
                  <div className="space-y-6">
                    <FormField label="Conditional Skip (Rhai Script)">
                      <Textarea
                        placeholder="ctx.input.score < 0.5"
                        className="bg-black/40 border-white/5 focus:border-primary/40 focus:ring-primary/10 font-mono text-[11px] min-h-[100px] rounded-2xl selection:bg-primary/30 leading-relaxed p-4"
                        value={node.data.skipCondition ?? ""}
                        onChange={(e) =>
                          updateNodeData(node.id, {
                            skipCondition: e.target.value,
                          })
                        }
                      />
                    </FormField>

                    <div className="flex items-center justify-between p-6 rounded-2xl bg-black/40 border border-white/5 shadow-xl">
                      <div className="space-y-1">
                        <label className="text-[10px] font-black text-white uppercase tracking-widest">
                          Fault Immunity
                        </label>
                        <p className="text-[9px] text-muted-foreground/40 font-bold uppercase tracking-tight">
                          Continue sequence despite operational failure
                        </p>
                      </div>
                      <div
                        onClick={() =>
                          updateNodeData(node.id, {
                            continueOnError: !node.data.continueOnError,
                          })
                        }
                        className={cn(
                          "w-12 h-6 rounded-full border p-1 cursor-pointer transition-premium relative",
                          node.data.continueOnError
                            ? "bg-primary/20 border-primary/40"
                            : "bg-white/5 border-white/10",
                        )}
                      >
                        <div
                          className={cn(
                            "w-4 h-4 rounded-full transition-premium shadow-lg",
                            node.data.continueOnError
                              ? "bg-primary translate-x-6"
                              : "bg-white/20 translate-x-0",
                          )}
                        />
                      </div>
                    </div>

                    <FormField label="Execution Deadline (Seconds)">
                      <Input
                        type="number"
                        placeholder="30"
                        className="bg-black/40 border-white/5 focus:border-primary/40 focus:ring-primary/10 rounded-2xl h-12 px-6"
                        value={node.data.timeoutSecs ?? ""}
                        onChange={(e) =>
                          updateNodeData(node.id, {
                            timeoutSecs: parseInt(e.target.value) || undefined,
                          })
                        }
                      />
                    </FormField>
                  </div>

                  <div className="space-y-6 pt-8 border-t border-white/5">
                    <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-[0.2em] ml-1">
                      Self-Healing Policy
                    </p>
                    <RetryPolicySection
                      nodeId={node.id}
                      data={node.data}
                      updateNodeData={updateNodeData}
                    />
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </div>

            {/* System Internals */}
            <div className="space-y-4">
              <Collapsible
                open={internalsOpen}
                onOpenChange={setInternalsOpen}
                className="border border-white/5 rounded-[2rem] bg-white/[0.01] overflow-hidden transition-premium hover:bg-white/[0.02]"
              >
                <CollapsibleTrigger className="flex items-center gap-4 w-full px-8 py-5 text-[10px] font-black text-muted-foreground/40 uppercase tracking-[0.3em] hover:text-white transition-premium group">
                  <Activity className="w-4 h-4 text-muted-foreground/20 group-hover:text-primary transition-premium" />
                  <span>Core Metadata</span>
                  <div className="flex-1 h-px bg-white/5" />
                  <ChevronDown
                    className={cn(
                      "w-4 h-4 transition-premium",
                      internalsOpen && "rotate-180",
                    )}
                  />
                </CollapsibleTrigger>
                <CollapsibleContent className="px-8 pb-8">
                  <SystemInternalsSection
                    node={node}
                    moduleId={node.data.moduleId as string}
                    copiedNodeId={copiedNodeId}
                    copiedModuleId={copiedModuleId}
                    onCopyNodeId={handleCopyNodeId}
                    onCopyModuleId={handleCopyModuleId}
                    onDelete={() => deleteNode(node.id)}
                  />
                </CollapsibleContent>
              </Collapsible>
            </div>
          </div>
        </TabsContent>

        <TabsContent
          value="logs"
          className="flex-1 overflow-auto p-8 space-y-10 custom-scrollbar focus:outline-none"
        >
          <div className="space-y-10 animate-in fade-in slide-in-from-bottom-2 duration-500">
            {/* Status Panel */}
            <div className="p-6 rounded-[2rem] bg-surface-3/40 border border-white/5 shadow-2xl glass-dark relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
              <div className="flex items-center justify-between relative z-10">
                <div className="flex items-center gap-5">
                  <div
                    className={cn(
                      "w-3 h-3 rounded-full relative",
                      STATUS_DOT[status],
                    )}
                  >
                    <div
                      className={cn(
                        "absolute inset-0 rounded-full animate-ping opacity-20",
                        STATUS_DOT[status],
                      )}
                    />
                  </div>
                  <span className="text-sm font-black text-white tracking-[0.2em] uppercase font-outfit">
                    {STATUS_LABEL[status]}
                  </span>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest">
                    REAL_TIME_TELEMETRY
                  </span>
                  <div className="flex gap-1">
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                        className="w-1 h-3 bg-primary/20 rounded-full animate-pulse"
                        style={{ animationDelay: `${i * 150}ms` }}
                      />
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {nodeStatus?.error && (
              <div className="p-8 rounded-[2rem] bg-destructive/5 border border-destructive/10 space-y-5 shadow-2xl relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-destructive/10 via-transparent to-transparent opacity-50" />
                <div className="flex items-center gap-4 text-destructive relative z-10">
                  <div className="w-10 h-10 rounded-2xl bg-destructive/10 border border-destructive/20 flex items-center justify-center">
                    <AlertCircle className="w-5 h-5" />
                  </div>
                  <span className="text-[11px] font-black uppercase tracking-[0.3em]">
                    CRITICAL_FAULT_DETECTED
                  </span>
                </div>
                <div className="bg-black/40 p-6 rounded-2xl border border-destructive/10 relative z-10">
                  <p className="text-[12px] text-destructive/90 leading-relaxed font-mono selection:bg-destructive/30 break-all">
                    {sanitizeErrorMessage(nodeStatus.error)}
                  </p>
                </div>
                {fixSuggestion && (
                  <div className="p-5 bg-warning/5 border border-warning/10 rounded-2xl text-warning relative z-10 flex gap-4 shadow-xl">
                    <Zap className="w-5 h-5 shrink-0 text-warning animate-pulse" />
                    <div className="space-y-1">
                      <span className="text-[9px] font-black uppercase tracking-widest opacity-40 block">
                        HEAL_DIRECTIVE
                      </span>
                      <p className="text-[11px] font-black uppercase tracking-tight leading-relaxed italic">
                        {fixSuggestion}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {!!nodeResult && (
              <div className="space-y-4">
                <div className="flex items-center justify-between px-2">
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                      <FileText size={16} />
                    </div>
                    <label className="text-[10px] font-black text-white uppercase tracking-[0.3em]">
                      Result Payload
                    </label>
                  </div>
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(
                          JSON.stringify(nodeResult, null, 2),
                        );
                        toast.success("Payload copied to clipboard");
                      } catch {
                        // Clipboard API unavailable
                      }
                    }}
                    className="w-10 h-10 flex items-center justify-center hover:bg-white/10 rounded-xl border border-white/5 text-muted-foreground/40 hover:text-white transition-premium shadow-xl"
                    title="Copy Payload"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
                <div className="p-6 bg-black/40 border border-white/5 rounded-[2rem] shadow-inner relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-20 pointer-events-none" />
                  <pre className="text-[11px] text-foreground/70 font-mono overflow-auto max-h-[400px] selection:bg-primary/30 relative z-10 leading-relaxed custom-scrollbar p-2">
                    {JSON.stringify(nodeResult, null, 2)}
                  </pre>
                  {/* Subtle scanline effect */}
                  <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.02),rgba(0,255,0,0.01),rgba(0,0,255,0.02))] bg-[length:100%_4px,3px_100%]" />
                </div>
              </div>
            )}

            {nodeEvents.length > 0 && (
              <div className="space-y-5">
                <div className="flex items-center gap-4 px-2">
                  <div className="w-8 h-8 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-muted-foreground/40">
                    <Clock size={16} />
                  </div>
                  <label className="text-[10px] font-black text-muted-foreground/40 uppercase tracking-[0.3em]">
                    Protocol Timeline
                  </label>
                </div>
                <div className="space-y-4 bg-white/[0.01] p-6 rounded-[2rem] border border-white/5 shadow-2xl relative overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-tr from-white/[0.01] to-transparent opacity-50 pointer-events-none" />
                  {nodeEvents.map((ev: TimedEvent, idx: number) => (
                    <div
                      key={`${ev.nodeId ?? "global"}-${ev.elapsedMs}-${idx}`}
                      className="flex gap-6 text-[10px] pb-5 border-b border-white/[0.03] last:border-0 last:pb-0 relative z-10 group"
                    >
                      <div className="flex flex-col items-center gap-2 shrink-0">
                        <span className="text-muted-foreground/20 font-black w-14 tabular-nums text-right group-hover:text-primary/40 transition-premium">
                          +{(ev.elapsedMs / 1000).toFixed(2)}s
                        </span>
                      </div>
                      <div className="flex-1 space-y-2">
                        <div className="flex items-center gap-3">
                          {ev.status === "SUCCESS" && (
                            <CheckCircle2 className="w-3.5 h-3.5 text-success/60" />
                          )}
                          <span
                            className={cn(
                              "block font-black uppercase tracking-widest text-[11px]",
                              ev.status === "FAILED"
                                ? "text-destructive"
                                : ev.status === "AwaitingApproval"
                                  ? "text-warning"
                                  : "text-white/60 group-hover:text-white transition-premium",
                            )}
                          >
                            {ev.logMessage || ev.status}
                          </span>
                        </div>
                        {ev.retryAttempt != null && ev.retryAttempt > 0 && (
                          <span className="inline-block text-[8px] px-3 py-1 rounded-full bg-warning/5 text-warning border border-warning/10 uppercase font-black tracking-[0.2em] shadow-lg">
                            RECOVERY_ATTEMPT_{ev.retryAttempt}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-10 border-t border-white/5">
              <div className="flex items-center gap-4 mb-6 px-2">
                <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                  <Activity size={16} />
                </div>
                <label className="text-[10px] font-black text-white uppercase tracking-[0.3em]">
                  Historical Metrics
                </label>
              </div>
              <ExecutionHistory moduleId={node.data.moduleId as string} />
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};
