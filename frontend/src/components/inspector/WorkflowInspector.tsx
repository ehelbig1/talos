import React from "react";
import { useNavigate } from "react-router-dom";
import {
  Layout,
  Info,
  AlertTriangle,
  Zap,
  X,
  Calendar,
  Webhook,
  Play,
  Clock,
  ChevronDown,
} from "lucide-react";
import { toast } from "sonner";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
  CopyField,
} from "@/components/ui";
import { WorkflowExecutionHistoryPanel } from "../WorkflowExecutionHistoryPanel";
import { useWorkflowStore } from "@/store/workflowStore";
import { useShallow } from "zustand/react/shallow";
import { cn } from "@/lib/utils";

function TriggersSection({ workflowId }: { workflowId: string | null }) {
  const navigate = useNavigate();

  if (!workflowId) return null;

  const triggers = [
    {
      icon: Calendar,
      label: "CHRONOS SCHEDULE",
      desc: "Deterministic time-based execution",
      onClick: () => navigate("/settings#schedules"),
      color: "text-warning",
      glow: "shadow-[0_0_15px_hsla(var(--warning),0.1)]",
    },
    {
      icon: Webhook,
      label: "UPLINK WEBHOOK",
      desc: "Reactive HTTP-triggered execution",
      onClick: () => navigate("/settings#webhooks"),
      color: "text-primary",
      glow: "shadow-[0_0_15px_hsla(var(--primary),0.1)]",
    },
    {
      icon: Play,
      label: "MANUAL COMMAND",
      desc: "Direct operator-led execution",
      onClick: undefined,
      color: "text-success",
      glow: "shadow-[0_0_15px_hsla(var(--success),0.1)]",
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-[10px] text-muted-foreground/40 uppercase tracking-[0.2em] font-black ml-1">
        OPERATIONAL TRIGGERS
      </p>
      <div className="grid grid-cols-1 gap-2">
        {triggers.map((t) => (
          <button
            key={t.label}
            onClick={t.onClick}
            disabled={!t.onClick}
            className={cn(
              "w-full flex items-center gap-4 px-4 py-3 rounded-2xl border border-white/5 bg-white/[0.02] hover:bg-white/[0.04] transition-premium text-left disabled:opacity-40 disabled:cursor-default group relative overflow-hidden",
              t.onClick && "hover:border-white/10 shadow-xl",
            )}
          >
            <div
              className={cn(
                "p-2 rounded-xl bg-white/5 border border-white/10 transition-premium group-hover:scale-110",
                t.color,
              )}
            >
              <t.icon className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] text-white font-black uppercase tracking-widest font-outfit">
                {t.label}
              </p>
              <p className="text-[9px] text-muted-foreground/40 font-bold uppercase tracking-tight">
                {t.desc}
              </p>
            </div>
            {t.onClick && (
              <span className="text-[9px] text-primary font-black uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-premium">
                CONFIGURE →
              </span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}

interface WorkflowInspectorProps {
  workflowName: string;
  workflowId: string | null;
  nodeCount: number;
  edgeCount: number;
  onClose: () => void;
}

export const WorkflowInspector: React.FC<WorkflowInspectorProps> = ({
  workflowName,
  workflowId,
  nodeCount,
  edgeCount,
  onClose,
}) => {
  const {
    maxConcurrentExecutions,
    setMaxConcurrentExecutions,
    priority,
    setPriority,
    intent,
    setIntent,
  } = useWorkflowStore(
    useShallow((s) => ({
      maxConcurrentExecutions: s.maxConcurrentExecutions,
      setMaxConcurrentExecutions: s.setMaxConcurrentExecutions,
      priority: s.priority,
      setPriority: s.setPriority,
      intent: s.intent,
      setIntent: s.setIntent,
    })),
  );

  const [jsonText, setJsonText] = React.useState(
    JSON.stringify(intent || {}, null, 2),
  );
  const [jsonError, setJsonError] = React.useState<string | null>(null);
  const [copiedWorkflowId, setCopiedWorkflowId] = React.useState(false);
  const copyTimeoutRef = React.useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  React.useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  // Sync the internal textarea buffer when the store's `intent` changes
  // externally. Done during render via the "store information from
  // previous renders" pattern (https://react.dev/learn/you-might-not-need-an-effect)
  // rather than a setState-in-effect: we re-serialize only when the
  // `intent` reference actually changes, and skip the sync while the
  // user has an unparseable edit in flight (`jsonError`) so we don't
  // clobber their in-progress text.
  const [lastSyncedIntent, setLastSyncedIntent] = React.useState(intent);
  if (intent !== lastSyncedIntent) {
    setLastSyncedIntent(intent);
    if (!jsonError) {
      try {
        const currentText = JSON.stringify(intent || {}, null, 2);
        if (currentText !== jsonText) {
          setJsonText(currentText);
        }
      } catch {
        // ignore serialization errors
      }
    }
  }

  const handleJsonChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    setJsonText(value);

    try {
      if (value.trim() === "") {
        setIntent({});
        setJsonError(null);
        return;
      }
      const parsed = JSON.parse(value);
      setIntent(parsed);
      setJsonError(null);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : "Invalid JSON");
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
            <Layout className="w-6 h-6 text-primary relative z-10" />
          </div>
          <div>
            <h3 className="text-lg font-black text-white tracking-tight font-outfit uppercase">
              Workflow Registry
            </h3>
            <p className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.2em] mt-1">
              Global Configuration Hub
            </p>
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
        defaultValue="info"
        className="flex-1 min-h-0 flex flex-col overflow-hidden relative z-10"
      >
        <div className="px-8 pt-6 pb-2 border-b border-white/5 bg-white/[0.01]">
          <TabsList className="w-full justify-start rounded-2xl border border-white/5 bg-black/20 p-1.5 gap-1 shrink-0 h-auto">
            <TabsTrigger
              value="info"
              className="flex-1 text-[10px] font-black uppercase tracking-[0.2em] data-[state=active]:text-white data-[state=active]:bg-primary/20 data-[state=active]:border-primary/20 border border-transparent text-muted-foreground/40 rounded-xl py-3 px-5 transition-premium"
            >
              <Info className="w-3.5 h-3.5 mr-2 opacity-40" />
              Manifest
            </TabsTrigger>
            <TabsTrigger
              value="executions"
              className="flex-1 text-[10px] font-black uppercase tracking-[0.2em] data-[state=active]:text-white data-[state=active]:bg-primary/20 data-[state=active]:border-primary/20 border border-transparent text-muted-foreground/40 rounded-xl py-3 px-5 transition-premium"
            >
              <Clock className="w-3.5 h-3.5 mr-2 opacity-40" />
              History
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent
          value="info"
          className="flex-1 min-h-0 overflow-auto p-8 space-y-10 animate-in fade-in slide-in-from-bottom-2 duration-500 custom-scrollbar focus:outline-none"
        >
          <div className="space-y-4">
            <label className="text-[10px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
              Protocol Designation
            </label>
            <div className="p-6 bg-surface-3/40 border border-white/5 rounded-[2rem] glass-dark shadow-2xl relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
              <p className="text-3xl font-black text-white tracking-tighter font-outfit leading-none selection:bg-primary/30 break-all">
                {workflowName || "UNTITLED_STREAM"}
              </p>
            </div>
          </div>

          {workflowId && (
            <div className="space-y-4">
              <label className="text-[10px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black ml-1">
                System Identity
              </label>
              <CopyField
                label="SYSTEM_UUID"
                value={workflowId}
                copied={copiedWorkflowId}
                onCopy={async () => {
                  try {
                    await navigator.clipboard.writeText(workflowId);
                    setCopiedWorkflowId(true);
                    if (copyTimeoutRef.current)
                      clearTimeout(copyTimeoutRef.current);
                    copyTimeoutRef.current = setTimeout(
                      () => setCopiedWorkflowId(false),
                      2000,
                    );
                    toast.success("Workflow ID copied");
                  } catch {
                    // Clipboard API unavailable
                  }
                }}
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="p-6 bg-white/[0.02] border border-white/5 rounded-[2rem] shadow-xl glass-dark group hover:bg-white/[0.04] transition-premium">
              <div className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black mb-3">
                TOPOLOGY_NODES
              </div>
              <div className="flex items-center gap-3">
                <div className="w-1.5 h-6 bg-primary/40 rounded-full" />
                <div className="text-3xl font-black text-white font-outfit">
                  {nodeCount}
                </div>
              </div>
            </div>
            <div className="p-6 bg-white/[0.02] border border-white/5 rounded-[2rem] shadow-xl glass-dark group hover:bg-white/[0.04] transition-premium">
              <div className="text-[9px] text-muted-foreground/30 uppercase tracking-[0.3em] font-black mb-3">
                DATA_EDGES
              </div>
              <div className="flex items-center gap-3">
                <div className="w-1.5 h-6 bg-success/40 rounded-full" />
                <div className="text-3xl font-black text-white font-outfit">
                  {edgeCount}
                </div>
              </div>
            </div>
          </div>

          <TriggersSection workflowId={workflowId} />

          <div className="p-8 bg-primary/5 border border-primary/10 rounded-[2.5rem] space-y-8 shadow-2xl relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-transparent to-transparent opacity-50" />
            <h4 className="text-[12px] font-black text-white flex items-center gap-4 uppercase tracking-[0.3em] font-outfit relative z-10">
              <div className="p-2.5 rounded-2xl bg-primary/10 border border-primary/20 shadow-[0_0_20px_hsla(var(--primary),0.15)] group-hover:scale-110 transition-premium">
                <Zap className="w-5 h-5 text-primary" />
              </div>
              Operational Constraints
            </h4>

            <div className="space-y-8 relative z-10">
              <div className="space-y-3">
                <label className="text-[10px] text-muted-foreground/40 uppercase tracking-[0.2em] font-black ml-1">
                  Concurrency Limit
                </label>
                <div className="flex items-center gap-5">
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={maxConcurrentExecutions}
                    onChange={(e) =>
                      setMaxConcurrentExecutions(parseInt(e.target.value) || 1)
                    }
                    className="w-24 bg-black/40 border border-white/5 rounded-2xl px-6 py-3 text-sm focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium font-black text-white shadow-inner"
                  />
                  <div className="text-[10px] text-muted-foreground/20 font-bold uppercase tracking-[0.2em] italic">
                    SYSTEM_DEFAULT: 01
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <label className="text-[10px] text-muted-foreground/40 uppercase tracking-[0.2em] font-black ml-1">
                  Runtime Priority
                </label>
                <div className="relative">
                  <select
                    value={priority}
                    onChange={(e) =>
                      setPriority(e.target.value as "high" | "normal" | "low")
                    }
                    className="w-full bg-black/40 border border-white/5 rounded-2xl px-6 py-4 text-[11px] font-black uppercase tracking-[0.3em] focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium appearance-none cursor-pointer hover:bg-black/60 text-white shadow-inner"
                  >
                    <option value="low">LOW_PRIORITY</option>
                    <option value="normal">NORMAL_PRIORITY</option>
                    <option value="high">HIGH_PRIORITY</option>
                  </select>
                  <ChevronDown className="absolute right-6 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/20 pointer-events-none" />
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex justify-between items-center px-1">
                  <label className="text-[10px] text-muted-foreground/40 uppercase tracking-[0.2em] font-black">
                    Intent Metadata (JSON)
                  </label>
                  {jsonError && (
                    <span className="text-[9px] text-destructive font-black animate-pulse uppercase tracking-widest bg-destructive/10 px-2 py-0.5 rounded border border-destructive/20">
                      SCHEMA_INVALID
                    </span>
                  )}
                </div>
                <textarea
                  value={jsonText}
                  onChange={handleJsonChange}
                  rows={6}
                  className={cn(
                    "w-full bg-black/40 border transition-premium rounded-[2rem] p-6 text-[11px] font-mono focus:outline-none focus:ring-4 resize-none shadow-inner leading-relaxed selection:bg-primary/30 custom-scrollbar",
                    jsonError
                      ? "border-destructive/40 focus:ring-destructive/10"
                      : "border-white/5 focus:border-primary/40 focus:ring-primary/10",
                  )}
                  placeholder='{ "OPERATIONAL_KEY": "VALUE" }'
                  spellCheck={false}
                />
              </div>
            </div>
          </div>

          {!workflowId && (
            <div className="p-6 bg-warning/5 border border-warning/10 rounded-[2rem] flex gap-5 shadow-2xl glass-dark animate-status-pulse">
              <AlertTriangle className="w-6 h-6 text-warning shrink-0 mt-0.5" />
              <p className="text-[10px] text-warning/80 font-black uppercase tracking-widest leading-relaxed">
                WORKFLOW NOT PERSISTED. SAVE PROTOCOL TO INITIALIZE DEPLOYMENT
                VECTORS AND TELEMETRY STREAMS.
              </p>
            </div>
          )}
        </TabsContent>

        <TabsContent
          value="executions"
          className="flex-1 min-h-0 overflow-auto p-4 custom-scrollbar focus:outline-none"
        >
          {workflowId ? (
            <WorkflowExecutionHistoryPanel workflowId={workflowId} />
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-12 text-center space-y-8 opacity-20 grayscale">
              <div className="p-10 rounded-[3.5rem] bg-surface-3/40 border border-white/5 shadow-2xl relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent" />
                <Zap className="w-12 h-12 text-muted-foreground/30 relative z-10" />
              </div>
              <p className="text-[12px] font-black uppercase tracking-[0.4em] text-muted-foreground/60 max-w-[240px] leading-relaxed">
                INITIALIZE PERSISTENCE TO ACTIVATE HISTORY
              </p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};
