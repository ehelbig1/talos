import React from "react";
import { Textarea } from "@/components/ui/textarea";
import { Select } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { useNavigate } from "react-router";
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
      label: "Schedule",
      desc: "Run on a timer",
      onClick: () => navigate("/settings#schedules"),
      color: "text-warning",
      glow: "",
    },
    {
      icon: Webhook,
      label: "Webhook",
      desc: "Run when an HTTP request arrives",
      onClick: () => navigate("/settings#webhooks"),
      color: "text-primary",
      glow: "",
    },
    {
      icon: Play,
      label: "Manual",
      desc: "Run it yourself from the toolbar",
      onClick: undefined,
      color: "text-success",
      glow: "",
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground/70 font-semibold ml-1">
        Triggers
      </p>
      <div className="grid grid-cols-1 gap-2">
        {triggers.map((t) => (
          <button
            key={t.label}
            onClick={t.onClick}
            disabled={!t.onClick}
            className={cn(
              "w-full flex items-center gap-4 px-4 py-3 rounded-2xl border border-white/5 bg-white/[0.02] hover:bg-white/[0.04] transition-ui text-left disabled:opacity-40 disabled:cursor-default group relative overflow-hidden",
              t.onClick && "hover:border-white/10",
            )}
          >
            <div
              className={cn(
                "p-2 rounded-xl bg-white/5 border border-white/10 transition-ui",
                t.color,
              )}
            >
              <t.icon className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-white font-semibold font-outfit">
                {t.label}
              </p>
              <p className="text-xs text-muted-foreground/70 font-medium">
                {t.desc}
              </p>
            </div>
            {t.onClick && (
              <span className="text-xs text-primary font-medium opacity-0 group-hover:opacity-100 transition-ui">
                Configure
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
    <div className="flex flex-col h-full bg-surface-2/80 relative border-l border-white/5">
      {/* Header */}
      <div className="flex items-center justify-between px-8 py-6 border-b border-white/5 bg-white/[0.02] relative z-10">
        <div className="flex items-center gap-5">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center relative group overflow-hidden">
            <Layout className="w-6 h-6 text-primary relative z-10" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white tracking-tight font-outfit">
              Workflow
            </h3>
            <p className="text-xs text-muted-foreground/70 font-medium mt-1">
              Name, description, actor and limits
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close inspector"
          className="w-10 h-10 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-muted-foreground/70 hover:text-white hover:bg-white/10 transition-ui"
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
              className="flex-1 text-sm font-semibold data-[state=active]:text-white data-[state=active]:bg-primary/20 data-[state=active]:border-primary/20 border border-transparent text-muted-foreground/70 rounded-xl py-3 px-5 transition-ui"
            >
              <Info className="w-3.5 h-3.5 mr-2 opacity-40" />
              Manifest
            </TabsTrigger>
            <TabsTrigger
              value="executions"
              className="flex-1 text-sm font-semibold data-[state=active]:text-white data-[state=active]:bg-primary/20 data-[state=active]:border-primary/20 border border-transparent text-muted-foreground/70 rounded-xl py-3 px-5 transition-ui"
            >
              <Clock className="w-3.5 h-3.5 mr-2 opacity-40" />
              History
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent
          value="info"
          className="flex-1 min-h-0 overflow-auto p-8 space-y-10 custom-scrollbar focus:outline-none"
        >
          <div className="space-y-4">
            <label className="text-xs text-muted-foreground/60 font-semibold ml-1">
              Name
            </label>
            <div className="p-6 bg-surface-3/40 border border-white/5 rounded-2xl bg-surface-3 border border-white/10 relative overflow-hidden group">
              <p className="text-3xl font-semibold text-white tracking-tight font-outfit leading-none selection:bg-primary/30 break-all">
                {workflowName || "Untitled workflow"}
              </p>
            </div>
          </div>

          {workflowId && (
            <div className="space-y-4">
              <label className="text-xs text-muted-foreground/60 font-semibold ml-1">
                Workflow ID
              </label>
              <CopyField
                label="ID"
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
            <div className="p-6 bg-white/[0.02] border border-white/5 rounded-2xl bg-surface-3 border border-white/10 group hover:bg-white/[0.04] transition-ui">
              <div className="text-2xs text-muted-foreground/60 uppercase tracking-wider font-semibold mb-3">
                Nodes
              </div>
              <div className="flex items-center gap-3">
                <div className="w-1.5 h-6 bg-primary/40 rounded-full" />
                <div className="text-3xl font-semibold text-white font-outfit">
                  {nodeCount}
                </div>
              </div>
            </div>
            <div className="p-6 bg-white/[0.02] border border-white/5 rounded-2xl bg-surface-3 border border-white/10 group hover:bg-white/[0.04] transition-ui">
              <div className="text-2xs text-muted-foreground/60 uppercase tracking-wider font-semibold mb-3">
                Edges
              </div>
              <div className="flex items-center gap-3">
                <div className="w-1.5 h-6 bg-success/40 rounded-full" />
                <div className="text-3xl font-semibold text-white font-outfit">
                  {edgeCount}
                </div>
              </div>
            </div>
          </div>

          <TriggersSection workflowId={workflowId} />

          <div className="p-8 bg-primary/5 border border-primary/10 rounded-2xl space-y-8 relative overflow-hidden group">
            <h4 className="text-xs font-semibold text-white flex items-center gap-4 font-outfit relative z-10">
              <div className="p-2.5 rounded-2xl bg-primary/10 border border-primary/20 transition-ui">
                <Zap className="w-5 h-5 text-primary" />
              </div>
              Limits
            </h4>

            <div className="space-y-8 relative z-10">
              <div className="space-y-3">
                <label className="text-xs text-muted-foreground/70 font-semibold ml-1">
                  Concurrency Limit
                </label>
                <div className="flex items-center gap-5">
                  <Input
                    type="number"
                    min={1}
                    max={100}
                    value={maxConcurrentExecutions}
                    onChange={(e) =>
                      setMaxConcurrentExecutions(parseInt(e.target.value) || 1)
                    }
                    className="w-24"
                  />
                  <div className="text-xs text-muted-foreground/50 font-bold italic">
                    Default: 1
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <label className="text-xs text-muted-foreground/70 font-semibold ml-1">
                  Runtime Priority
                </label>
                <div className="relative">
                  <Select
                    value={priority}
                    onChange={(e) =>
                      setPriority(e.target.value as "high" | "normal" | "low")
                    }
                  >
                    <option value="low">Low</option>
                    <option value="normal">Normal</option>
                    <option value="high">High</option>
                  </Select>
                  <ChevronDown className="absolute right-6 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/50 pointer-events-none" />
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex justify-between items-center px-1">
                  <label className="text-xs text-muted-foreground/70 font-semibold">
                    Intent Metadata (JSON)
                  </label>
                  {jsonError && (
                    <span className="text-2xs text-destructive font-semibold bg-destructive/10 px-2 py-0.5 rounded border border-destructive/20">
                      Invalid JSON
                    </span>
                  )}
                </div>
                <Textarea
                  value={jsonText}
                  onChange={handleJsonChange}
                  rows={6}
                  className={cn(
                    "text-xs font-mono resize-none custom-scrollbar",
                    jsonError &&
                      "border-destructive/40 focus:ring-destructive/10",
                  )}
                  placeholder='{ "key": "value" }'
                  spellCheck={false}
                />
              </div>
            </div>
          </div>

          {!workflowId && (
            <div className="p-6 bg-warning/5 border border-warning/10 rounded-2xl flex gap-5 bg-surface-3 border border-white/10">
              <AlertTriangle className="w-6 h-6 text-warning shrink-0 mt-0.5" />
              <p className="text-xs text-warning/80 leading-relaxed">
                This workflow is not saved yet. Save it to set up triggers and
                see run history.
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
              <div className="p-10 rounded-[3.5rem] bg-surface-3/40 border border-white/5 relative overflow-hidden group">
                <Zap className="w-12 h-12 text-muted-foreground/60 relative z-10" />
              </div>
              <p className="text-xs text-muted-foreground/60 max-w-[240px] leading-relaxed">
                Save the workflow to see its run history
              </p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};
