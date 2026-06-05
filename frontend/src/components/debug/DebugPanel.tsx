import React, { useState, useMemo, useRef, useEffect } from "react";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from "@/components/ui";
import {
  useEphemeralExecutionStore,
  type EphemeralSlice,
  type TimedEvent,
} from "@/store/executionStore";
import { useShallow } from "zustand/react/shallow";
import { cn } from "@/lib/utils";
import { formatDuration } from "@/lib/utils";
import {
  Copy,
  Check,
  Play,
  ArrowDownToLine,
  ArrowUpFromLine,
  Info,
} from "lucide-react";
import { NodeDataViewer } from "./NodeDataViewer";

interface DebugPanelProps {
  nodeId: string;
}

export const DebugPanel: React.FC<DebugPanelProps> = ({ nodeId }) => {
  const [copiedTab, setCopiedTab] = useState<string | null>(null);
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  const nodeStatus = useEphemeralExecutionStore(
    (state: EphemeralSlice) => state.nodeStatuses[nodeId],
  );

  const nodeResult = useEphemeralExecutionStore(
    (state: EphemeralSlice) => state.nodeResults[nodeId],
  );

  const nodeEvents = useEphemeralExecutionStore(
    useShallow((state: EphemeralSlice) =>
      state.events.filter((e: TimedEvent) => e.nodeId === nodeId),
    ),
  );

  const executionId = useEphemeralExecutionStore(
    (state: EphemeralSlice) => state.currentExecutionId,
  );

  // Derive the input from the first event for this node (the triggering data)
  const nodeInput = useMemo(() => {
    if (nodeEvents.length === 0) return null;
    // Look for the first event that carries a log message about input or just return
    // the first event's contextual data
    const firstEvent = nodeEvents[0];
    return {
      executionId: firstEvent.executionId,
      status: firstEvent.status,
      logMessage: firstEvent.logMessage,
      retryAttempt: firstEvent.retryAttempt,
      maxRetries: firstEvent.maxRetries,
    };
  }, [nodeEvents]);

  // Derive metadata from status + events
  const metadata = useMemo(() => {
    const retryEvents = nodeEvents.filter(
      (e) => e.retryAttempt != null && e.retryAttempt > 0,
    );
    return {
      status: nodeStatus?.status ?? "idle",
      durationMs: nodeStatus?.durationMs ?? null,
      startedAt: nodeStatus?.startedAt ?? null,
      retryCount: retryEvents.length,
      maxRetries: nodeEvents.find((e) => e.maxRetries != null)?.maxRetries ?? 0,
      eventCount: nodeEvents.length,
      executionId: executionId ?? "N/A",
      error: nodeStatus?.error ?? null,
    };
  }, [nodeStatus, nodeEvents, executionId]);

  const handleCopy = async (tab: string, data: unknown) => {
    try {
      const text =
        typeof data === "string" ? data : JSON.stringify(data, null, 2);
      await navigator.clipboard.writeText(text);
      setCopiedTab(tab);
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopiedTab(null), 2000);
    } catch {
      // Clipboard API unavailable — fail silently
    }
  };

  const STATUS_COLOR: Record<string, string> = {
    idle: "text-muted-foreground",
    running: "text-blue-400",
    success: "text-green-400",
    failed: "text-red-400",
    awaiting_approval: "text-amber-400",
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border/10 bg-secondary/5">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
            <Info className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white tracking-tight">
              Debug Inspector
            </h3>
            <p className="text-[9px] text-muted-foreground font-mono truncate max-w-[260px]">
              {nodeId}
            </p>
          </div>
        </div>
      </div>

      <Tabs
        defaultValue="input"
        className="flex-1 flex flex-col overflow-hidden"
      >
        <TabsList className="w-full justify-start rounded-none border-b border-border/5 bg-transparent px-2 gap-1 shrink-0">
          <TabsTrigger
            value="input"
            className="text-[10px] font-bold uppercase tracking-widest data-[state=active]:text-cyan-400 data-[state=active]:bg-secondary/5 text-muted-foreground rounded-md py-2 px-3"
          >
            <ArrowDownToLine className="w-3 h-3 mr-1.5" />
            Input
          </TabsTrigger>
          <TabsTrigger
            value="output"
            className="text-[10px] font-bold uppercase tracking-widest data-[state=active]:text-cyan-400 data-[state=active]:bg-secondary/5 text-muted-foreground rounded-md py-2 px-3"
          >
            <ArrowUpFromLine className="w-3 h-3 mr-1.5" />
            Output
          </TabsTrigger>
          <TabsTrigger
            value="metadata"
            className="text-[10px] font-bold uppercase tracking-widest data-[state=active]:text-cyan-400 data-[state=active]:bg-secondary/5 text-muted-foreground rounded-md py-2 px-3"
          >
            <Info className="w-3 h-3 mr-1.5" />
            Metadata
          </TabsTrigger>
        </TabsList>

        {/* Input tab */}
        <TabsContent
          value="input"
          className="flex-1 overflow-auto p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <label className="text-[9px] font-bold text-cyan-400 uppercase tracking-widest">
              Node Input
            </label>
            <CopyButton
              copied={copiedTab === "input"}
              onClick={() => handleCopy("input", nodeInput)}
            />
          </div>
          <div className="p-3 bg-black/40 border border-white/5 rounded-xl font-mono text-[10px] leading-relaxed overflow-auto max-h-[400px]">
            {nodeInput ? (
              <NodeDataViewer data={nodeInput} />
            ) : (
              <span className="text-muted-foreground italic">
                No input data captured. Input data is available after the node
                has started execution.
              </span>
            )}
          </div>
        </TabsContent>

        {/* Output tab */}
        <TabsContent
          value="output"
          className="flex-1 overflow-auto p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <label className="text-[9px] font-bold text-cyan-400 uppercase tracking-widest">
              Node Output
            </label>
            <CopyButton
              copied={copiedTab === "output"}
              onClick={() => handleCopy("output", nodeResult)}
            />
          </div>
          <div className="p-3 bg-black/40 border border-white/5 rounded-xl font-mono text-[10px] leading-relaxed overflow-auto max-h-[400px]">
            {nodeResult != null ? (
              <NodeDataViewer data={nodeResult} />
            ) : (
              <span className="text-muted-foreground italic">
                No output data yet. Output appears after the node completes
                execution.
              </span>
            )}
          </div>
        </TabsContent>

        {/* Metadata tab */}
        <TabsContent
          value="metadata"
          className="flex-1 overflow-auto p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <label className="text-[9px] font-bold text-cyan-400 uppercase tracking-widest">
              Execution Metadata
            </label>
            <CopyButton
              copied={copiedTab === "metadata"}
              onClick={() => handleCopy("metadata", metadata)}
            />
          </div>

          <div className="space-y-2">
            <MetadataRow label="Status">
              <span
                className={cn(
                  "font-bold uppercase text-[10px] tracking-wider",
                  STATUS_COLOR[metadata.status] ?? "text-muted-foreground",
                )}
              >
                {metadata.status}
              </span>
            </MetadataRow>

            <MetadataRow label="Duration">
              <span className="text-foreground/80 font-mono">
                {metadata.durationMs != null
                  ? formatDuration(metadata.durationMs)
                  : "--"}
              </span>
            </MetadataRow>

            <MetadataRow label="Retry Count">
              <span className="text-foreground/80 font-mono">
                {metadata.retryCount} / {metadata.maxRetries}
              </span>
            </MetadataRow>

            <MetadataRow label="Events">
              <span className="text-foreground/80 font-mono">
                {metadata.eventCount}
              </span>
            </MetadataRow>

            <MetadataRow label="Execution ID">
              <span className="text-muted-foreground font-mono text-[9px] truncate max-w-[200px] block">
                {metadata.executionId}
              </span>
            </MetadataRow>

            {metadata.error && (
              <div className="mt-3 p-3 rounded-lg bg-red-500/5 border border-red-500/10">
                <p className="text-[9px] font-bold text-red-400 uppercase tracking-widest mb-1">
                  Error
                </p>
                <p className="text-[10px] text-red-300 leading-relaxed font-mono break-words">
                  {metadata.error}
                </p>
              </div>
            )}
          </div>

          {/* Replay button */}
          <div className="pt-4 border-t border-border/5">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    disabled
                    className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 text-cyan-400/50 text-xs font-bold cursor-not-allowed transition-premium"
                  >
                    <Play className="w-3.5 h-3.5" />
                    Replay from here
                  </button>
                </TooltipTrigger>
                <TooltipContent side="top">
                  <p>Coming soon</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

const MetadataRow: React.FC<{
  label: string;
  children: React.ReactNode;
}> = ({ label, children }) => (
  <div className="flex items-center justify-between p-2.5 rounded-lg bg-secondary/5 border border-border/10">
    <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest">
      {label}
    </span>
    {children}
  </div>
);

const CopyButton: React.FC<{
  copied: boolean;
  onClick: () => void;
}> = ({ copied, onClick }) => (
  <button
    type="button"
    onClick={onClick}
    className="p-1 hover:bg-white/5 rounded transition-premium"
    aria-label="Copy JSON"
  >
    {copied ? (
      <Check className="w-3 h-3 text-green-400" />
    ) : (
      <Copy className="w-3 h-3 text-muted-foreground" />
    )}
  </button>
);
