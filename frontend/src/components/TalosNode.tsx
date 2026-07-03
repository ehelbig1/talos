import React, { useState, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import type { NodeProps, Node } from "@xyflow/react";
import type { NodeStatusType } from "@/store/executionStore";
import { useEphemeralExecutionStore } from "@/store/executionStore";
import {
  Timer,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  Search,
} from "lucide-react";
import { useWorkflowStore } from "@/store/workflowStore";
import { useUIStore } from "@/store/uiStore";
import { getFixSuggestion } from "@/lib/fixSuggestions";
import { getCategoryIcon, getCategoryColor } from "@/lib/categoryIcons";
import { cn } from "@/lib/utils";
import { StatusDot, STATUS_BORDER } from "./nodes/NodeStatus";
import { NodeBadges, getSystemNodeStyle } from "./nodes/NodeBadges";
import { NodeContextMenu } from "./nodes/NodeContextMenu";
import { NodeHandles } from "./nodes/NodeHandles";
import { NodeErrorOverlay } from "./nodes/NodeErrorOverlay";

export interface TalosNodeData {
  [key: string]: unknown;
  label: string;
  moduleId: string;
  moduleName?: string;
  category?: string;
  config?: Record<string, unknown>;
  systemNodeKind?: string;
  capabilityWorld?: string;
  joinMode?: string;
  executionStatus?: string;
  lastError?: string;
  sourceCode?: string;
  importedInterfaces?: string[];
}

type TalosNodeType = Node<TalosNodeData, "talosNode">;

export const TalosNode: React.FC<NodeProps<TalosNodeType>> = React.memo(
  ({ data, selected, id, dragging }) => {
    const nodeStatus = useEphemeralExecutionStore(
      (state) => state.nodeStatuses[id],
    );
    const nodeResult = useEphemeralExecutionStore(
      (state) => state.nodeResults[id],
    );
    const streamingContent = useEphemeralExecutionStore(
      (state) => state.nodeStreamingContent[id],
    );
    const status: NodeStatusType =
      nodeStatus?.status ?? (data.executionStatus as NodeStatusType) ?? "idle";
    const error = nodeStatus?.error ?? data.lastError;

    const fixSuggestion = useMemo(
      () =>
        status === "failed" && error ? getFixSuggestion(error) : undefined,
      [status, error],
    );

    const [menuPos, setMenuPos] = useState<{ x: number; y: number } | null>(
      null,
    );
    const duplicateNode = useWorkflowStore((state) => state.duplicateNode);
    const deleteNode = useWorkflowStore((state) => state.deleteNode);
    const setShowInspector = useUIStore((state) => state.setShowInspector);
    const setDebugNodeId = useUIStore((state) => state.setDebugNodeId);

    const CategoryIcon = useMemo(
      () => getCategoryIcon(data.category),
      [data.category],
    );
    const categoryColor = useMemo(
      () => getCategoryColor(data.category),
      [data.category],
    );
    const configCount = useMemo(
      () => (data.config ? Object.keys(data.config).length : 0),
      [data.config],
    );
    const systemStyle = useMemo(
      () =>
        data.systemNodeKind ? getSystemNodeStyle(data.systemNodeKind) : null,
      [data.systemNodeKind],
    );

    const hasResults = nodeResult != null || status !== "idle";

    const handleDoubleClick = React.useCallback(
      (e: React.MouseEvent) => {
        if (hasResults) {
          e.stopPropagation();
          setDebugNodeId(id);
        }
      },
      [hasResults, setDebugNodeId, id],
    );

    const handleInspectClick = React.useCallback(
      (e: React.MouseEvent) => {
        e.stopPropagation();
        setDebugNodeId(id);
      },
      [setDebugNodeId, id],
    );

    const handleContextMenu = React.useCallback((e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setMenuPos({ x: e.clientX, y: e.clientY });
    }, []);

    const handleDuplicate = React.useCallback(() => {
      duplicateNode(id);
      setMenuPos(null);
    }, [duplicateNode, id]);

    const handleDeleteNode = React.useCallback(() => {
      deleteNode(id);
      setShowInspector(false);
      setMenuPos(null);
    }, [deleteNode, id, setShowInspector]);

    const handleKeyDown = React.useCallback(
      (e: React.KeyboardEvent) => {
        // Shortcuts only when focused
        const isInput = (e.target as HTMLElement).closest(
          "input, textarea, .monaco-editor",
        );
        if (isInput) return;

        if (e.key === "Delete" || e.key === "Backspace") {
          handleDeleteNode();
        } else if ((e.metaKey || e.ctrlKey) && e.key === "d") {
          e.preventDefault();
          handleDuplicate();
        }
      },
      [handleDeleteNode, handleDuplicate],
    );

    const resultPreview = useMemo(() => {
      if (streamingContent) return streamingContent;
      if (nodeResult == null) return null;
      const str =
        typeof nodeResult === "string"
          ? nodeResult
          : JSON.stringify(nodeResult);
      return str.length > 60 ? str.slice(0, 60) + "..." : str;
    }, [streamingContent, nodeResult]);

    const displayName = data.moduleName || data.label || "Untitled Node";

    return (
      <>
        <div
          onContextMenu={handleContextMenu}
          onDoubleClick={handleDoubleClick}
          onKeyDown={handleKeyDown}
          tabIndex={0}
          role="button"
          aria-label={`${displayName} node. Status: ${status}. ${configCount} configured fields.`}
          className={cn(
            "relative border-l-[4px] outline-none transition-premium duration-500",
            "bg-surface-3/40 backdrop-blur-2xl border-y border-r border-white/5 px-5 py-4 min-w-[220px] shadow-2xl glass",
            dragging && "transition-none",
            "group active:scale-[0.98] hover:-translate-y-2 hover:bg-surface-3/60",
            systemStyle ? "rounded-[2rem]" : "rounded-2xl",
            selected
              ? "ring-2 ring-primary/40 border-y-primary/20 border-r-primary/20 shadow-[0_0_30px_hsla(var(--primary),0.15)]"
              : "hover:border-white/10",
            status === "failed" &&
              "shadow-[0_0_30px_hsla(var(--destructive),0.1)] ring-1 ring-destructive/20",
            status === "running" &&
              "shadow-[0_0_30px_hsla(var(--primary),0.1)]",
            systemStyle ? systemStyle.bg : STATUS_BORDER[status],
          )}
        >
          {/* Status Glow Overlay */}
          <div
            className={cn(
              "absolute inset-0 rounded-[inherit] opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none",
              status === "success" &&
                "bg-success/5 shadow-[inset_0_0_20px_hsla(var(--success),0.1)]",
              status === "failed" &&
                "bg-destructive/5 shadow-[inset_0_0_20px_hsla(var(--destructive),0.1)]",
              status === "running" &&
                "bg-primary/5 shadow-[inset_0_0_20px_hsla(var(--primary),0.1)]",
            )}
          />

          {/* Status dot + name */}
          <div className="flex items-center gap-3 relative z-10">
            <StatusDot status={status} />
            {data.category && (
              <div className="p-1.5 bg-white/5 rounded-lg border border-white/5 group-hover:bg-white/10 transition-premium">
                <CategoryIcon
                  className={cn(
                    "w-3.5 h-3.5 shrink-0 transition-transform group-hover:scale-110",
                    categoryColor,
                  )}
                />
              </div>
            )}
            <span className="text-sm font-black text-white tracking-tight leading-tight truncate font-outfit">
              {displayName}
            </span>
          </div>

          <div className="relative z-10">
            <NodeBadges
              systemNodeKind={data.systemNodeKind}
              capabilityWorld={data.capabilityWorld}
              joinMode={data.joinMode}
            />
          </div>

          {/* Execution metrics */}
          {status !== "idle" && (
            <div className="flex items-center gap-3 mt-3 relative z-10">
              {nodeStatus?.durationMs != null && (
                <div className="px-2 py-0.5 rounded-md bg-white/5 border border-white/5 flex items-center gap-1.5">
                  <Timer className="w-2.5 h-2.5 text-muted-foreground/60" />
                  <span className="text-[9px] font-black font-mono text-muted-foreground/80 uppercase tracking-widest">
                    {nodeStatus.durationMs >= 1000
                      ? `${(nodeStatus.durationMs / 1000).toFixed(1)}s`
                      : `${nodeStatus.durationMs}ms`}
                  </span>
                </div>
              )}
              {status === "success" && (
                <CheckCircle2 className="w-3.5 h-3.5 text-success drop-shadow-[0_0_8px_hsla(var(--success),0.4)]" />
              )}
              {status === "failed" && (
                <XCircle className="w-3.5 h-3.5 text-destructive drop-shadow-[0_0_8px_hsla(var(--destructive),0.4)]" />
              )}
              {status === "awaiting_approval" && (
                <ShieldAlert className="w-3.5 h-3.5 text-warning animate-status-pulse" />
              )}
            </div>
          )}

          {/* Compact output preview or streaming content */}
          {resultPreview && (status === "success" || status === "running") && (
            <div className="mt-3 px-3 py-2 rounded-xl bg-surface-4/60 border border-white/5 relative z-10 group/preview hover:bg-surface-4 transition-premium overflow-hidden">
              <p
                className={cn(
                  "text-[9px] font-mono tracking-tight",
                  status === "running"
                    ? "text-primary/70"
                    : "text-muted-foreground/50 truncate max-w-[180px]",
                )}
                title={
                  typeof nodeResult === "string"
                    ? nodeResult
                    : JSON.stringify(nodeResult)
                }
              >
                {resultPreview}
                {status === "running" && (
                  <span className="w-1 h-2.5 bg-primary/40 animate-pulse inline-block ml-1 align-middle" />
                )}
              </p>
            </div>
          )}

          {/* Running progress bar */}
          {status === "running" && (
            <div className="absolute bottom-0 left-0 right-0 h-1 overflow-hidden rounded-b-[inherit] z-20">
              <div className="h-full bg-primary animate-progress-bar shadow-[0_0_10px_hsla(var(--primary),0.5)]" />
            </div>
          )}

          {/* Config subtitle */}
          {configCount > 0 && (
            <div className="mt-4 flex items-center gap-2 relative z-10 opacity-60 group-hover:opacity-100 transition-opacity">
              <div className="w-1.5 h-1.5 rounded-full bg-primary/40 shadow-[0_0_5px_hsla(var(--primary),0.5)]" />
              <p className="text-[9px] font-black text-muted-foreground uppercase tracking-[0.2em]">
                {configCount} Protocol Field{configCount !== 1 ? "s" : ""}
              </p>
            </div>
          )}

          {/* Inspect icon — shown on hover when node has execution results */}
          {hasResults && (
            <button
              type="button"
              onClick={handleInspectClick}
              aria-label="Inspect node execution data"
              className="absolute top-3 right-3 p-2 rounded-xl bg-surface-4/80 border border-white/10 text-primary opacity-0 group-hover:opacity-100 transition-premium hover:scale-110 hover:bg-primary hover:text-white shadow-xl z-30"
            >
              <Search className="w-3.5 h-3.5" />
            </button>
          )}

          <NodeErrorOverlay error={error} fixSuggestion={fixSuggestion} />

          <NodeHandles />
        </div>

        {menuPos && (
          <NodeContextMenu
            pos={menuPos}
            nodeId={id}
            onClose={() => setMenuPos(null)}
            onDuplicate={handleDuplicate}
            onDelete={handleDeleteNode}
          />
        )}
      </>
    );
  },
);
