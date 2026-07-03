import React, { useState } from "react";
import { getBezierPath, EdgeLabelRenderer, BaseEdge } from "@xyflow/react";
import type { EdgeProps, Edge } from "@xyflow/react";
import { cn } from "@/lib/utils";
import { useEphemeralExecutionStore } from "@/store/executionStore";
import type { EdgeData } from "@/store/workflowStore";
import { Zap, AlertTriangle } from "lucide-react";

type ConditionEdgeType = Edge<EdgeData, "conditionEdge">;

export function ConditionEdge({
  source,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
  selected,
}: EdgeProps<ConditionEdgeType>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetPosition,
    targetX,
    targetY,
  });

  const [isHovered, setIsHovered] = useState(false);
  const nodeResults = useEphemeralExecutionStore((s) => s.nodeResults);
  const isRunning = useEphemeralExecutionStore((s) => s.isRunning);
  const result = nodeResults[source];

  const hasCondition = !!data?.condition;
  const isOnFailure = data?.edgeType === "OnFailure";
  const isErrorEdge = data?.edgeType === "error";

  const isAlert = isOnFailure || isErrorEdge;

  // Dynamic colors for premium feel
  const activeColor = isAlert
    ? "hsl(var(--destructive))"
    : "hsl(var(--primary))";
  const inactiveColor = isAlert
    ? "hsla(var(--destructive), 0.4)"
    : hasCondition
      ? "hsla(var(--warning), 0.4)"
      : "hsla(var(--muted-foreground), 0.5)";
  const glowColor = isAlert
    ? "hsla(var(--destructive), 0.3)"
    : "hsla(var(--primary), 0.3)";

  return (
    <>
      {/* Background glow path (visible on hover/select) */}
      {(selected || isHovered) && (
        <path
          d={edgePath}
          fill="none"
          stroke={glowColor}
          strokeWidth={6}
          className="animate-pulse"
          style={{
            filter: "blur(4px)",
            transition: "stroke 300ms",
          }}
        />
      )}

      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          ...style,
          stroke: selected || isHovered ? activeColor : inactiveColor,
          strokeWidth: selected || isHovered ? 2.5 : 1.5,
          strokeDasharray: isRunning ? "8 8" : "none",
          animation: isRunning ? "edge-flow 2s linear infinite" : "none",
          transition: "all 300ms cubic-bezier(0.4, 0, 0.2, 1)",
          cursor: "help",
        }}
      />

      {/* Invisible wider path for hover detection */}
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={20}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        className="cursor-pointer"
      />

      {(hasCondition ||
        isOnFailure ||
        isErrorEdge ||
        (isHovered && result)) && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: "all",
              zIndex: 1000,
            }}
            className="nodrag nopan"
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
          >
            {isHovered && result ? (
              <div className="bg-background/95 backdrop-blur-2xl border border-primary/30 rounded-xl p-3 shadow-[0_12px_40px_rgba(0,0,0,0.6)] max-w-sm overflow-hidden animate-in fade-in zoom-in duration-200">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse shadow-[0_0_10px_hsla(var(--primary),0.8)]" />
                    <span className="text-[10px] font-bold text-primary uppercase tracking-widest">
                      Output Data
                    </span>
                  </div>
                  <span className="text-[9px] text-muted-foreground font-mono bg-muted/50 px-1.5 py-0.5 rounded border border-border/50">
                    {source.slice(0, 8)}
                  </span>
                </div>
                <div className="relative group">
                  <pre className="text-[10px] text-foreground/80 font-mono overflow-x-auto max-h-48 thin-scrollbar leading-relaxed bg-muted/40 rounded-lg p-2 border border-border shadow-inner">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              </div>
            ) : isOnFailure ? (
              <div
                className={cn(
                  "flex items-center gap-1.5 px-2 py-1 rounded-full border text-[10px] font-bold shadow-lg transition-premium duration-300 backdrop-blur-md",
                  selected
                    ? "bg-destructive border-destructive-foreground text-destructive-foreground scale-110 shadow-destructive/20"
                    : "bg-background/80 border-destructive/40 text-destructive hover:border-destructive",
                )}
              >
                <div
                  className={cn(
                    "w-1 h-1 rounded-full bg-current",
                    selected && "animate-ping",
                  )}
                />
                FAIL
              </div>
            ) : isErrorEdge ? (
              <div
                className={cn(
                  "flex items-center gap-1.5 px-2 py-1 rounded-full border text-[10px] font-bold shadow-lg transition-premium duration-300 backdrop-blur-md",
                  selected
                    ? "bg-destructive border-destructive-foreground text-destructive-foreground scale-110 shadow-destructive/20"
                    : "bg-background/80 border-destructive/40 text-destructive hover:border-destructive",
                )}
              >
                <AlertTriangle className="w-3 h-3" />
                ERROR
              </div>
            ) : hasCondition ? (
              <div
                className={cn(
                  "flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold shadow-lg transition-premium duration-300 backdrop-blur-md group cursor-help",
                  selected || isHovered
                    ? "bg-primary border-primary-foreground text-primary-foreground scale-110 shadow-[0_0_20px_hsla(var(--primary),0.4)]"
                    : "bg-background/80 border-warning/40 text-warning hover:border-warning",
                )}
              >
                <Zap
                  className={cn(
                    "w-3 h-3 transition-transform duration-300",
                    isHovered && "rotate-12",
                  )}
                />
                IF
                {data?.condition && isHovered && (
                  <span className="ml-1 pl-1.5 border-l border-white/20 text-[10px] text-white/90 font-mono font-medium hidden group-hover:block transition-premium max-w-[150px] truncate drop-shadow-sm">
                    {data.condition}
                  </span>
                )}
              </div>
            ) : null}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
