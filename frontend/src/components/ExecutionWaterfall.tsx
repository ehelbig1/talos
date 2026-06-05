import React, { useMemo } from "react";
import type { TimedEvent } from "@/store/executionStore";
import { cn } from "@/lib/utils";

interface WaterfallProps {
  events: TimedEvent[];
  nodeNames: Record<string, string>;
}

interface NodeBar {
  nodeId: string;
  nodeName: string;
  startMs: number;
  durationMs: number;
  status: "success" | "failed" | "running";
}

const STATUS_COLORS = {
  success: "hsl(var(--success))",
  failed: "hsl(var(--destructive))",
  running: "hsl(var(--primary))",
} as const;

/**
 * Horizontal bar chart showing per-node execution timing.
 */
export function ExecutionWaterfall({ events, nodeNames }: WaterfallProps) {
  const bars = useMemo(() => {
    if (!events.length) return [];

    const nodeStarts = new Map<string, number>();
    const result: NodeBar[] = [];

    // Track the absolute start timestamp of the execution
    const firstTimestamp = new Date(
      events[0]?.timestamp ?? Date.now(),
    ).getTime();

    for (const ev of events) {
      const nodeId = ev.nodeId;
      if (!nodeId) continue;

      const evTimestamp = new Date(ev.timestamp ?? Date.now()).getTime();
      const relativeMs = evTimestamp - firstTimestamp;

      if (
        ev.status === "NodeStarted" ||
        ev.status === "Running" ||
        ev.status === "RUNNING" ||
        ev.status === "AwaitingApproval"
      ) {
        nodeStarts.set(nodeId, relativeMs);
      }

      if (
        ev.status === "NodeCompleted" ||
        ev.status === "COMPLETED" ||
        ev.status === "NodeFailed" ||
        ev.status === "FAILED"
      ) {
        const startMs = nodeStarts.get(nodeId) ?? relativeMs;
        const durationMs =
          (ev as any).durationMs ?? Math.max(1, relativeMs - startMs);
        const isFailed = ev.status === "NodeFailed" || ev.status === "FAILED";

        result.push({
          nodeId,
          nodeName: nodeNames[nodeId] ?? nodeId.slice(0, 8),
          startMs,
          durationMs,
          status: isFailed ? "failed" : "success",
        });
      }
    }

    // Add bars for still-running nodes
    const totalElapsed = events.length
      ? new Date(events[events.length - 1]?.timestamp ?? Date.now()).getTime() -
        firstTimestamp
      : 0;

    for (const [nodeId, startMs] of nodeStarts) {
      if (!result.find((b) => b.nodeId === nodeId)) {
        result.push({
          nodeId,
          nodeName: nodeNames[nodeId] ?? nodeId.slice(0, 8),
          startMs,
          durationMs: Math.max(1, totalElapsed - startMs),
          status: "running",
        });
      }
    }

    return result.sort((a, b) => a.startMs - b.startMs);
  }, [events, nodeNames]);

  if (!bars.length) {
    return (
      <div className="flex flex-col items-center justify-center py-12 gap-4 opacity-20 grayscale">
        <div className="p-5 rounded-2xl bg-surface-3/40 border border-white/5">
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M3 9h18" />
            <path d="M9 21V9" />
          </svg>
        </div>
        <p className="text-[10px] font-black uppercase tracking-[0.3em]">
          No Telemetry Data
        </p>
      </div>
    );
  }

  const maxEndMs = Math.max(...bars.map((b) => b.startMs + b.durationMs), 1);
  const ROW_HEIGHT = 40;
  const LABEL_WIDTH = 180;
  const BAR_AREA_WIDTH = 500;
  const SVG_WIDTH = LABEL_WIDTH + BAR_AREA_WIDTH + 80;
  const SVG_HEIGHT = bars.length * ROW_HEIGHT + 60;

  return (
    <div className="overflow-x-auto custom-scrollbar pb-4">
      <svg
        width={SVG_WIDTH}
        height={SVG_HEIGHT}
        className="font-outfit"
        role="img"
        aria-label="Execution waterfall chart"
      >
        {/* Subtle grid background */}
        <defs>
          <linearGradient id="barGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.8" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.4" />
          </linearGradient>
        </defs>

        {/* Time axis labels */}
        {[0, 0.25, 0.5, 0.75, 1].map((frac) => {
          const x = LABEL_WIDTH + frac * BAR_AREA_WIDTH;
          const ms = Math.round(frac * maxEndMs);
          return (
            <g key={frac}>
              <line
                x1={x}
                y1={0}
                x2={x}
                y2={SVG_HEIGHT - 40}
                stroke="white"
                strokeOpacity={0.03}
                strokeDasharray="4,4"
              />
              <text
                x={x}
                y={SVG_HEIGHT - 15}
                textAnchor="middle"
                className="fill-white/20 font-black text-[9px] tracking-widest"
              >
                {ms >= 1000 ? `${(ms / 1000).toFixed(1)}S` : `${ms}MS`}
              </text>
            </g>
          );
        })}

        {/* Bars */}
        {bars.map((bar, i) => {
          const y = i * ROW_HEIGHT + 20;
          const barX = LABEL_WIDTH + (bar.startMs / maxEndMs) * BAR_AREA_WIDTH;
          const barW = Math.max(
            4,
            (bar.durationMs / maxEndMs) * BAR_AREA_WIDTH,
          );
          const color = STATUS_COLORS[bar.status];

          return (
            <g
              key={`${bar.nodeId}-${i}`}
              className="group/bar transition-premium"
            >
              {/* Row background hover */}
              <rect
                x={0}
                y={y - 10}
                width={SVG_WIDTH}
                height={ROW_HEIGHT}
                fill="white"
                fillOpacity={0}
                className="group-hover/bar:fill-white/[0.02] transition-premium"
              />

              {/* Node label */}
              <text
                x={LABEL_WIDTH - 20}
                y={y + ROW_HEIGHT / 2 - 2}
                textAnchor="end"
                className="fill-white/40 group-hover/bar:fill-white font-black text-[10px] uppercase tracking-widest transition-premium"
              >
                {bar.nodeName.length > 24
                  ? bar.nodeName.slice(0, 22) + "..."
                  : bar.nodeName}
              </text>

              {/* Bar Glow */}
              <rect
                x={barX}
                y={y + 6}
                width={barW}
                height={ROW_HEIGHT - 20}
                rx={6}
                fill={color}
                fillOpacity={0.15}
                className={cn(bar.status === "running" && "animate-pulse")}
              />

              {/* Bar */}
              <rect
                x={barX}
                y={y + 6}
                width={barW}
                height={ROW_HEIGHT - 20}
                rx={6}
                fill={color}
                className={cn(
                  "transition-premium",
                  bar.status === "running" && "animate-pulse",
                )}
              />

              {/* Duration label (right of bar) */}
              <text
                x={barX + barW + 12}
                y={y + ROW_HEIGHT / 2 - 2}
                className="fill-white/20 font-mono text-[9px] font-bold group-hover/bar:fill-white/60 transition-premium"
              >
                {bar.durationMs >= 1000
                  ? `${(bar.durationMs / 1000).toFixed(1)}S`
                  : `${Math.round(bar.durationMs)}MS`}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
