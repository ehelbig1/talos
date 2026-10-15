/**
 * One comparison lane on the Actor Strategic Compare page: actor header,
 * status badge, execution meta, error card, output payload, and the
 * telemetry-log toggle. Strictly presentational — lane state comes in
 * via props (useCompareRun owns it).
 */

import React, { useState, useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import {
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Bot,
  AlertTriangle,
} from "lucide-react";
import type { ExecStatus, LaneState } from "./types";

// ── helpers ───────────────────────────────────────────────────────────────────

export function StatusBadge({ status }: { status: ExecStatus }) {
  const map: Record<
    ExecStatus,
    { label: string; className: string; icon: React.ReactNode; glow: string }
  > = {
    idle: {
      label: "Idle",
      className: "text-muted-foreground/70 bg-white/5",
      icon: <Clock className="w-3 h-3" />,
      glow: "",
    },
    triggering: {
      label: "Starting…",
      className: "text-primary bg-primary/10",
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
      glow: "",
    },
    queued: {
      label: "Queued",
      className: "text-warning bg-warning/10",
      icon: <Clock className="w-3 h-3" />,
      glow: "",
    },
    running: {
      label: "Running",
      className: "text-primary bg-primary/10",
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
      glow: "",
    },
    completed: {
      label: "Succeeded",
      className: "text-success bg-success/10",
      icon: <CheckCircle2 className="w-3 h-3" />,
      glow: "",
    },
    failed: {
      label: "Failed",
      className: "text-destructive bg-destructive/10",
      icon: <XCircle className="w-3 h-3" />,
      glow: "",
    },
    cancelled: {
      label: "Cancelled",
      className: "text-muted-foreground/60 bg-white/5",
      icon: <XCircle className="w-3 h-3" />,
      glow: "",
    },
  };
  const { label, className, icon, glow } = map[status] ?? map.idle;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 text-xs font-semibold px-3 py-1 rounded-full border border-white/5 transition-ui",
        className,
        glow,
      )}
    >
      {icon}
      {label}
    </span>
  );
}

function formatDuration(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms}MS`;
  return `${(ms / 1000).toFixed(1)}S`;
}

function tryPrettyJson(raw: string | null): string {
  if (!raw) return "—";
  try {
    const parsed = JSON.parse(raw);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return raw;
  }
}

// ── CompareLane ───────────────────────────────────────────────────────────────

export function CompareLane({ lane }: { lane: LaneState }) {
  const [showLogs, setShowLogs] = useState(false);
  const logsRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (showLogs && logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [lane.logs, showLogs]);

  const isActive = lane.status === "running" || lane.status === "queued";

  return (
    <div
      className={cn(
        "flex flex-col gap-6 rounded-2xl border p-8 transition-ui relative overflow-hidden bg-surface-3 border border-white/10",
        isActive
          ? "border-primary/30 bg-primary/5 ring-1 ring-primary/20"
          : lane.status === "completed"
            ? "border-success/20 bg-success/[0.02]"
            : lane.status === "failed"
              ? "border-destructive/20 bg-destructive/[0.02]"
              : "border-white/5 bg-surface-1/40",
      )}
    >
      {/* Actor header */}
      <div className="flex items-start justify-between gap-4 relative z-10">
        <div className="flex items-center gap-4 min-w-0">
          <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0 transition-ui">
            <Bot className="w-6 h-6 text-primary" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white truncate font-outfit">
              {lane.actor.name}
            </p>
            {lane.actor.description && (
              <p className="text-xs text-muted-foreground/70 font-bold truncate mt-1">
                {lane.actor.description}
              </p>
            )}
          </div>
        </div>
        <StatusBadge status={lane.status} />
      </div>

      <div className="space-y-6 relative z-10">
        {/* Execution Meta */}
        <div className="flex items-center justify-between px-1">
          {lane.executionId && (
            <div className="flex flex-col gap-1">
              <span className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                Run ID
              </span>
              <span className="text-xs text-white font-mono opacity-60">
                {lane.executionId.slice(0, 12)}...
              </span>
            </div>
          )}
          {(lane.status === "completed" || lane.status === "failed") && (
            <div className="flex flex-col gap-1 items-end">
              <span className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                Duration
              </span>
              <span className="text-xs text-white font-semibold">
                {formatDuration(lane.durationMs)}
              </span>
            </div>
          )}
        </div>

        {/* Error */}
        {lane.status === "failed" && lane.errorMessage && (
          <div className="flex items-start gap-3 bg-destructive/10 border border-destructive/20 rounded-2xl px-5 py-4">
            <AlertTriangle className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
            <p className="text-xs text-destructive/80 font-bold leading-relaxed">
              {lane.errorMessage}
            </p>
          </div>
        )}

        {/* Output */}
        {lane.output && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 ml-1">
              <div className="w-1.5 h-1.5 rounded-full bg-primary" />
              <p className="text-xs text-muted-foreground/70 font-semibold">
                Output
              </p>
            </div>
            <div className="relative group">
              <pre className="text-xs text-white/80 bg-surface-4/60 border border-white/5 rounded-2xl p-5 overflow-auto max-h-80 whitespace-pre-wrap break-words font-mono leading-relaxed selection:bg-primary/30">
                {tryPrettyJson(lane.output)}
              </pre>
            </div>
          </div>
        )}

        {/* Logs toggle */}
        {lane.logs.length > 0 && (
          <div className="space-y-3 pt-2">
            <button
              onClick={() => setShowLogs((v) => !v)}
              className="flex items-center gap-3 px-4 py-2 rounded-xl bg-white/5 border border-white/5 text-xs text-muted-foreground/60 font-semibold hover:text-white hover:bg-white/10 transition-ui"
            >
              <Clock className="w-3 h-3" />
              {showLogs ? "Hide logs" : `Show logs (${lane.logs.length})`}
            </button>
            {showLogs && (
              <div
                ref={logsRef}
                className="text-xs font-mono text-muted-foreground/70 bg-surface-4/60 border border-white/5 rounded-2xl p-5 max-h-48 overflow-y-auto space-y-1 custom-scrollbar"
              >
                {lane.logs.map((line, i) => (
                  <div
                    key={i}
                    className="leading-relaxed selection:bg-primary/20"
                  >
                    <span className="opacity-20 mr-3">
                      [{i.toString().padStart(3, "0")}]
                    </span>
                    {line}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Idle placeholder */}
        {lane.status === "idle" && (
          <div className="flex flex-col items-center justify-center py-10 opacity-20 gap-3 grayscale">
            <div className="p-4 rounded-2xl bg-white/5 border border-white/10">
              <Bot className="w-8 h-8 text-muted-foreground/60" />
            </div>
            <p className="text-xs text-muted-foreground/60 font-semibold">
              Waiting to start
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
