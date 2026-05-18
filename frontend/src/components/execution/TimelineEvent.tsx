import React from "react";
import { ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui";
import { cn, formatDuration } from "@/lib/utils";
import type { TimedEvent } from "@/store/executionStore";

interface TimelineEventProps {
  ev: TimedEvent;
  idx: number;
  nodeName?: string;
}

/**
 * Renders a single event entry in the execution timeline.
 * Extracted from ExecutionPanel for readability and reuse.
 */
export function TimelineEvent({ ev, idx: _idx, nodeName }: TimelineEventProps) {
  const isFailed = ev.status === "NodeFailed" || ev.status === "FAILED";
  const isCompleted = ev.status === "NodeCompleted" || ev.status === "COMPLETED";
  const isRunningStatus = ev.status === "NodeRunning" || ev.status === "RUNNING";
  const isApproval = ev.status === "AwaitingApproval";

  return (
    <div className="flex gap-6 group animate-in fade-in slide-in-from-left-4 duration-500">
      {/* Timestamp */}
      <div className="w-14 pt-1.5 shrink-0 text-right">
        <span className="text-[10px] font-black font-mono text-muted-foreground/20 group-hover:text-primary transition-premium tracking-tighter">
          +{formatDuration(ev.elapsedMs)}
        </span>
      </div>

      {/* Node dot & content */}
      <div className="flex-1 flex gap-6 min-w-0">
        <div className="relative z-10 flex flex-col items-center shrink-0 pt-2">
          <div
            className={cn(
              "w-3 h-3 rounded-full border-2 bg-background transition-premium group-hover:scale-150 relative",
              isFailed
                ? "border-destructive shadow-[0_0_15px_hsla(var(--destructive),0.4)]"
                : isCompleted
                  ? "border-success shadow-[0_0_15px_hsla(var(--success),0.4)]"
                  : isRunningStatus
                    ? "border-primary animate-status-pulse shadow-[0_0_15px_hsla(var(--primary),0.4)]"
                    : isApproval
                      ? "border-warning shadow-[0_0_15px_hsla(var(--warning),0.4)]"
                      : "border-muted-foreground/10",
            )}
          >
             {isRunningStatus && (
               <div className="absolute inset-0 rounded-full animate-ping bg-primary/20" />
             )}
          </div>
        </div>

        <div className="flex-1 min-w-0 pb-8 border-b border-white/[0.03] group-last:border-0">
          <div className="flex flex-wrap items-center gap-3 mb-3">
            <span className={cn(
              "text-[9px] font-black px-2.5 py-1 rounded-full uppercase tracking-[0.2em] shadow-sm",
              isFailed
                ? "bg-destructive/10 text-destructive border border-destructive/20"
                : isCompleted
                  ? "bg-success/10 text-success border border-success/20"
                  : isApproval
                    ? "bg-warning/10 text-warning border border-warning/20"
                    : "bg-primary/10 text-primary border border-primary/20",
            )}>
              {ev.status}
            </span>

            {ev.nodeId && (
              <span className="text-sm font-black text-white font-outfit tracking-tight truncate max-w-[220px] group-hover:text-primary transition-premium">
                {nodeName}
              </span>
            )}

            <div className="flex items-center gap-2">
              {ev.retryAttempt != null && ev.retryAttempt > 0 && (
                <Badge className="bg-warning/5 text-warning/80 text-[8px] font-black h-4 px-2 border-warning/20 rounded-md tracking-widest uppercase">
                  RETRY_{ev.retryAttempt}
                </Badge>
              )}
              {ev.iterationIndex != null && (
                <Badge className="bg-primary/5 text-primary/80 text-[8px] font-black h-4 px-2 border-primary/20 rounded-md tracking-widest uppercase">
                  ITER_{ev.iterationIndex + 1}
                  {ev.iterationTotal ? `/${ev.iterationTotal}` : ""}
                </Badge>
              )}
              {ev.checkpointSaved && (
                <Badge className="bg-success/5 text-success/80 text-[8px] font-black h-4 px-2 border-success/20 rounded-md tracking-widest uppercase">
                  SNAPSHOT_STORED
                </Badge>
              )}
            </div>

            {ev.traceId && /^[0-9a-f]{16,64}$/i.test(ev.traceId) && import.meta.env.VITE_JAEGER_URL && (
              <a
                href={`${import.meta.env.VITE_JAEGER_URL}${ev.traceId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/20 hover:text-primary flex items-center gap-2 ml-auto transition-premium group/link"
              >
                <ExternalLink className="h-3 w-3 group-hover:scale-110 transition-transform" />
                Trace_Link
              </a>
            )}
          </div>

          {ev.logMessage && (
            <div className="mt-4 relative group/logbox">
              <div className="absolute -inset-0.5 bg-primary/5 rounded-2xl opacity-0 group-hover/logbox:opacity-100 transition-premium pointer-events-none" />
              <div className="relative bg-surface-4/40 rounded-2xl p-5 border border-white/5 shadow-2xl glass-dark optimize-blur transition-premium group-hover:border-white/10 group-hover:bg-surface-4/60">
                <p className="text-[11px] leading-relaxed text-muted-foreground group-hover:text-white/80 transition-colors font-mono break-words selection:bg-primary/30">
                  {ev.logMessage}
                </p>
              </div>
            </div>
          )}

          {isApproval && ev.approvalRequired && (
            <div className="flex flex-wrap gap-2 mt-4">
              {ev.approvalRequired.map((op) => (
                <span
                  key={op}
                  className="text-[9px] px-3 py-1 rounded-full bg-warning/5 text-warning/60 border border-warning/10 font-black uppercase tracking-[0.2em] shadow-sm"
                >
                  {op}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
