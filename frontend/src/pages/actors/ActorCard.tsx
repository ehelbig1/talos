import React, { useState } from "react";
import { Play, Copy, CheckSquare, Square as SquareIcon, Trash2, GitBranch, Zap, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import { ConfirmDialog } from "@/components/ui";
import { relativeTime } from "@/lib/formatTime";
import { getCapabilityConfig } from "@/lib/capabilityConfig";
import { statusColors } from "@/pages/actor-detail/shared";
export { statusColors };
import type { ActorSummary } from "@/lib/graphqlClient";

// ── CapabilityBadge ───────────────────────────────────────────────────────────

export function CapabilityBadge({ world, size = "md" }: { world: string; size?: "sm" | "md" }) {
  const cfg = getCapabilityConfig(world);
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-black uppercase tracking-widest",
        cfg.textColor, cfg.bgColor, cfg.borderColor,
        size === "sm" ? "text-[8px] px-2 py-0.5" : "text-[9px] px-2.5 py-0.5 shadow-sm",
      )}
    >
      {cfg.label}
    </span>
  );
}

export interface ActorCardProps {
  actor: ActorSummary;
  onToggle: () => void;
  onTerminate: () => void;
  onView: () => void;
  onQuickRun: () => void;
  onClone: () => void;
  isToggling: boolean;
  isTerminating: boolean;
  isCloningId: string | null;
  compareMode: boolean;
  selectedForCompare: boolean;
  onToggleCompare: () => void;
}

export function ActorCard({
  actor,
  onToggle,
  onTerminate,
  onView,
  onQuickRun,
  onClone,
  isToggling,
  isTerminating,
  isCloningId,
  compareMode,
  selectedForCompare,
  onToggleCompare,
}: ActorCardProps) {
  const isCloning = isCloningId === actor.id;
  const [showConfirm, setShowConfirm] = useState(false);
  const colors = statusColors(actor.status);
  const isTerminated = actor.status === "terminated";

  return (
    <div
      className={cn(
        "group relative flex flex-col gap-6 p-7 rounded-[2.5rem] bg-surface-3/40 border border-white/10 backdrop-blur-3xl transition-premium hover:border-primary/20 hover:scale-[1.02] active:scale-[0.98] shadow-2xl overflow-hidden glass gpu",
        compareMode && selectedForCompare && "ring-2 ring-primary shadow-[0_0_30px_hsla(var(--primary),0.2)]",
        isTerminated && "opacity-60 grayscale-[0.5]"
      )}
    >
      <ConfirmDialog
        open={showConfirm}
        title="Identity Decommission"
        message={`Decommission identity "${actor.name}"? This action will suspend all active protocols for this entity.`}
        confirmLabel="Decommission"
        destructive
        isLoading={isTerminating}
        onConfirm={() => { setShowConfirm(false); onTerminate(); }}
        onCancel={() => setShowConfirm(false)}
      />

      {compareMode && !isTerminated && (
        <button
          onClick={(e) => { e.stopPropagation(); onToggleCompare(); }}
          className="absolute top-6 right-6 z-10 p-2.5 rounded-2xl bg-surface-4/80 border border-white/10 text-primary transition-premium hover:scale-110 active:scale-90 shadow-2xl backdrop-blur-md"
        >
          {selectedForCompare ? (
            <CheckSquare className="w-6 h-6 drop-shadow-[0_0_8px_hsla(var(--primary),0.6)]" />
          ) : (
            <SquareIcon className="w-6 h-6 text-muted-foreground/20 hover:text-primary transition-colors" />
          )}
        </button>
      )}

      {/* Decorative Glow */}
      <div className="absolute -top-16 -right-16 w-32 h-32 bg-primary/5 blur-[50px] group-hover:bg-primary/10 transition-premium" />

      {/* Header */}
      <div className="flex items-start justify-between gap-5 relative z-10">
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex items-center gap-3 flex-wrap">
            <h3 
              onClick={onView}
              className="text-xl font-black text-white tracking-tighter hover:text-primary transition-premium cursor-pointer truncate leading-tight font-outfit uppercase"
            >
              {actor.name}
            </h3>
            <CapabilityBadge world={actor.maxCapabilityWorld} size="sm" />
          </div>
          {actor.description ? (
            <p className="text-muted-foreground/60 text-xs font-bold line-clamp-1 leading-relaxed uppercase tracking-wide">{actor.description}</p>
          ) : (
            <p className="text-muted-foreground/20 text-[10px] font-black uppercase tracking-[0.3em] italic leading-none">ID Unclassified</p>
          )}
        </div>
        
        <span className={cn(
          "shrink-0 px-3 py-1 rounded-lg border border-white/5 text-[9px] font-black uppercase tracking-[0.2em] flex items-center gap-2 shadow-sm transition-premium",
          colors.badge
        )}>
          <span className={cn("w-2 h-2 rounded-full", colors.dot, actor.status === "active" && "animate-status-pulse shadow-[0_0_8px_currentColor]")} />
          {actor.status}
        </span>
      </div>

      {/* Metrics Registry */}
      <div className="grid grid-cols-3 gap-3 relative z-10">
        {[
          { label: "Logic", value: actor.workflowCount, icon: GitBranch, accent: "group-hover/m:text-primary" },
          { label: "Cycles", value: actor.executionCount >= 1000 ? `${(actor.executionCount/1000).toFixed(1)}k` : actor.executionCount, icon: Zap, accent: "group-hover/m:text-success" },
          { label: "Activity", value: relativeTime(actor.updatedAt), icon: Clock, accent: "group-hover/m:text-warning" },
        ].map((s) => (
          <div key={s.label} className="bg-surface-4/40 border border-white/5 rounded-2xl p-4 text-center transition-premium hover:bg-surface-4/60 hover:border-white/20 glass-light group/m shadow-sm">
            <div className="flex items-center justify-center gap-2 mb-2 opacity-30 group-hover/m:opacity-100 transition-premium">
              <s.icon className={cn("w-3 h-3 transition-colors", s.accent)} />
              <span className="text-[8px] font-black uppercase tracking-[0.3em]">{s.label}</span>
            </div>
            <div className="text-sm font-black text-white font-outfit tracking-tighter truncate">{s.value}</div>
          </div>
        ))}
      </div>

      {/* Controller Actions */}
      <div className="mt-auto pt-6 border-t border-white/5 flex items-center justify-between gap-4 relative z-10">
        <span className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-[0.3em]">
          Provisioned <span className="text-white/20">{relativeTime(actor.createdAt)}</span>
        </span>

        {!isTerminated && (
          <div className="flex items-center gap-2">
            {actor.status === "active" && (
              <button 
                onClick={(e) => { e.stopPropagation(); onQuickRun(); }} 
                className="w-10 h-10 flex items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 hover:border-primary/40 transition-premium shadow-xl active:scale-90"
                title="Execute Manual Cycle"
              >
                <Play className="w-4.5 h-4.5" fill="currentColor" />
              </button>
            )}
            
            <div className="h-6 w-px bg-white/5 mx-1" />

            <button 
              onClick={(e) => { e.stopPropagation(); onClone(); }} 
              disabled={isCloning}
              className="w-10 h-10 flex items-center justify-center rounded-xl bg-surface-4/60 text-muted-foreground/40 border border-white/5 hover:text-white hover:bg-surface-4 hover:border-white/20 transition-premium active:scale-95 disabled:opacity-30 shadow-xl glass-light"
              title="Duplicate Identity"
            >
              <Copy className="w-4 h-4" />
            </button>

            <button 
              onClick={(e) => { e.stopPropagation(); onToggle(); }} 
              disabled={isToggling}
              className={cn(
                "h-10 px-5 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border transition-premium active:scale-95 disabled:opacity-30 shadow-xl",
                actor.status === "active" 
                  ? "bg-warning/5 text-warning/80 border-warning/20 hover:bg-warning/10 hover:border-warning/40 shadow-warning/5" 
                  : "bg-success/5 text-success/80 border-success/20 hover:bg-success/10 hover:border-success/40 shadow-success/5"
              )}
            >
              {isToggling ? "..." : actor.status === "active" ? "Suspend" : "Deploy"}
            </button>

            <button 
              onClick={(e) => { e.stopPropagation(); setShowConfirm(true); }} 
              className="w-10 h-10 flex items-center justify-center rounded-xl text-muted-foreground/20 hover:text-destructive hover:bg-destructive/10 hover:border-destructive/20 border border-transparent transition-premium active:scale-90"
              title="Terminate Protocol"
            >
              <Trash2 className="w-4.5 h-4.5" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
