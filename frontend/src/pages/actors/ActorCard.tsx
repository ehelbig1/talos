import React, { useState } from "react";
import {
  Play,
  Copy,
  CheckSquare,
  Square as SquareIcon,
  Trash2,
  GitBranch,
  Zap,
  Clock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ConfirmDialog } from "@/components/ui";
import { relativeTime } from "@/lib/formatTime";
import { getCapabilityConfig } from "@/lib/capabilityConfig";
import { statusColors } from "@/pages/actor-detail/shared";
export { statusColors };
import type { ActorSummary } from "@/lib/graphqlApi";

// ── CapabilityBadge ───────────────────────────────────────────────────────────

export function CapabilityBadge({
  world,
  size = "md",
}: {
  world: string;
  size?: "sm" | "md";
}) {
  const cfg = getCapabilityConfig(world);
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-semibold",
        cfg.textColor,
        cfg.bgColor,
        cfg.borderColor,
        size === "sm"
          ? "text-2xs px-2 py-0.5"
          : "text-2xs px-2.5 py-0.5 shadow-sm",
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
        "group relative flex flex-col gap-6 p-7 rounded-2xl bg-surface-3/40 border border-white/10 transition-premium hover:border-primary/20 hover:scale-[1.02] active:scale-[0.98] overflow-hidden",
        compareMode && selectedForCompare && "ring-2 ring-primary",
        isTerminated && "opacity-60 grayscale-[0.5]",
      )}
    >
      <ConfirmDialog
        open={showConfirm}
        title="Delete actor"
        message={`Delete actor "${actor.name}"? Its workflows will stop running as it.`}
        confirmLabel="Delete actor"
        destructive
        isLoading={isTerminating}
        onConfirm={() => {
          setShowConfirm(false);
          onTerminate();
        }}
        onCancel={() => setShowConfirm(false)}
      />

      {compareMode && !isTerminated && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggleCompare();
          }}
          className="absolute top-6 right-6 z-10 p-2.5 rounded-2xl bg-surface-4/80 border border-white/10 text-primary transition-premium active:scale-90"
        >
          {selectedForCompare ? (
            <CheckSquare className="w-6 h-6" />
          ) : (
            <SquareIcon className="w-6 h-6 text-muted-foreground/50 hover:text-primary transition-colors" />
          )}
        </button>
      )}

      {/* Decorative Glow */}

      {/* Header */}
      <div className="flex items-start justify-between gap-5 relative z-10">
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex items-center gap-3 flex-wrap">
            <h3
              onClick={onView}
              className="text-xl font-semibold text-white tracking-tight hover:text-primary transition-premium cursor-pointer truncate leading-tight font-outfit"
            >
              {actor.name}
            </h3>
            <CapabilityBadge world={actor.maxCapabilityWorld} size="sm" />
          </div>
          {actor.description ? (
            <p className="text-muted-foreground/60 text-xs font-bold line-clamp-1 leading-relaxed">
              {actor.description}
            </p>
          ) : (
            <p className="text-muted-foreground/50 text-xs font-semibold italic leading-none">
              ID Unclassified
            </p>
          )}
        </div>

        <span
          className={cn(
            "shrink-0 px-3 py-1 rounded-lg border border-white/5 text-2xs font-semibold uppercase tracking-wider flex items-center gap-2 shadow-sm transition-premium",
            colors.badge,
          )}
        >
          <span
            className={cn(
              "w-2 h-2 rounded-full",
              colors.dot,
              actor.status === "active" && "animate-status-pulse",
            )}
          />
          {actor.status}
        </span>
      </div>

      {/* Metrics Registry */}
      <div className="grid grid-cols-3 gap-3 relative z-10">
        {[
          {
            label: "Logic",
            value: actor.workflowCount,
            icon: GitBranch,
            accent: "group-hover/m:text-primary",
          },
          {
            label: "Cycles",
            value:
              actor.executionCount >= 1000
                ? `${(actor.executionCount / 1000).toFixed(1)}k`
                : actor.executionCount,
            icon: Zap,
            accent: "group-hover/m:text-success",
          },
          {
            label: "Activity",
            value: relativeTime(actor.updatedAt),
            icon: Clock,
            accent: "group-hover/m:text-warning",
          },
        ].map((s) => (
          <div
            key={s.label}
            className="bg-surface-4/40 border border-white/5 rounded-2xl p-4 text-center transition-premium hover:bg-surface-4/60 hover:border-white/20 bg-white/[0.03] border border-white/5 group/m shadow-sm"
          >
            <div className="flex items-center justify-center gap-2 mb-2 opacity-30 group-hover/m:opacity-100 transition-premium">
              <s.icon className={cn("w-3 h-3 transition-colors", s.accent)} />
              <span className="text-2xs font-semibold uppercase tracking-wider">
                {s.label}
              </span>
            </div>
            <div className="text-sm font-semibold text-white font-outfit tracking-tighter truncate">
              {s.value}
            </div>
          </div>
        ))}
      </div>

      {/* Controller Actions */}
      <div className="mt-auto pt-6 border-t border-white/5 flex items-center justify-between gap-4 relative z-10">
        <span className="text-2xs font-semibold text-muted-foreground/50 uppercase tracking-wider">
          Created{" "}
          <span className="text-white/50">{relativeTime(actor.createdAt)}</span>
        </span>

        {!isTerminated && (
          <div className="flex items-center gap-2">
            {actor.status === "active" && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onQuickRun();
                }}
                className="w-10 h-10 flex items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 hover:border-primary/40 transition-premium active:scale-90"
                title="Execute Manual Cycle"
              >
                <Play className="w-4.5 h-4.5" fill="currentColor" />
              </button>
            )}

            <div className="h-6 w-px bg-white/5 mx-1" />

            <button
              onClick={(e) => {
                e.stopPropagation();
                onClone();
              }}
              disabled={isCloning}
              className="w-10 h-10 flex items-center justify-center rounded-xl bg-surface-4/60 text-muted-foreground/70 border border-white/5 hover:text-white hover:bg-surface-4 hover:border-white/20 transition-premium active:scale-95 disabled:opacity-30 bg-white/[0.03] border border-white/5"
              title="Duplicate actor"
            >
              <Copy className="w-4 h-4" />
            </button>

            <button
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
              disabled={isToggling}
              className={cn(
                "h-10 px-5 rounded-xl text-sm font-semibold border transition-premium active:scale-95 disabled:opacity-30",
                actor.status === "active"
                  ? "bg-warning/5 text-warning/80 border-warning/20 hover:bg-warning/10 hover:border-warning/40"
                  : "bg-success/5 text-success/80 border-success/20 hover:bg-success/10 hover:border-success/40",
              )}
            >
              {isToggling
                ? "..."
                : actor.status === "active"
                  ? "Suspend"
                  : "Deploy"}
            </button>

            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowConfirm(true);
              }}
              className="w-10 h-10 flex items-center justify-center rounded-xl text-muted-foreground/50 hover:text-destructive hover:bg-destructive/10 hover:border-destructive/20 border border-transparent transition-premium active:scale-90"
              title="Delete actor"
            >
              <Trash2 className="w-4.5 h-4.5" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
