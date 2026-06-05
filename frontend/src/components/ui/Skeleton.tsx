import React from "react";
import { cn } from "@/lib/utils";

/**
 * Skeleton loading primitives with shimmer animation.
 * Use while data is fetching to give the illusion of instant content.
 */

interface SkeletonProps {
  className?: string;
}

/** A single shimmering line placeholder. */
export const SkeletonLine: React.FC<SkeletonProps & { width?: string }> = ({
  className = "",
  width = "w-full",
}) => (
  <div
    className={cn("h-3 rounded animate-shimmer", width, className)}
    aria-hidden="true"
  />
);

/** A rectangular block placeholder (for config/content areas). */
export const SkeletonBlock: React.FC<SkeletonProps & { height?: string }> = ({
  className = "",
  height = "h-20",
}) => (
  <div
    className={cn("rounded-lg animate-shimmer w-full", height, className)}
    aria-hidden="true"
  />
);

/**
 * Card-shaped skeleton matching the WorkflowCard dimensions.
 * Shows a status dot, title line, meta lines, and action button placeholder.
 */
export const SkeletonCard: React.FC<SkeletonProps> = ({ className = "" }) => (
  <div
    className={cn(
      "bg-surface-3/60 border border-white/5 border-l-4 border-l-secondary",
      "rounded-lg p-4 flex flex-col gap-3 animate-fade-in-up",
      className,
    )}
    aria-hidden="true"
  >
    {/* Header row */}
    <div className="flex items-center gap-2">
      <div className="w-2 h-2 rounded-full animate-shimmer shrink-0" />
      <SkeletonLine width="w-3/5" />
    </div>
    {/* Meta lines */}
    <div className="space-y-1.5">
      <SkeletonLine width="w-2/5" />
      <SkeletonLine width="w-1/3" />
    </div>
    {/* Action button */}
    <div className="mt-auto pt-1">
      <div className="h-7 rounded animate-shimmer w-full" />
    </div>
  </div>
);

/**
 * Inspector config skeleton — shows placeholder for node name,
 * capability badge, and config fields.
 */
/** Row of 4 stat cards — matches Dashboard/ActorDetail stats layout. */
export const SkeletonStatRow: React.FC<SkeletonProps> = ({
  className = "",
}) => (
  <div
    className={cn("grid grid-cols-2 md:grid-cols-4 gap-3", className)}
    aria-hidden="true"
    data-testid="skeleton-stat-row"
  >
    {[0, 1, 2, 3].map((i) => (
      <div
        key={i}
        className="bg-surface-3/60 border border-white/5 rounded-lg p-4 space-y-2"
      >
        <SkeletonLine width="w-1/2" />
        <div className="h-7 rounded animate-shimmer w-2/3" />
        <SkeletonLine width="w-1/3" />
      </div>
    ))}
  </div>
);

/** Table skeleton — header + 5 shimmer rows, matches workflow/memory tables. */
export const SkeletonTable: React.FC<SkeletonProps & { rows?: number }> = ({
  className = "",
  rows = 5,
}) => (
  <div
    className={cn("w-full space-y-1", className)}
    aria-hidden="true"
    data-testid="skeleton-table"
  >
    {/* Header */}
    <div className="flex gap-4 px-3 py-2 border-b border-white/5">
      <SkeletonLine width="w-1/4" />
      <SkeletonLine width="w-1/6" />
      <SkeletonLine width="w-1/5" />
      <SkeletonLine width="w-1/6" />
    </div>
    {/* Rows */}
    {Array.from({ length: rows }, (_, i) => (
      <div key={i} className="flex gap-4 px-3 py-3">
        <SkeletonLine width="w-1/4" />
        <SkeletonLine width="w-1/6" />
        <SkeletonLine width="w-1/5" />
        <SkeletonLine width="w-1/6" />
      </div>
    ))}
  </div>
);

/** Timeline skeleton — matches ExecutionPanel event timeline. */
export const SkeletonTimeline: React.FC<SkeletonProps> = ({
  className = "",
}) => (
  <div
    className={cn("space-y-3 py-4", className)}
    aria-hidden="true"
    data-testid="skeleton-timeline"
  >
    {[0, 1, 2, 3].map((i) => (
      <div key={i} className="flex items-center gap-3 px-4">
        <div className="w-8 h-8 rounded-full animate-shimmer shrink-0" />
        <div className="flex-1 space-y-1.5">
          <SkeletonLine width="w-2/5" />
          <SkeletonLine width="w-3/5" />
        </div>
        <SkeletonLine width="w-16" />
      </div>
    ))}
  </div>
);

export const SkeletonInspector: React.FC<SkeletonProps> = ({
  className = "",
}) => (
  <div
    className={cn("space-y-4 p-3 animate-fade-in-up", className)}
    aria-hidden="true"
    data-testid="skeleton-inspector"
  >
    {/* Module name */}
    <div className="space-y-2">
      <SkeletonLine width="w-1/4" />
      <SkeletonLine width="w-3/5" className="h-4" />
    </div>
    {/* Capability badge area */}
    <SkeletonBlock height="h-16" />
    {/* Config fields */}
    <div className="space-y-3 pt-2">
      <SkeletonLine width="w-1/3" />
      <SkeletonBlock height="h-9" />
      <SkeletonLine width="w-1/4" />
      <SkeletonBlock height="h-9" />
    </div>
  </div>
);
