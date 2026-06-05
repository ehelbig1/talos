import React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple loading spinner used as a fallback for lazy‑loaded dialogs.
 * Keeps the UI responsive while code splitting chunks are fetched.
 */
interface LoadingSpinnerProps extends React.HTMLAttributes<HTMLDivElement> {}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  className,
  ...props
}) => (
  <div
    className={cn(
      "flex flex-col items-center justify-center py-12 gap-4",
      className,
    )}
    aria-label="Loading"
    {...props}
  >
    <div className="relative">
      <div className="absolute inset-0 bg-primary/20 rounded-full blur-xl animate-status-pulse" />
      <svg
        className="animate-spin h-10 w-10 text-primary relative z-10 icon-glow"
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
      >
        <circle
          className="opacity-10"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="3"
        />
        <path
          className="opacity-90"
          fill="currentColor"
          d="M4 12a8 8 0 018-8v2a6 6 0 00-6 6H4z"
        />
      </svg>
    </div>
    <div className="flex flex-col items-center gap-1">
      <span className="text-[10px] font-black text-white uppercase tracking-[0.4em] animate-pulse">
        Initializing
      </span>
      <span className="text-[8px] font-bold text-muted-foreground/40 uppercase tracking-[0.2em]">
        Operational Uplink Pending
      </span>
    </div>
  </div>
);
