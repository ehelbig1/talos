import React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple wrapper that applies the shared card styling.
 * Uses the Tiered Glassmorphism surface tokens for consistent theming.
 */
export const Card: React.FC<{
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}> = ({ children, className, style }) => (
  <div
    className={cn(
      "bg-surface-3/60 rounded-xl p-4 border border-white/5 shadow-lg transition-premium",
      className,
    )}
    style={style}
  >
    {children}
  </div>
);
