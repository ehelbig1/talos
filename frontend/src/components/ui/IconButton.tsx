import React from "react";
import { cn } from "@/lib/utils";

/**
 * Common, themed icon button with consistent hover and focus states.
 * Uses glassmorphic surface tokens for consistent theming.
 */
export const IconButton: React.FC<{
  onClick?: (e: React.MouseEvent) => void;
  title?: string;
  "aria-label"?: string;
  disabled?: boolean;
  className?: string;
  children: React.ReactNode;
}> = ({
  onClick,
  title,
  "aria-label": ariaLabel,
  disabled,
  className,
  children,
}) => (
  <button
    type="button"
    onClick={onClick}
    title={title}
    aria-label={ariaLabel ?? title}
    disabled={disabled}
    className={cn(
      "p-1.5 rounded-xl border border-white/5 bg-white/5 hover:bg-white/10 hover:border-white/10 text-muted-foreground hover:text-foreground transition-premium flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 active:scale-95",
      className,
    )}
  >
    {children}
  </button>
);
