import React from "react";
import { cn } from "@/lib/utils";

/**
 * Small pill‑shaped label used throughout the UI (e.g., module IDs).
 * Uses glassmorphic surface tokens for consistent dark-theme appearance.
 */
export const Badge: React.FC<
  React.PropsWithChildren<{
    className?: string;
    variant?: "default" | "outline";
  }>
> = ({ children, className, variant = "default" }) => (
  <span
    className={cn(
      "px-2.5 py-0.5 rounded-lg text-[10px] font-bold uppercase tracking-wider leading-none inline-flex items-center justify-center transition-premium",
      variant === "default"
        ? "bg-white/5 text-muted-foreground border border-white/5"
        : "bg-transparent border border-white/10 text-muted-foreground/70",
      className,
    )}
  >
    {children}
  </span>
);
