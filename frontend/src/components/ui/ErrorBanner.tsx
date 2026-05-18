import React from "react";
import { cn } from "@/lib/utils";
import { AlertCircle } from "lucide-react";

/**
 * Simple, reusable error banner used across dialogs.
 * Standardized to use theme variables and consistent dark-mode styling.
 */
export const ErrorBanner: React.FC<{ message: string; className?: string }> = ({
  message,
  className,
}) => (
  <div
    role="alert"
    className={cn(
      "bg-destructive/5 border border-destructive/20 text-destructive px-5 py-4 rounded-2xl mb-6 flex items-center gap-4 text-[11px] font-black uppercase tracking-widest shadow-2xl relative overflow-hidden group",
      className,
    )}
  >
    <AlertCircle className="h-4 w-4 shrink-0 opacity-80" />
    <span className="relative z-10">{message}</span>
    <div className="absolute inset-0 bg-destructive/5 opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
  </div>
);
