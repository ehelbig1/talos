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
      "bg-destructive/10 border border-destructive/20 text-destructive px-4 py-3 rounded-xl mb-6 flex items-start gap-3 text-sm",
      className,
    )}
  >
    <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
    <span className="break-words">{message}</span>
  </div>
);
