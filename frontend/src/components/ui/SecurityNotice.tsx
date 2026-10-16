import React from "react";
import { cn } from "@/lib/utils";
import { ShieldAlert } from "lucide-react";

/**
 * Reusable notice used to warn users about secret handling.
 * Standardized to use theme-consistent amber colors and Lucide icons.
 */
export const SecurityNotice: React.FC<{
  children: React.ReactNode;
  className?: string;
}> = ({ children, className }) => (
  <div
    className={cn(
      "mt-2 p-3 bg-warning/10 border border-warning/20 rounded-lg flex items-start gap-2",
      className,
    )}
  >
    <ShieldAlert className="h-4 w-4 text-warning shrink-0 mt-0.5" />
    <div className="text-sm text-warning/90 font-medium">{children}</div>
  </div>
);
