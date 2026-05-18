import React from "react";
import { cn } from "@/lib/utils";
import { Lightbulb } from "lucide-react";

/**
 * Small reusable tip banner used throughout the UI.
 * Standardized to use Lucide icons and theme variables.
 */
export const InfoTip: React.FC<{
  children: React.ReactNode;
  className?: string;
}> = ({ children, className }) => (
  <div
    className={cn(
      "flex items-start gap-2 text-sm text-muted-foreground bg-primary/5 border border-primary/10 rounded-lg p-3",
      className,
    )}
  >
    <Lightbulb className="h-4 w-4 text-primary shrink-0 mt-0.5" />
    <div>
      <strong className="text-primary/90 font-semibold mr-1">Tip:</strong>
      {children}
    </div>
  </div>
);
