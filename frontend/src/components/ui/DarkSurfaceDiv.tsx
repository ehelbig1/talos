import React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple wrapper that applies the shared dark surface styling to a div.
 * Uses Tailwind CSS classes for consistent theme adherence.
 */
export const DarkSurfaceDiv = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("bg-card text-card-foreground rounded-lg", className)}
      {...props}
    />
  );
});

DarkSurfaceDiv.displayName = "DarkSurfaceDiv";
