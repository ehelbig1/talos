import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple wrapper that adds a default bottom margin (1.5rem/mb-6) to its children.
 * Useful for reducing repetitive margin classes throughout dialogs and forms.
 */
export const Section = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => {
  return (
    <div ref={ref} className={cn("mb-6", className)} {...props}>
      {children}
    </div>
  );
});

Section.displayName = "Section";
