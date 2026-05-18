import React from "react";
import { cn } from "@/lib/utils";

/**
 * Simple wrapper for informational notes used across the builder UI.
 * Uses Tailwind CSS classes for consistent theme adherence.
 */
export const NoteBox = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn(
        "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 p-3 rounded-lg text-sm",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
});

NoteBox.displayName = "NoteBox";
