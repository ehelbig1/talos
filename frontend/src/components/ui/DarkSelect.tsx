import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Reusable dark‑theme `select` element.
 * Standardized to use theme variables.
 */
export const DarkSelect = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>((props, ref) => {
  const { className, ...rest } = props;
  return (
    <select
      ref={ref}
      className={cn(
        "bg-surface-4/60 border border-white/10 text-foreground rounded-xl px-4 text-sm h-10 transition-premium appearance-none leading-normal",
        "focus:outline-none focus:border-primary/40 focus:ring-2 focus:ring-primary/20",
        className,
      )}
      {...rest}
    />
  );
});

DarkSelect.displayName = "DarkSelect";
