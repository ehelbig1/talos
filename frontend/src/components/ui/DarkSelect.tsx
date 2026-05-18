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
        "bg-surface-4/40 backdrop-blur-xl border border-white/5 text-foreground rounded-2xl px-5 text-sm h-11 transition-premium appearance-none gpu shadow-inner leading-normal",
        "focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 focus:shadow-[0_0_30px_hsla(var(--primary),0.15),inset_0_0_10px_rgba(0,0,0,0.2)]",
        className,
      )}
      {...rest}
    />
  );
});

DarkSelect.displayName = "DarkSelect";
