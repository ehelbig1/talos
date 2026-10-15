import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Re‑usable dark‑theme input field.
 * Standardized to use theme variables and consistent ring styling.
 */
export const DarkInput = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement>
>((props, ref) => {
  const { className, ...rest } = props;
  return (
    <input
      ref={ref}
      className={cn(
        "w-full bg-surface-4/60 border border-white/10 text-foreground rounded-xl px-4 h-10 text-sm transition-premium placeholder:text-muted-foreground/60 leading-normal",
        "focus:outline-none focus:border-primary/40 focus:ring-2 focus:ring-primary/20",
        className,
      )}
      {...rest}
    />
  );
});

DarkInput.displayName = "DarkInput";
