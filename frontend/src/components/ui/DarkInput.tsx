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
        "w-full bg-surface-4/40 backdrop-blur-xl border border-white/5 text-foreground rounded-2xl px-5 h-11 text-sm transition-premium placeholder:text-muted-foreground/20 gpu shadow-inner leading-normal",
        "focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 focus:shadow-[0_0_30px_hsla(var(--primary),0.15),inset_0_0_10px_rgba(0,0,0,0.2)]",
        className,
      )}
      {...rest}
    />
  );
});

DarkInput.displayName = "DarkInput";
