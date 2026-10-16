import * as React from "react";
import { cn } from "@/lib/utils";

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {}

/**
 * The one native select. Same height, radius, surface and focus ring as
 * `Input`; the chevron is drawn by the `select-chevron` utility so the
 * element stays a single `<select>` and `className` applies to it directly.
 */
const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, ...props }, ref) => {
    return (
      <select
        ref={ref}
        className={cn(
          "select-chevron flex h-10 w-full cursor-pointer appearance-none rounded-xl border border-white/10 bg-surface-4/60 py-2 pl-4 pr-10 text-sm text-foreground transition-ui focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:border-primary/50 disabled:cursor-not-allowed disabled:opacity-40",
          className,
        )}
        {...props}
      />
    );
  },
);

Select.displayName = "Select";
export { Select };
