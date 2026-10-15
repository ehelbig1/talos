import * as React from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>((props, ref) => {
  return (
    <input
      ref={ref}
      className={cn(
        "flex h-10 w-full rounded-xl border border-white/10 bg-surface-4/60 px-4 py-2 text-sm transition-ui file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 focus-visible:border-primary/50 disabled:cursor-not-allowed disabled:opacity-40",
        props.className,
      )}
      {...props}
    />
  );
});

Input.displayName = "Input";
export { Input };
