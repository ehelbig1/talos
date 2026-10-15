import React from "react";
import { cn } from "@/lib/utils";

/**
 * Small pill-shaped label (a status, a count, an id). Sentence case: the
 * content is the message, so it is not shouted.
 */
export const Badge: React.FC<
  React.PropsWithChildren<{
    className?: string;
    variant?: "default" | "outline";
  }>
> = ({ children, className, variant = "default" }) => (
  <span
    className={cn(
      "px-2 py-0.5 rounded-md text-2xs font-medium leading-4 inline-flex items-center justify-center whitespace-nowrap",
      variant === "default"
        ? "bg-white/5 text-muted-foreground border border-white/5"
        : "bg-transparent border border-white/10 text-muted-foreground/70",
      className,
    )}
  >
    {children}
  </span>
);
