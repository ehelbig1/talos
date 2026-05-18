import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Small inline button used for actions like "Show/Hide" where the visual
 * appearance is a simple text link with underline.
 * Standardized to use theme variables and consistent hover states.
 */
export const TextButton: React.FC<{
  onClick: () => void;
  ariaLabel?: string;
  children: React.ReactNode;
  className?: string;
}> = ({ onClick, ariaLabel, children, className }) => (
  <button
    type="button"
    onClick={onClick}
    aria-label={ariaLabel}
    className={cn(
      "bg-transparent border-none text-primary hover:text-primary/80 cursor-pointer text-sm underline transition-premium p-0 font-medium",
      className,
    )}
  >
    {children}
  </button>
);
