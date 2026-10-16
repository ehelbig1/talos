import * as React from "react";
import { Loader2, type LucideProps } from "lucide-react";
import { cn } from "@/lib/utils";

export interface SpinnerProps extends LucideProps {
  /** Announce the spinner to assistive technology. Without it the spinner is decorative. */
  label?: string;
}

/**
 * The one inline loading indicator: a spinning ring that takes the text
 * colour and is w-4 h-4 unless the className says otherwise.
 */
export function Spinner({ className, label, ...props }: SpinnerProps) {
  return (
    <Loader2
      className={cn("w-4 h-4 shrink-0 animate-spin", className)}
      aria-hidden={label ? undefined : true}
      role={label ? "status" : undefined}
      aria-label={label}
      {...props}
    />
  );
}

export interface LoadingStateProps extends React.HTMLAttributes<HTMLDivElement> {
  /** One plain line under the spinner. */
  label?: string;
}

/**
 * The one block loading state: a centred spinner and one plain line,
 * announced once to assistive technology.
 */
export function LoadingState({
  label = "Loading…",
  className,
  ...props
}: LoadingStateProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground",
        className,
      )}
      {...props}
    >
      <Spinner className="w-8 h-8 text-primary" />
      <span className="text-sm">{label}</span>
    </div>
  );
}
