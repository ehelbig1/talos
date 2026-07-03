import React from "react";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import { Button } from "./button";

interface EmptyStatePropsWithChildren {
  children: React.ReactNode;
  className?: string;
  icon?: never;
  title?: never;
}

interface EmptyStatePropsStructured {
  /** Icon displayed above the message. Defaults to Inbox. */
  icon?: LucideIcon;
  /** Main heading. */
  title: string;
  /** Optional description below the heading. */
  description?: string;
  /** Optional CTA button label. */
  actionLabel?: string;
  /** Callback for the CTA button. */
  onAction?: () => void;
  className?: string;
  children?: never;
}

type EmptyStateProps = EmptyStatePropsWithChildren | EmptyStatePropsStructured;

/**
 * Consistent empty state for lists, tables, and panels.
 *
 * Supports two modes:
 * - **Structured:** pass `title`, optional `icon`, `description`, and `actionLabel`
 * - **Freeform:** pass `children` for custom content (backward-compatible)
 */
export const EmptyState: React.FC<EmptyStateProps> = (props) => {
  // Freeform mode (backward-compatible)
  if ("children" in props && props.children) {
    return (
      <div
        className={cn(
          "bg-surface-3/60 text-foreground p-8 rounded-xl border border-white/5 text-center",
          props.className,
        )}
      >
        {props.children}
      </div>
    );
  }

  // Structured mode
  const {
    icon: Icon = Inbox,
    title,
    description,
    actionLabel,
    onAction,
    className,
  } = props as EmptyStatePropsStructured;

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-16 px-8 text-center",
        className,
      )}
    >
      <div className="p-4 rounded-2xl bg-white/5 border border-white/5 mb-4">
        <Icon className="h-10 w-10 text-muted-foreground/40 stroke-[1.5px]" />
      </div>
      <h3 className="text-sm font-semibold text-foreground/80 mb-1">{title}</h3>
      {description && (
        <p className="text-xs text-muted-foreground/60 max-w-[280px] mb-4">
          {description}
        </p>
      )}
      {actionLabel && onAction && (
        <Button size="sm" variant="outline" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
};
