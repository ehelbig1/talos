/**
 * Shared panel chrome for the watch-channel settings panels: loading
 * placeholder, error card with retry, header row (icon + title +
 * subtitle + Refresh/Create actions), and the dashed empty-state CTA.
 *
 * Strictly presentational — all data/actions come in via props so the
 * calendar and cloud panels keep their own data layers.
 */

import React from "react";
import { RefreshCw, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function WatchPanelLoading({
  message,
}: {
  message: string;
}): React.ReactElement {
  return (
    <div className="mt-10 p-6 bg-muted/10 border border-border/30 rounded-2xl text-sm text-muted-foreground">
      {message}
    </div>
  );
}

export function WatchPanelError({
  title,
  description,
  onRetry,
}: {
  title: string;
  description: string;
  onRetry: () => void;
}): React.ReactElement {
  return (
    <div className="mt-10 p-6 bg-destructive/5 border border-destructive/20 rounded-2xl">
      <p className="text-sm font-semibold text-foreground mb-1">{title}</p>
      <p className="text-xs text-muted-foreground mb-3">{description}</p>
      <Button
        variant="outline"
        size="sm"
        onClick={onRetry}
        className="h-8 px-3 text-xs"
      >
        <RefreshCw size={13} className="mr-1.5" /> Retry
      </Button>
    </div>
  );
}

export function WatchPanelHeader({
  icon,
  title,
  subtitle,
  isFetching,
  isLoading,
  onRefresh,
  onCreate,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  isFetching: boolean;
  isLoading: boolean;
  onRefresh: () => void;
  onCreate: () => void;
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 text-primary flex items-center justify-center">
          {icon}
        </div>
        <div>
          <h3 className="text-sm font-bold text-foreground">{title}</h3>
          <p className="text-xs text-muted-foreground">
            {subtitle}
            {isFetching && !isLoading && (
              <span className="ml-2 inline-flex items-center gap-1 text-[10px] text-muted-foreground/70">
                <span className="w-2 h-2 bg-primary/50 rounded-full animate-pulse" />
                refreshing
              </span>
            )}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={isFetching}
          className="h-8 px-3 text-xs"
        >
          <RefreshCw
            size={13}
            className={cn("mr-1.5", isFetching && "animate-spin")}
          />
          Refresh
        </Button>
        <Button size="sm" onClick={onCreate} className="h-8 px-3 text-xs">
          <Plus size={13} className="mr-1.5" /> Create
        </Button>
      </div>
    </div>
  );
}

export function WatchPanelEmptyState({
  icon,
  title,
  description,
  ctaLabel,
  onCreate,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  ctaLabel: string;
  onCreate: () => void;
}): React.ReactElement {
  return (
    <div className="border border-dashed border-border/60 rounded-2xl p-8 text-center">
      <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-primary/5 border border-primary/20 flex items-center justify-center text-primary">
        {icon}
      </div>
      <p className="text-sm font-semibold text-foreground mb-1">{title}</p>
      <p className="text-xs text-muted-foreground max-w-md mx-auto mb-5">
        {description}
      </p>
      <Button onClick={onCreate} className="h-9 px-5 text-xs font-bold">
        <Plus size={13} className="mr-1.5" />
        {ctaLabel}
      </Button>
    </div>
  );
}
