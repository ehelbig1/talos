/**
 * Status ticker shown while a comparison run is in flight: avatar stack
 * plus pending/active/complete counts. Strictly presentational.
 */

import React from "react";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";
import { Bot } from "lucide-react";
import type { LaneState } from "./types";

export function RunTicker({ lanes }: { lanes: LaneState[] }) {
  return (
    <div className="flex items-center gap-6 px-8 py-4 bg-primary/5 border border-primary/10 rounded-2xl">
      <div className="flex -space-x-3">
        {lanes.map((l, i) => (
          <div
            key={l.actor.id}
            className="w-8 h-8 rounded-full border-2 border-background bg-surface-4 flex items-center justify-center"
            style={{ zIndex: 10 - i }}
          >
            <Bot
              className={cn(
                "w-4 h-4",
                l.status === "running"
                  ? "text-primary"
                  : "text-muted-foreground/50",
              )}
            />
          </div>
        ))}
      </div>
      <div className="flex-1 flex items-center gap-4 text-xs font-semibold text-primary">
        <Spinner className="w-4 h-4" />
        Running all actors…
        <div className="ml-auto flex gap-6">
          <span className="text-white/70">
            PENDING:{" "}
            {
              lanes.filter(
                (l) => l.status === "queued" || l.status === "triggering",
              ).length
            }
          </span>
          <span>
            ACTIVE: {lanes.filter((l) => l.status === "running").length}
          </span>
          <span className="text-success">
            COMPLETE: {lanes.filter((l) => l.status === "completed").length}
          </span>
        </div>
      </div>
    </div>
  );
}
