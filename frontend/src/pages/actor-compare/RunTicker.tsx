/**
 * Status ticker shown while a comparison run is in flight: avatar stack
 * plus pending/active/complete counts. Strictly presentational.
 */

import React from "react";
import { cn } from "@/lib/utils";
import { Loader2, Bot } from "lucide-react";
import type { LaneState } from "./types";

export function RunTicker({ lanes }: { lanes: LaneState[] }) {
  return (
    <div className="flex items-center gap-6 px-8 py-4 bg-primary/5 border border-primary/10 rounded-2xl shadow-2xl animate-in slide-in-from-top-4">
      <div className="flex -space-x-3">
        {lanes.map((l, i) => (
          <div
            key={l.actor.id}
            className="w-8 h-8 rounded-full border-2 border-background bg-surface-4 flex items-center justify-center shadow-xl"
            style={{ zIndex: 10 - i }}
          >
            <Bot
              className={cn(
                "w-4 h-4",
                l.status === "running"
                  ? "text-primary animate-pulse"
                  : "text-muted-foreground/20",
              )}
            />
          </div>
        ))}
      </div>
      <div className="flex-1 flex items-center gap-4 text-[10px] font-black uppercase tracking-[0.2em] text-primary">
        <Loader2 className="w-4 h-4 animate-spin" />
        SYSTEM_BROADCAST: SYNCHRONIZED EXECUTION IN PROGRESS...
        <div className="ml-auto flex gap-6">
          <span className="text-white/40">
            PENDING:{" "}
            {
              lanes.filter(
                (l) => l.status === "queued" || l.status === "triggering",
              ).length
            }
          </span>
          <span className="animate-pulse">
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
