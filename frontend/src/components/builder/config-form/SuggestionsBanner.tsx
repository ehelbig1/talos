/**
 * Smart-suggestions banner for the node ConfigForm ("N Structural
 * Insight(s) detected") with the expandable review list and
 * apply/discard actions.
 *
 * Strictly presentational — suggestion state lives in the parent.
 */

import React from "react";
import { Lightbulb, X, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SmartSuggestion } from "./types";

export function SuggestionsBanner({
  suggestions,
  showSuggestions,
  onShow,
  onHide,
  onApply,
  onDiscard,
}: {
  suggestions: SmartSuggestion[];
  showSuggestions: boolean;
  onShow: () => void;
  onHide: () => void;
  onApply: () => void;
  onDiscard: () => void;
}) {
  return (
    <div
      className={cn(
        "relative group/suggestions p-6 rounded-[2rem] border transition-premium overflow-hidden",
        showSuggestions
          ? "bg-primary/5 border-primary/20 shadow-2xl"
          : "bg-primary/5 border-primary/10 hover:border-primary/30",
      )}
    >
      <div className="absolute top-0 right-0 p-4 opacity-10 pointer-events-none">
        <Lightbulb className="w-12 h-12 text-primary" />
      </div>
      <div className="flex items-center justify-between mb-4 relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-primary/20 text-primary animate-pulse">
            <Zap className="h-4 w-4" />
          </div>
          <span className="text-[10px] font-black text-white uppercase tracking-[0.2em]">
            {suggestions.length} Structural Insight
            {suggestions.length > 1 ? "s" : ""} detected
          </span>
        </div>
        {!showSuggestions ? (
          <button
            onClick={onShow}
            className="text-[9px] font-black text-primary uppercase tracking-widest hover:text-white transition-premium"
          >
            Review Analysis
          </button>
        ) : (
          <button
            onClick={onHide}
            className="p-1.5 rounded-lg hover:bg-white/5 text-muted-foreground/20 hover:text-white transition-premium"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {showSuggestions && (
        <div className="space-y-6 relative z-10 animate-in fade-in slide-in-from-top-2">
          <ul className="space-y-3">
            {suggestions.map((s) => (
              <li key={s.field} className="flex gap-4 items-start group/s">
                <div className="mt-1 w-1.5 h-1.5 rounded-full bg-primary/40 group-hover/s:bg-primary transition-premium" />
                <div className="space-y-1">
                  <p className="text-[11px] font-bold text-white/60">
                    Override <span className="text-primary">{s.field}</span>{" "}
                    with{" "}
                    <code className="px-1.5 py-0.5 bg-white/5 rounded font-mono text-primary/80">
                      {JSON.stringify(s.value)}
                    </code>
                  </p>
                  <p className="text-[9px] font-black uppercase tracking-widest text-muted-foreground/20">
                    Reason: {s.reason}
                  </p>
                </div>
              </li>
            ))}
          </ul>
          <div className="flex items-center gap-3 pt-4 border-t border-white/5">
            <button
              onClick={onApply}
              className="px-6 h-9 bg-primary hover:bg-primary/90 text-white text-[9px] font-black uppercase tracking-widest rounded-xl transition-premium shadow-lg shadow-primary/20"
            >
              Apply Optimization
            </button>
            <button
              onClick={onDiscard}
              className="px-6 h-9 bg-surface-3 hover:bg-surface-4 text-muted-foreground/40 hover:text-white text-[9px] font-black uppercase tracking-widest rounded-xl transition-premium border border-white/5"
            >
              Discard
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
