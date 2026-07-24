/**
 * Pre-run setup panel for the Actor Strategic Compare page: the target
 * workflow selector and the actor-cohort multi-select. Strictly
 * presentational — selection state lives in the parent.
 */

import React from "react";
import { cn } from "@/lib/utils";
import { CheckCircle2, Clock, Loader2, Bot } from "lucide-react";
import type { ActorSummary } from "@/lib/graphqlApi";
import type { WorkflowOption } from "./types";

export function SetupPanel({
  workflows,
  loadingWorkflows,
  selectedWorkflowId,
  onSelectWorkflow,
  activeActors,
  loadingActors,
  selectedActorIds,
  onToggleActor,
  onGoToActors,
}: {
  workflows: WorkflowOption[];
  loadingWorkflows: boolean;
  selectedWorkflowId: string;
  onSelectWorkflow: (id: string) => void;
  activeActors: ActorSummary[];
  loadingActors: boolean;
  selectedActorIds: Set<string>;
  onToggleActor: (id: string) => void;
  onGoToActors: () => void;
}) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Workflow selector */}
      <div className="bg-surface-1/40 border border-white/5 rounded-[2.5rem] p-10 space-y-6 glass-dark shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-5">
          <Clock size={120} />
        </div>
        <h2 className="text-[10px] font-black text-primary uppercase tracking-[0.3em] flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full bg-primary animate-status-pulse" />
          01. SELECT TARGET WORKFLOW
        </h2>
        {loadingWorkflows ? (
          <div className="flex items-center gap-3 text-muted-foreground/30 animate-pulse py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-xs font-bold uppercase tracking-widest">
              Accessing Registry...
            </span>
          </div>
        ) : workflows.length === 0 ? (
          <p className="text-muted-foreground/40 text-xs font-bold uppercase tracking-widest py-4">
            No active protocols detected.
          </p>
        ) : (
          <div className="relative group">
            <div className="absolute -inset-px bg-gradient-to-r from-primary/20 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition-premium" />
            <select
              value={selectedWorkflowId}
              onChange={(e) => onSelectWorkflow(e.target.value)}
              className="w-full bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-4 text-xs font-bold text-white uppercase tracking-widest focus:outline-none focus:ring-2 focus:ring-primary/40 transition-premium appearance-none cursor-pointer relative z-10 shadow-inner"
            >
              <option value="" className="bg-surface-4">
                — SELECT PROTOCOL —
              </option>
              {workflows.map((w) => (
                <option key={w.id} value={w.id} className="bg-surface-4">
                  {w.name}
                </option>
              ))}
            </select>
          </div>
        )}
        <p className="text-[10px] text-muted-foreground/20 font-bold uppercase tracking-widest leading-relaxed">
          Choose the shared operational sequence to evaluate across multiple
          actor profiles.
        </p>
      </div>

      {/* Actor selector */}
      <div className="bg-surface-1/40 border border-white/5 rounded-[2.5rem] p-10 space-y-6 glass-dark shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-5">
          <Bot size={120} />
        </div>
        <h2 className="text-[10px] font-black text-primary uppercase tracking-[0.3em] flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full bg-primary animate-status-pulse" />
          02. IDENTIFY ACTOR COHORT
          <span className="text-muted-foreground/40 normal-case font-bold tracking-widest ml-auto">
            (MIN_REQ: 2)
          </span>
        </h2>
        {loadingActors ? (
          <div className="flex items-center gap-3 text-muted-foreground/30 animate-pulse py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-xs font-bold uppercase tracking-widest">
              Scanning Identities...
            </span>
          </div>
        ) : activeActors.length === 0 ? (
          <p className="text-muted-foreground/40 text-xs font-bold uppercase tracking-widest py-4">
            No active identities.{" "}
            <button
              onClick={onGoToActors}
              className="text-primary hover:text-white transition-premium underline"
            >
              REGISTER_NEW →
            </button>
          </p>
        ) : (
          <div className="space-y-3 max-h-72 overflow-y-auto pr-3 custom-scrollbar">
            {activeActors.map((actor) => {
              const selected = selectedActorIds.has(actor.id);
              return (
                <label
                  key={actor.id}
                  className={cn(
                    "flex items-center gap-4 p-4 rounded-2xl cursor-pointer transition-premium group relative overflow-hidden",
                    selected
                      ? "bg-primary/5 border-primary/20 shadow-xl"
                      : "bg-surface-3/40 border border-white/5 hover:border-white/20",
                  )}
                >
                  <div
                    className={cn(
                      "w-5 h-5 rounded-md border transition-premium flex items-center justify-center shrink-0",
                      selected
                        ? "bg-primary border-primary shadow-[0_0_10px_hsla(var(--primary),0.5)]"
                        : "border-white/10 group-hover:border-white/30",
                    )}
                  >
                    {selected && (
                      <CheckCircle2 className="w-3 h-3 text-white" />
                    )}
                  </div>
                  <input
                    type="checkbox"
                    checked={selected}
                    onChange={() => onToggleActor(actor.id)}
                    className="hidden"
                  />
                  <div className="min-w-0 flex-1">
                    <p className="text-[11px] font-black text-white uppercase tracking-widest truncate">
                      {actor.name}
                    </p>
                    {actor.description && (
                      <p className="text-[9px] text-muted-foreground/40 font-bold uppercase tracking-tight truncate mt-1">
                        {actor.description}
                      </p>
                    )}
                  </div>
                  <span className="text-[9px] text-primary/40 font-black tracking-widest uppercase shrink-0">
                    {actor.maxCapabilityWorld}
                  </span>
                </label>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
