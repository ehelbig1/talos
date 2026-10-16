/**
 * Pre-run setup panel for the Actor Strategic Compare page: the target
 * workflow selector and the actor-cohort multi-select. Strictly
 * presentational — selection state lives in the parent.
 */

import React from "react";
import { Select } from "@/components/ui/select";
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
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
      {/* Workflow selector */}
      <div className="bg-surface-1/40 border border-white/5 rounded-2xl p-10 space-y-6 bg-surface-3 border border-white/10 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-5">
          <Clock size={120} />
        </div>
        <h2 className="text-xs font-semibold text-primary flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full bg-primary" />
          01. SELECT TARGET WORKFLOW
        </h2>
        {loadingWorkflows ? (
          <div className="flex items-center gap-3 text-muted-foreground/60 py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-xs font-bold">Accessing Registry...</span>
          </div>
        ) : workflows.length === 0 ? (
          <p className="text-muted-foreground/70 text-sm font-bold py-4">
            No workflows yet.
          </p>
        ) : (
          <div className="relative group">
            <Select
              value={selectedWorkflowId}
              onChange={(e) => onSelectWorkflow(e.target.value)}
              className="relative z-10"
            >
              <option value="" className="bg-surface-4">
                Select a workflow…
              </option>
              {workflows.map((w) => (
                <option key={w.id} value={w.id} className="bg-surface-4">
                  {w.name}
                </option>
              ))}
            </Select>
          </div>
        )}
        <p className="text-xs text-muted-foreground/50 leading-relaxed">
          Every actor runs this same workflow.
        </p>
      </div>

      {/* Actor selector */}
      <div className="bg-surface-1/40 border border-white/5 rounded-2xl p-10 space-y-6 bg-surface-3 border border-white/10 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-5">
          <Bot size={120} />
        </div>
        <h2 className="text-xs font-semibold text-primary flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full bg-primary" />
          02. Choose actors
          <span className="text-muted-foreground/70 normal-case font-bold tracking-wider ml-auto">
            (at least 2)
          </span>
        </h2>
        {loadingActors ? (
          <div className="flex items-center gap-3 text-muted-foreground/60 py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-xs font-bold">Loading actors…</span>
          </div>
        ) : activeActors.length === 0 ? (
          <p className="text-muted-foreground/70 text-sm font-bold py-4">
            No active actors.{" "}
            <button
              onClick={onGoToActors}
              className="text-primary hover:text-white transition-ui underline"
            >
              Create one →
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
                    "flex items-center gap-4 p-4 rounded-2xl cursor-pointer transition-ui group relative overflow-hidden",
                    selected
                      ? "bg-primary/5 border-primary/20"
                      : "bg-surface-3/40 border border-white/5 hover:border-white/20",
                  )}
                >
                  <div
                    className={cn(
                      "w-5 h-5 rounded-md border transition-ui flex items-center justify-center shrink-0",
                      selected
                        ? "bg-primary border-primary"
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
                    <p className="text-xs font-semibold text-white truncate">
                      {actor.name}
                    </p>
                    {actor.description && (
                      <p className="text-2xs text-muted-foreground/70 font-bold truncate mt-1">
                        {actor.description}
                      </p>
                    )}
                  </div>
                  <span className="text-2xs text-primary/70 font-semibold tracking-wider uppercase shrink-0">
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
