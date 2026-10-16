/**
 * Pre-run setup panel for the Actor Strategic Compare page: the target
 * workflow selector and the actor-cohort multi-select. Strictly
 * presentational — selection state lives in the parent.
 */

import React from "react";
import { Spinner } from "@/components/ui/spinner";
import { Select } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { CheckCircle2 } from "lucide-react";
import { CapabilityBadge } from "@/components/CapabilityBadge";
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
      <div className="bg-surface-3 border border-white/10 rounded-2xl p-6 space-y-6">
        <h2 className="text-sm font-semibold text-white">Workflow</h2>
        {loadingWorkflows ? (
          <div className="flex items-center gap-3 text-muted-foreground/60 py-4">
            <Spinner className="w-4 h-4" />
            <span className="text-xs">Loading workflows…</span>
          </div>
        ) : workflows.length === 0 ? (
          <p className="text-muted-foreground/70 text-sm font-medium py-4">
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
      <div className="bg-surface-3 border border-white/10 rounded-2xl p-6 space-y-6">
        <h2 className="text-sm font-semibold text-white flex items-center gap-3">
          Actors
          <span className="text-xs text-muted-foreground font-medium ml-auto">
            at least 2
          </span>
        </h2>
        {loadingActors ? (
          <div className="flex items-center gap-3 text-muted-foreground/60 py-4">
            <Spinner className="w-4 h-4" />
            <span className="text-xs font-bold">Loading actors…</span>
          </div>
        ) : activeActors.length === 0 ? (
          <p className="text-muted-foreground/70 text-sm font-medium py-4">
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
                      <p className="text-2xs text-muted-foreground/70 font-medium truncate mt-1">
                        {actor.description}
                      </p>
                    )}
                  </div>
                  <CapabilityBadge
                    world={actor.maxCapabilityWorld}
                    className="shrink-0"
                  />
                </label>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
