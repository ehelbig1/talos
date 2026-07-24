import React, { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { listActors, type ActorSummary } from "@/lib/graphqlApi";
import { useListWorkflowNamesQuery } from "@/generated/graphql";
import { cn } from "@/lib/utils";
import {
  ChevronLeft,
  Play,
  RefreshCw,
  Loader2,
  GitCompare,
} from "lucide-react";
import type { WorkflowOption } from "./actor-compare/types";
import { CompareLane } from "./actor-compare/CompareLane";
import { useCompareRun } from "./actor-compare/useCompareRun";
import { SetupPanel } from "./actor-compare/SetupPanel";
import { RunTicker } from "./actor-compare/RunTicker";

// ── ActorCompare page ─────────────────────────────────────────────────────────

export default function ActorCompare() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Pre-select actors from URL (?actors=id1,id2)
  const preselectedActorIds =
    searchParams.get("actors")?.split(",").filter(Boolean) ?? [];

  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string>("");
  const [selectedActorIds, setSelectedActorIds] = useState<Set<string>>(
    new Set(preselectedActorIds),
  );

  const { data: actors = [], isLoading: loadingActors } = useQuery<
    ActorSummary[]
  >({
    queryKey: ["actors"],
    queryFn: listActors,
  });

  const { data: workflows = [], isLoading: loadingWorkflows } =
    useListWorkflowNamesQuery(undefined, {
      select: (result): WorkflowOption[] => result.workflows,
    });

  const activeActors = actors.filter((a) => a.status === "active");

  const toggleActor = (id: string) => {
    setSelectedActorIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const { lanes, running, allDone, handleRun, handleReset } = useCompareRun({
    selectedWorkflowId,
    selectedActorIds,
    activeActors,
  });

  const canRun = !running && selectedWorkflowId && selectedActorIds.size >= 2;

  return (
    <div className="min-h-screen bg-background text-white relative overflow-hidden font-inter">
      {/* Ambient background glows */}
      <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] bg-primary/5 rounded-full blur-[120px] animate-pulse" />
      <div className="absolute bottom-[-5%] left-[-5%] w-[40%] h-[40%] bg-violet-500/5 rounded-full blur-[100px] animate-pulse delay-700" />

      <div className="max-w-7xl mx-auto px-8 py-10 space-y-12 relative z-10">
        {/* Page header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-6">
            <button
              onClick={() => navigate("/actors")}
              className="p-3 rounded-2xl bg-white/5 border border-white/10 text-muted-foreground/60 hover:text-white hover:bg-white/10 transition-premium shadow-xl"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-5">
              <div className="p-3.5 rounded-2xl bg-primary/10 border border-primary/20 shadow-[0_0_20px_hsla(var(--primary),0.15)]">
                <GitCompare className="w-7 h-7 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-black tracking-tight font-outfit uppercase">
                  Actor Strategic Compare
                </h1>
                <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em] mt-1">
                  Simultaneous multi-actor protocol evaluation
                </p>
              </div>
            </div>
          </div>

          {/* Global Actions */}
          <div className="flex items-center gap-4">
            {lanes.length > 0 && allDone && (
              <button
                onClick={handleReset}
                className="flex items-center gap-3 px-6 py-3 rounded-2xl bg-surface-2/40 border border-white/5 text-[11px] font-black uppercase tracking-widest text-muted-foreground/60 hover:text-white hover:bg-surface-2/60 transition-premium shadow-2xl active:scale-95"
              >
                <RefreshCw className="w-4 h-4" />
                New Analysis
              </button>
            )}
            <button
              onClick={handleRun}
              disabled={!canRun}
              className="flex items-center gap-3 px-8 py-3.5 rounded-2xl bg-primary hover:bg-primary/90 disabled:opacity-40 disabled:grayscale disabled:cursor-not-allowed text-white text-[11px] font-black uppercase tracking-[0.2em] transition-premium shadow-[0_0_30px_hsla(var(--primary),0.2)] active:scale-95"
            >
              {running ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              {running ? "ANALYZING..." : "INITIATE PROTOCOL"}
            </button>
          </div>
        </div>

        {/* Setup panel (hidden after run starts) */}
        {lanes.length === 0 && (
          <SetupPanel
            workflows={workflows}
            loadingWorkflows={loadingWorkflows}
            selectedWorkflowId={selectedWorkflowId}
            onSelectWorkflow={setSelectedWorkflowId}
            activeActors={activeActors}
            loadingActors={loadingActors}
            selectedActorIds={selectedActorIds}
            onToggleActor={toggleActor}
            onGoToActors={() => navigate("/actors")}
          />
        )}

        {/* Status ticker when running */}
        {running && <RunTicker lanes={lanes} />}

        {/* Comparison grid */}
        {lanes.length > 0 && (
          <div
            className={cn(
              "grid gap-8 animate-in fade-in zoom-in-95 duration-700",
              lanes.length === 2
                ? "grid-cols-1 lg:grid-cols-2"
                : lanes.length === 3
                  ? "grid-cols-1 lg:grid-cols-3"
                  : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4",
            )}
          >
            {lanes.map((lane) => (
              <CompareLane key={lane.actor.id} lane={lane} />
            ))}
          </div>
        )}

        {/* Empty prompt */}
        {lanes.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 gap-8 text-center animate-in fade-in duration-1000">
            <div className="relative">
              <div className="absolute -inset-10 bg-primary/5 rounded-full blur-3xl animate-pulse" />
              <GitCompare className="w-24 h-24 text-white/5 relative z-10" />
            </div>
            <div className="space-y-3 relative z-10">
              <p className="text-sm font-black text-white/40 uppercase tracking-[0.3em] font-outfit">
                Strategic Analysis Engine Offline
              </p>
              <p className="text-[10px] text-muted-foreground/20 font-bold uppercase tracking-widest max-w-sm leading-relaxed">
                Awaiting protocol designation and actor cohort assignment to
                begin comparative telemetry collection.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
