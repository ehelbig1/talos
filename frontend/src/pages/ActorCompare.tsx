import React, { useState } from "react";
import { Spinner } from "@/components/ui/spinner";
import { useNavigate, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { listActors, type ActorSummary } from "@/lib/graphqlApi";
import { useListWorkflowNamesQuery } from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { Play, RefreshCw, GitCompare } from "lucide-react";
import type { WorkflowOption } from "./actor-compare/types";
import { CompareLane } from "./actor-compare/CompareLane";
import { useCompareRun } from "./actor-compare/useCompareRun";
import { SetupPanel } from "./actor-compare/SetupPanel";
import { RunTicker } from "./actor-compare/RunTicker";
import { Button, PageContainer, PageHeader } from "@/components/ui";

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
    <div className="h-full overflow-auto bg-background text-white custom-scrollbar">
      <PageContainer className="space-y-12">
        <PageHeader
          backTo={{ to: "/actors", label: "Actors" }}
          title="Compare actors"
          description="Run one workflow as several actors side by side."
          actions={
            <>
              {lanes.length > 0 && allDone && (
                <Button variant="outline" onClick={handleReset}>
                  <RefreshCw className="w-4 h-4" />
                  Start over
                </Button>
              )}
              <Button onClick={handleRun} disabled={!canRun}>
                {running ? (
                  <Spinner className="w-4 h-4" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                {running ? "Running…" : "Run comparison"}
              </Button>
            </>
          }
          className="mb-0"
        />

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
              "grid gap-8",
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
          <div className="flex flex-col items-center justify-center py-20 gap-8 text-center">
            <div className="relative">
              <GitCompare className="w-24 h-24 text-white/5 relative z-10" />
            </div>
            <div className="space-y-3 relative z-10">
              <p className="text-sm font-semibold text-white/70 font-outfit">
                Nothing to compare yet
              </p>
              <p className="text-xs text-muted-foreground/50 max-w-sm leading-relaxed">
                Pick a workflow and at least two actors to start.
              </p>
            </div>
          </div>
        )}
      </PageContainer>
    </div>
  );
}
