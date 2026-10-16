import React from "react";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui";
import { Play, RefreshCw, Loader2, Activity } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ActorSummary } from "@/lib/graphqlApi";

interface Workflow {
  id: string;
  name: string;
}

interface ExecutionHeaderProps {
  workflowId: string;
  workflows: Workflow[];
  loadingWorkflows: boolean;
  onWorkflowSelect: (id: string) => void;
  onRefresh: () => void;
  actors: ActorSummary[];
  selectedActorId: string;
  onActorSelect: (id: string) => void;
  isRunning: boolean;
  loading: boolean;
  onRun: () => void;
  showTimeline: boolean;
  onToggleTimeline: () => void;
  eventCount: number;
  /** The editing tools, rendered between the workflow picker and Run. */
  children?: React.ReactNode;
}

/**
 * The editor's one header row: which workflow (left), what you can do to
 * it (middle, passed in), and running it (right).
 */
export function ExecutionHeader({
  workflowId,
  workflows,
  loadingWorkflows,
  onWorkflowSelect,
  onRefresh,
  actors,
  selectedActorId,
  onActorSelect,
  isRunning,
  loading,
  onRun,
  showTimeline,
  onToggleTimeline,
  eventCount,
  children,
}: ExecutionHeaderProps) {
  const canRun = !loading && !!workflowId && workflowId !== "new";
  const timelineLabel = showTimeline ? "Hide timeline" : "Show timeline";

  return (
    <div className="px-4 py-2 border-b border-white/5 bg-surface-1/60 backdrop-blur-xl flex items-center gap-3 flex-wrap shrink-0">
      <div className="flex items-center gap-1 min-w-0">
        <label htmlFor="workflow-select" className="sr-only">
          Workflow
        </label>
        <Select
          id="workflow-select"
          value={workflowId || "new"}
          onChange={(e) => onWorkflowSelect(e.target.value)}
          disabled={loadingWorkflows}
          className="h-9 w-48 xl:w-60 text-sm bg-surface-3/40 border-white/5 rounded-lg"
        >
          {loadingWorkflows ? (
            <option value={workflowId || "new"}>Loading…</option>
          ) : workflows.length === 0 ? (
            <option value="new">No workflows yet</option>
          ) : (
            <>
              <option value="new">+ New workflow</option>
              {workflows.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </>
          )}
        </Select>
        <Button
          variant="ghost"
          size="icon"
          onClick={onRefresh}
          disabled={loadingWorkflows}
          aria-label="Refresh workflows"
          title="Refresh workflows"
          className="h-9 w-9 text-muted-foreground/70 hover:text-white rounded-lg"
        >
          <RefreshCw
            className={cn("h-4 w-4", loadingWorkflows && "animate-spin")}
          />
        </Button>
      </div>

      {children && (
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          {children}
        </div>
      )}

      <div className="ml-auto flex items-center gap-2">
        {actors.length > 0 && (
          <>
            <label htmlFor="actor-select" className="sr-only">
              Run as actor
            </label>
            <Select
              id="actor-select"
              value={selectedActorId}
              onChange={(e) => onActorSelect(e.target.value)}
              className="h-9 w-40 text-sm bg-surface-3/40 border-white/5 rounded-lg"
              title="Run as an actor, so its memory and ceilings apply"
            >
              <option value="">No actor</option>
              {actors.map((a) => (
                <option key={a.id} value={a.id.toString()}>
                  Run as {a.name}
                </option>
              ))}
            </Select>
          </>
        )}

        {isRunning && (
          <span className="inline-flex items-center gap-2 px-2.5 h-9 bg-primary/10 border border-primary/20 rounded-lg text-xs font-semibold text-primary">
            <Activity className="w-3.5 h-3.5 animate-spin" />
            Running
          </span>
        )}

        <Button onClick={onRun} disabled={!canRun} className="h-9 px-4 text-sm">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5 fill-current" />
          )}
          Run
        </Button>

        <Button
          variant={showTimeline ? "secondary" : "ghost"}
          size="sm"
          onClick={onToggleTimeline}
          aria-label={timelineLabel}
          title={timelineLabel}
          aria-pressed={showTimeline}
          className={cn(
            "h-9 px-3 rounded-lg",
            showTimeline
              ? "bg-white/5 text-white border border-white/10"
              : "text-muted-foreground/70 hover:text-white",
          )}
        >
          <Activity className="w-4 h-4" />
          <span className="hidden 2xl:inline">Timeline</span>
          {eventCount > 0 && !showTimeline && (
            <span className="px-1.5 py-0.5 bg-primary text-primary-foreground rounded-full text-2xs font-semibold tabular-nums">
              {eventCount}
            </span>
          )}
        </Button>
      </div>
    </div>
  );
}
