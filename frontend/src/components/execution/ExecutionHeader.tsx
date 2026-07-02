import React from "react";
import { Button, DarkSelect } from "@/components/ui";
import { Play, RefreshCw, Bot, Loader2 } from "lucide-react";
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
}

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
}: ExecutionHeaderProps) {
  return (
    <div className="px-6 py-3 border-b border-white/5 bg-surface-2/40 backdrop-blur-xl flex items-center gap-4 flex-wrap shrink-0 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30" />

      <div className="flex items-center gap-6 flex-1 min-w-[300px] relative z-10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_15px_hsla(var(--primary),0.1)]">
            <Bot className="h-5 w-5 text-primary" />
          </div>
          <div className="flex flex-col">
            <span className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 leading-none mb-1">
              Mission Profile
            </span>
            <span className="text-sm font-black text-white tracking-tight font-outfit truncate max-w-[150px]">
              {workflows.find((w) => w.id === workflowId)?.name ||
                "New Protocol"}
            </span>
          </div>
        </div>

        <div className="h-8 w-px bg-white/5 mx-1" />

        <div className="flex-1 max-w-[240px]">
          <DarkSelect
            id="workflow-select"
            value={workflowId || "new"}
            onChange={(e) => onWorkflowSelect(e.target.value)}
            disabled={loadingWorkflows}
            className="w-full h-10 text-[11px] font-bold uppercase tracking-widest bg-surface-3/40 border-white/5 focus:border-primary/50 transition-premium"
          >
            {loadingWorkflows ? (
              <option value={workflowId || "new"}>SYNCING...</option>
            ) : workflows.length === 0 ? (
              <option value="new">NO DATA FOUND</option>
            ) : (
              <>
                <option value="new">+ NEW PROTOCOL</option>
                {workflows.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name.toUpperCase()}
                  </option>
                ))}
              </>
            )}
          </DarkSelect>
        </div>

        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            onClick={onRefresh}
            disabled={loadingWorkflows}
            aria-label="Refresh workflows"
            className="h-9 w-9 text-muted-foreground/40 hover:text-white hover:bg-white/5 rounded-xl transition-premium"
          >
            <RefreshCw
              className={cn("h-4 w-4", loadingWorkflows && "animate-spin")}
            />
          </Button>
        </div>

        {actors.length > 0 && (
          <>
            <div className="h-8 w-px bg-white/5 mx-1" />
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex flex-col items-end mr-1">
                <span className="text-[8px] font-black text-muted-foreground/30 uppercase tracking-widest">
                  Operator
                </span>
                <span className="text-[10px] font-bold text-muted-foreground/60">
                  Persona
                </span>
              </div>
              <DarkSelect
                id="actor-select"
                value={selectedActorId}
                onChange={(e) => onActorSelect(e.target.value)}
                className="h-10 text-[11px] font-bold uppercase tracking-widest bg-surface-3/40 border-white/5 focus:border-primary/50 transition-premium max-w-[160px]"
                title="Run as actor (optional) — injects actor persona memories into the execution"
              >
                <option value="">STANDALONE</option>
                {actors.map((a) => (
                  <option key={a.id} value={a.id.toString()}>
                    {a.name.toUpperCase()}
                  </option>
                ))}
              </DarkSelect>
            </div>
          </>
        )}
      </div>

      <div className="flex items-center gap-3 relative z-10">
        {isRunning && (
          <div className="flex items-center gap-2.5 px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-full animate-in fade-in zoom-in-95 duration-500 shadow-[0_0_15px_hsla(var(--primary),0.1)]">
            <div className="w-2 h-2 rounded-full bg-primary animate-status-pulse" />
            <span className="text-[10px] font-black uppercase tracking-widest text-primary">
              Live Link
            </span>
          </div>
        )}

        <Button
          onClick={onRun}
          disabled={loading || !workflowId || workflowId === "new"}
          variant="premium"
          className="h-10 px-6 font-black text-xs shadow-lg shadow-primary/20"
        >
          {loading ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Play className="mr-2 h-3.5 w-3.5 fill-current" />
          )}
          RUN PROTOCOL
        </Button>

        <div className="w-[1px] h-8 bg-white/5 mx-2" />

        <Button
          variant="ghost"
          size="sm"
          onClick={onToggleTimeline}
          className={cn(
            "h-10 px-4 text-[10px] font-black uppercase tracking-[0.2em] transition-premium rounded-xl group",
            showTimeline
              ? "bg-white/5 text-white border border-white/10"
              : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
          )}
        >
          {showTimeline ? "Hide Telemetry" : "Show Telemetry"}
          {eventCount > 0 && !showTimeline && (
            <span className="ml-3 px-2 py-0.5 bg-primary text-primary-foreground rounded-full text-[8px] font-black shadow-lg shadow-primary/20 group-hover:scale-110 transition-transform">
              {eventCount}
            </span>
          )}
        </Button>
      </div>
    </div>
  );
}
