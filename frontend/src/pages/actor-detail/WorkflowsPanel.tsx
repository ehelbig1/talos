import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Sparkles, Play, RefreshCw, Shuffle } from "lucide-react";
import { cn } from "@/lib/utils";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  getActorWorkflows,
  triggerWorkflowAsActor,
  type ActorWorkflowItem,
} from "@/lib/graphqlApi";
import { isAiWorkflow } from "@/lib/capabilityConfig";
import { SkeletonTable } from "@/components/ui";
import { workflowStatusColor, LocalEmptyState, relativeTime } from "./shared";

export function WorkflowsPanel({ actorId }: { actorId: string }) {
  const navigate = useNavigate();
  const [triggeringId, setTriggeringId] = useState<string | null>(null);

  const { data: workflows = [], isLoading } = useQuery<ActorWorkflowItem[]>({
    queryKey: ["actorWorkflows", actorId],
    queryFn: () => getActorWorkflows(actorId),
  });

  const handleTrigger = async (workflowId: string) => {
    setTriggeringId(workflowId);
    try {
      const execution = await triggerWorkflowAsActor(workflowId, actorId);
      toast.success(`Execution started: ${execution.id.slice(0, 8)}…`);
    } catch (e) {
      toast.error(
        sanitizeErrorMessage(e instanceof Error ? e.message : String(e)),
      );
    } finally {
      setTriggeringId(null);
    }
  };

  if (isLoading) return <SkeletonTable rows={4} className="mt-4" />;

  if (workflows.length === 0)
    return (
      <LocalEmptyState
        icon={<Shuffle size={40} />}
        message="No workflows owned by this Actor yet"
      />
    );

  return (
    <div className="bg-surface-3/60 border border-white/5 rounded-2xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/5">
            <th className="text-left text-xs font-medium text-muted-foreground px-5 py-3">
              Name
            </th>
            <th className="text-left text-xs font-medium text-muted-foreground px-4 py-3">
              Status
            </th>
            <th className="text-right text-xs font-medium text-muted-foreground px-4 py-3">
              Nodes
            </th>
            <th className="text-right text-xs font-medium text-muted-foreground px-5 py-3">
              Updated
            </th>
            <th className="text-right text-xs font-medium text-muted-foreground px-5 py-3" />
          </tr>
        </thead>
        <tbody>
          {workflows.map((wf) => {
            const aiWf = wf.graphJson ? isAiWorkflow(wf.graphJson) : false;
            return (
              <tr
                key={wf.id}
                className="border-b border-[rgba(255,255,255,0.04)] last:border-0 hover:bg-[rgba(255,255,255,0.03)] transition-premium"
              >
                <td className="px-5 py-3">
                  <span className="text-white font-medium flex items-center gap-2">
                    {wf.name}
                    {aiWf && (
                      <span title="LLM workflow with memory injection">
                        <Sparkles className="w-3 h-3 text-violet-400" />
                      </span>
                    )}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={cn(
                      "capitalize text-xs",
                      workflowStatusColor(wf.status),
                    )}
                  >
                    {wf.status ?? "—"}
                  </span>
                </td>
                <td className="px-4 py-3 text-right text-muted-foreground tabular-nums">
                  {wf.nodeCount}
                </td>
                <td className="px-5 py-3 text-right text-muted-foreground text-xs">
                  {relativeTime(wf.updatedAt)}
                </td>
                <td className="px-5 py-3 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => handleTrigger(wf.id.toString())}
                      disabled={
                        triggeringId === wf.id.toString() ||
                        wf.status !== "published"
                      }
                      title={
                        wf.status !== "published"
                          ? "Publish workflow to enable triggering"
                          : "Run as this actor"
                      }
                      className="flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 disabled:opacity-30 disabled:cursor-not-allowed transition-premium px-2 py-1 rounded-md border border-emerald-500/20 hover:bg-emerald-500/10"
                    >
                      {triggeringId === wf.id.toString() ? (
                        <RefreshCw className="w-3 h-3 animate-spin" />
                      ) : (
                        <Play className="w-3 h-3 fill-current" />
                      )}
                      Run
                    </button>
                    <button
                      onClick={() => navigate(`/editor/${wf.id}`)}
                      className="text-xs text-violet-400 hover:text-violet-300 transition-premium px-2 py-1 rounded-md border border-violet-500/20 hover:bg-violet-500/10"
                    >
                      Open
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
