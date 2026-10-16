import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { useQuery, useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, Loader2, ChevronRight } from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  getActorWorkflows,
  triggerWorkflowAsActor,
  type ActorSummary,
  type ActorWorkflowItem,
} from "@/lib/graphqlApi";
import { Dialog } from "@/components/ui/dialog";

interface QuickRunModalProps {
  actor: ActorSummary;
  onClose: () => void;
}

export function QuickRunModal({ actor, onClose }: QuickRunModalProps) {
  const [selectedWorkflowId, setSelectedWorkflowId] = useState("");
  const [result, setResult] = useState<{ execId: string } | null>(null);

  const { data: workflows = [], isLoading } = useQuery<ActorWorkflowItem[]>({
    queryKey: ["actorWorkflows", actor.id],
    queryFn: () => getActorWorkflows(actor.id),
  });

  const published = workflows.filter((w) => w.status === "published");

  const triggerMut = useMutation({
    mutationFn: async (workflowId: string) => {
      const execution = await triggerWorkflowAsActor(workflowId, actor.id);
      return execution.id;
    },
    onSuccess: (execId) => setResult({ execId }),
    onError: (e: Error) => toast.error(sanitizeErrorMessage(e.message)),
  });

  return (
    <Dialog
      open={true}
      onClose={onClose}
      title="Initialize Execution"
      className="max-w-md"
    >
      <div className="space-y-8 relative z-10 p-2 -mt-4">
        <p className="text-muted-foreground/60 text-xs font-semibold leading-none mb-6">
          Executing as <span className="text-primary">{actor.name}</span>
        </p>

        <div className="relative z-10">
          {result ? (
            <div className="space-y-8">
              <div className="bg-success/5 border border-success/20 rounded-2xl p-6 bg-white/[0.03] border border-white/5 relative group overflow-hidden">
                <div className="absolute inset-0 bg-success/5 opacity-0 group-hover:opacity-100 transition-ui" />
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-2 h-2 rounded-full bg-success" />
                  <p className="text-success text-xs font-semibold">
                    Run started
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-muted-foreground/70 text-2xs font-bold uppercase tracking-wider">
                    Execution id
                  </p>
                  <p className="text-white font-mono text-xs break-all selection:bg-success/30">
                    {result.execId}
                  </p>
                </div>
              </div>
              <Button variant="outline" className="w-full" onClick={onClose}>
                Close
              </Button>
            </div>
          ) : (
            <div className="space-y-8">
              {isLoading ? (
                <div className="flex items-center gap-4 text-muted-foreground/70 text-xs font-semibold py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-primary" />
                  Synchronizing Workflows...
                </div>
              ) : published.length === 0 ? (
                <div className="py-10 text-center bg-white/2 rounded-2xl border border-white/5 border-dashed">
                  <p className="text-muted-foreground/70 text-xs font-semibold">
                    No published workflows yet
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  <label className="text-xs font-semibold text-muted-foreground/60 ml-1">
                    Select Execution Logic
                  </label>
                  <div className="relative group/select">
                    <select
                      value={selectedWorkflowId}
                      onChange={(e) => setSelectedWorkflowId(e.target.value)}
                      className="w-full bg-surface-4/40 border border-white/10 rounded-2xl px-6 py-4 text-sm text-white focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-ui appearance-none relative z-10 font-medium"
                    >
                      <option value="" className="bg-surface-3">
                        Select a workflow…
                      </option>
                      {published.map((w) => (
                        <option
                          key={w.id}
                          value={w.id}
                          className="bg-surface-3"
                        >
                          {w.name.toUpperCase()}
                        </option>
                      ))}
                    </select>
                    <div className="absolute right-6 top-1/2 -translate-y-1/2 pointer-events-none z-20">
                      <ChevronRight className="w-4 h-4 text-muted-foreground/50 rotate-90" />
                    </div>
                  </div>
                </div>
              )}

              <Button
                size="lg"
                className="w-full"
                onClick={() =>
                  selectedWorkflowId && triggerMut.mutate(selectedWorkflowId)
                }
                disabled={!selectedWorkflowId || triggerMut.isPending}
              >
                {triggerMut.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    Starting…
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5 fill-current" />
                    Run workflow
                  </>
                )}
              </Button>
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
