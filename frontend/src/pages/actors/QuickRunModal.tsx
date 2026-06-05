import React, { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, Loader2, ChevronRight } from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  graphqlRequest,
  getActorWorkflows,
  type ActorSummary,
  type ActorWorkflowItem,
} from "@/lib/graphqlClient";
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
      const data = await graphqlRequest<{ triggerWorkflow: { id: string } }>(
        `mutation ($wId: UUID!, $aId: UUID) { triggerWorkflow(workflowId: $wId, actorId: $aId) { id } }`,
        { wId: workflowId, aId: actor.id },
      );
      return data.triggerWorkflow.id;
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
        <p className="text-muted-foreground/30 text-[10px] font-black uppercase tracking-[0.3em] leading-none mb-6">
          Executing as <span className="text-primary">{actor.name}</span>
        </p>

        <div className="relative z-10">
          {result ? (
            <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
              <div className="bg-success/5 border border-success/20 rounded-[1.5rem] p-6 glass-light shadow-xl relative group overflow-hidden">
                <div className="absolute inset-0 bg-success/5 opacity-0 group-hover:opacity-100 transition-premium" />
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-2 h-2 rounded-full bg-success animate-status-pulse shadow-[0_0_8px_hsla(var(--success),0.5)]" />
                  <p className="text-success text-[10px] font-black uppercase tracking-[0.2em]">
                    Protocol Sequence Synchronized
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-muted-foreground/40 text-[9px] font-bold uppercase tracking-widest">
                    Execution Trace Identifier
                  </p>
                  <p className="text-white font-mono text-xs break-all selection:bg-success/30">
                    {result.execId}
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="w-full py-4 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-white/5 border border-white/5 rounded-2xl hover:bg-white/10 hover:border-white/20 transition-premium active:scale-95 shadow-xl glass-light"
              >
                Abort Viewport
              </button>
            </div>
          ) : (
            <div className="space-y-8">
              {isLoading ? (
                <div className="flex items-center gap-4 text-muted-foreground/40 text-[10px] font-black uppercase tracking-[0.2em] py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-primary" />
                  Synchronizing Workflows...
                </div>
              ) : published.length === 0 ? (
                <div className="py-10 text-center bg-white/2 rounded-2xl border border-white/5 border-dashed">
                  <p className="text-muted-foreground/40 text-[10px] font-black uppercase tracking-[0.2em]">
                    No Published Protocols Detected
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  <label className="text-[10px] font-black text-muted-foreground/30 uppercase tracking-[0.3em] ml-1">
                    Select Execution Logic
                  </label>
                  <div className="relative group/select">
                    <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within/select:opacity-100 transition-premium pointer-events-none" />
                    <select
                      value={selectedWorkflowId}
                      onChange={(e) => setSelectedWorkflowId(e.target.value)}
                      className="w-full bg-surface-4/40 backdrop-blur-xl border border-white/10 rounded-2xl px-6 py-4 text-sm text-white focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium appearance-none relative z-10 font-medium"
                    >
                      <option value="" className="bg-surface-3">
                        —— IDENTIFY SEQUENCE ——
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
                      <ChevronRight className="w-4 h-4 text-muted-foreground/20 rotate-90" />
                    </div>
                  </div>
                </div>
              )}

              <button
                onClick={() =>
                  selectedWorkflowId && triggerMut.mutate(selectedWorkflowId)
                }
                disabled={!selectedWorkflowId || triggerMut.isPending}
                className="w-full flex items-center justify-center gap-4 bg-primary hover:bg-primary/90 disabled:opacity-20 disabled:cursor-not-allowed text-white text-[10px] font-black uppercase tracking-[0.2em] py-5 rounded-2xl transition-premium shadow-2xl hover:shadow-[0_15px_30px_-5px_hsla(var(--primary),0.4)] hover:scale-105 active:scale-95 border border-white/20"
              >
                {triggerMut.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    Initializing Trigger...
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5 fill-current" />
                    Deploy Sequence
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </Dialog>
  );
}
