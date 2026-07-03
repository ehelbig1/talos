import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  Ghost,
  RotateCcw,
  AlertCircle,
  Bug,
  ExternalLink,
  Webhook,
  Loader2,
  Database,
  Search,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  useGetDeadLetterQueueQuery,
  useGetWebhookDeadLetterQueueQuery,
  useReplayDeadLetterEntryMutation,
  useReplayWebhookDeadLetterEntryMutation,
} from "@/generated/graphql";
import { gql, subscribeDlqUpdates } from "@/lib/graphqlClient";
import { useEffect } from "react";

const _GET_DEAD_LETTER_QUEUE = gql`
  query GetDeadLetterQueue {
    deadLetterQueue {
      id
      workflowId
      executionId
      nodeId
      errorMessage
      payload
      createdAt
      replayedAt
      replayedBy
    }
  }
`;

const _GET_WEBHOOK_DEAD_LETTER_QUEUE = gql`
  query GetWebhookDeadLetterQueue {
    webhookDeadLetterQueue {
      id
      triggerId
      dropReason
      headers
      payload
      sourceIp
      createdAt
      replayedAt
      replayedBy
    }
  }
`;

const _REPLAY_DEAD_LETTER_ENTRY = gql`
  mutation ReplayDeadLetterEntry($id: UUID!) {
    replayDeadLetterEntry(id: $id)
  }
`;

const _REPLAY_WEBHOOK_DEAD_LETTER_ENTRY = gql`
  mutation ReplayWebhookDeadLetterEntry($id: UUID!) {
    replayWebhookDeadLetterEntry(id: $id)
  }
`;

type Tab = "nodes" | "webhooks";

const DROP_REASON_LABELS: Record<string, { label: string; color: string }> = {
  circuit_breaker: {
    label: "Circuit Breaker",
    color: "text-red-400 bg-red-400/10 border-red-400/20",
  },
  rate_limit: {
    label: "Rate Limit",
    color: "text-amber-400 bg-amber-400/10 border-amber-400/20",
  },
  sig_invalid: {
    label: "Sig Invalid",
    color: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  },
  disabled: {
    label: "Disabled",
    color: "text-muted-foreground bg-white/5 border-white/10",
  },
};

function DropReasonBadge({ reason }: { reason: string }) {
  const cfg = DROP_REASON_LABELS[reason] ?? {
    label: reason.toUpperCase(),
    color: "text-muted-foreground bg-white/5 border-white/10",
  };
  return (
    <span
      className={cn(
        "text-[9px] font-black uppercase tracking-widest border rounded-lg px-2 py-0.5 shadow-sm",
        cfg.color,
      )}
    >
      {cfg.label}
    </span>
  );
}

export function DLQViewer() {
  const [activeTab, setActiveTab] = useState<Tab>("nodes");
  const queryClient = useQueryClient();

  // ── Node failures tab ───────────────────────────────────────────────────────

  const {
    data: nodeData,
    isLoading: nodeLoading,
    refetch: refetchNodes,
  } = useGetDeadLetterQueueQuery(
    {},
    {
      // Polling removed in favor of real-time WebSocket subscriptions
    },
  );

  const nodeEntries = nodeData?.deadLetterQueue ?? [];

  const { mutateAsync: replayNode, isPending: isReplayingNode } =
    useReplayDeadLetterEntryMutation({
      onSuccess: () => {
        toast.success("Protocol job replayed successfully");
        refetchNodes();
      },
      onError: () => {
        toast.error("Failed to replay protocol job from DLQ");
      },
    });

  const handleNodeReplay = async (entryId: string) => {
    await replayNode({ id: entryId });
  };

  // ── Webhook drops tab ───────────────────────────────────────────────────────

  const {
    data: webhookData,
    isLoading: webhookLoading,
    refetch: refetchWebhooks,
  } = useGetWebhookDeadLetterQueueQuery(
    {},
    {
      // Polling removed in favor of real-time WebSocket subscriptions
    },
  );

  const webhookEntries = webhookData?.webhookDeadLetterQueue ?? [];

  const { mutateAsync: replayWebhook, isPending: isReplayingWebhook } =
    useReplayWebhookDeadLetterEntryMutation({
      onSuccess: () => {
        toast.success("Webhook payload synchronized and replayed");
        refetchWebhooks();
      },
      onError: () => {
        toast.error("Failed to re-sync webhook payload");
      },
    });

  // ── Real-time Subscriptions ──────────────────────────────────────────────────

  useEffect(() => {
    const unsubscribe = subscribeDlqUpdates((event) => {
      // Invalidate both node and webhook DLQ queries to trigger a fresh fetch
      queryClient.invalidateQueries({ queryKey: ["GetDeadLetterQueue"] });
      queryClient.invalidateQueries({
        queryKey: ["GetWebhookDeadLetterQueue"],
      });

      // Provide immediate feedback via toast
      toast.info(
        `New fault entry: ${event.errorMessage || "Unknown drop reason"}`,
        {
          icon: <Bug size={14} className="text-destructive" />,
          duration: 3000,
        },
      );
    });
    return unsubscribe;
  }, [queryClient]);

  // ── Counts ──────────────────────────────────────────────────────────────────

  const pendingNodes = (nodeEntries || []).filter((e) => !e.replayedAt);
  const pendingWebhooks = (webhookEntries || []).filter((e) => !e.replayedAt);

  const isLoading = activeTab === "nodes" ? nodeLoading : webhookLoading;

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-48 gap-6 animate-in fade-in duration-700">
        <div className="relative">
          <div className="w-16 h-16 border-2 border-destructive/10 rounded-full" />
          <div className="w-16 h-16 border-t-2 border-destructive rounded-full animate-spin absolute inset-0" />
        </div>
        <p className="text-[10px] text-destructive/60 font-black uppercase tracking-[0.4em] animate-status-pulse">
          Scanning Fault Registry...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-1000">
      <div className="bg-surface-3/30 border border-white/5 rounded-[3rem] p-10 shadow-2xl backdrop-blur-3xl relative overflow-hidden group/header">
        <div className="absolute inset-0 bg-gradient-to-br from-destructive/10 via-transparent to-transparent opacity-50 pointer-events-none transition-premium group-hover/header:opacity-100" />

        <div className="flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-destructive/10 border border-destructive/20 rounded-[1.5rem] flex items-center justify-center text-destructive shadow-[0_0_30px_hsla(var(--destructive),0.1)] group-hover/header:scale-110 transition-premium">
              <Ghost size={32} />
            </div>
            <div className="space-y-1.5">
              <h2 className="text-2xl md:text-3xl font-black text-white tracking-tighter uppercase leading-tight">
                Fault Containment
              </h2>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 bg-destructive/10 border border-destructive/20 px-3 py-1 rounded-full">
                  <div className="w-1.5 h-1.5 rounded-full bg-destructive animate-pulse" />
                  <span className="text-[9px] text-destructive font-black uppercase tracking-widest leading-none">
                    Active_DLQ_Monitor
                  </span>
                </div>
                <div className="w-1 h-1 rounded-full bg-white/10" />
                <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.2em] leading-none">
                  Registry of Non-Deterministic States
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-10">
            <div className="flex flex-col items-end gap-1">
              <span className="text-3xl font-black text-white tracking-tighter leading-none">
                {activeTab === "nodes"
                  ? pendingNodes.length
                  : pendingWebhooks.length}
              </span>
              <span className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em] leading-none">
                {activeTab === "nodes" ? "PENDING_FAULTS" : "DROPPED_PAYLOADS"}
              </span>
            </div>
            <button
              onClick={() =>
                activeTab === "nodes" ? refetchNodes() : refetchWebhooks()
              }
              className="w-14 h-14 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-center text-muted-foreground/40 hover:text-white hover:bg-white/10 transition-premium active:scale-90"
            >
              <RotateCcw
                size={20}
                className={isLoading ? "animate-spin" : ""}
              />
            </button>
          </div>
        </div>
      </div>

      <div className="flex gap-2 p-2 bg-surface-3/30 border border-white/5 rounded-[2rem] backdrop-blur-xl max-w-xl mx-auto shadow-2xl">
        <button
          onClick={() => setActiveTab("nodes")}
          className={cn(
            "flex-1 flex items-center justify-center gap-3 py-4 rounded-[1.25rem] text-[10px] font-black uppercase tracking-[0.2em] transition-premium relative overflow-hidden group",
            activeTab === "nodes"
              ? "bg-destructive text-white shadow-2xl shadow-destructive/20"
              : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
          )}
        >
          <Bug className="w-4 h-4 relative z-10" />
          <span className="relative z-10">Node_Failures</span>
          {pendingNodes.length > 0 && (
            <span
              className={cn(
                "px-2 py-0.5 rounded-lg text-[9px] font-black min-w-[1.2rem] text-center relative z-10 transition-premium",
                activeTab === "nodes"
                  ? "bg-white text-destructive shadow-lg"
                  : "bg-destructive/10 text-destructive",
              )}
            >
              {pendingNodes.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab("webhooks")}
          className={cn(
            "flex-1 flex items-center justify-center gap-3 py-4 rounded-[1.25rem] text-[10px] font-black uppercase tracking-[0.2em] transition-premium relative overflow-hidden group",
            activeTab === "webhooks"
              ? "bg-amber-500 text-black shadow-2xl shadow-amber-500/20"
              : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
          )}
        >
          <Webhook className="w-4 h-4 relative z-10" />
          <span className="relative z-10">Webhook_Drops</span>
          {pendingWebhooks.length > 0 && (
            <span
              className={cn(
                "px-2 py-0.5 rounded-lg text-[9px] font-black min-w-[1.2rem] text-center relative z-10 transition-premium",
                activeTab === "webhooks"
                  ? "bg-black text-amber-500 shadow-lg"
                  : "bg-amber-500/10 text-amber-500",
              )}
            >
              {pendingWebhooks.length}
            </span>
          )}
        </button>
      </div>

      <div className="space-y-6">
        {activeTab === "nodes" ? (
          pendingNodes.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-32 bg-surface-3/20 border border-dashed border-white/5 rounded-[3rem] text-center group">
              <div className="w-20 h-20 bg-white/5 border border-white/5 rounded-[2rem] flex items-center justify-center text-muted-foreground/10 mb-8 transition-premium group-hover:scale-110 group-hover:rotate-12 group-hover:text-success/20">
                <Shield size={40} />
              </div>
              <h3 className="text-2xl font-black text-white/40 tracking-tight uppercase mb-4">
                Protocol_State_Nominal
              </h3>
              <p className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.3em] max-w-sm leading-relaxed">
                No unresolved execution faults detected in the containment
                registry.
              </p>
            </div>
          ) : (
            pendingNodes.map((entry) => (
              <div
                key={entry.id}
                className="bg-surface-3/30 border border-white/5 rounded-[2.5rem] p-8 transition-premium hover:border-white/10 hover:shadow-2xl group relative overflow-hidden"
              >
                <div className="absolute inset-0 bg-gradient-to-br from-destructive/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

                <div className="flex items-start justify-between mb-8 relative z-10">
                  <div className="flex items-center gap-5">
                    <div className="w-12 h-12 rounded-xl bg-destructive/10 border border-destructive/20 flex items-center justify-center text-destructive">
                      <Bug size={20} />
                    </div>
                    <div>
                      <span className="text-[11px] font-black text-destructive uppercase tracking-[0.2em] bg-destructive/5 px-3 py-1 rounded-lg border border-destructive/10">
                        NODE_{entry.nodeId.slice(0, 8)}
                      </span>
                      <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em] mt-2">
                        CAPTURED: {new Date(entry.createdAt).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1.5">
                    <span className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-widest">
                      TRACE_ID
                    </span>
                    <code className="text-[10px] font-mono text-white/40 bg-black/40 px-3 py-1 rounded-lg border border-white/5">
                      {entry.executionId.slice(0, 16)}...
                    </code>
                  </div>
                </div>

                <div className="mb-8 relative z-10">
                  <div className="bg-black/60 border border-white/5 rounded-[1.5rem] p-6 shadow-inner relative overflow-hidden group/error">
                    <div className="absolute top-0 right-0 p-3 opacity-20 group-hover/error:opacity-100 transition-premium">
                      <AlertCircle size={14} className="text-destructive" />
                    </div>
                    <p className="text-xs text-destructive/80 font-mono leading-relaxed selection:bg-destructive/30">
                      {sanitizeErrorMessage(
                        entry.errorMessage ?? "NULL_FAULT_TELEMETRY",
                      )}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between relative z-10 pt-4 border-t border-white/5">
                  <button className="flex items-center gap-3 text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest hover:text-white transition-premium group/link">
                    <ExternalLink
                      size={14}
                      className="group-hover/link:translate-x-0.5 group-hover/link:-translate-y-0.5 transition-premium"
                    />
                    Open_Source_Workflow
                  </button>

                  <button
                    onClick={() => handleNodeReplay(entry.id)}
                    disabled={isReplayingNode}
                    className="h-12 px-8 bg-destructive text-white rounded-2xl text-[10px] font-black uppercase tracking-[0.3em] transition-premium hover:shadow-[0_0_20px_hsla(var(--destructive),0.3)] active:scale-95 disabled:opacity-50 flex items-center gap-3 shadow-2xl"
                  >
                    {isReplayingNode ? (
                      <Loader2 size={14} className="animate-spin" />
                    ) : (
                      <RotateCcw size={14} />
                    )}
                    REPLAY_PROTOCOL_JOB
                  </button>
                </div>
              </div>
            ))
          )
        ) : pendingWebhooks.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-32 bg-surface-3/20 border border-dashed border-white/5 rounded-[3rem] text-center group">
            <div className="w-20 h-20 bg-white/5 border border-white/5 rounded-[2rem] flex items-center justify-center text-muted-foreground/10 mb-8 transition-premium group-hover:scale-110 group-hover:rotate-12 group-hover:text-amber-500/20">
              <Database size={40} />
            </div>
            <h3 className="text-2xl font-black text-white/40 tracking-tight uppercase mb-4">
              Ingress_Sync_Verified
            </h3>
            <p className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.3em] max-w-sm leading-relaxed">
              No dropped or non-deterministic webhook payloads detected.
            </p>
          </div>
        ) : (
          pendingWebhooks.map((entry) => (
            <div
              key={entry.id}
              className="bg-surface-3/30 border border-white/5 rounded-[2.5rem] p-8 transition-premium hover:border-white/10 hover:shadow-2xl group relative overflow-hidden"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-amber-500/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

              <div className="flex items-start justify-between mb-8 relative z-10">
                <div className="flex items-center gap-5">
                  <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-500">
                    <Webhook size={20} />
                  </div>
                  <div className="space-y-1.5">
                    <DropReasonBadge reason={entry.dropReason} />
                    <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.2em]">
                      DROPPED: {new Date(entry.createdAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1.5">
                  <span className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-widest">
                    SOURCE_UPLINK
                  </span>
                  <code className="text-[10px] font-mono text-white/40 bg-black/40 px-3 py-1 rounded-lg border border-white/5">
                    {entry.sourceIp || "ANONYMOUS_PROTOCOL"}
                  </code>
                </div>
              </div>

              {entry.payload && (
                <div className="mb-8 relative z-10">
                  <div className="bg-black/60 border border-white/5 rounded-[1.5rem] p-6 shadow-inner max-h-40 overflow-y-auto custom-scrollbar group/code">
                    <div className="absolute top-3 right-5 opacity-0 group-hover/code:opacity-100 transition-premium">
                      <span className="text-[8px] font-black text-primary/40 uppercase tracking-widest">
                        UPLINK_PAYLOAD
                      </span>
                    </div>
                    <pre className="text-[11px] font-mono text-foreground/60 leading-relaxed whitespace-pre-wrap break-all selection:bg-primary/30">
                      {entry.payload}
                    </pre>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between relative z-10 pt-4 border-t border-white/5">
                <div className="flex items-center gap-6">
                  <div className="flex flex-col gap-1">
                    <span className="text-[8px] text-muted-foreground/20 font-black uppercase tracking-widest">
                      TRIGGER_ID
                    </span>
                    <span className="text-[10px] text-white/40 font-black tracking-tight">
                      {entry.triggerId?.slice(0, 12) ?? "unknown"}...
                    </span>
                  </div>
                </div>

                <button
                  onClick={() => replayWebhook({ id: entry.id })}
                  disabled={isReplayingWebhook}
                  className="h-12 px-8 bg-amber-500 text-black rounded-2xl text-[10px] font-black uppercase tracking-[0.3em] transition-premium hover:shadow-[0_0_20px_hsla(var(--warning),0.3)] active:scale-95 disabled:opacity-50 flex items-center gap-3 shadow-2xl"
                >
                  {isReplayingWebhook ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <RotateCcw size={14} />
                  )}
                  RE-SYNC_PAYLOAD
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="flex items-center justify-between px-10 py-8 bg-surface-3/20 border border-white/5 rounded-[2.5rem] shadow-2xl relative overflow-hidden group/footer">
        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
        <div className="flex items-center gap-4 relative z-10">
          <div className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
          <span className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em]">
            Fault Container online &bull; Automated Pruning after 30 Cycles
          </span>
        </div>
        <div className="flex items-center gap-3 relative z-10 group-hover/footer:scale-105 transition-premium">
          <Search size={14} className="text-muted-foreground/20" />
          <span className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-[0.4em]">
            REGISTRY_V4.2
          </span>
        </div>
      </div>
    </div>
  );
}
