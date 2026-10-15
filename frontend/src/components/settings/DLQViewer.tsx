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
        "text-2xs font-semibold uppercase tracking-wider border rounded-lg px-2 py-0.5 shadow-sm",
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
        toast.success("Job replayed");
        refetchNodes();
      },
      onError: () => {
        toast.error("Failed to replay job");
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
      <div className="flex flex-col items-center justify-center py-48 gap-6">
        <div className="relative">
          <div className="w-16 h-16 border-2 border-destructive/10 rounded-full" />
          <div className="w-16 h-16 border-t-2 border-destructive rounded-full animate-spin absolute inset-0" />
        </div>
        <p className="text-xs text-destructive/60 font-semibold">
          Scanning Fault Registry...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-10 relative overflow-hidden group/header">
        <div className="flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-destructive/10 border border-destructive/20 rounded-2xl flex items-center justify-center text-destructive transition-ui">
              <Ghost size={32} />
            </div>
            <div className="space-y-1.5">
              <h2 className="text-2xl md:text-3xl font-semibold text-white tracking-tight leading-tight">
                Dead-letter queue
              </h2>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 bg-destructive/10 border border-destructive/20 px-3 py-1 rounded-full">
                  <div className="w-1.5 h-1.5 rounded-full bg-destructive" />
                  <span className="text-2xs text-destructive font-semibold uppercase tracking-wider leading-none">
                    Monitoring
                  </span>
                </div>
                <div className="w-1 h-1 rounded-full bg-white/10" />
                <span className="text-2xs text-muted-foreground/70 font-semibold uppercase tracking-wider leading-none">
                  Failed node jobs and dropped webhook deliveries
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-10">
            <div className="flex flex-col items-end gap-1">
              <span className="text-3xl font-semibold text-white tracking-tight leading-none">
                {activeTab === "nodes"
                  ? pendingNodes.length
                  : pendingWebhooks.length}
              </span>
              <span className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider leading-none">
                {activeTab === "nodes" ? "failed jobs" : "dropped deliveries"}
              </span>
            </div>
            <button
              onClick={() =>
                activeTab === "nodes" ? refetchNodes() : refetchWebhooks()
              }
              className="w-14 h-14 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-center text-muted-foreground/70 hover:text-white hover:bg-white/10 transition-ui"
            >
              <RotateCcw
                size={20}
                className={isLoading ? "animate-spin" : ""}
              />
            </button>
          </div>
        </div>
      </div>

      <div className="flex gap-2 p-2 bg-surface-3/30 border border-white/5 rounded-2xl max-w-xl mx-auto">
        <button
          onClick={() => setActiveTab("nodes")}
          className={cn(
            "flex-1 flex items-center justify-center gap-3 py-4 rounded-2xl text-sm font-semibold transition-ui relative overflow-hidden group",
            activeTab === "nodes"
              ? "bg-destructive text-white"
              : "text-muted-foreground/70 hover:text-white hover:bg-white/5",
          )}
        >
          <Bug className="w-4 h-4 relative z-10" />
          <span className="relative z-10">Node failures</span>
          {pendingNodes.length > 0 && (
            <span
              className={cn(
                "px-2 py-0.5 rounded-lg text-2xs font-semibold min-w-[1.2rem] text-center relative z-10 transition-ui",
                activeTab === "nodes"
                  ? "bg-white text-destructive"
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
            "flex-1 flex items-center justify-center gap-3 py-4 rounded-2xl text-sm font-semibold transition-ui relative overflow-hidden group",
            activeTab === "webhooks"
              ? "bg-amber-500 text-black shadow-amber-500/20"
              : "text-muted-foreground/70 hover:text-white hover:bg-white/5",
          )}
        >
          <Webhook className="w-4 h-4 relative z-10" />
          <span className="relative z-10">Dropped webhooks</span>
          {pendingWebhooks.length > 0 && (
            <span
              className={cn(
                "px-2 py-0.5 rounded-lg text-2xs font-semibold min-w-[1.2rem] text-center relative z-10 transition-ui",
                activeTab === "webhooks"
                  ? "bg-black text-amber-500"
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
            <div className="flex flex-col items-center justify-center py-32 bg-surface-3/20 border border-dashed border-white/5 rounded-2xl text-center group">
              <div className="w-20 h-20 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-center text-muted-foreground/30 mb-8 transition-ui group-hover:text-success/20">
                <Shield size={40} />
              </div>
              <h3 className="text-2xl font-semibold text-white/70 tracking-tight mb-4">
                Nothing to review
              </h3>
              <p className="text-xs text-muted-foreground/50 max-w-sm leading-relaxed">
                No failed node jobs are waiting for a replay.
              </p>
            </div>
          ) : (
            pendingNodes.map((entry) => (
              <div
                key={entry.id}
                className="bg-surface-3/30 border border-white/5 rounded-2xl p-8 transition-ui hover:border-white/10 group relative overflow-hidden"
              >
                <div className="flex items-start justify-between mb-8 relative z-10">
                  <div className="flex items-center gap-5">
                    <div className="w-12 h-12 rounded-xl bg-destructive/10 border border-destructive/20 flex items-center justify-center text-destructive">
                      <Bug size={20} />
                    </div>
                    <div>
                      <span className="text-xs font-semibold text-destructive bg-destructive/5 px-3 py-1 rounded-lg border border-destructive/10">
                        Node {entry.nodeId.slice(0, 8)}
                      </span>
                      <p className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider mt-2">
                        Failed {new Date(entry.createdAt).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1.5">
                    <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
                      Run
                    </span>
                    <code className="text-xs font-mono text-white/70 bg-black/40 px-3 py-1 rounded-lg border border-white/5">
                      {entry.executionId.slice(0, 16)}...
                    </code>
                  </div>
                </div>

                <div className="mb-8 relative z-10">
                  <div className="bg-black/60 border border-white/5 rounded-2xl p-6 relative overflow-hidden group/error">
                    <div className="absolute top-0 right-0 p-3 opacity-20 group-hover/error:opacity-100 transition-ui">
                      <AlertCircle size={14} className="text-destructive" />
                    </div>
                    <p className="text-xs text-destructive/80 font-mono leading-relaxed selection:bg-destructive/30">
                      {sanitizeErrorMessage(
                        entry.errorMessage ?? "No error message recorded",
                      )}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between relative z-10 pt-4 border-t border-white/5">
                  <button className="flex items-center gap-3 text-xs text-muted-foreground/70 font-semibold hover:text-white transition-ui group/link">
                    <ExternalLink size={14} className="transition-ui" />
                    Open workflow
                  </button>

                  <button
                    onClick={() => handleNodeReplay(entry.id)}
                    disabled={isReplayingNode}
                    className="h-12 px-8 bg-destructive text-white rounded-2xl text-sm font-semibold transition-ui disabled:opacity-50 flex items-center gap-3"
                  >
                    {isReplayingNode ? (
                      <Loader2 size={14} className="animate-spin" />
                    ) : (
                      <RotateCcw size={14} />
                    )}
                    Replay job
                  </button>
                </div>
              </div>
            ))
          )
        ) : pendingWebhooks.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-32 bg-surface-3/20 border border-dashed border-white/5 rounded-2xl text-center group">
            <div className="w-20 h-20 bg-white/5 border border-white/5 rounded-2xl flex items-center justify-center text-muted-foreground/30 mb-8 transition-ui group-hover:text-amber-500/20">
              <Database size={40} />
            </div>
            <h3 className="text-2xl font-semibold text-white/70 tracking-tight mb-4">
              Nothing to review
            </h3>
            <p className="text-xs text-muted-foreground/50 max-w-sm leading-relaxed">
              No webhook deliveries have been dropped.
            </p>
          </div>
        ) : (
          pendingWebhooks.map((entry) => (
            <div
              key={entry.id}
              className="bg-surface-3/30 border border-white/5 rounded-2xl p-8 transition-ui hover:border-white/10 group relative overflow-hidden"
            >
              <div className="flex items-start justify-between mb-8 relative z-10">
                <div className="flex items-center gap-5">
                  <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-500">
                    <Webhook size={20} />
                  </div>
                  <div className="space-y-1.5">
                    <DropReasonBadge reason={entry.dropReason} />
                    <p className="text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider">
                      Dropped {new Date(entry.createdAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1.5">
                  <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
                    Source IP
                  </span>
                  <code className="text-xs font-mono text-white/70 bg-black/40 px-3 py-1 rounded-lg border border-white/5">
                    {entry.sourceIp || "unknown"}
                  </code>
                </div>
              </div>

              {entry.payload && (
                <div className="mb-8 relative z-10">
                  <div className="bg-black/60 border border-white/5 rounded-2xl p-6 max-h-40 overflow-y-auto custom-scrollbar group/code">
                    <div className="absolute top-3 right-5 opacity-0 group-hover/code:opacity-100 transition-ui">
                      <span className="text-2xs font-semibold text-primary/70 uppercase tracking-wider">
                        Payload
                      </span>
                    </div>
                    <pre className="text-xs font-mono text-foreground/60 leading-relaxed whitespace-pre-wrap break-all selection:bg-primary/30">
                      {entry.payload}
                    </pre>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between relative z-10 pt-4 border-t border-white/5">
                <div className="flex items-center gap-6">
                  <div className="flex flex-col gap-1">
                    <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
                      Webhook
                    </span>
                    <span className="text-xs text-white/70 font-semibold tracking-tight">
                      {entry.triggerId?.slice(0, 12) ?? "unknown"}...
                    </span>
                  </div>
                </div>

                <button
                  onClick={() => replayWebhook({ id: entry.id })}
                  disabled={isReplayingWebhook}
                  className="h-12 px-8 bg-amber-500 text-black rounded-2xl text-sm font-semibold transition-ui disabled:opacity-50 flex items-center gap-3"
                >
                  {isReplayingWebhook ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <RotateCcw size={14} />
                  )}
                  Replay delivery
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="flex items-center justify-between px-10 py-8 bg-surface-3/20 border border-white/5 rounded-2xl relative overflow-hidden group/footer">
        <div className="flex items-center gap-4 relative z-10">
          <div className="w-2 h-2 rounded-full bg-primary" />
          <span className="text-xs text-muted-foreground/70 font-semibold">
            Fault Container online &bull; Automated Pruning after 30 Cycles
          </span>
        </div>
        <div className="flex items-center gap-3 relative z-10 transition-ui">
          <Search size={14} className="text-muted-foreground/50" />
          <span className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
            REGISTRY_V4.2
          </span>
        </div>
      </div>
    </div>
  );
}
