import React, { useState, useRef, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Webhook,
  Plus,
  Copy,
  CheckCircle2,
  XCircle,
  Zap,
  Clock,
  X,
  Shield,
  TrendingUp,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { relativeTime } from "@/lib/formatTime";
import type { WorkflowsQuery } from "@/generated/graphql";
import {
  useWebhookTriggersQuery,
  useCreateWebhookTriggerMutation,
  useWorkflowsQuery,
} from "@/generated/graphql";

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy — clipboard unavailable (requires HTTPS)");
    }
  };
  return (
    <button
      onClick={handleCopy}
      className="p-1 hover:bg-muted rounded transition-premium text-muted-foreground hover:text-foreground"
      title="Copy"
    >
      {copied ? (
        <CheckCircle2 className="w-3.5 h-3.5 text-success" />
      ) : (
        <Copy className="w-3.5 h-3.5" />
      )}
    </button>
  );
}

interface CreateDialogProps {
  onClose: () => void;
}

function CreateWebhookDialog({ onClose }: CreateDialogProps) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [moduleId, setModuleId] = useState("");
  const [rateLimit, setRateLimit] = useState(60);
  const [result, setResult] = useState<{
    webhookUrl: string;
    verificationToken?: string | null;
  } | null>(null);

  const { data: workflowsData } = useWorkflowsQuery(undefined, {
    select: (d: WorkflowsQuery) => d.workflows,
  });

  const createMutation = useCreateWebhookTriggerMutation({
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["WebhookTriggers"] });
      setResult({
        webhookUrl: data.createWebhookTrigger.webhookUrl,
        verificationToken: data.createWebhookTrigger.verificationToken,
      });
    },
    onError: () => toast.error("Failed to create webhook trigger"),
  });

  if (result) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 animate-in fade-in duration-500">
        <div className="bg-surface-3/90 border border-white/10 rounded-2xl p-10 w-full max-w-lg relative overflow-hidden">
          <div className="flex items-center gap-5 mb-10 relative z-10">
            <div className="w-14 h-14 bg-success/10 border border-success/20 rounded-2xl flex items-center justify-center">
              <CheckCircle2 className="w-7 h-7 text-success" />
            </div>
            <div>
              <h3 className="text-xl font-semibold text-white tracking-tight font-outfit">
                Webhook created
              </h3>
              <p className="text-xs text-muted-foreground/70 font-bold mt-1">
                Save these details now; the secret is shown once
              </p>
            </div>
          </div>

          <div className="space-y-6 relative z-10">
            <div className="space-y-2">
              <p className="text-xs font-semibold text-muted-foreground/70 ml-1">
                Webhook URL
              </p>
              <div className="flex items-center gap-4 bg-black/40 border border-white/5 rounded-2xl px-5 py-4 group">
                <code className="text-xs font-mono text-primary flex-1 truncate selection:bg-primary/30">
                  {result.webhookUrl}
                </code>
                <CopyButton value={result.webhookUrl} />
              </div>
            </div>
            {result.verificationToken && (
              <div className="space-y-2">
                <p className="text-xs font-semibold text-muted-foreground/70 ml-1">
                  Verification token
                </p>
                <div className="flex items-center gap-4 bg-black/40 border border-white/5 rounded-2xl px-5 py-4 group">
                  <code className="text-xs font-mono text-warning/80 flex-1 truncate selection:bg-warning/30">
                    {result.verificationToken}
                  </code>
                  <CopyButton value={result.verificationToken} />
                </div>
              </div>
            )}
          </div>

          <Button
            className="w-full mt-10 h-14 rounded-2xl font-semibold text-sm"
            onClick={onClose}
            variant="premium"
          >
            Done
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 animate-in fade-in duration-500">
      <div className="bg-surface-3/90 border border-white/10 rounded-2xl p-10 w-full max-w-md relative overflow-hidden">
        <div className="flex items-center justify-between mb-10 relative z-10">
          <div className="space-y-1">
            <h3 className="text-xl font-semibold text-white tracking-tight font-outfit">
              New webhook
            </h3>
            <p className="text-xs text-muted-foreground/70 font-bold">
              Start a workflow from an HTTP request
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-premium text-muted-foreground hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-6 relative z-10">
          <div className="space-y-2">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. GitHub push"
              className="w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-sm font-semibold text-white placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Workflow
            </label>
            <select
              value={moduleId}
              onChange={(e) => setModuleId(e.target.value)}
              className="w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-sm font-semibold text-white focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium appearance-none cursor-pointer"
            >
              <option value="" className="bg-surface-3">
                Select a workflow…
              </option>
              {workflowsData?.map((w) => (
                <option key={w.id} value={w.id} className="bg-surface-3">
                  {w.name}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Rate Threshold (Req/Min)
            </label>
            <input
              type="number"
              min={1}
              max={1000}
              value={rateLimit}
              onChange={(e) => setRateLimit(parseInt(e.target.value, 10) || 60)}
              className="w-full bg-black/40 border border-white/5 rounded-2xl px-5 py-4 text-xs font-semibold text-white focus:outline-none focus:border-primary/40 focus:ring-4 focus:ring-primary/10 transition-premium"
            />
          </div>

          <div className="flex gap-4 pt-4">
            <Button
              className="flex-1 h-14 rounded-2xl"
              disabled={!name.trim() || !moduleId || createMutation.isPending}
              variant="premium"
              onClick={() =>
                createMutation.mutate({
                  input: { name, moduleId, maxRequestsPerMinute: rateLimit },
                })
              }
            >
              {createMutation.isPending ? "Creating…" : "Create webhook"}
            </Button>
            <Button
              variant="ghost"
              className="px-6 h-14 rounded-2xl text-xs font-semibold tracking-wider"
              onClick={onClose}
            >
              Cancel
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function WebhookManager() {
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading } = useWebhookTriggersQuery(
    {},
    { refetchInterval: 30_000, refetchOnWindowFocus: true },
  );
  const triggers = data?.webhookTriggers ?? [];

  if (isLoading) {
    return (
      <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-10" />
        <div className="space-y-4">
          {[1, 2].map((i) => (
            <div
              key={i}
              className="h-32 bg-white/[0.02] border border-white/5 rounded-2xl"
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <>
      {showCreate && (
        <CreateWebhookDialog onClose={() => setShowCreate(false)} />
      )}

      <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 relative overflow-hidden">
        {/* Header */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8 mb-12 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center transition-premium">
              <Webhook className="w-8 h-8 text-primary" />
            </div>
            <div>
              <h3 className="text-2xl md:text-3xl font-semibold text-white tracking-tight font-outfit leading-tight">
                Webhooks
              </h3>
              <p className="text-xs text-muted-foreground/70 font-semibold mt-2">
                Start workflows from incoming HTTP requests
              </p>
            </div>
          </div>
          <Button
            onClick={() => setShowCreate(true)}
            variant="premium"
            className="h-14 px-8 rounded-2xl flex items-center gap-3 w-full md:w-auto"
          >
            <Plus className="w-5 h-5" />
            New webhook
          </Button>
        </div>

        {triggers.length === 0 ? (
          <div className="text-center py-24 bg-white/[0.01] border border-dashed border-white/5 rounded-2xl relative group overflow-hidden">
            <Webhook className="w-16 h-16 text-muted-foreground/30 mb-6 mx-auto group-hover:text-primary/20 transition-premium" />
            <p className="text-sm text-muted-foreground font-semibold">
              No webhooks yet
            </p>
            <p className="text-xs text-muted-foreground/60 mt-2 max-w-xs mx-auto leading-relaxed">
              Create a webhook to start a workflow from an incoming HTTP
              request.
            </p>
          </div>
        ) : (
          <div className="space-y-4 relative z-10">
            {triggers.map((t) => {
              const successRate =
                t.triggerCount > 0
                  ? Math.round((t.successCount / t.triggerCount) * 100)
                  : null;

              return (
                <div
                  key={t.id}
                  className="bg-white/[0.02] border border-white/5 rounded-2xl p-6 hover:bg-white/[0.04] hover:border-white/10 transition-premium group relative overflow-hidden"
                >
                  <div className="flex items-start justify-between gap-6 mb-5 relative z-10">
                    <div className="flex items-center gap-4 min-w-0">
                      <div
                        className={cn(
                          "w-2.5 h-2.5 rounded-full shrink-0",
                          t.enabled
                            ? "bg-success animate-status-pulse"
                            : "bg-muted-foreground/30",
                        )}
                      />
                      <div className="min-w-0">
                        <span className="text-lg font-semibold text-white tracking-tight font-outfit truncate group-hover:text-primary transition-premium">
                          {t.name}
                        </span>
                        <div className="flex items-center gap-3 mt-1">
                          <span className="text-2xs text-muted-foreground/70 font-semibold uppercase tracking-wider">
                            ID: {t.id.slice(0, 8)}...
                          </span>
                          {!t.enabled && (
                            <span className="text-2xs font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-white/5 text-muted-foreground/60 border border-white/10">
                              Disabled
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-6 shrink-0 pt-1">
                      {successRate !== null && (
                        <div
                          className={cn(
                            "flex flex-col items-end",
                            successRate >= 90
                              ? "text-success"
                              : successRate >= 70
                                ? "text-warning"
                                : "text-destructive",
                          )}
                        >
                          <span className="text-2xs font-semibold uppercase tracking-wider opacity-40 mb-1">
                            Success rate
                          </span>
                          <div className="flex items-center gap-1.5 text-sm font-semibold tracking-tighter">
                            <TrendingUp className="w-3.5 h-3.5" />
                            {successRate}%
                          </div>
                        </div>
                      )}
                      {t.lastTriggeredAt && (
                        <div className="flex flex-col items-end text-muted-foreground">
                          <span className="text-2xs font-semibold uppercase tracking-wider opacity-40 mb-1">
                            Last received
                          </span>
                          <div className="flex items-center gap-1.5 text-xs font-semibold tracking-tighter">
                            <Clock className="w-3.5 h-3.5 opacity-30" />
                            {relativeTime(t.lastTriggeredAt)}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Stats row */}
                  <div className="flex items-center gap-3 mb-6 relative z-10">
                    <div className="flex items-center gap-2 text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider bg-white/5 border border-white/5 px-3 py-1.5 rounded-xl shadow-sm">
                      <Zap className="w-3 h-3 text-primary" />
                      {t.triggerCount.toLocaleString()} received
                    </div>
                    <div className="flex items-center gap-2 text-2xs text-success font-semibold uppercase tracking-wider bg-success/5 border border-success/10 px-3 py-1.5 rounded-xl shadow-sm">
                      <CheckCircle2 className="w-3 h-3" />
                      {t.successCount.toLocaleString()} succeeded
                    </div>
                    {t.errorCount > 0 && (
                      <div className="flex items-center gap-2 text-2xs text-destructive font-semibold uppercase tracking-wider bg-destructive/5 border border-destructive/10 px-3 py-1.5 rounded-xl shadow-sm">
                        <XCircle className="w-3 h-3" />
                        {t.errorCount.toLocaleString()} failed
                      </div>
                    )}
                    <div className="flex items-center gap-2 text-2xs text-muted-foreground/60 font-semibold uppercase tracking-wider ml-auto">
                      <Shield className="w-3 h-3" />
                      {t.maxRequestsPerMinute} requests/min
                    </div>
                  </div>

                  {/* URL */}
                  <div className="flex items-center gap-4 bg-black/40 border border-white/5 rounded-2xl px-5 py-4 relative z-10">
                    <code className="text-xs font-mono text-primary/80 flex-1 truncate selection:bg-primary/30 tracking-tight">
                      {t.webhookUrl}
                    </code>
                    <CopyButton value={t.webhookUrl} />
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-10 pt-6 border-t border-white/5 flex items-center justify-between relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-xs text-muted-foreground/70 font-semibold">
              Ingress Monitoring Active &bull; Polling 30s Intervals
            </span>
          </div>
          <span className="text-xs text-muted-foreground/50 font-semibold">
            {triggers.length} webhook
            {triggers.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>
    </>
  );
}
