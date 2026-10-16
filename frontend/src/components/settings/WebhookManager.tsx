import React, { useState, useRef, useEffect } from "react";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Dialog } from "@/components/ui/dialog";
import { Select } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
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
      className="p-1 hover:bg-muted rounded transition-ui text-muted-foreground hover:text-foreground"
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
      <Dialog
        open
        onClose={onClose}
        title="Webhook created"
        className="max-w-lg"
      >
        <p className="text-sm text-muted-foreground -mt-4 mb-6">
          Save these details now; the secret is shown once.
        </p>

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
          className="w-full mt-8 h-14 rounded-2xl font-semibold text-sm"
          onClick={onClose}
        >
          Done
        </Button>
      </Dialog>
    );
  }

  return (
    <Dialog open onClose={onClose} title="New webhook" className="max-w-md">
      <p className="text-sm text-muted-foreground -mt-4 mb-6">
        Start a workflow from an HTTP request.
      </p>

      <div className="space-y-6 relative z-10">
        <div className="space-y-2">
          <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
            Name
          </label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. GitHub push"
          />
        </div>

        <div className="space-y-2">
          <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
            Workflow
          </label>
          <Select
            value={moduleId}
            onChange={(e) => setModuleId(e.target.value)}
          >
            <option value="" className="bg-surface-3">
              Select a workflow…
            </option>
            {workflowsData?.map((w) => (
              <option key={w.id} value={w.id} className="bg-surface-3">
                {w.name}
              </option>
            ))}
          </Select>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
            Rate Threshold (Req/Min)
          </label>
          <Input
            type="number"
            min={1}
            max={1000}
            value={rateLimit}
            onChange={(e) => setRateLimit(parseInt(e.target.value, 10) || 60)}
            className="text-xs"
          />
        </div>

        <div className="flex gap-4 pt-4">
          <Button
            className="flex-1 h-14 rounded-2xl"
            disabled={!name.trim() || !moduleId || createMutation.isPending}
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
    </Dialog>
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
      <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-6 animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-6" />
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

      <div className="space-y-8">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <SectionHeader
              level="h2"
              className="text-2xl font-semibold text-white tracking-tight"
            >
              Webhooks
            </SectionHeader>
            <p className="text-sm text-muted-foreground mt-2">
              Start workflows from incoming HTTP requests.
            </p>
          </div>
          <Button
            onClick={() => setShowCreate(true)}
            className="w-full md:w-auto"
          >
            <Plus className="w-4 h-4" />
            New webhook
          </Button>
        </div>

        <div className="bg-surface-3/30 border border-white/5 rounded-2xl p-6">
          {triggers.length === 0 ? (
            <div className="text-center py-16 bg-white/[0.01] border border-dashed border-white/5 rounded-2xl relative group overflow-hidden">
              <Webhook className="w-10 h-10 text-muted-foreground/30 mb-6 mx-auto group-hover:text-primary/20 transition-ui" />
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
                    className="bg-white/[0.02] border border-white/5 rounded-2xl p-6 hover:bg-white/[0.04] hover:border-white/10 transition-ui group relative overflow-hidden"
                  >
                    <div className="flex items-start justify-between gap-6 mb-5 relative z-10">
                      <div className="flex items-center gap-4 min-w-0">
                        <div
                          className={cn(
                            "w-2.5 h-2.5 rounded-full shrink-0",
                            t.enabled ? "bg-success" : "bg-muted-foreground/30",
                          )}
                        />
                        <div className="min-w-0">
                          <span className="text-lg font-semibold text-white tracking-tight font-outfit truncate group-hover:text-primary transition-ui">
                            {t.name}
                          </span>
                          <div className="flex items-center gap-3 mt-1">
                            <span className="text-xs text-muted-foreground/70 font-medium">
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
                      <div className="flex items-center gap-2 text-xs text-muted-foreground/60 font-medium bg-white/5 border border-white/5 px-3 py-1.5 rounded-xl shadow-sm">
                        <Zap className="w-3 h-3 text-primary" />
                        {t.triggerCount.toLocaleString()} received
                      </div>
                      <div className="flex items-center gap-2 text-xs text-success font-medium bg-success/5 border border-success/10 px-3 py-1.5 rounded-xl shadow-sm">
                        <CheckCircle2 className="w-3 h-3" />
                        {t.successCount.toLocaleString()} succeeded
                      </div>
                      {t.errorCount > 0 && (
                        <div className="flex items-center gap-2 text-xs text-destructive font-medium bg-destructive/5 border border-destructive/10 px-3 py-1.5 rounded-xl shadow-sm">
                          <XCircle className="w-3 h-3" />
                          {t.errorCount.toLocaleString()} failed
                        </div>
                      )}
                      <div className="flex items-center gap-2 text-xs text-muted-foreground/60 font-medium ml-auto">
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
        </div>
      </div>
    </>
  );
}
