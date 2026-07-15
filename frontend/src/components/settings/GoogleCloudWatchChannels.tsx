/**
 * Google Cloud watch-channel panel. Mirrors GmailWatchChannels but for
 * Cloud Monitoring push: each watch stores its own service-account
 * email, and there is NO renew action (the user owns the upstream
 * Pub/Sub subscription — nothing on our side expires).
 *
 * Renders nothing when the user has no connected Google Cloud
 * integration. When integrated but no watch exists, shows an empty-state
 * CTA.
 *
 * The `push_endpoint` (which embeds the raw push token) is shown to the
 * OWNER so they can wire it into `gcloud pubsub subscriptions create
 * --push-endpoint=...`. It is surfaced prominently once on create, and
 * copyable from each row thereafter.
 */

import React, { useEffect, useState } from "react";
import type { QueryKey } from "@tanstack/react-query";
import {
  useQuery,
  useMutation,
  useQueryClient,
  useIsFetching,
} from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Cloud,
  RefreshCw,
  Activity,
  XCircle,
  Plus,
  Check,
  AlertTriangle,
  KeyRound,
  Copy,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui";
import { getCsrfToken } from "@/lib/csrf";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";

function authedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const csrf = getCsrfToken();
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (csrf) headers["X-CSRF-Token"] = csrf;
  return fetch(url, { ...init, credentials: "include", headers });
}

interface GcpWatchSummary {
  channel_uuid: string;
  integration_id: string;
  display_name: string;
  expected_sa_email: string;
  push_endpoint: string;
  module_id: string | null;
  module_name: string | null;
  last_push_received?: string;
  created_at: string;
  recent_failure?: {
    error_message: string;
    failed_at: string;
    likely_oauth_failure: boolean;
  };
}

interface GcpIntegrationInfo {
  id: string;
  account_email: string | null;
  is_active: boolean;
}

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

const WATCHES_KEY: QueryKey = ["gcp", "watch-channels"];
const INTEGRATIONS_KEY: QueryKey = ["gcp", "integrations"];

function formatRelative(iso?: string): string {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return "just now";
  const m = Math.floor(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast.success("Push endpoint copied");
  } catch {
    toast.error("Could not copy — copy it manually");
  }
}

async function fetchWatches(): Promise<GcpWatchSummary[]> {
  const res = await authedFetch("/api/gcp/watch-channels");
  if (res.status === 401 || res.status === 404) return [];
  const body: ApiResponse<GcpWatchSummary[]> = await res.json();
  if (!body.success)
    throw new Error(body.error ?? "Failed to load GCP watches");
  return body.data ?? [];
}

async function fetchGcpIntegrations(): Promise<GcpIntegrationInfo[]> {
  const res = await authedFetch("/api/gcp/integrations");
  if (res.status === 401) return [];
  const body: ApiResponse<GcpIntegrationInfo[]> = await res.json();
  if (!body.success)
    throw new Error(body.error ?? "Failed to load GCP integrations");
  return (body.data ?? []).filter((i) => i.is_active);
}

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateGcpWatchDialog({
  integrations,
  open,
  onClose,
  onCreated,
}: {
  integrations: GcpIntegrationInfo[];
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}): React.ReactElement {
  const qc = useQueryClient();
  const [integrationId, setIntegrationId] = useState<string>(
    integrations[0]?.id ?? "",
  );
  const [saEmail, setSaEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [moduleId, setModuleId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // The push endpoint returned by create — surfaced ONCE here with a
  // copy button so the user can paste it into `gcloud`.
  const [createdEndpoint, setCreatedEndpoint] = useState<string | null>(null);
  const watchesFetching = useIsFetching({ queryKey: WATCHES_KEY }) > 0;

  const [lastIntegrations, setLastIntegrations] = useState(integrations);
  if (integrations !== lastIntegrations) {
    setLastIntegrations(integrations);
    if (!integrationId && integrations[0]) setIntegrationId(integrations[0].id);
  }

  useEffect(() => {
    if (open) qc.invalidateQueries({ queryKey: WATCHES_KEY });
  }, [open, qc]);

  // Reset the one-time endpoint reveal when the dialog is dismissed (in
  // an event handler, not an effect — a fresh open then starts clean).
  const closeDialog = () => {
    setCreatedEndpoint(null);
    onClose();
  };

  const handleSubmit = async () => {
    if (!integrationId || !saEmail.trim()) return;
    setSubmitting(true);
    try {
      const res = await authedFetch("/api/gcp/watch-channels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          integration_id: integrationId,
          expected_sa_email: saEmail.trim(),
          display_name: displayName.trim() || null,
          module_id: moduleId.trim() || null,
        }),
      });
      const body: ApiResponse<{ push_endpoint?: string }> = await res.json();
      if (!body.success) {
        toast.error(sanitizeErrorMessage(body.error ?? "Create failed"));
        return;
      }
      toast.success("GCP watch created");
      await qc.invalidateQueries({ queryKey: WATCHES_KEY });
      onCreated();
      setCreatedEndpoint(body.data?.push_endpoint ?? null);
    } catch (e) {
      toast.error(
        sanitizeErrorMessage(e instanceof Error ? e.message : String(e)),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => !submitting && closeDialog()}
      title="Create Google Cloud watch"
    >
      {createdEndpoint ? (
        <div className="space-y-5">
          <div>
            <p className="text-sm font-semibold text-foreground mb-1">
              Watch created — copy your push endpoint
            </p>
            <p className="text-xs text-muted-foreground mb-3">
              Paste this into your Pub/Sub push subscription (
              <code>--push-endpoint</code>). It embeds a secret token — this is
              the one prominent place we show it (you can re-copy it from the
              row later).
            </p>
            <div className="flex items-center gap-2 p-3 bg-muted/30 border border-border/60 rounded-lg">
              <code className="text-xs break-all flex-1">
                {createdEndpoint}
              </code>
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyToClipboard(createdEndpoint)}
                className="h-8 px-2.5 text-xs shrink-0"
              >
                <Copy size={13} className="mr-1.5" /> Copy
              </Button>
            </div>
          </div>
          <div className="flex justify-end pt-2">
            <Button
              onClick={closeDialog}
              className="h-10 px-6 text-xs font-bold"
              disabled={watchesFetching}
            >
              <Check size={13} className="mr-1.5" /> Done
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Google Cloud account
            </label>
            <select
              value={integrationId}
              onChange={(e) => setIntegrationId(e.target.value)}
              disabled={submitting || integrations.length === 0}
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              {integrations.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.account_email ?? i.id}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Push service-account email
            </label>
            <input
              type="text"
              value={saEmail}
              onChange={(e) => setSaEmail(e.target.value)}
              disabled={submitting}
              placeholder="talos-gcp-pusher@my-project.iam.gserviceaccount.com"
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
            <p className="text-[11px] text-muted-foreground mt-1.5">
              The service account your Pub/Sub subscription signs pushes with (
              <code>--push-auth-service-account</code>). Every push JWT must be
              issued by this account.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Display name (optional)
            </label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              disabled={submitting}
              placeholder="Prod alerting"
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Module ID (optional)
            </label>
            <input
              type="text"
              value={moduleId}
              onChange={(e) => setModuleId(e.target.value)}
              disabled={submitting}
              placeholder="UUID of the module to run on each incident"
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
            <p className="text-[11px] text-muted-foreground mt-1.5">
              Leave blank to bind a module later in the workflow builder.
            </p>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="outline"
              onClick={closeDialog}
              disabled={submitting}
              className="h-10 px-5 text-xs font-bold"
            >
              Cancel
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={
                submitting ||
                watchesFetching ||
                !integrationId ||
                !saEmail.trim()
              }
              className="h-10 px-6 text-xs font-bold"
            >
              {submitting ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2" />
                  Creating…
                </>
              ) : watchesFetching ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-foreground/30 border-t-foreground rounded-full animate-spin mr-2" />
                  Syncing…
                </>
              ) : (
                <>
                  <Check size={13} className="mr-1.5" />
                  Create watch
                </>
              )}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function GoogleCloudWatchChannels(): React.ReactElement | null {
  const qc = useQueryClient();
  const [flashedAt, setFlashedAt] = useState<Record<string, number>>({});
  const [createOpen, setCreateOpen] = useState(false);

  const watchesQuery = useQuery({
    queryKey: WATCHES_KEY,
    queryFn: fetchWatches,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    staleTime: 10_000,
  });
  const watches = watchesQuery.data ?? [];

  const integrationsQuery = useQuery({
    queryKey: INTEGRATIONS_KEY,
    queryFn: fetchGcpIntegrations,
    staleTime: 60_000,
  });
  const integrations = integrationsQuery.data ?? [];

  const flashTimersRef = React.useRef<Set<number>>(new Set());
  React.useEffect(() => {
    const timers = flashTimersRef.current;
    return () => {
      timers.forEach(clearTimeout);
      timers.clear();
    };
  }, []);
  const triggerFlash = (ch: string) => {
    const now = Date.now();
    setFlashedAt((p) => ({ ...p, [ch]: now }));
    const timer = window.setTimeout(() => {
      flashTimersRef.current.delete(timer);
      setFlashedAt((p) => {
        if (p[ch] !== now) return p;
        const n = { ...p };
        delete n[ch];
        return n;
      });
    }, 1600);
    flashTimersRef.current.add(timer);
  };

  const testMutation = useMutation({
    mutationFn: async (ch: string) => {
      const res = await authedFetch(`/api/gcp/watch-channels/${ch}/test`, {
        method: "POST",
      });
      const body: ApiResponse<{ oauth_ok: boolean; duration_ms: number }> =
        await res.json();
      if (!body.success || !body.data)
        throw new Error(body.error ?? "Test failed");
      return body.data;
    },
    onSuccess: (data, ch) => {
      triggerFlash(ch);
      if (data.oauth_ok) {
        toast.success(`OAuth OK — GCP responded in ${data.duration_ms} ms`);
      } else {
        toast.error("GCP probe failed");
      }
    },
    onError: (err) => {
      toast.error(
        sanitizeErrorMessage(err instanceof Error ? err.message : String(err)),
      );
    },
  });

  const stopMutation = useMutation({
    mutationFn: async (ch: string) => {
      const res = await authedFetch(`/api/gcp/watch-channels/${ch}`, {
        method: "DELETE",
      });
      const body: ApiResponse<string> = await res.json();
      if (!body.success) throw new Error(body.error ?? "Stop failed");
    },
    onMutate: async (ch) => {
      await qc.cancelQueries({ queryKey: WATCHES_KEY });
      const prev = qc.getQueryData<GcpWatchSummary[]>(WATCHES_KEY);
      qc.setQueryData<GcpWatchSummary[]>(WATCHES_KEY, (old) =>
        (old ?? []).filter((w) => w.channel_uuid !== ch),
      );
      return { prev };
    },
    onError: (err, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(WATCHES_KEY, ctx.prev);
      toast.error(
        sanitizeErrorMessage(err instanceof Error ? err.message : String(err)),
      );
    },
    onSuccess: () => toast.success("Watch stopped"),
    onSettled: () => qc.invalidateQueries({ queryKey: WATCHES_KEY }),
  });

  const pendingFor = (ch: string): "test" | "stop" | null => {
    if (testMutation.isPending && testMutation.variables === ch) return "test";
    if (stopMutation.isPending && stopMutation.variables === ch) return "stop";
    return null;
  };

  const oauthFailingIntegrationIds = new Set(
    watches
      .filter((w) => w.recent_failure?.likely_oauth_failure)
      .map((w) => w.integration_id),
  );
  const hasAnyOauthFailure = oauthFailingIntegrationIds.size > 0;

  if (integrationsQuery.isLoading || watchesQuery.isLoading) {
    return (
      <div className="mt-10 p-6 bg-muted/10 border border-border/30 rounded-2xl text-sm text-muted-foreground">
        Loading Google Cloud watch channels…
      </div>
    );
  }
  if (integrations.length === 0) return null;

  if (watchesQuery.isError) {
    return (
      <div className="mt-10 p-6 bg-destructive/5 border border-destructive/20 rounded-2xl">
        <p className="text-sm font-semibold text-foreground mb-1">
          Could not load Google Cloud watches
        </p>
        <p className="text-xs text-muted-foreground mb-3">
          The server returned an error. Retry now or wait for the next refresh.
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => watchesQuery.refetch()}
          className="h-8 px-3 text-xs"
        >
          <RefreshCw size={13} className="mr-1.5" /> Retry
        </Button>
      </div>
    );
  }

  const header = (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 text-primary flex items-center justify-center">
          <Cloud size={16} />
        </div>
        <div>
          <h3 className="text-sm font-bold text-foreground">
            Google Cloud Watch Channels
          </h3>
          <p className="text-xs text-muted-foreground">
            {watches.length === 0
              ? "None active — create one to receive Cloud Monitoring incident pushes"
              : `${watches.length} active · user-owned Pub/Sub subscriptions`}
            {watchesQuery.isFetching && !watchesQuery.isLoading && (
              <span className="ml-2 inline-flex items-center gap-1 text-[10px] text-muted-foreground/70">
                <span className="w-2 h-2 bg-primary/50 rounded-full animate-pulse" />
                refreshing
              </span>
            )}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => watchesQuery.refetch()}
          disabled={watchesQuery.isFetching}
          className="h-8 px-3 text-xs"
        >
          <RefreshCw
            size={13}
            className={cn("mr-1.5", watchesQuery.isFetching && "animate-spin")}
          />
          Refresh
        </Button>
        <Button
          size="sm"
          onClick={() => setCreateOpen(true)}
          className="h-8 px-3 text-xs"
        >
          <Plus size={13} className="mr-1.5" /> Create
        </Button>
      </div>
    </div>
  );

  return (
    <div className="mt-10">
      {header}

      {hasAnyOauthFailure && (
        <div className="mb-4 p-4 bg-destructive/5 border border-destructive/20 rounded-2xl flex items-start gap-4">
          <div className="w-10 h-10 bg-destructive/10 border border-destructive/20 rounded-lg flex items-center justify-center text-destructive shrink-0">
            <KeyRound size={18} />
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold text-foreground mb-1">
              Reconnect your Google Cloud account
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed mb-3">
              One or more Google Cloud watches are failing because the OAuth
              credentials for{" "}
              {oauthFailingIntegrationIds.size === 1
                ? "this account have"
                : `${oauthFailingIntegrationIds.size} accounts have`}{" "}
              expired or been revoked. Incident dispatch will fail until
              reconnected.
            </p>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const el = document.querySelector(
                  '[data-provider-id="google_cloud"]',
                );
                if (el instanceof HTMLElement) {
                  el.scrollIntoView({ behavior: "smooth", block: "center" });
                } else {
                  window.scrollTo({ top: 0, behavior: "smooth" });
                }
              }}
              className="h-8 px-3 text-xs font-bold"
            >
              Go to Google Cloud provider card ↑
            </Button>
          </div>
        </div>
      )}

      {watches.length === 0 ? (
        <div className="border border-dashed border-border/60 rounded-2xl p-8 text-center">
          <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-primary/5 border border-primary/20 flex items-center justify-center text-primary">
            <Cloud size={20} />
          </div>
          <p className="text-sm font-semibold text-foreground mb-1">
            No Google Cloud watches yet
          </p>
          <p className="text-xs text-muted-foreground max-w-md mx-auto mb-5">
            A watch receives Cloud Monitoring incident notifications via a
            Pub/Sub push subscription you point at Talos. Bind a WASM module to
            run automations on every incident.
          </p>
          <Button
            onClick={() => setCreateOpen(true)}
            className="h-9 px-5 text-xs font-bold"
          >
            <Plus size={13} className="mr-1.5" /> Create your first GCP watch
          </Button>
        </div>
      ) : (
        <div className="border border-border/40 rounded-2xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-xs text-muted-foreground">
              <tr>
                <th className="text-left px-4 py-2.5 font-semibold">Name</th>
                <th className="text-left px-4 py-2.5 font-semibold">
                  Service account
                </th>
                <th className="text-left px-4 py-2.5 font-semibold">Module</th>
                <th className="text-left px-4 py-2.5 font-semibold">
                  Last push
                </th>
                <th className="text-left px-4 py-2.5 font-semibold">Status</th>
                <th className="text-right px-4 py-2.5 font-semibold">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {watches.map((w) => {
                const cur = pendingFor(w.channel_uuid);
                const flashing = flashedAt[w.channel_uuid] !== undefined;
                const dim = cur !== null;
                return (
                  <tr
                    key={w.channel_uuid}
                    className={cn(
                      "border-t border-border/30 transition-premium duration-700",
                      flashing && "bg-primary/5",
                      dim && "opacity-60",
                      !flashing && !dim && "hover:bg-muted/20",
                    )}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-foreground">
                        {w.display_name}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs font-mono break-all">
                      {w.expected_sa_email}
                    </td>
                    <td className="px-4 py-3">
                      {w.module_name ? (
                        <span className="text-foreground">{w.module_name}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground italic">
                          (no module bound)
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-foreground">
                      {formatRelative(w.last_push_received)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1 items-start">
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                          active
                        </span>
                        {w.recent_failure && (
                          <span
                            className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-destructive/10 text-destructive border border-destructive/20"
                            title={`${w.recent_failure.error_message}\n\nFailed at: ${new Date(w.recent_failure.failed_at).toLocaleString()}`}
                          >
                            <AlertTriangle size={10} />
                            push failing
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(w.push_endpoint)}
                          disabled={cur !== null}
                          title="Copy the Pub/Sub push endpoint (contains the token)."
                          className="h-8 px-2.5 text-xs"
                        >
                          <Copy size={13} />
                          <span className="ml-1.5">Endpoint</span>
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => testMutation.mutate(w.channel_uuid)}
                          disabled={cur !== null}
                          title="Read-only OAuth probe against Google Cloud."
                          className="h-8 px-2.5 text-xs"
                        >
                          {cur === "test" ? (
                            <span className="w-3 h-3 border-2 border-foreground/30 border-t-foreground rounded-full animate-spin" />
                          ) : (
                            <Activity size={13} />
                          )}
                          <span className="ml-1.5">Test</span>
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            if (
                              window.confirm(
                                `Stop GCP watch "${w.display_name}"?`,
                              )
                            ) {
                              stopMutation.mutate(w.channel_uuid);
                            }
                          }}
                          disabled={cur !== null}
                          className="h-8 px-2.5 text-xs text-destructive hover:text-destructive"
                        >
                          {cur === "stop" ? (
                            <span className="w-3 h-3 border-2 border-destructive/30 border-t-destructive rounded-full animate-spin" />
                          ) : (
                            <XCircle size={13} />
                          )}
                          <span className="ml-1.5">Stop</span>
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <CreateGcpWatchDialog
        integrations={integrations}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => qc.invalidateQueries({ queryKey: WATCHES_KEY })}
      />
    </div>
  );
}
