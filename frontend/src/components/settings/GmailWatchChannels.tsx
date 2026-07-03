/**
 * Gmail watch-channel panel. Mirrors GoogleCalendarWatchChannels but
 * with Gmail-specific fields: email_address, topic_name, history_id,
 * label_ids. Shares `RenewalFailure` shape and the OAuth-dead banner
 * treatment from gcal.
 *
 * Renders nothing when the user has no connected Gmail integration.
 * When integrated but no watch exists, shows an empty-state CTA.
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
  Mail,
  RefreshCw,
  Activity,
  XCircle,
  Plus,
  Check,
  AlertTriangle,
  KeyRound,
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

interface GmailWatchSummary {
  channel_uuid: string;
  integration_id: string;
  email_address: string;
  topic_name: string;
  history_id: number;
  label_ids: string[];
  expiration: string;
  module_id: string | null;
  module_name: string | null;
  updated_at: string;
  recent_failure?: {
    error_message: string;
    failed_at: string;
    likely_oauth_failure: boolean;
  };
}

interface GmailIntegrationInfo {
  id: string;
  email_address: string;
  is_active: boolean;
}

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

const WATCHES_KEY: QueryKey = ["gmail", "watch-channels"];
const INTEGRATIONS_KEY: QueryKey = ["gmail", "integrations"];

function formatExpiration(iso: string): string {
  const now = Date.now();
  const when = new Date(iso).getTime();
  const diff = when - now;
  const d = Math.floor(diff / 86_400_000);
  const h = Math.floor((diff % 86_400_000) / 3_600_000);
  if (diff < 0) return "expired";
  if (d > 1) return `in ${d}d ${h}h`;
  if (d === 1) return `in 1d ${h}h`;
  if (h > 0) return `in ${h}h`;
  return "< 1h";
}

async function fetchWatches(): Promise<GmailWatchSummary[]> {
  const res = await authedFetch("/api/gmail/watch-channels");
  if (res.status === 401 || res.status === 404) return [];
  const body: ApiResponse<GmailWatchSummary[]> = await res.json();
  if (!body.success)
    throw new Error(body.error ?? "Failed to load gmail watches");
  return body.data ?? [];
}

async function fetchGmailIntegrations(): Promise<GmailIntegrationInfo[]> {
  const res = await authedFetch("/api/gmail/integrations");
  if (res.status === 401) return [];
  const body: ApiResponse<GmailIntegrationInfo[]> = await res.json();
  if (!body.success)
    throw new Error(body.error ?? "Failed to load gmail integrations");
  return (body.data ?? []).filter((i) => i.is_active);
}

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateGmailWatchDialog({
  integrations,
  existingWatches,
  open,
  onClose,
  onCreated,
}: {
  integrations: GmailIntegrationInfo[];
  existingWatches: GmailWatchSummary[];
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}): React.ReactElement {
  const qc = useQueryClient();
  const [integrationId, setIntegrationId] = useState<string>(
    integrations[0]?.id ?? "",
  );
  const [labels, setLabels] = useState<string>("INBOX");
  const [submitting, setSubmitting] = useState(false);
  const watchesFetching = useIsFetching({ queryKey: WATCHES_KEY }) > 0;

  // Default the select to the first integration once the list loads
  // after mount (it may be empty on first render). Done during render via
  // the "store information from previous renders" pattern
  // (https://react.dev/learn/you-might-not-need-an-effect) instead of a
  // setState-in-effect; the `!integrationId` guard means a user choice is
  // never overridden.
  const [lastIntegrations, setLastIntegrations] = useState(integrations);
  if (integrations !== lastIntegrations) {
    setLastIntegrations(integrations);
    if (!integrationId && integrations[0]) setIntegrationId(integrations[0].id);
  }

  useEffect(() => {
    if (open) qc.invalidateQueries({ queryKey: WATCHES_KEY });
  }, [open, qc]);

  const integrationAlreadyWatched = existingWatches.some(
    (w) => w.integration_id === integrationId,
  );

  const handleSubmit = async () => {
    if (!integrationId || integrationAlreadyWatched) return;
    setSubmitting(true);
    try {
      const label_ids = labels
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const res = await authedFetch("/api/gmail/watch-channels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          integration_id: integrationId,
          label_ids: label_ids.length > 0 ? label_ids : null,
        }),
      });
      const body: ApiResponse<Record<string, unknown>> = await res.json();
      if (!body.success) {
        toast.error(sanitizeErrorMessage(body.error ?? "Create failed"));
        return;
      }
      toast.success("Gmail watch created");
      await qc.invalidateQueries({ queryKey: WATCHES_KEY });
      onCreated();
      onClose();
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
      onClose={() => !submitting && onClose()}
      title="Create Gmail watch"
    >
      <div className="space-y-5">
        <div>
          <label className="block text-xs font-semibold text-muted-foreground mb-2">
            Gmail account
          </label>
          <select
            value={integrationId}
            onChange={(e) => setIntegrationId(e.target.value)}
            disabled={submitting || integrations.length === 0}
            className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
          >
            {integrations.map((i) => (
              <option key={i.id} value={i.id}>
                {i.email_address}
              </option>
            ))}
          </select>
          {integrationAlreadyWatched && (
            <p className="text-[11px] text-warning mt-2">
              This account already has an active watch. Stop the existing one
              first if you want to re-create.
            </p>
          )}
        </div>

        <div>
          <label className="block text-xs font-semibold text-muted-foreground mb-2">
            Label IDs (comma-separated)
          </label>
          <input
            type="text"
            value={labels}
            onChange={(e) => setLabels(e.target.value)}
            disabled={submitting}
            placeholder="INBOX, IMPORTANT"
            className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
          />
          <p className="text-[11px] text-muted-foreground mt-1.5">
            Gmail only publishes pushes for messages matching these labels.
            Leave as <code>INBOX</code> for standard inbox-arrives-trigger
            behavior. Use <code>STARRED</code> / <code>IMPORTANT</code> for
            narrower filters.
          </p>
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <Button
            variant="outline"
            onClick={onClose}
            disabled={submitting}
            className="h-10 px-5 text-xs font-bold"
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={
              submitting ||
              integrationAlreadyWatched ||
              watchesFetching ||
              !integrationId
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
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function GmailWatchChannels(): React.ReactElement | null {
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
    queryFn: fetchGmailIntegrations,
    staleTime: 60_000,
  });
  const integrations = integrationsQuery.data ?? [];

  // MCP-893 (2026-05-14): sibling to the GoogleCalendarWatchChannels
  // fix — track flash timers in a ref so unmount cancels them and
  // setState doesn't fire on an unmounted component.
  const flashTimersRef = React.useRef<Set<number>>(new Set());
  React.useEffect(() => {
    return () => {
      flashTimersRef.current.forEach(clearTimeout);
      flashTimersRef.current.clear();
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

  const renewMutation = useMutation({
    mutationFn: async (ch: string) => {
      const res = await authedFetch(`/api/gmail/watch-channels/${ch}/renew`, {
        method: "POST",
      });
      const body: ApiResponse<{ channel_uuid: string; expiration_ms: number }> =
        await res.json();
      if (!body.success || !body.data)
        throw new Error(body.error ?? "Renew failed");
      return body.data;
    },
    onMutate: async (ch) => {
      await qc.cancelQueries({ queryKey: WATCHES_KEY });
      const prev = qc.getQueryData<GmailWatchSummary[]>(WATCHES_KEY);
      qc.setQueryData<GmailWatchSummary[]>(WATCHES_KEY, (old) =>
        (old ?? []).map((w) =>
          w.channel_uuid === ch
            ? {
                ...w,
                expiration: new Date(Date.now() + 7 * 86_400_000).toISOString(),
                updated_at: new Date().toISOString(),
              }
            : w,
        ),
      );
      return { prev };
    },
    onError: (err, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(WATCHES_KEY, ctx.prev);
      toast.error(
        sanitizeErrorMessage(err instanceof Error ? err.message : String(err)),
      );
    },
    onSuccess: (data) => {
      triggerFlash(data.channel_uuid);
      toast.success("Gmail watch renewed");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: WATCHES_KEY }),
  });

  const testMutation = useMutation({
    mutationFn: async (ch: string) => {
      const res = await authedFetch(`/api/gmail/watch-channels/${ch}/test`, {
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
        toast.success(`OAuth OK — Gmail responded in ${data.duration_ms} ms`);
      } else {
        toast.error("Gmail probe failed");
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
      const res = await authedFetch(`/api/gmail/watch-channels/${ch}`, {
        method: "DELETE",
      });
      const body: ApiResponse<string> = await res.json();
      if (!body.success) throw new Error(body.error ?? "Stop failed");
    },
    onMutate: async (ch) => {
      await qc.cancelQueries({ queryKey: WATCHES_KEY });
      const prev = qc.getQueryData<GmailWatchSummary[]>(WATCHES_KEY);
      qc.setQueryData<GmailWatchSummary[]>(WATCHES_KEY, (old) =>
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

  const pendingFor = (ch: string): "renew" | "test" | "stop" | null => {
    if (renewMutation.isPending && renewMutation.variables === ch)
      return "renew";
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
        Loading Gmail watch channels…
      </div>
    );
  }
  if (integrations.length === 0) return null;

  if (watchesQuery.isError) {
    return (
      <div className="mt-10 p-6 bg-destructive/5 border border-destructive/20 rounded-2xl">
        <p className="text-sm font-semibold text-foreground mb-1">
          Could not load Gmail watches
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
          <Mail size={16} />
        </div>
        <div>
          <h3 className="text-sm font-bold text-foreground">
            Gmail Watch Channels
          </h3>
          <p className="text-xs text-muted-foreground">
            {watches.length === 0
              ? "None active — create one to receive push notifications on new email"
              : `${watches.length} active · rotated automatically every 7 days`}
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
              Reconnect your Gmail account
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed mb-3">
              One or more Gmail watches are failing to renew because the OAuth
              credentials for{" "}
              {oauthFailingIntegrationIds.size === 1
                ? "this account have"
                : `${oauthFailingIntegrationIds.size} accounts have`}{" "}
              expired or been revoked. Push notifications will stop at Google's
              7-day expiry if not reconnected.
            </p>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const el = document.querySelector('[data-provider-id="gmail"]');
                if (el instanceof HTMLElement) {
                  el.scrollIntoView({ behavior: "smooth", block: "center" });
                } else {
                  window.scrollTo({ top: 0, behavior: "smooth" });
                }
              }}
              className="h-8 px-3 text-xs font-bold"
            >
              Go to Gmail provider card ↑
            </Button>
          </div>
        </div>
      )}

      {watches.length === 0 ? (
        <div className="border border-dashed border-border/60 rounded-2xl p-8 text-center">
          <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-primary/5 border border-primary/20 flex items-center justify-center text-primary">
            <Mail size={20} />
          </div>
          <p className="text-sm font-semibold text-foreground mb-1">
            No Gmail watches yet
          </p>
          <p className="text-xs text-muted-foreground max-w-md mx-auto mb-5">
            A Gmail watch receives real-time push notifications via Google Cloud
            Pub/Sub whenever a matching message arrives. Bind one to a WASM
            module in the workflow builder to run automations on every email.
          </p>
          <Button
            onClick={() => setCreateOpen(true)}
            className="h-9 px-5 text-xs font-bold"
          >
            <Plus size={13} className="mr-1.5" /> Create your first Gmail watch
          </Button>
        </div>
      ) : (
        <div className="border border-border/40 rounded-2xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-xs text-muted-foreground">
              <tr>
                <th className="text-left px-4 py-2.5 font-semibold">Account</th>
                <th className="text-left px-4 py-2.5 font-semibold">Labels</th>
                <th className="text-left px-4 py-2.5 font-semibold">Module</th>
                <th className="text-left px-4 py-2.5 font-semibold">Expires</th>
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
                        {w.email_address}
                      </div>
                      <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                        historyId {w.history_id}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {w.label_ids.length === 0 ? (
                        <span className="text-muted-foreground italic">
                          all
                        </span>
                      ) : (
                        w.label_ids.join(", ")
                      )}
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
                      {formatExpiration(w.expiration)}
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
                            renewal failing
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => testMutation.mutate(w.channel_uuid)}
                          disabled={cur !== null}
                          title="Read-only OAuth probe against Gmail."
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
                          onClick={() => renewMutation.mutate(w.channel_uuid)}
                          disabled={cur !== null}
                          className="h-8 px-2.5 text-xs"
                        >
                          {cur === "renew" ? (
                            <span className="w-3 h-3 border-2 border-foreground/30 border-t-foreground rounded-full animate-spin" />
                          ) : (
                            <RefreshCw size={13} />
                          )}
                          <span className="ml-1.5">Renew</span>
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            if (
                              window.confirm(
                                `Stop Gmail watch for ${w.email_address}?`,
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

      <CreateGmailWatchDialog
        integrations={integrations}
        existingWatches={watches}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => qc.invalidateQueries({ queryKey: WATCHES_KEY })}
      />
    </div>
  );
}
