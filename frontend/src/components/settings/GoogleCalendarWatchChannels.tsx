/**
 * Watch-channels panel for the settings page.
 *
 * Surfaces every active Google Calendar watch channel the signed-in
 * user has, with per-row actions for the three diagnostic operations
 * the backend exposes. Built on React Query for seamless UX.
 *
 * Empty state:
 *   - If the user has at least one connected gcal integration but no
 *     active watch channels, we render an empty state with a CTA to
 *     open the create-channel dialog.
 *   - If the user has no gcal integrations at all, we render
 *     nothing — the "Connect" card elsewhere on the page is the
 *     right entry point for that flow.
 *
 * Create flow:
 *   - Dialog lets the user pick an integration, lists their
 *     calendars fetched live from Google, and creates a watch per
 *     selected calendar. Channel creation invalidates the list
 *     query so the new rows appear immediately.
 *
 * Per-row actions:
 *   - Test   — read-only OAuth probe (no state change)
 *   - Renew  — forces rotation, with optimistic expiration bump
 *   - Stop   — tears down + removes row, with optimistic removal
 */

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  useQuery,
  useMutation,
  useQueryClient,
  useIsFetching,
  QueryKey,
} from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Calendar as CalendarIcon,
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

interface WatchChannelSummary {
  channel_uuid: string;
  integration_id: string;
  calendar_id: string;
  google_channel_id: string;
  webhook_url: string;
  expiration: string;
  has_sync_token: boolean;
  module_id: string | null;
  module_name: string | null;
  last_message_number: number;
  updated_at: string;
  // Present iff the most recent renewal attempt failed. The
  // backend omits the field via serde's skip_serializing_if, so
  // undefined is the common case.
  recent_failure?: {
    error_message: string;
    failed_at: string;
    likely_oauth_failure: boolean;
  };
}

interface IntegrationInfo {
  id: string;
  email: string | null;
  is_active: boolean;
}

interface CalendarInfo {
  id: string;
  summary: string;
  primary?: boolean;
}

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

interface TestResult {
  oauth_ok: boolean;
  calendar_still_accessible: boolean;
  calendars_visible: number;
  duration_ms: number;
  note: string;
}

interface RenewResult {
  channel_uuid: string;
  google_channel_id: string;
  calendar_id: string;
  expiration: string;
}

const CHANNELS_KEY: QueryKey = ["gcal", "watch-channels"];
const INTEGRATIONS_KEY: QueryKey = ["gcal", "integrations"];

function formatExpiration(iso: string): string {
  const now = Date.now();
  const when = new Date(iso).getTime();
  const diffMs = when - now;
  const days = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  const hours = Math.floor((diffMs % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
  if (diffMs < 0) return "expired";
  if (days > 1) return `in ${days}d ${hours}h`;
  if (days === 1) return `in 1d ${hours}h`;
  if (hours > 0) return `in ${hours}h`;
  return "< 1h";
}

async function fetchChannels(): Promise<WatchChannelSummary[]> {
  const res = await authedFetch("/api/google-calendar/watch-channels");
  if (res.status === 401) return [];
  const body: ApiResponse<WatchChannelSummary[]> = await res.json();
  if (!body.success) throw new Error(body.error ?? "Failed to load watch channels");
  return body.data ?? [];
}

async function fetchIntegrations(): Promise<IntegrationInfo[]> {
  const res = await authedFetch("/api/google-calendar/integrations");
  if (res.status === 401) return [];
  const body: ApiResponse<IntegrationInfo[]> = await res.json();
  if (!body.success) throw new Error(body.error ?? "Failed to load integrations");
  return (body.data ?? []).filter((i) => i.is_active);
}

// ---------------------------------------------------------------------------
// Create-channel dialog — lists calendars for the chosen integration,
// submits one POST /watch/create per selected calendar.
// ---------------------------------------------------------------------------

function CreateChannelDialog({
  integrations,
  existingChannels,
  open,
  onClose,
  onCreated,
}: {
  integrations: IntegrationInfo[];
  existingChannels: WatchChannelSummary[];
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}): React.ReactElement {
  const qc = useQueryClient();
  const [integrationId, setIntegrationId] = useState<string>(
    integrations[0]?.id ?? "",
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  // True while a post-submit refetch of the channel list is in-
  // flight. The Submit button stays disabled until it resolves so a
  // rapid second click can't create a duplicate — the fresh
  // `existingChannels` snapshot will have the newly-created row and
  // the "already watched" disable kicks in.
  const channelsFetching = useIsFetching({ queryKey: CHANNELS_KEY }) > 0;

  // Keep the integration select in sync if the first integration
  // changes between renders (e.g. the list loaded after mount).
  useEffect(() => {
    if (!integrationId && integrations[0]) {
      setIntegrationId(integrations[0].id);
    }
  }, [integrations, integrationId]);

  // Every time the dialog opens, force-refetch the channel list so
  // `existingChannels` reflects any creations that happened outside
  // this dialog (e.g. a previous dialog session, another tab, the
  // workflow builder's auto-setup). Without this, the "already
  // watched" set is whatever the last query returned, which may be
  // stale by several refetch cycles.
  useEffect(() => {
    if (open) {
      qc.invalidateQueries({ queryKey: CHANNELS_KEY });
    }
  }, [open, qc]);

  // Fetch calendars for the chosen integration. Paused until a
  // real integration is picked.
  const calendarsQuery = useQuery({
    queryKey: ["gcal", "integration-calendars", integrationId],
    queryFn: async (): Promise<CalendarInfo[]> => {
      const res = await authedFetch(
        `/api/google-calendar/integrations/${integrationId}/calendars`,
      );
      const body: ApiResponse<CalendarInfo[]> = await res.json();
      if (!body.success) throw new Error(body.error ?? "Failed to load calendars");
      return body.data ?? [];
    },
    enabled: open && !!integrationId,
    staleTime: 30_000,
  });

  // Disable already-watched calendars for the selected integration
  // so the user can't accidentally double-subscribe.
  const alreadyWatched = useMemo(
    () =>
      new Set(
        existingChannels
          .filter((c) => c.integration_id === integrationId)
          .map((c) => c.calendar_id),
      ),
    [existingChannels, integrationId],
  );

  const toggle = (calId: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(calId) ? next.delete(calId) : next.add(calId);
      return next;
    });
  };

  const handleSubmit = async () => {
    if (!integrationId || selected.size === 0) return;
    setSubmitting(true);
    let created = 0;
    let failed = 0;
    for (const calId of selected) {
      try {
        const res = await authedFetch(
          "/api/google-calendar/watch/create",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              integration_id: integrationId,
              calendar_id: calId,
            }),
          },
        );
        const body: ApiResponse<Record<string, unknown>> = await res.json();
        if (body.success) created++;
        else {
          failed++;
          toast.error(
            sanitizeErrorMessage(
              `${calId}: ${body.error ?? "create failed"}`,
            ),
          );
        }
      } catch (e) {
        failed++;
        toast.error(
          sanitizeErrorMessage(
            `${calId}: ${e instanceof Error ? e.message : String(e)}`,
          ),
        );
      }
    }
    if (created > 0) {
      toast.success(
        `Created ${created} watch channel${created === 1 ? "" : "s"}`,
      );
      // Wait for the fresh channel list to arrive BEFORE releasing
      // the submit guard. Otherwise a rapid second click would
      // submit against stale `existingChannels` (our own freshly-
      // created row not yet visible), bypassing the "already
      // watched" disable and producing a duplicate Google channel.
      //
      // `invalidateQueries` returns a promise that resolves after
      // all triggered refetches complete, so a separate
      // `refetchQueries` call would be redundant work.
      await qc.invalidateQueries({ queryKey: CHANNELS_KEY });
      onCreated();
    }
    setSubmitting(false);
    if (failed === 0) {
      setSelected(new Set());
      onClose();
    }
  };

  // Only calendars with at least read access can be watched; Google
  // returns accessRole but we're lenient here — the backend rejects
  // if permissions are insufficient.
  const availableCount = (calendarsQuery.data ?? []).filter(
    (c) => !alreadyWatched.has(c.id),
  ).length;

  return (
    <Dialog open={open} onClose={() => !submitting && onClose()} title="Create watch channel">
      <div className="space-y-5">
        <div>
          <label className="block text-xs font-semibold text-muted-foreground mb-2">
            Google Calendar account
          </label>
          <select
            value={integrationId}
            onChange={(e) => {
              setIntegrationId(e.target.value);
              setSelected(new Set());
            }}
            disabled={submitting || integrations.length === 0}
            className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
          >
            {integrations.map((i) => (
              <option key={i.id} value={i.id}>
                {i.email ?? i.id}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-semibold text-muted-foreground mb-2">
            Calendars to watch
          </label>
          {calendarsQuery.isLoading ? (
            <div className="text-xs text-muted-foreground py-4">
              Loading calendars…
            </div>
          ) : calendarsQuery.isError ? (
            <div className="text-xs text-destructive py-4">
              Could not load calendars.
            </div>
          ) : availableCount === 0 ? (
            <div className="text-xs text-muted-foreground py-4">
              All calendars on this account already have active watch channels.
            </div>
          ) : (
            <div className="max-h-56 overflow-y-auto border border-border/40 rounded-lg divide-y divide-border/30">
              {(calendarsQuery.data ?? []).map((c) => {
                const already = alreadyWatched.has(c.id);
                const isChecked = selected.has(c.id);
                return (
                  <label
                    key={c.id}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2.5 text-sm cursor-pointer",
                      already ? "opacity-50 cursor-not-allowed" : "hover:bg-muted/20",
                    )}
                  >
                    <input
                      type="checkbox"
                      disabled={already || submitting}
                      checked={isChecked}
                      onChange={() => toggle(c.id)}
                      className="w-4 h-4"
                    />
                    <span className="flex-1 truncate">
                      {c.summary}
                      {c.primary && (
                        <span className="ml-2 text-[10px] font-bold text-primary">
                          PRIMARY
                        </span>
                      )}
                    </span>
                    {already && (
                      <span className="text-[10px] text-muted-foreground italic">
                        already watched
                      </span>
                    )}
                  </label>
                );
              })}
            </div>
          )}
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
            // Disabled when:
            //   - already submitting (one POST still in-flight)
            //   - nothing selected
            //   - the channel list is refetching, so `alreadyWatched`
            //     isn't trustworthy yet. This closes the double-
            //     submit window that earlier let one user create two
            //     Google-side channels for the same calendar.
            disabled={
              submitting || selected.size === 0 || channelsFetching
            }
            className="h-10 px-6 text-xs font-bold"
          >
            {submitting ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2" />
                Creating…
              </>
            ) : channelsFetching ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-foreground/30 border-t-foreground rounded-full animate-spin mr-2" />
                Syncing…
              </>
            ) : (
              <>
                <Check size={13} className="mr-1.5" />
                Create {selected.size} watch{selected.size === 1 ? "" : "es"}
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

export function GoogleCalendarWatchChannels(): React.ReactElement | null {
  const qc = useQueryClient();
  const [flashedAt, setFlashedAt] = useState<Record<string, number>>({});
  const [createOpen, setCreateOpen] = useState(false);

  const channelsQuery = useQuery({
    queryKey: CHANNELS_KEY,
    queryFn: fetchChannels,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    staleTime: 10_000,
  });
  const channels = channelsQuery.data ?? [];

  const integrationsQuery = useQuery({
    queryKey: INTEGRATIONS_KEY,
    queryFn: fetchIntegrations,
    staleTime: 60_000,
  });
  const integrations = integrationsQuery.data ?? [];

  // MCP-893 (2026-05-14): track flash timers in a ref so unmount can
  // cancel them. Pre-fix `window.setTimeout(...)` was orphaned — if
  // the user navigated away within the 1.6s flash window, the
  // setState fired on an unmounted component, producing React
  // strict-mode warnings and (in dev) leaked closure references.
  const flashTimersRef = useRef<Set<number>>(new Set());
  useEffect(() => {
    return () => {
      flashTimersRef.current.forEach(clearTimeout);
      flashTimersRef.current.clear();
    };
  }, []);
  const triggerFlash = (channelUuid: string) => {
    const now = Date.now();
    setFlashedAt((prev) => ({ ...prev, [channelUuid]: now }));
    const timer = window.setTimeout(() => {
      flashTimersRef.current.delete(timer);
      setFlashedAt((prev) => {
        if (prev[channelUuid] !== now) return prev;
        const next = { ...prev };
        delete next[channelUuid];
        return next;
      });
    }, 1600);
    flashTimersRef.current.add(timer);
  };

  const renewMutation = useMutation({
    mutationFn: async (channelUuid: string): Promise<RenewResult> => {
      const res = await authedFetch(
        `/api/google-calendar/watch-channels/${channelUuid}/renew`,
        { method: "POST" },
      );
      const body: ApiResponse<RenewResult> = await res.json();
      if (!body.success || !body.data) throw new Error(body.error ?? "Renew failed");
      return body.data;
    },
    onMutate: async (channelUuid) => {
      await qc.cancelQueries({ queryKey: CHANNELS_KEY });
      const prev = qc.getQueryData<WatchChannelSummary[]>(CHANNELS_KEY);
      qc.setQueryData<WatchChannelSummary[]>(CHANNELS_KEY, (old) =>
        (old ?? []).map((ch) =>
          ch.channel_uuid === channelUuid
            ? {
                ...ch,
                expiration: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
                updated_at: new Date().toISOString(),
              }
            : ch,
        ),
      );
      return { prev };
    },
    onError: (err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(CHANNELS_KEY, ctx.prev);
      toast.error(sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    },
    onSuccess: (data) => {
      triggerFlash(data.channel_uuid);
      toast.success(`Channel renewed — new Google channel ${data.google_channel_id.slice(0, 8)}…`);
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: CHANNELS_KEY });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (channelUuid: string): Promise<TestResult> => {
      const res = await authedFetch(
        `/api/google-calendar/watch-channels/${channelUuid}/test`,
        { method: "POST" },
      );
      const body: ApiResponse<TestResult> = await res.json();
      if (!body.success || !body.data) throw new Error(body.error ?? "Test failed");
      return body.data;
    },
    onSuccess: (data, channelUuid) => {
      triggerFlash(channelUuid);
      if (data.oauth_ok && data.calendar_still_accessible) {
        toast.success(
          `OAuth OK — ${data.calendars_visible} calendar${data.calendars_visible === 1 ? "" : "s"} visible (${data.duration_ms} ms)`,
        );
      } else if (data.oauth_ok && !data.calendar_still_accessible) {
        toast.warning(
          `OAuth OK but target calendar no longer visible to this account — ${data.calendars_visible} others visible`,
        );
      } else {
        toast.error("Channel probe failed");
      }
    },
    onError: (err) => {
      toast.error(sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    },
  });

  const stopMutation = useMutation({
    mutationFn: async (channelUuid: string): Promise<void> => {
      const res = await authedFetch(
        `/api/google-calendar/watch-channels/${channelUuid}`,
        { method: "DELETE" },
      );
      const body: ApiResponse<string> = await res.json();
      if (!body.success) throw new Error(body.error ?? "Stop failed");
    },
    onMutate: async (channelUuid) => {
      await qc.cancelQueries({ queryKey: CHANNELS_KEY });
      const prev = qc.getQueryData<WatchChannelSummary[]>(CHANNELS_KEY);
      qc.setQueryData<WatchChannelSummary[]>(CHANNELS_KEY, (old) =>
        (old ?? []).filter((ch) => ch.channel_uuid !== channelUuid),
      );
      return { prev };
    },
    onError: (err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(CHANNELS_KEY, ctx.prev);
      toast.error(sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
    },
    onSuccess: () => {
      toast.success("Channel stopped");
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: CHANNELS_KEY });
    },
  });

  const pendingFor = (channelUuid: string): "renew" | "test" | "stop" | null => {
    if (renewMutation.isPending && renewMutation.variables === channelUuid) return "renew";
    if (testMutation.isPending && testMutation.variables === channelUuid) return "test";
    if (stopMutation.isPending && stopMutation.variables === channelUuid) return "stop";
    return null;
  };

  // Integration health summary — if ANY channel has an OAuth-shaped
  // recent failure, surface a single banner at the top with a
  // Reconnect affordance. Channels with non-OAuth failures get the
  // per-row badge only; the banner is specifically for the
  // "refresh token died, reconnect to recover" case.
  const oauthFailingIntegrationIds = new Set(
    channels
      .filter((c) => c.recent_failure?.likely_oauth_failure)
      .map((c) => c.integration_id),
  );
  const hasAnyOauthFailure = oauthFailingIntegrationIds.size > 0;

  // Hide entirely if the user has no gcal integration connected —
  // the "Connect" card above is the right entry point for that flow.
  if (integrationsQuery.isLoading || channelsQuery.isLoading) {
    return (
      <div className="mt-10 p-6 bg-muted/10 border border-border/30 rounded-2xl text-sm text-muted-foreground">
        Loading Google Calendar watch channels…
      </div>
    );
  }
  if (integrations.length === 0) {
    return null;
  }

  if (channelsQuery.isError) {
    return (
      <div className="mt-10 p-6 bg-destructive/5 border border-destructive/20 rounded-2xl">
        <p className="text-sm font-semibold text-foreground mb-1">
          Could not load watch channels
        </p>
        <p className="text-xs text-muted-foreground mb-3">
          The server returned an error. Retry now or wait for the next automatic refresh.
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => channelsQuery.refetch()}
          className="h-8 px-3 text-xs"
        >
          <RefreshCw size={13} className="mr-1.5" /> Retry
        </Button>
      </div>
    );
  }

  // ---- Header (same for empty + populated state) -------------------
  const header = (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 text-primary flex items-center justify-center">
          <CalendarIcon size={16} />
        </div>
        <div>
          <h3 className="text-sm font-bold text-foreground">
            Google Calendar Watch Channels
          </h3>
          <p className="text-xs text-muted-foreground">
            {channels.length === 0
              ? "None active — create one to receive push notifications on calendar changes"
              : `${channels.length} active · rotated automatically every 7 days`}
            {channelsQuery.isFetching && !channelsQuery.isLoading && (
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
          onClick={() => channelsQuery.refetch()}
          disabled={channelsQuery.isFetching}
          className="h-8 px-3 text-xs"
        >
          <RefreshCw
            size={13}
            className={cn("mr-1.5", channelsQuery.isFetching && "animate-spin")}
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
              Reconnect your Google Calendar
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed mb-3">
              One or more watch channels are failing to renew because the
              OAuth credentials for{" "}
              {oauthFailingIntegrationIds.size === 1
                ? "this account have"
                : `${oauthFailingIntegrationIds.size} accounts have`}{" "}
              expired or been revoked. New calendar events won't dispatch to
              your modules until you reconnect. Existing channels will die at
              Google's 7-day expiry if left unreconnected.
            </p>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                // Scroll up to the provider cards — the "Connect"
                // button for Google Calendar is there. We don't
                // programmatically launch the OAuth flow because
                // the existing provider-card path handles
                // state-token CSRF + redirect sequencing.
                const el = document.querySelector(
                  "[data-provider-id=\"google-calendar\"]",
                );
                if (el instanceof HTMLElement) {
                  el.scrollIntoView({ behavior: "smooth", block: "center" });
                } else {
                  window.scrollTo({ top: 0, behavior: "smooth" });
                }
              }}
              className="h-8 px-3 text-xs font-bold"
            >
              Go to Google Calendar provider card ↑
            </Button>
          </div>
        </div>
      )}

      {channels.length === 0 ? (
        <div className="border border-dashed border-border/60 rounded-2xl p-8 text-center">
          <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-primary/5 border border-primary/20 flex items-center justify-center text-primary">
            <CalendarIcon size={20} />
          </div>
          <p className="text-sm font-semibold text-foreground mb-1">
            No watch channels yet
          </p>
          <p className="text-xs text-muted-foreground max-w-md mx-auto mb-5">
            A watch channel lets Talos receive real-time push notifications
            when events change on a calendar. Bind one to a WASM module (via
            the workflow builder) to dispatch jobs per event, or leave it
            unbound to keep the sync token fresh for other integrations.
          </p>
          <Button
            onClick={() => setCreateOpen(true)}
            className="h-9 px-5 text-xs font-bold"
          >
            <Plus size={13} className="mr-1.5" />
            Create your first watch channel
          </Button>
        </div>
      ) : (
        <div className="border border-border/40 rounded-2xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-xs text-muted-foreground">
              <tr>
                <th className="text-left px-4 py-2.5 font-semibold">Calendar</th>
                <th className="text-left px-4 py-2.5 font-semibold">Module</th>
                <th className="text-left px-4 py-2.5 font-semibold">Expires</th>
                <th className="text-left px-4 py-2.5 font-semibold">Status</th>
                <th className="text-right px-4 py-2.5 font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {channels.map((ch) => {
                const currentAction = pendingFor(ch.channel_uuid);
                const flashing = flashedAt[ch.channel_uuid] !== undefined;
                const rowDim = currentAction !== null;
                return (
                  <tr
                    key={ch.channel_uuid}
                    className={cn(
                      "border-t border-border/30 transition-premium duration-700",
                      flashing && "bg-primary/5",
                      rowDim && "opacity-60",
                      !flashing && !rowDim && "hover:bg-muted/20",
                    )}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-foreground">{ch.calendar_id}</div>
                      <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                        {ch.google_channel_id.slice(0, 12)}…
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {ch.module_name ? (
                        <span className="text-foreground">{ch.module_name}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground italic">
                          (no module bound — sync only)
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-foreground">
                      {formatExpiration(ch.expiration)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1 items-start">
                        {ch.has_sync_token ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                            synced
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/20">
                            pending first sync
                          </span>
                        )}
                        {ch.recent_failure && (
                          <span
                            className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-destructive/10 text-destructive border border-destructive/20"
                            title={`${ch.recent_failure.error_message}\n\nFailed at: ${new Date(ch.recent_failure.failed_at).toLocaleString()}`}
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
                          onClick={() => testMutation.mutate(ch.channel_uuid)}
                          disabled={currentAction !== null}
                          title="Read-only probe: verifies OAuth + permissions against Google. No state changes."
                          className="h-8 px-2.5 text-xs"
                        >
                          {currentAction === "test" ? (
                            <span className="w-3 h-3 border-2 border-foreground/30 border-t-foreground rounded-full animate-spin" />
                          ) : (
                            <Activity size={13} />
                          )}
                          <span className="ml-1.5">Test</span>
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => renewMutation.mutate(ch.channel_uuid)}
                          disabled={currentAction !== null}
                          title="Rotates the channel now instead of waiting for the hourly scheduler."
                          className="h-8 px-2.5 text-xs"
                        >
                          {currentAction === "renew" ? (
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
                                `Stop watch channel for ${ch.calendar_id}? Any module bound to this channel will stop receiving webhook events until you recreate it.`,
                              )
                            ) {
                              stopMutation.mutate(ch.channel_uuid);
                            }
                          }}
                          disabled={currentAction !== null}
                          title="Tears down the channel on Google's side and removes the row."
                          className="h-8 px-2.5 text-xs text-destructive hover:text-destructive"
                        >
                          {currentAction === "stop" ? (
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

      <CreateChannelDialog
        integrations={integrations}
        existingChannels={channels}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => qc.invalidateQueries({ queryKey: CHANNELS_KEY })}
      />
    </div>
  );
}
