/**
 * Data layer for the Google Calendar watch-channels panel: REST
 * types, query keys, fetchers, and the queries + per-row mutations
 * hook. Built on React Query for seamless UX.
 */

import type { QueryKey } from "@tanstack/react-query";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import type { ApiResponse, RecentFailure } from "../watch-channels/api";
import { authedFetch } from "../watch-channels/api";

export interface WatchChannelSummary {
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
  recent_failure?: RecentFailure;
}

export interface IntegrationInfo {
  id: string;
  email: string | null;
  is_active: boolean;
}

export interface CalendarInfo {
  id: string;
  summary: string;
  primary?: boolean;
}

export interface TestResult {
  oauth_ok: boolean;
  calendar_still_accessible: boolean;
  calendars_visible: number;
  duration_ms: number;
  note: string;
}

export interface RenewResult {
  channel_uuid: string;
  google_channel_id: string;
  calendar_id: string;
  expiration: string;
}

export const CHANNELS_KEY: QueryKey = ["gcal", "watch-channels"];
export const INTEGRATIONS_KEY: QueryKey = ["gcal", "integrations"];

export function formatExpiration(iso: string): string {
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
  if (!body.success)
    throw new Error(body.error ?? "Failed to load watch channels");
  return body.data ?? [];
}

async function fetchIntegrations(): Promise<IntegrationInfo[]> {
  const res = await authedFetch("/api/google-calendar/integrations");
  if (res.status === 401) return [];
  const body: ApiResponse<IntegrationInfo[]> = await res.json();
  if (!body.success)
    throw new Error(body.error ?? "Failed to load integrations");
  return (body.data ?? []).filter((i) => i.is_active);
}

export type PendingAction = "renew" | "test" | "stop" | null;

/**
 * Queries + per-row mutations for the panel. `onFlash` fires after a
 * successful renew/test so the row can flash-highlight.
 */
export function useWatchChannels({
  onFlash,
}: {
  onFlash: (channelUuid: string) => void;
}) {
  const qc = useQueryClient();

  const channelsQuery = useQuery({
    queryKey: CHANNELS_KEY,
    queryFn: fetchChannels,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    staleTime: 10_000,
  });

  const integrationsQuery = useQuery({
    queryKey: INTEGRATIONS_KEY,
    queryFn: fetchIntegrations,
    staleTime: 60_000,
  });

  const renewMutation = useMutation({
    mutationFn: async (channelUuid: string): Promise<RenewResult> => {
      const res = await authedFetch(
        `/api/google-calendar/watch-channels/${channelUuid}/renew`,
        { method: "POST" },
      );
      const body: ApiResponse<RenewResult> = await res.json();
      if (!body.success || !body.data)
        throw new Error(body.error ?? "Renew failed");
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
                expiration: new Date(
                  Date.now() + 7 * 24 * 60 * 60 * 1000,
                ).toISOString(),
                updated_at: new Date().toISOString(),
              }
            : ch,
        ),
      );
      return { prev };
    },
    onError: (err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(CHANNELS_KEY, ctx.prev);
      toast.error(
        sanitizeErrorMessage(err instanceof Error ? err.message : String(err)),
      );
    },
    onSuccess: (data) => {
      onFlash(data.channel_uuid);
      toast.success(
        `Channel renewed — new Google channel ${data.google_channel_id.slice(0, 8)}…`,
      );
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
      if (!body.success || !body.data)
        throw new Error(body.error ?? "Test failed");
      return body.data;
    },
    onSuccess: (data, channelUuid) => {
      onFlash(channelUuid);
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
      toast.error(
        sanitizeErrorMessage(err instanceof Error ? err.message : String(err)),
      );
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
      toast.error(
        sanitizeErrorMessage(err instanceof Error ? err.message : String(err)),
      );
    },
    onSuccess: () => {
      toast.success("Channel stopped");
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: CHANNELS_KEY });
    },
  });

  const pendingFor = (channelUuid: string): PendingAction => {
    if (renewMutation.isPending && renewMutation.variables === channelUuid)
      return "renew";
    if (testMutation.isPending && testMutation.variables === channelUuid)
      return "test";
    if (stopMutation.isPending && stopMutation.variables === channelUuid)
      return "stop";
    return null;
  };

  return {
    channelsQuery,
    integrationsQuery,
    renewMutation,
    testMutation,
    stopMutation,
    pendingFor,
  };
}
