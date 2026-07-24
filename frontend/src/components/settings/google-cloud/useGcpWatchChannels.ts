/**
 * Data layer for the Google Cloud watch-channel panel: REST types,
 * query keys, fetchers, and the queries + per-row mutations hook.
 *
 * Unlike Google Calendar there is NO renew action — the user owns the
 * upstream Pub/Sub subscription, so nothing on our side expires.
 */

import type { QueryKey } from "@tanstack/react-query";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import type { ApiResponse, RecentFailure } from "../watch-channels/api";
import { authedFetch } from "../watch-channels/api";

export interface GcpWatchSummary {
  channel_uuid: string;
  integration_id: string;
  display_name: string;
  expected_sa_email: string;
  push_endpoint: string;
  module_id: string | null;
  module_name: string | null;
  last_push_received?: string;
  created_at: string;
  recent_failure?: RecentFailure;
}

export interface GcpIntegrationInfo {
  id: string;
  account_email: string | null;
  is_active: boolean;
  // Consent tier — `'read'` (default), `'write'` (Phase C provisioning), or
  // `'full'` (Phase D impersonation base: broad cloud-platform, host-reserved).
  // The same Google account can hold a row for each tier simultaneously.
  tier: string;
}

export const WATCHES_KEY: QueryKey = ["gcp", "watch-channels"];
export const INTEGRATIONS_KEY: QueryKey = ["gcp", "integrations"];

export function formatRelative(iso?: string): string {
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

export async function copyToClipboard(text: string): Promise<void> {
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

export type GcpPendingAction = "test" | "stop" | null;

/**
 * Queries + per-row mutations for the panel. `onFlash` fires after a
 * successful test so the row can flash-highlight.
 */
export function useGcpWatchChannels({
  onFlash,
}: {
  onFlash: (channelUuid: string) => void;
}) {
  const qc = useQueryClient();

  const watchesQuery = useQuery({
    queryKey: WATCHES_KEY,
    queryFn: fetchWatches,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    staleTime: 10_000,
  });

  const integrationsQuery = useQuery({
    queryKey: INTEGRATIONS_KEY,
    queryFn: fetchGcpIntegrations,
    staleTime: 60_000,
  });

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
      onFlash(ch);
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

  const pendingFor = (ch: string): GcpPendingAction => {
    if (testMutation.isPending && testMutation.variables === ch) return "test";
    if (stopMutation.isPending && stopMutation.variables === ch) return "stop";
    return null;
  };

  return {
    watchesQuery,
    integrationsQuery,
    testMutation,
    stopMutation,
    pendingFor,
  };
}
