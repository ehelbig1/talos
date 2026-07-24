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
 * Decomposed (2026-07): data layer in google-calendar/useWatchChannels,
 * dialog in google-calendar/CreateChannelDialog, table in
 * google-calendar/ChannelTable, shared chrome in watch-channels/.
 */

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Calendar as CalendarIcon } from "lucide-react";
import { useRowFlash } from "./watch-channels/useRowFlash";
import {
  WatchPanelEmptyState,
  WatchPanelError,
  WatchPanelHeader,
  WatchPanelLoading,
} from "./watch-channels/PanelChrome";
import { OAuthReconnectBanner } from "./watch-channels/OAuthReconnectBanner";
import {
  CHANNELS_KEY,
  useWatchChannels,
} from "./google-calendar/useWatchChannels";
import { CreateChannelDialog } from "./google-calendar/CreateChannelDialog";
import { ChannelTable } from "./google-calendar/ChannelTable";

export function GoogleCalendarWatchChannels(): React.ReactElement | null {
  const qc = useQueryClient();
  const { flashedAt, triggerFlash } = useRowFlash();
  const [createOpen, setCreateOpen] = useState(false);

  const {
    channelsQuery,
    integrationsQuery,
    renewMutation,
    testMutation,
    stopMutation,
    pendingFor,
  } = useWatchChannels({ onFlash: triggerFlash });
  const channels = channelsQuery.data ?? [];
  const integrations = integrationsQuery.data ?? [];

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
      <WatchPanelLoading message="Loading Google Calendar watch channels…" />
    );
  }
  if (integrations.length === 0) {
    return null;
  }

  if (channelsQuery.isError) {
    return (
      <WatchPanelError
        title="Could not load watch channels"
        description="The server returned an error. Retry now or wait for the next automatic refresh."
        onRetry={() => channelsQuery.refetch()}
      />
    );
  }

  return (
    <div className="mt-10">
      <WatchPanelHeader
        icon={<CalendarIcon size={16} />}
        title="Google Calendar Watch Channels"
        subtitle={
          channels.length === 0
            ? "None active — create one to receive push notifications on calendar changes"
            : `${channels.length} active · rotated automatically every 7 days`
        }
        isFetching={channelsQuery.isFetching}
        isLoading={channelsQuery.isLoading}
        onRefresh={() => channelsQuery.refetch()}
        onCreate={() => setCreateOpen(true)}
      />

      {hasAnyOauthFailure && (
        <OAuthReconnectBanner
          title="Reconnect your Google Calendar"
          description={
            <>
              One or more watch channels are failing to renew because the OAuth
              credentials for{" "}
              {oauthFailingIntegrationIds.size === 1
                ? "this account have"
                : `${oauthFailingIntegrationIds.size} accounts have`}{" "}
              expired or been revoked. New calendar events won't dispatch to
              your modules until you reconnect. Existing channels will die at
              Google's 7-day expiry if left unreconnected.
            </>
          }
          providerId="google-calendar"
          buttonLabel="Go to Google Calendar provider card ↑"
        />
      )}

      {channels.length === 0 ? (
        <WatchPanelEmptyState
          icon={<CalendarIcon size={20} />}
          title="No watch channels yet"
          description="A watch channel lets Talos receive real-time push notifications when events change on a calendar. Bind one to a WASM module (via the workflow builder) to dispatch jobs per event, or leave it unbound to keep the sync token fresh for other integrations."
          ctaLabel="Create your first watch channel"
          onCreate={() => setCreateOpen(true)}
        />
      ) : (
        <ChannelTable
          channels={channels}
          flashedAt={flashedAt}
          pendingFor={pendingFor}
          onTest={(uuid) => testMutation.mutate(uuid)}
          onRenew={(uuid) => renewMutation.mutate(uuid)}
          onStop={(uuid) => stopMutation.mutate(uuid)}
        />
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
