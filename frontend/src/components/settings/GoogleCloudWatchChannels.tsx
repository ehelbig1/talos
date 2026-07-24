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
 *
 * Decomposed (2026-07): data layer in google-cloud/useGcpWatchChannels,
 * dialog in google-cloud/CreateGcpWatchDialog, table in
 * google-cloud/GcpWatchTable, shared chrome in watch-channels/.
 */

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Cloud } from "lucide-react";
import { useRowFlash } from "./watch-channels/useRowFlash";
import {
  WatchPanelEmptyState,
  WatchPanelError,
  WatchPanelHeader,
  WatchPanelLoading,
} from "./watch-channels/PanelChrome";
import { OAuthReconnectBanner } from "./watch-channels/OAuthReconnectBanner";
import {
  WATCHES_KEY,
  useGcpWatchChannels,
} from "./google-cloud/useGcpWatchChannels";
import { CreateGcpWatchDialog } from "./google-cloud/CreateGcpWatchDialog";
import { GcpWatchTable } from "./google-cloud/GcpWatchTable";
import { GcpConnectedAccounts } from "./google-cloud/GcpConnectedAccounts";

export function GoogleCloudWatchChannels(): React.ReactElement | null {
  const qc = useQueryClient();
  const { flashedAt, triggerFlash } = useRowFlash();
  const [createOpen, setCreateOpen] = useState(false);

  const {
    watchesQuery,
    integrationsQuery,
    testMutation,
    stopMutation,
    pendingFor,
  } = useGcpWatchChannels({ onFlash: triggerFlash });
  const watches = watchesQuery.data ?? [];
  const integrations = integrationsQuery.data ?? [];

  const oauthFailingIntegrationIds = new Set(
    watches
      .filter((w) => w.recent_failure?.likely_oauth_failure)
      .map((w) => w.integration_id),
  );
  const hasAnyOauthFailure = oauthFailingIntegrationIds.size > 0;

  if (integrationsQuery.isLoading || watchesQuery.isLoading) {
    return <WatchPanelLoading message="Loading Google Cloud watch channels…" />;
  }
  if (integrations.length === 0) return null;

  if (watchesQuery.isError) {
    return (
      <WatchPanelError
        title="Could not load Google Cloud watches"
        description="The server returned an error. Retry now or wait for the next refresh."
        onRetry={() => watchesQuery.refetch()}
      />
    );
  }

  return (
    <div className="mt-10">
      <WatchPanelHeader
        icon={<Cloud size={16} />}
        title="Google Cloud Watch Channels"
        subtitle={
          watches.length === 0
            ? "None active — create one to receive Cloud Monitoring incident pushes"
            : `${watches.length} active · user-owned Pub/Sub subscriptions`
        }
        isFetching={watchesQuery.isFetching}
        isLoading={watchesQuery.isLoading}
        onRefresh={() => watchesQuery.refetch()}
        onCreate={() => setCreateOpen(true)}
      />

      <GcpConnectedAccounts integrations={integrations} />

      {hasAnyOauthFailure && (
        <OAuthReconnectBanner
          title="Reconnect your Google Cloud account"
          description={
            <>
              One or more Google Cloud watches are failing because the OAuth
              credentials for{" "}
              {oauthFailingIntegrationIds.size === 1
                ? "this account have"
                : `${oauthFailingIntegrationIds.size} accounts have`}{" "}
              expired or been revoked. Incident dispatch will fail until
              reconnected.
            </>
          }
          providerId="google_cloud"
          buttonLabel="Go to Google Cloud provider card ↑"
        />
      )}

      {watches.length === 0 ? (
        <WatchPanelEmptyState
          icon={<Cloud size={20} />}
          title="No Google Cloud watches yet"
          description="A watch receives Cloud Monitoring incident notifications via a Pub/Sub push subscription you point at Talos. Bind a WASM module to run automations on every incident."
          ctaLabel="Create your first GCP watch"
          onCreate={() => setCreateOpen(true)}
        />
      ) : (
        <GcpWatchTable
          watches={watches}
          flashedAt={flashedAt}
          pendingFor={pendingFor}
          onTest={(uuid) => testMutation.mutate(uuid)}
          onStop={(uuid) => stopMutation.mutate(uuid)}
        />
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
