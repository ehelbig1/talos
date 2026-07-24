/**
 * Connected Google Cloud accounts, tier-badged. Phase C: the same
 * account can hold BOTH a read row and a write (provisioning) row —
 * this is the one place the `tier` field is available to the UI (the
 * generic serviceIntegrations GraphQL card has no tier field; it
 * instead gets a server-appended "(provisioning)" label suffix).
 * Explicitly labeled + divided from the channel list: an unlabeled
 * account chip inside this panel reads as "a watch channel was
 * created" (observed 2026-07-15) — these are OAuth consents, and
 * connecting one creates NO watch channel and NO GCP resources.
 */

import React from "react";
import type { GcpIntegrationInfo } from "./useGcpWatchChannels";

export function GcpConnectedAccounts({
  integrations,
}: {
  integrations: GcpIntegrationInfo[];
}): React.ReactElement {
  return (
    <div className="mb-4 pb-4 border-b border-border/40">
      <p
        className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground mb-1.5"
        title="OAuth consents available to watch channels and provisioning workflows. Connecting an account does not create a watch channel or any Pub/Sub resources — create a channel below, or run the GCP provisioning modules in a workflow."
      >
        Connected accounts
        <span className="ml-1.5 normal-case font-normal tracking-normal text-muted-foreground/70">
          — OAuth consents only; not watch channels
        </span>
      </p>
      <div className="flex flex-wrap gap-2">
        {integrations.map((i) => (
          <div
            key={i.id}
            className="inline-flex items-center gap-2 px-3 py-1.5 bg-muted/10 border border-border/40 rounded-xl text-xs"
          >
            <span className="text-foreground font-medium">
              {i.account_email ?? "Google Cloud"}
            </span>
            {i.tier === "full" ? (
              <span className="inline-flex items-center text-[10px] font-semibold px-2 py-0.5 rounded-full bg-destructive/10 text-destructive border border-destructive/20">
                Impersonation
              </span>
            ) : i.tier === "write" ? (
              <span className="inline-flex items-center text-[10px] font-semibold px-2 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/20">
                Provisioning
              </span>
            ) : (
              <span className="inline-flex items-center text-[10px] font-semibold px-2 py-0.5 rounded-full bg-muted/20 text-muted-foreground border border-border/40">
                Read-only
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
