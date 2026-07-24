/**
 * Watch-channel table with per-row actions:
 *   - Test   — read-only OAuth probe (no state change)
 *   - Renew  — forces rotation, with optimistic expiration bump
 *   - Stop   — tears down + removes row, with optimistic removal
 */

import React from "react";
import { Activity, RefreshCw, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  RecentFailureBadge,
  WatchChannelStatusBadge,
} from "../watch-channels/WatchChannelStatusBadge";
import type { PendingAction, WatchChannelSummary } from "./useWatchChannels";
import { formatExpiration } from "./useWatchChannels";

export function ChannelTable({
  channels,
  flashedAt,
  pendingFor,
  onTest,
  onRenew,
  onStop,
}: {
  channels: WatchChannelSummary[];
  flashedAt: Record<string, number>;
  pendingFor: (channelUuid: string) => PendingAction;
  onTest: (channelUuid: string) => void;
  onRenew: (channelUuid: string) => void;
  onStop: (channelUuid: string) => void;
}): React.ReactElement {
  return (
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
                  <div className="font-medium text-foreground">
                    {ch.calendar_id}
                  </div>
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
                      <WatchChannelStatusBadge tone="ok">
                        synced
                      </WatchChannelStatusBadge>
                    ) : (
                      <WatchChannelStatusBadge tone="warn">
                        pending first sync
                      </WatchChannelStatusBadge>
                    )}
                    {ch.recent_failure && (
                      <RecentFailureBadge
                        failure={ch.recent_failure}
                        label="renewal failing"
                      />
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onTest(ch.channel_uuid)}
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
                      onClick={() => onRenew(ch.channel_uuid)}
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
                          onStop(ch.channel_uuid);
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
  );
}
