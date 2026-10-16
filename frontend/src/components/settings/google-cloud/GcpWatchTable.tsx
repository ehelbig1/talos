/**
 * GCP watch table with per-row actions: copy push endpoint, read-only
 * OAuth probe, and stop (delete).
 */

import React from "react";
import { Spinner } from "@/components/ui/spinner";
import { Activity, Copy, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { cn } from "@/lib/utils";
import {
  RecentFailureBadge,
  WatchChannelStatusBadge,
} from "../watch-channels/WatchChannelStatusBadge";
import type { GcpPendingAction, GcpWatchSummary } from "./useGcpWatchChannels";
import { copyToClipboard, formatRelative } from "./useGcpWatchChannels";

export function GcpWatchTable({
  watches,
  flashedAt,
  pendingFor,
  onTest,
  onStop,
}: {
  watches: GcpWatchSummary[];
  flashedAt: Record<string, number>;
  pendingFor: (channelUuid: string) => GcpPendingAction;
  onTest: (channelUuid: string) => void;
  onStop: (channelUuid: string) => void;
}): React.ReactElement {
  const [watchToStop, setWatchToStop] = React.useState<GcpWatchSummary | null>(
    null,
  );
  return (
    <div className="border border-border/40 rounded-2xl overflow-hidden">
      <ConfirmDialog
        open={watchToStop !== null}
        title="Stop this watch?"
        message={`Google Cloud stops pushing incidents for “${watchToStop?.display_name ?? ""}” to Talos. A workflow bound to this watch is not started by an incident again until you create the watch again.`}
        confirmLabel="Stop watch"
        destructive
        onConfirm={() => {
          if (watchToStop) onStop(watchToStop.channel_uuid);
          setWatchToStop(null);
        }}
        onCancel={() => setWatchToStop(null)}
      />
      <table className="w-full text-sm">
        <thead className="bg-muted/30 text-xs text-muted-foreground">
          <tr>
            <th className="text-left px-4 py-2.5 font-semibold">Name</th>
            <th className="text-left px-4 py-2.5 font-semibold">
              Service account
            </th>
            <th className="text-left px-4 py-2.5 font-semibold">Module</th>
            <th className="text-left px-4 py-2.5 font-semibold">Last push</th>
            <th className="text-left px-4 py-2.5 font-semibold">Status</th>
            <th className="text-right px-4 py-2.5 font-semibold">Actions</th>
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
                  "border-t border-border/30 transition-ui",
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
                    <WatchChannelStatusBadge tone="ok">
                      active
                    </WatchChannelStatusBadge>
                    {w.recent_failure && (
                      <RecentFailureBadge
                        failure={w.recent_failure}
                        label="push failing"
                      />
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
                      onClick={() => onTest(w.channel_uuid)}
                      disabled={cur !== null}
                      title="Read-only OAuth probe against Google Cloud."
                      className="h-8 px-2.5 text-xs"
                    >
                      {cur === "test" ? (
                        <Spinner className="w-3 h-3" />
                      ) : (
                        <Activity size={13} />
                      )}
                      <span className="ml-1.5">Test</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setWatchToStop(w)}
                      disabled={cur !== null}
                      className="h-8 px-2.5 text-xs text-destructive hover:text-destructive"
                    >
                      {cur === "stop" ? (
                        <Spinner className="w-3 h-3 text-destructive" />
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
