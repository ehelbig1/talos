/**
 * Create-channel dialog — lists calendars for the chosen integration,
 * submits one POST /watch/create per selected calendar.
 */

import React, { useEffect, useMemo, useState } from "react";
import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";
import type { ApiResponse } from "../watch-channels/api";
import { authedFetch } from "../watch-channels/api";
import type {
  CalendarInfo,
  IntegrationInfo,
  WatchChannelSummary,
} from "./useWatchChannels";
import { CHANNELS_KEY } from "./useWatchChannels";

export function CreateChannelDialog({
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
  // changes between renders (e.g. the list loaded after mount). Done
  // during render via the "store information from previous renders"
  // pattern (https://react.dev/learn/you-might-not-need-an-effect)
  // instead of a setState-in-effect; the `!integrationId` guard means a
  // user choice is never overridden.
  const [lastIntegrations, setLastIntegrations] = useState(integrations);
  if (integrations !== lastIntegrations) {
    setLastIntegrations(integrations);
    if (!integrationId && integrations[0]) {
      setIntegrationId(integrations[0].id);
    }
  }

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
      if (!body.success)
        throw new Error(body.error ?? "Failed to load calendars");
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
        const res = await authedFetch("/api/google-calendar/watch/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            integration_id: integrationId,
            calendar_id: calId,
          }),
        });
        const body: ApiResponse<Record<string, unknown>> = await res.json();
        if (body.success) created++;
        else {
          failed++;
          toast.error(
            sanitizeErrorMessage(`${calId}: ${body.error ?? "create failed"}`),
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
    <Dialog
      open={open}
      onClose={() => !submitting && onClose()}
      title="Create watch channel"
    >
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
                      already
                        ? "opacity-50 cursor-not-allowed"
                        : "hover:bg-muted/20",
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
            disabled={submitting || selected.size === 0 || channelsFetching}
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
