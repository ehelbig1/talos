/**
 * Create-watch dialog for Google Cloud Monitoring push.
 *
 * The `push_endpoint` (which embeds the raw push token) is surfaced
 * prominently ONCE after create so the user can wire it into
 * `gcloud pubsub subscriptions create --push-endpoint=...`.
 */

import React, { useEffect, useState } from "react";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui";
import { useMyModulesQuery } from "@/generated/graphql";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import type { ApiResponse } from "../watch-channels/api";
import { authedFetch } from "../watch-channels/api";
import type { GcpIntegrationInfo } from "./useGcpWatchChannels";
import { WATCHES_KEY, copyToClipboard } from "./useGcpWatchChannels";

export function CreateGcpWatchDialog({
  integrations,
  open,
  onClose,
  onCreated,
}: {
  integrations: GcpIntegrationInfo[];
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}): React.ReactElement {
  const qc = useQueryClient();
  const [integrationId, setIntegrationId] = useState<string>(
    integrations[0]?.id ?? "",
  );
  const [saEmail, setSaEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [moduleId, setModuleId] = useState("");
  // Installed-modules dropdown: the previous free-text field expected a
  // raw UUID — users naturally typed the module NAME, the server
  // rejected the body, and pre-ApiJson that rejection was plain text
  // that crashed res.json(). Fetch lazily (only while the dialog is
  // open) and fall back to free-text entry if the query fails.
  const modulesQuery = useMyModulesQuery(
    { limit: 200, offset: 0 },
    { enabled: open, staleTime: 60_000 },
  );
  const moduleOptions = modulesQuery.data?.myModules ?? [];
  const [submitting, setSubmitting] = useState(false);
  // The push endpoint returned by create — surfaced ONCE here with a
  // copy button so the user can paste it into `gcloud`.
  const [createdEndpoint, setCreatedEndpoint] = useState<string | null>(null);
  const watchesFetching = useIsFetching({ queryKey: WATCHES_KEY }) > 0;

  const [lastIntegrations, setLastIntegrations] = useState(integrations);
  if (integrations !== lastIntegrations) {
    setLastIntegrations(integrations);
    if (!integrationId && integrations[0]) setIntegrationId(integrations[0].id);
  }

  useEffect(() => {
    if (open) qc.invalidateQueries({ queryKey: WATCHES_KEY });
  }, [open, qc]);

  // Reset the one-time endpoint reveal when the dialog is dismissed (in
  // an event handler, not an effect — a fresh open then starts clean).
  const closeDialog = () => {
    setCreatedEndpoint(null);
    onClose();
  };

  const handleSubmit = async () => {
    if (!integrationId || !saEmail.trim()) return;
    setSubmitting(true);
    try {
      const res = await authedFetch("/api/gcp/watch-channels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          integration_id: integrationId,
          expected_sa_email: saEmail.trim(),
          display_name: displayName.trim() || null,
          module_id: moduleId.trim() || null,
        }),
      });
      // Defense in depth alongside the server-side ApiJson envelope: a
      // proxy/middleware plain-text error must surface as a message, not
      // as "Unexpected token ... is not valid JSON".
      const raw = await res.text();
      let body: ApiResponse<{ push_endpoint?: string }>;
      try {
        body = JSON.parse(raw);
      } catch {
        toast.error(
          sanitizeErrorMessage(raw.slice(0, 200) || `HTTP ${res.status}`),
        );
        return;
      }
      if (!body.success) {
        toast.error(sanitizeErrorMessage(body.error ?? "Create failed"));
        return;
      }
      toast.success("GCP watch created");
      await qc.invalidateQueries({ queryKey: WATCHES_KEY });
      onCreated();
      setCreatedEndpoint(body.data?.push_endpoint ?? null);
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
      onClose={() => !submitting && closeDialog()}
      title="Create Google Cloud watch"
    >
      {createdEndpoint ? (
        <div className="space-y-5">
          <div>
            <p className="text-sm font-semibold text-foreground mb-1">
              Watch created — copy your push endpoint
            </p>
            <p className="text-xs text-muted-foreground mb-3">
              Paste this into your Pub/Sub push subscription (
              <code>--push-endpoint</code>). It embeds a secret token — this is
              the one prominent place we show it (you can re-copy it from the
              row later).
            </p>
            <div className="flex items-center gap-2 p-3 bg-muted/30 border border-border/60 rounded-lg">
              <code className="text-xs break-all flex-1">
                {createdEndpoint}
              </code>
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyToClipboard(createdEndpoint)}
                className="h-8 px-2.5 text-xs shrink-0"
              >
                <Copy size={13} className="mr-1.5" /> Copy
              </Button>
            </div>
          </div>
          <div className="flex justify-end pt-2">
            <Button
              onClick={closeDialog}
              className="h-10 px-6 text-xs font-bold"
              disabled={watchesFetching}
            >
              <Check size={13} className="mr-1.5" /> Done
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Google Cloud account
            </label>
            <select
              value={integrationId}
              onChange={(e) => setIntegrationId(e.target.value)}
              disabled={submitting || integrations.length === 0}
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              {integrations.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.account_email ?? i.id}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Push service-account email
            </label>
            <input
              type="text"
              value={saEmail}
              onChange={(e) => setSaEmail(e.target.value)}
              disabled={submitting}
              placeholder="talos-gcp-pusher@my-project.iam.gserviceaccount.com"
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
            <p className="text-[11px] text-muted-foreground mt-1.5">
              The service account your Pub/Sub subscription signs pushes with (
              <code>--push-auth-service-account</code>). Every push JWT must be
              issued by this account.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Display name (optional)
            </label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              disabled={submitting}
              placeholder="Prod alerting"
              className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-muted-foreground mb-2">
              Module ID (optional)
            </label>
            {moduleOptions.length > 0 ? (
              <select
                value={moduleId}
                onChange={(e) => setModuleId(e.target.value)}
                disabled={submitting}
                className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
              >
                <option value="">(none — bind later)</option>
                {moduleOptions.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={moduleId}
                onChange={(e) => setModuleId(e.target.value)}
                disabled={submitting}
                placeholder="UUID of the module to run on each incident"
                className="w-full h-10 px-3 text-sm bg-background border border-border/60 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40"
              />
            )}
            <p className="text-[11px] text-muted-foreground mt-1.5">
              The module that runs on each incident. Leave unset to bind one
              later in the workflow builder.
            </p>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="outline"
              onClick={closeDialog}
              disabled={submitting}
              className="h-10 px-5 text-xs font-bold"
            >
              Cancel
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={
                submitting ||
                watchesFetching ||
                !integrationId ||
                !saEmail.trim()
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
      )}
    </Dialog>
  );
}
