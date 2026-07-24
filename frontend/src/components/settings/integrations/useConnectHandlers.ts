/**
 * Connect-flow handlers for IntegrationsManager: the dedicated Google
 * Calendar popup flow (with popup-blocker handling + capped watcher), the
 * generic redirect-based OAuth connect, the GCP write/full-tier variants,
 * and the GitHub App install flow.
 */

import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { validateOAuthUrl } from "@/lib/oauthUtils";
import { authedFetch } from "../watch-channels/api";

export function useConnectHandlers(refetchIntegrations: () => void) {
  const pollTimerRef = useRef<number | null>(null);

  // Clear any in-flight OAuth popup poller on unmount.
  useEffect(() => {
    return () => {
      if (pollTimerRef.current !== null) {
        clearInterval(pollTimerRef.current);
      }
    };
  }, []);

  // Connect Services
  const handleConnectGcal = async () => {
    // Use the DEDICATED Calendar OAuth flow. The old flow hit
    // /auth/oauth/google/login (SSO login), whose callback refuses to link a
    // Google identity onto an existing password account and 500s. The backend
    // /api/google-calendar/connect endpoint builds the authorize URL with
    // read-only calendar scopes and binds the user into the CSRF state token,
    // so the (unauthenticated) callback recovers identity from the token.
    let authUrl: string;
    try {
      const res = await authedFetch("/api/google-calendar/connect");
      if (!res.ok) {
        toast.error(
          res.status === 503
            ? "Google Calendar OAuth is not configured on this server"
            : `Service error: ${res.status}`,
        );
        return;
      }
      const d = await res.json();
      if (!d.success || !d.data?.authorization_url) {
        toast.error(
          sanitizeErrorMessage(`Connect failed: ${d.error || "Unknown error"}`),
        );
        return;
      }
      if (!validateOAuthUrl(d.data.authorization_url)) {
        toast.error("Invalid OAuth authorization URL received from server");
        return;
      }
      authUrl = d.data.authorization_url;
    } catch (err) {
      if (import.meta.env.DEV) console.error("GCal connect error:", err);
      toast.error("Error connecting Google Calendar");
      return;
    }

    const width = 600;
    const height = 700;
    const left = window.screen.width / 2 - width / 2;
    const top = window.screen.height / 2 - height / 2;

    const popup = window.open(
      authUrl,
      "Connect Google Calendar",
      `width=${width},height=${height},left=${left},top=${top}`,
    );

    // MCP-929 (2026-05-14): handle popup-blocker case. `window.open`
    // returns `null` when the browser refuses to open the popup
    // (popup blocker active, request not in response to a user
    // gesture, etc.). Pre-fix the poller installed below uses
    // `popup?.closed` — optional chaining on null yields `undefined`,
    // which is falsy, so the "popup closed → re-fetch integrations"
    // branch never fires. The poller then runs for the full
    // MCP-891 10-minute timeout doing nothing (1200 useless 500ms
    // polls). And the user sees no feedback that their click
    // produced no result. Surface the failure with an actionable
    // toast and skip installing the poller entirely.
    if (!popup) {
      toast.error(
        "Couldn't open the Google Calendar connection window — allow popups for this site and try again.",
      );
      return;
    }

    if (pollTimerRef.current !== null) {
      clearInterval(pollTimerRef.current);
    }
    // MCP-891 (2026-05-14): cap popup watcher at 10 minutes. Pre-fix
    // the 500ms `popup.closed` poll ran indefinitely if the user
    // never closed the popup (left it backgrounded, navigated tabs,
    // forgot about it) — ~7,200 polls/hour for nothing. OAuth flows
    // legitimately complete within 30 seconds; 10 minutes is a
    // generous timeout that catches abandoned popups and stops the
    // watcher so a re-trigger isn't blocked.
    const POPUP_WATCH_MAX_MS = 10 * 60 * 1000;
    const watchStartedAt = Date.now();
    pollTimerRef.current = window.setInterval(() => {
      if (popup?.closed) {
        clearInterval(pollTimerRef.current!);
        pollTimerRef.current = null;
        refetchIntegrations();
        return;
      }
      if (Date.now() - watchStartedAt > POPUP_WATCH_MAX_MS) {
        clearInterval(pollTimerRef.current!);
        pollTimerRef.current = null;
      }
    }, 500);
  };

  // `path` lets callers hit a non-default connect route (e.g. the GCP
  // write-tier / provisioning consent below) while reusing the same
  // response handling + error messaging.
  const handleConnectService = async (type: string, path?: string) => {
    try {
      const res = await authedFetch(path ?? `/api/${type}/connect`);
      if (res.ok) {
        const d = await res.json();
        if (d.success && d.data?.authorization_url) {
          if (!validateOAuthUrl(d.data.authorization_url)) {
            toast.error("Invalid OAuth authorization URL received from server");
            return;
          }
          // Intentional browser navigation to the OAuth authorization URL in
          // an async click handler (not a render-time mutation of external
          // state); the URL is validated above.
          window.location.href = d.data.authorization_url;
        } else {
          toast.error(
            sanitizeErrorMessage(
              `Connect failed: ${d.error || "Unknown error"}`,
            ),
          );
        }
      } else {
        toast.error(`Service error: ${res.status}`);
      }
    } catch (err) {
      if (import.meta.env.DEV) console.error("Connect service error:", err);
      toast.error(`Error connecting ${type}`);
    }
  };

  // GCP Phase C: a SEPARATE, scope-narrowed OAuth consent (Pub/Sub +
  // Monitoring only, never cloud-platform) used by provisioning workflows.
  // Deliberately independent of the read-tier `/api/gcp/connect` flow above
  // — the user can hold both a read row and a write row for the same
  // Google account (see talos-google-cloud::GcpTier).
  const handleConnectGcpWrite = () =>
    handleConnectService("Google Cloud provisioning", "/api/gcp/connect-write");

  // GCP Phase D: the BROADEST consent — a full `cloud-platform` token that is
  // host-reserved (never handed to a workflow module). It exists ONLY so the
  // controller can mint short-lived (~10 min) impersonated service-account
  // tokens for Cloud Run / compute workflows, each scoped to ONE SA and bounded
  // by that SA's IAM roles. Highest-privilege grant on the card — styled
  // destructive to set it apart from the amber provisioning consent. See
  // talos-google-cloud::impersonation and docs/gcp-impersonation-setup.md.
  const handleConnectGcpFull = () =>
    handleConnectService("Google Cloud impersonation", "/api/gcp/connect-full");

  // GitHub App install flow (RFC 0008). Unlike OAuth providers, the backend
  // returns a GitHub *install* URL (not an authorization_url) which we navigate
  // to; GitHub then redirects back to /api/github/setup. A 503 means the App
  // isn't configured on this server.
  const handleConnectGithub = async () => {
    try {
      const res = await authedFetch("/api/github/connect");
      if (!res.ok) {
        toast.error(
          res.status === 503
            ? "GitHub App is not configured on this server"
            : `Service error: ${res.status}`,
        );
        return;
      }
      const d = await res.json();
      const url: unknown = d?.install_url;
      // Precise validation: the install URL is always a github.com App page.
      if (
        d?.success &&
        typeof url === "string" &&
        url.startsWith("https://github.com/apps/")
      ) {
        window.location.href = url;
      } else {
        toast.error(
          sanitizeErrorMessage(
            `Connect failed: ${d?.error || "Unknown error"}`,
          ),
        );
      }
    } catch (err) {
      if (import.meta.env.DEV) console.error("GitHub connect error:", err);
      toast.error("Error connecting GitHub");
    }
  };

  return {
    handleConnectGcal,
    handleConnectService,
    handleConnectGcpWrite,
    handleConnectGcpFull,
    handleConnectGithub,
  };
}
