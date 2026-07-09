import { sanitizeErrorMessage } from "@/lib/sanitize";
import React, { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { getCsrfToken } from "@/lib/csrf";
import { validateOAuthUrl, loadOAuthHosts } from "@/lib/oauthUtils";
import { toast } from "sonner";
import {
  Calendar,
  Github,
  LayoutGrid,
  Mail,
  MessageSquare,
  Plug,
  Plus,
  ExternalLink,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Loader2,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Dialog } from "@/components/ui";
import { GoogleCalendarWatchChannels } from "./GoogleCalendarWatchChannels";
import { GmailWatchChannels } from "./GmailWatchChannels";

import type {
  IntegrationService,
  ServiceIntegration as GqlServiceIntegration,
} from "@/lib/graphqlApi";
import {
  listServiceIntegrations,
  disconnectServiceIntegration,
} from "@/lib/graphqlApi";

function authedFetch(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const csrfToken = getCsrfToken();
  const headers: Record<string, string> = {
    ...((options.headers as Record<string, string>) ?? {}),
  };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  return fetch(url, { ...options, credentials: "include", headers });
}

/** Shape returned by GET /api/integrations/providers */
interface ProviderInfo {
  id: string;
  display_name: string;
  description: string;
  icon: string;
  color: string;
  graphql_enum: string;
  oauth_hosts: string[];
  configured: boolean;
  connect_url: string;
}

/** Shape returned by GET /api/github/installations (RFC 0008). */
interface GithubInstallation {
  installation_id: number;
  account_login: string;
  account_type?: string | null;
  repository_selection?: string | null;
}

/** Maps an icon name string from the API to the corresponding Lucide component. */
const ICON_MAP: Record<string, LucideIcon> = {
  Calendar,
  Mail,
  MessageSquare,
  LayoutGrid,
};

function getIcon(iconName: string): LucideIcon {
  return ICON_MAP[iconName] ?? Plug;
}

export function IntegrationsManager() {
  // Service integrations are fetched via react-query so the loading/data
  // state is derived, not mirrored through a setState-in-effect. `refetch`
  // is used by the connect / disconnect / OAuth-callback paths below.
  const {
    data: integrations = [],
    isLoading: loadingServices,
    isError: integrationsError,
    refetch: refetchIntegrations,
  } = useQuery<GqlServiceIntegration[]>({
    queryKey: ["serviceIntegrations"],
    queryFn: listServiceIntegrations,
  });
  const [confirmModal, setConfirmModal] = useState<{
    open: boolean;
    service: IntegrationService | null;
    id: string;
    accountIdentifier: string;
  }>({ open: false, service: null, id: "", accountIdentifier: "" });
  const [disconnecting, setDisconnecting] = useState(false);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const pollTimerRef = React.useRef<number | null>(null);

  // Connected GitHub App installations (RFC 0008) — react-query owns the state
  // so the card can show the linked account without a setState-in-effect.
  const { data: githubInstallations = [], refetch: refetchGithub } = useQuery<
    GithubInstallation[]
  >({
    queryKey: ["githubInstallations"],
    queryFn: async () => {
      const res = await authedFetch("/api/github/installations");
      if (!res.ok) return [];
      const d = await res.json();
      return Array.isArray(d?.installations) ? d.installations : [];
    },
  });

  // Clear any in-flight OAuth popup poller on unmount.
  useEffect(() => {
    return () => {
      if (pollTimerRef.current !== null) {
        clearInterval(pollTimerRef.current);
      }
    };
  }, []);

  // Fetch provider metadata from the backend and warm the OAuth host cache.
  useEffect(() => {
    async function fetchProviders() {
      try {
        const res = await authedFetch("/api/integrations/providers");
        if (res.ok) {
          const data: ProviderInfo[] = await res.json();
          setProviders(data);
        }
      } catch {
        // Best-effort — the grid will simply be empty until retry.
        if (import.meta.env.DEV)
          console.error("Failed to fetch integration providers");
      }
    }
    fetchProviders();
    loadOAuthHosts();
  }, []);

  // Surface load failures as a toast (the fetch + retry is owned by
  // react-query above). No setState here, so this stays a pure
  // side-effect synchronization.
  useEffect(() => {
    if (integrationsError) toast.error("Failed to load integrations");
  }, [integrationsError]);

  // Handle OAuth callback query params for any provider (e.g. {provider.id}_connected / _error)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    let dirty = false;

    // Check every loaded provider for callback params
    for (const provider of providers) {
      const connectedKey = `${provider.id.replace(/-/g, "_")}_connected`;
      const errorKey = `${provider.id.replace(/-/g, "_")}_error`;

      const connectedVal = params.get(connectedKey);
      if (connectedVal) {
        toast.success(`${provider.display_name} connected: ${connectedVal}`);
        refetchIntegrations();
        params.delete(connectedKey);
        dirty = true;
      }

      const errorVal = params.get(errorKey);
      if (errorVal) {
        toast.error(
          sanitizeErrorMessage(
            `${provider.display_name} connection failed: ${errorVal}`,
          ),
        );
        params.delete(errorKey);
        dirty = true;
      }
    }

    // Also check legacy keys that the backend may emit before providers load
    const legacyKeys = [
      { param: "atlassian_connected", label: "Jira", isError: false },
      { param: "atlassian_error", label: "Jira", isError: true },
      { param: "gmail_connected", label: "Gmail", isError: false },
      { param: "gmail_error", label: "Gmail", isError: true },
      { param: "github_connected", label: "GitHub", isError: false },
      { param: "github_error", label: "GitHub", isError: true },
    ];
    for (const { param, label, isError } of legacyKeys) {
      const val = params.get(param);
      if (val) {
        if (isError) {
          toast.error(
            sanitizeErrorMessage(`${label} connection failed: ${val}`),
          );
        } else {
          toast.success(`${label} connected: ${val}`);
          refetchIntegrations();
          if (param === "github_connected") refetchGithub();
        }
        params.delete(param);
        dirty = true;
      }
    }

    if (dirty) {
      window.history.replaceState(
        {},
        "",
        `${window.location.pathname}${params.toString() ? `?${params}` : ""}`,
      );
    }
  }, [providers, refetchIntegrations, refetchGithub]);

  // Disconnect Service
  const handleDisconnectService = async () => {
    const { service, id } = confirmModal;
    if (!service) return;

    setDisconnecting(true);
    try {
      const success = await disconnectServiceIntegration(id, service);
      if (success) {
        refetchIntegrations();
        toast.success(`${service} integration disconnected`);
        setConfirmModal({
          open: false,
          service: null,
          id: "",
          accountIdentifier: "",
        });
      } else {
        toast.error("Failed to disconnect integration.");
      }
    } catch (e) {
      if (import.meta.env.DEV)
        console.error("Disconnect integration error:", e);
      toast.error("Error disconnecting integration.");
    } finally {
      setDisconnecting(false);
    }
  };

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

  const handleConnectService = async (type: string) => {
    try {
      const res = await authedFetch(`/api/${type}/connect`);
      if (res.ok) {
        const d = await res.json();
        if (d.success && d.data?.authorization_url) {
          if (!validateOAuthUrl(d.data.authorization_url)) {
            toast.error("Invalid OAuth authorization URL received from server");
            return;
          }
          // eslint-disable-next-line react-hooks/immutability -- intentional browser navigation to the OAuth authorization URL in an async click handler (not a render-time mutation of external state); the URL is validated above.
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

  const ServiceCard = ({
    title,
    description,
    icon: Icon,
    color,
    serviceType,
    onConnect,
    configured = true,
    providerId,
  }: {
    title: string;
    description: string;
    icon: React.ComponentType<{ size?: number }>;
    color: string;
    serviceType: IntegrationService;
    onConnect: () => void;
    configured?: boolean;
    providerId?: string;
  }) => {
    const serviceIntegrations = integrations.filter(
      (i) => i.service === serviceType,
    );

    return (
      <div
        data-provider-id={providerId}
        className="bg-surface-3/30 border border-white/5 rounded-[2rem] p-6 transition-premium hover:border-white/10 hover:shadow-2xl hover:shadow-primary/5 group relative overflow-hidden flex flex-col h-full"
      >
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex items-start justify-between mb-8 relative z-10">
          <div className="flex items-center gap-5">
            <div
              className="w-14 h-14 rounded-2xl flex items-center justify-center text-white shadow-2xl transition-premium group-hover:scale-110 group-hover:rotate-3"
              style={{
                background: `linear-gradient(135deg, ${color}, ${color}dd)`,
                boxShadow: `0 10px 25px -5px ${color}44`,
              }}
            >
              <Icon size={28} />
            </div>
            <div>
              <h3 className="text-xl font-black text-white tracking-tight">
                {title}
              </h3>
              <p className="text-[10px] text-muted-foreground/60 font-black uppercase tracking-widest mt-0.5">
                {description}
              </p>
            </div>
          </div>
          {configured ? (
            <button
              onClick={onConnect}
              className="p-2.5 bg-white/5 border border-white/5 hover:bg-primary/10 hover:border-primary/20 hover:text-primary transition-premium rounded-xl active:scale-90"
              title="Connect Account"
            >
              <Plus size={18} />
            </button>
          ) : (
            <span className="text-[8px] font-black text-muted-foreground/20 uppercase tracking-[0.2em] px-3 py-1.5 border border-white/5 rounded-xl">
              LOCK_PENDING
            </span>
          )}
        </div>

        <div className="space-y-3 mt-auto relative z-10">
          {serviceIntegrations.length > 0 ? (
            serviceIntegrations.map((i) => (
              <div
                key={i.id}
                className="bg-black/20 border border-white/5 rounded-2xl px-5 py-4 flex items-center justify-between group/item hover:bg-black/40 transition-premium shadow-inner"
              >
                <div className="flex flex-col">
                  <span className="text-[11px] font-black text-white/80 tracking-tight">
                    {i.accountIdentifier || "Protocol_Entity"}
                  </span>
                  <div className="flex items-center gap-2 mt-1">
                    <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                    <span className="text-[8px] text-success font-black uppercase tracking-widest">
                      {i.status || "Authenticated"}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() =>
                    setConfirmModal({
                      open: true,
                      service: serviceType,
                      id: i.id,
                      accountIdentifier: i.accountIdentifier,
                    })
                  }
                  className="opacity-0 group-hover/item:opacity-100 p-2 text-muted-foreground/40 hover:text-destructive hover:bg-destructive/10 rounded-xl transition-premium"
                >
                  <XCircle size={16} />
                </button>
              </div>
            ))
          ) : (
            <div className="h-[68px] border border-dashed border-white/5 rounded-[1.5rem] flex items-center justify-center bg-black/10 group-hover:bg-black/20 transition-premium">
              <p className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-[0.3em]">
                NO_ACTIVE_UPLINK
              </p>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-6xl mx-auto space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-1000">
      <div className="relative group">
        <div className="absolute -inset-8 bg-primary/5 rounded-[4rem] blur-[80px] opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 relative z-10">
          <div className="space-y-4">
            <div className="flex items-center gap-5">
              <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[1.5rem] flex items-center justify-center text-primary shadow-[0_0_30px_hsla(var(--primary),0.1)] group-hover:scale-110 transition-premium">
                <ExternalLink size={28} />
              </div>
              <div className="flex flex-col">
                <h2 className="text-3xl md:text-4xl font-black text-white tracking-tighter uppercase">
                  Service Uplinks
                </h2>
                <div className="flex flex-wrap items-center gap-3 mt-2">
                  <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full shrink-0">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                    <span className="text-[9px] text-primary font-black uppercase tracking-widest leading-none">
                      Active_Interlink
                    </span>
                  </div>
                  <div className="hidden sm:block w-1 h-1 rounded-full bg-white/10 shrink-0" />
                  <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.2em] leading-none shrink-0">
                    Cross-Protocol Integration
                  </span>
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/60 leading-relaxed max-w-2xl font-medium">
              Establish secure communication channels with external cognitive
              frameworks and data silos. Authenticated entities can be leveraged
              as autonomous triggers or operational endpoints.
            </p>
          </div>
        </div>
      </div>

      {loadingServices ? (
        <div className="flex flex-col items-center justify-center py-32 gap-6">
          <div className="relative">
            <div className="w-16 h-16 border-2 border-primary/10 rounded-full" />
            <div className="w-16 h-16 border-t-2 border-primary rounded-full animate-spin absolute inset-0" />
          </div>
          <p className="text-[10px] text-primary/60 font-black uppercase tracking-[0.4em] animate-status-pulse">
            Establishing Protocol Link...
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {providers.map((provider) => (
            <ServiceCard
              key={provider.id}
              title={provider.display_name}
              description={provider.description}
              icon={getIcon(provider.icon)}
              color={provider.color}
              serviceType={provider.graphql_enum as IntegrationService}
              configured={provider.configured}
              providerId={provider.id}
              onConnect={
                provider.id === "google-calendar"
                  ? handleConnectGcal
                  : () => handleConnectService(provider.id)
              }
            />
          ))}
        </div>
      )}

      {/* GitHub App (RFC 0008) — not a registry OAuth provider; bespoke card.
          Initiates the App install flow; the result toast is handled by the
          github_connected / github_error query-param effect above. */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <div className="bg-surface-3/30 border border-white/5 rounded-[2rem] p-6 transition-premium hover:border-white/10 hover:shadow-2xl hover:shadow-primary/5 group relative overflow-hidden flex flex-col h-full">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
          <div className="flex items-start justify-between mb-8 relative z-10">
            <div className="flex items-center gap-5">
              <div
                className="w-14 h-14 rounded-2xl flex items-center justify-center text-white shadow-2xl transition-premium group-hover:scale-110 group-hover:rotate-3"
                style={{
                  background: "linear-gradient(135deg, #24292f, #24292fdd)",
                  boxShadow: "0 10px 25px -5px #24292f44",
                }}
              >
                <Github size={28} />
              </div>
              <div>
                <h3 className="text-xl font-black text-white tracking-tight">
                  GitHub App
                </h3>
                <p className="text-[10px] text-muted-foreground/60 font-black uppercase tracking-widest mt-0.5">
                  Scoped, auto-rotating repo access
                </p>
              </div>
            </div>
            <button
              onClick={handleConnectGithub}
              className="p-2.5 bg-white/5 border border-white/5 hover:bg-primary/10 hover:border-primary/20 hover:text-primary transition-premium rounded-xl active:scale-90"
              title="Install GitHub App"
            >
              <Plus size={18} />
            </button>
          </div>
          <div className="space-y-3 mt-auto relative z-10">
            {githubInstallations.length > 0 ? (
              githubInstallations.map((inst) => (
                <div
                  key={inst.installation_id}
                  className="bg-black/20 border border-white/5 rounded-2xl px-5 py-4 flex items-center justify-between shadow-inner"
                >
                  <div className="flex flex-col">
                    <span className="text-[11px] font-black text-white/80 tracking-tight">
                      {inst.account_login}
                    </span>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                      <span className="text-[8px] text-success font-black uppercase tracking-widest">
                        {inst.repository_selection === "all"
                          ? "All repositories"
                          : "Selected repositories"}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="h-[68px] border border-dashed border-white/5 rounded-[1.5rem] flex items-center justify-center bg-black/10 group-hover:bg-black/20 transition-premium px-4">
                <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.25em] text-center leading-relaxed">
                  Install to grant short-lived, per-repo tokens
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Per-channel management for Google Calendar */}
      <div className="animate-in fade-in duration-700 delay-300">
        <GoogleCalendarWatchChannels />
      </div>

      {/* Gmail watch channels */}
      <div className="animate-in fade-in duration-700 delay-500">
        <GmailWatchChannels />
      </div>

      {/* Disconnect Confirmation Dialog */}
      <Dialog
        open={confirmModal.open}
        onClose={() =>
          !disconnecting && setConfirmModal({ ...confirmModal, open: false })
        }
        title="Protocol_Severance_Notice"
      >
        <div className="space-y-8 p-2">
          <div className="flex items-start gap-6 p-8 bg-destructive/5 border border-destructive/20 rounded-[2rem] shadow-2xl relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-destructive/10 to-transparent opacity-50" />
            <div className="w-14 h-14 bg-destructive/10 rounded-2xl flex items-center justify-center text-destructive shrink-0 border border-destructive/20 relative z-10">
              <AlertTriangle size={28} />
            </div>
            <div className="relative z-10 space-y-2">
              <p className="text-xl font-black text-white tracking-tight">
                Sever Link: {confirmModal.service}?
              </p>
              <p className="text-xs text-muted-foreground leading-relaxed font-medium">
                This will terminate autonomous access to{" "}
                <span className="text-destructive font-black underline underline-offset-4">
                  {confirmModal.accountIdentifier}
                </span>
                . Downstream protocols depending on this uplink will enter a
                suspended state.
              </p>
            </div>
          </div>

          <div className="flex justify-end gap-4">
            <button
              onClick={() => setConfirmModal({ ...confirmModal, open: false })}
              disabled={disconnecting}
              className="px-8 py-4 text-[10px] font-black uppercase tracking-[0.2em] border border-white/5 hover:bg-white/5 rounded-2xl transition-premium active:scale-95 text-muted-foreground hover:text-white"
            >
              Retain_Link
            </button>
            <button
              onClick={handleDisconnectService}
              disabled={disconnecting}
              className="px-10 py-4 text-[10px] font-black uppercase tracking-[0.2em] bg-destructive text-white rounded-2xl shadow-2xl shadow-destructive/20 transition-premium active:scale-95 hover:bg-destructive/90"
            >
              {disconnecting ? (
                <div className="flex items-center gap-3">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>SEVERING...</span>
                </div>
              ) : (
                "SEVER_PROTOCOL_LINK"
              )}
            </button>
          </div>
        </div>
      </Dialog>

      <div className="p-10 bg-surface-3/40 border border-white/5 rounded-[3rem] flex flex-col md:flex-row items-start md:items-center gap-8 relative overflow-hidden group hover:border-white/10 transition-premium shadow-2xl">
        <div className="absolute inset-0 bg-gradient-to-r from-warning/5 via-transparent to-transparent opacity-50" />
        <div className="w-16 h-16 bg-warning/10 border border-warning/20 rounded-[1.5rem] flex items-center justify-center text-warning shrink-0 group-hover:scale-110 group-hover:rotate-6 transition-premium shadow-[0_0_30px_hsla(var(--warning),0.1)]">
          <HelpCircle size={32} />
        </div>
        <div className="space-y-2">
          <h4 className="text-xl font-black text-white uppercase tracking-tighter">
            Protocol Expansion Required?
          </h4>
          <p className="text-sm text-muted-foreground/60 leading-relaxed font-medium max-w-3xl">
            If a native uplink is not listed, utilize the{" "}
            <span className="text-primary font-bold">Webhook Gateway</span> or
            the{" "}
            <span className="text-primary font-bold">Generic HTTP Engine</span>{" "}
            to interface with any REST-compliant API endpoint. New autonomous
            providers are integrated into the core framework on a recurring
            cycle.
          </p>
        </div>
      </div>
    </div>
  );
}

export default React.memo(IntegrationsManager);
