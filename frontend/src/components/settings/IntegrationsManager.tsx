import React, { useState } from "react";
import { toast } from "sonner";
import { ExternalLink, HelpCircle } from "lucide-react";
import { GoogleCalendarWatchChannels } from "./GoogleCalendarWatchChannels";
import { GmailWatchChannels } from "./GmailWatchChannels";
import { GoogleCloudWatchChannels } from "./GoogleCloudWatchChannels";

import type { IntegrationService } from "@/lib/graphqlApi";
import { disconnectServiceIntegration } from "@/lib/graphqlApi";
import { getIcon } from "./integrations/types";
import { useIntegrationsData } from "./integrations/useIntegrationsData";
import { useConnectHandlers } from "./integrations/useConnectHandlers";
import { ServiceCard } from "./integrations/ServiceCard";
import { GithubAppCard } from "./integrations/GithubAppCard";
import { DisconnectDialog } from "./integrations/DisconnectDialog";

export function IntegrationsManager() {
  const {
    integrations,
    loadingServices,
    refetchIntegrations,
    providers,
    githubInstallations,
  } = useIntegrationsData();

  const {
    handleConnectPlaid,
    handleConnectGcal,
    handleConnectService,
    handleConnectGcpWrite,
    handleConnectGcpFull,
    handleConnectGithub,
  } = useConnectHandlers(refetchIntegrations);

  const [confirmModal, setConfirmModal] = useState<{
    open: boolean;
    service: IntegrationService | null;
    id: string;
    accountIdentifier: string;
  }>({ open: false, service: null, id: "", accountIdentifier: "" });
  const [disconnecting, setDisconnecting] = useState(false);

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

  return (
    <div className="max-w-6xl mx-auto space-y-12">
      <div className="relative group">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8 relative z-10">
          <div className="space-y-4">
            <div className="flex items-center gap-5">
              <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary transition-ui">
                <ExternalLink size={28} />
              </div>
              <div className="flex flex-col">
                <h2 className="text-3xl md:text-4xl font-semibold text-white tracking-tight">
                  Integrations
                </h2>
                <div className="flex flex-wrap items-center gap-3 mt-2">
                  <div className="flex items-center gap-2 bg-primary/10 border border-primary/20 px-3 py-1 rounded-full shrink-0">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                    <span className="text-2xs text-primary font-semibold uppercase tracking-wider leading-none">
                      Connected services
                    </span>
                  </div>
                  <div className="hidden sm:block w-1 h-1 rounded-full bg-white/10 shrink-0" />
                  <span className="text-2xs text-muted-foreground/70 font-semibold uppercase tracking-wider leading-none shrink-0">
                    OAuth and API connections
                  </span>
                </div>
              </div>
            </div>
            <p className="text-sm text-muted-foreground/60 leading-relaxed max-w-2xl font-medium">
              Connect external services so workflows can read from them and
              write to them. A connected account can start a workflow or be
              called from one.
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
          <p className="text-xs text-primary/60 font-semibold">Loading…</p>
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
                  : provider.id === "plaid"
                    ? handleConnectPlaid
                    : () => handleConnectService(provider.id)
              }
              secondaryLabel={
                provider.id === "gcp" ? "Enable provisioning" : undefined
              }
              secondaryTooltip={
                provider.id === "gcp"
                  ? "Grants Talos write access to Pub/Sub and Monitoring only — used by provisioning workflows"
                  : undefined
              }
              onSecondaryConnect={
                provider.id === "gcp" ? handleConnectGcpWrite : undefined
              }
              tertiaryLabel={
                provider.id === "gcp" ? "Enable impersonation" : undefined
              }
              tertiaryTooltip={
                provider.id === "gcp"
                  ? "Broadest consent — a full cloud-platform token, held host-side and never handed to a workflow module. Used only to mint short-lived impersonated service-account tokens for Cloud Run / compute workflows."
                  : undefined
              }
              onTertiaryConnect={
                provider.id === "gcp" ? handleConnectGcpFull : undefined
              }
              integrations={integrations}
              onDisconnect={(service, id, accountIdentifier) =>
                setConfirmModal({
                  open: true,
                  service,
                  id,
                  accountIdentifier,
                })
              }
            />
          ))}
        </div>
      )}

      {/* GitHub App (RFC 0008) — not a registry OAuth provider; bespoke card.
          Initiates the App install flow; the result toast is handled by the
          github_connected / github_error query-param effect above. */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <GithubAppCard
          installations={githubInstallations}
          onConnect={handleConnectGithub}
        />
      </div>

      {/* Per-channel management for Google Calendar */}
      <div>
        <GoogleCalendarWatchChannels />
      </div>

      {/* Gmail watch channels */}
      <div>
        <GmailWatchChannels />
      </div>

      {/* Google Cloud watch channels */}
      <div>
        <GoogleCloudWatchChannels />
      </div>

      {/* Disconnect Confirmation Dialog */}
      <DisconnectDialog
        open={confirmModal.open}
        service={confirmModal.service}
        accountIdentifier={confirmModal.accountIdentifier}
        disconnecting={disconnecting}
        onClose={() =>
          !disconnecting && setConfirmModal({ ...confirmModal, open: false })
        }
        onConfirm={handleDisconnectService}
      />

      <div className="p-10 bg-surface-3/40 border border-white/5 rounded-2xl flex flex-col md:flex-row items-start md:items-center gap-8 relative overflow-hidden group hover:border-white/10 transition-ui">
        <div className="w-16 h-16 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center text-warning shrink-0 transition-ui">
          <HelpCircle size={32} />
        </div>
        <div className="space-y-2">
          <h4 className="text-xl font-semibold text-white tracking-tight">
            Need another service?
          </h4>
          <p className="text-sm text-muted-foreground/60 leading-relaxed font-medium max-w-3xl">
            If a service is not listed, use a{" "}
            <span className="text-primary font-bold">webhook</span> or an{" "}
            <span className="text-primary font-bold">HTTP module</span> to reach
            any REST API. New integrations are added regularly.
          </p>
        </div>
      </div>
    </div>
  );
}

export default React.memo(IntegrationsManager);
