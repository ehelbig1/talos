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
      <div className="animate-in fade-in duration-700 delay-300">
        <GoogleCalendarWatchChannels />
      </div>

      {/* Gmail watch channels */}
      <div className="animate-in fade-in duration-700 delay-500">
        <GmailWatchChannels />
      </div>

      {/* Google Cloud watch channels */}
      <div className="animate-in fade-in duration-700 delay-500">
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
