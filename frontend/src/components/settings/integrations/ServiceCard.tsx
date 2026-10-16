/**
 * Provider card for the IntegrationsManager grid: connect action(s),
 * optional secondary/tertiary consent buttons (GCP write / full tier),
 * and the list of connected accounts with per-account disconnect.
 *
 * Strictly presentational — integrations data and the disconnect
 * confirmation flow are owned by the parent.
 */

import React from "react";
import { Plus, XCircle, ShieldPlus, Fingerprint } from "lucide-react";
import type {
  IntegrationService,
  ServiceIntegration as GqlServiceIntegration,
} from "@/lib/graphqlApi";

export function ServiceCard({
  title,
  description,
  icon: Icon,
  color,
  serviceType,
  onConnect,
  configured = true,
  providerId,
  secondaryLabel,
  secondaryTooltip,
  onSecondaryConnect,
  tertiaryLabel,
  tertiaryTooltip,
  onTertiaryConnect,
  integrations,
  onDisconnect,
}: {
  title: string;
  description: string;
  icon: React.ComponentType<{ size?: number }>;
  color: string;
  serviceType: IntegrationService;
  onConnect: () => void;
  configured?: boolean;
  providerId?: string;
  /** Optional secondary consent action (e.g. GCP write-tier provisioning). */
  secondaryLabel?: string;
  secondaryTooltip?: string;
  onSecondaryConnect?: () => void;
  /**
   * Optional tertiary consent action, rendered in a stronger (destructive)
   * style than the secondary one — for the highest-privilege grant on a card
   * (e.g. GCP full-tier impersonation, which mints broad cloud-platform
   * tokens host-side).
   */
  tertiaryLabel?: string;
  tertiaryTooltip?: string;
  onTertiaryConnect?: () => void;
  /** All connected service integrations (filtered per-card by serviceType). */
  integrations: GqlServiceIntegration[];
  /** Opens the disconnect confirmation for one connected account. */
  onDisconnect: (
    service: IntegrationService,
    id: string,
    accountIdentifier: string,
  ) => void;
}) {
  const serviceIntegrations = integrations.filter(
    (i) => i.service === serviceType,
  );

  return (
    <div
      data-provider-id={providerId}
      className="bg-surface-3/30 border border-white/5 rounded-2xl p-6 transition-ui hover:border-white/10 group relative overflow-hidden flex flex-col h-full"
    >
      <div className="flex items-start justify-between gap-3 mb-8 relative z-10">
        <div className="flex items-center gap-5 min-w-0">
          <div
            className="w-14 h-14 rounded-2xl flex items-center justify-center text-white transition-ui"
            style={{
              background: `linear-gradient(135deg, ${color}, ${color}dd)`,
              boxShadow: `0 10px 25px -5px ${color}44`,
            }}
          >
            <Icon size={28} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-white tracking-tight">
              {title}
            </h3>
            <p className="text-xs text-muted-foreground/60 font-semibold mt-0.5">
              {description}
            </p>
          </div>
        </div>
        {configured ? (
          <button
            onClick={onConnect}
            className="p-2.5 bg-white/5 border border-white/5 hover:bg-primary/10 hover:border-primary/20 hover:text-primary transition-ui rounded-xl"
            title="Connect account"
            aria-label="Connect account"
          >
            <Plus size={18} />
          </button>
        ) : (
          <span className="shrink-0 whitespace-nowrap text-2xs font-semibold text-muted-foreground/50 uppercase tracking-wider px-3 py-1.5 border border-white/5 rounded-xl">
            Coming soon
          </span>
        )}
      </div>

      {(onSecondaryConnect || onTertiaryConnect) && (
        <div className="relative z-10 self-start mb-6 flex flex-wrap items-center gap-2">
          {onSecondaryConnect && (
            <button
              onClick={onSecondaryConnect}
              title={secondaryTooltip}
              className="inline-flex items-center gap-1.5 text-2xs font-semibold text-warning/80 hover:text-warning border border-warning/20 hover:border-warning/40 bg-warning/5 hover:bg-warning/10 px-3 py-1.5 rounded-xl transition-ui"
            >
              <ShieldPlus size={12} />
              {secondaryLabel ?? "Enable provisioning"}
            </button>
          )}
          {onTertiaryConnect && (
            <button
              onClick={onTertiaryConnect}
              title={tertiaryTooltip}
              className="inline-flex items-center gap-1.5 text-2xs font-semibold text-destructive/80 hover:text-destructive border border-destructive/20 hover:border-destructive/40 bg-destructive/5 hover:bg-destructive/10 px-3 py-1.5 rounded-xl transition-ui"
            >
              <Fingerprint size={12} />
              {tertiaryLabel ?? "Enable impersonation"}
            </button>
          )}
        </div>
      )}

      <div className="space-y-3 mt-auto relative z-10">
        {serviceIntegrations.length > 0 ? (
          serviceIntegrations.map((i) => (
            <div
              key={i.id}
              className="bg-black/20 border border-white/5 rounded-2xl px-5 py-4 flex items-center justify-between group/item hover:bg-black/40 transition-ui"
            >
              <div className="flex flex-col">
                <span className="text-xs font-semibold text-white/80 tracking-tight">
                  {i.accountIdentifier || "Connected account"}
                </span>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-1.5 h-1.5 rounded-full bg-success" />
                  <span className="text-2xs text-success font-semibold uppercase tracking-wider">
                    {i.status || "Connected"}
                  </span>
                </div>
              </div>
              <button
                onClick={() =>
                  onDisconnect(serviceType, i.id, i.accountIdentifier)
                }
                aria-label="Disconnect account"
                className="opacity-0 group-hover/item:opacity-100 p-2 text-muted-foreground/70 hover:text-destructive hover:bg-destructive/10 rounded-xl transition-ui"
              >
                <XCircle size={16} />
              </button>
            </div>
          ))
        ) : (
          <div className="h-[68px] border border-dashed border-white/5 rounded-2xl flex items-center justify-center bg-black/10 group-hover:bg-black/20 transition-ui">
            <p className="text-2xs text-muted-foreground/50 font-semibold uppercase tracking-wider">
              Not connected
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
