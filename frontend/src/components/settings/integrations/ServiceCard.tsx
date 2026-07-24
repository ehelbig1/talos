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

      {(onSecondaryConnect || onTertiaryConnect) && (
        <div className="relative z-10 self-start mb-6 flex flex-wrap items-center gap-2">
          {onSecondaryConnect && (
            <button
              onClick={onSecondaryConnect}
              title={secondaryTooltip}
              className="inline-flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-warning/80 hover:text-warning border border-warning/20 hover:border-warning/40 bg-warning/5 hover:bg-warning/10 px-3 py-1.5 rounded-xl transition-premium active:scale-95"
            >
              <ShieldPlus size={12} />
              {secondaryLabel ?? "Enable provisioning"}
            </button>
          )}
          {onTertiaryConnect && (
            <button
              onClick={onTertiaryConnect}
              title={tertiaryTooltip}
              className="inline-flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-destructive/80 hover:text-destructive border border-destructive/20 hover:border-destructive/40 bg-destructive/5 hover:bg-destructive/10 px-3 py-1.5 rounded-xl transition-premium active:scale-95"
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
                  onDisconnect(serviceType, i.id, i.accountIdentifier)
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
}
