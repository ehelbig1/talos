/**
 * Disconnect confirmation dialog for IntegrationsManager. Strictly
 * presentational — the confirm-modal state and disconnect mutation are
 * owned by the parent.
 */

import React from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { Dialog } from "@/components/ui";
import type { IntegrationService } from "@/lib/graphqlApi";

export function DisconnectDialog({
  open,
  service,
  accountIdentifier,
  disconnecting,
  onClose,
  onConfirm,
}: {
  open: boolean;
  service: IntegrationService | null;
  accountIdentifier: string;
  disconnecting: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Protocol_Severance_Notice">
      <div className="space-y-8 p-2">
        <div className="flex items-start gap-6 p-8 bg-destructive/5 border border-destructive/20 rounded-[2rem] shadow-2xl relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-destructive/10 to-transparent opacity-50" />
          <div className="w-14 h-14 bg-destructive/10 rounded-2xl flex items-center justify-center text-destructive shrink-0 border border-destructive/20 relative z-10">
            <AlertTriangle size={28} />
          </div>
          <div className="relative z-10 space-y-2">
            <p className="text-xl font-black text-white tracking-tight">
              Sever Link: {service}?
            </p>
            <p className="text-xs text-muted-foreground leading-relaxed font-medium">
              This will terminate autonomous access to{" "}
              <span className="text-destructive font-black underline underline-offset-4">
                {accountIdentifier}
              </span>
              . Downstream protocols depending on this uplink will enter a
              suspended state.
            </p>
          </div>
        </div>

        <div className="flex justify-end gap-4">
          <button
            onClick={onClose}
            disabled={disconnecting}
            className="px-8 py-4 text-[10px] font-black uppercase tracking-[0.2em] border border-white/5 hover:bg-white/5 rounded-2xl transition-premium active:scale-95 text-muted-foreground hover:text-white"
          >
            Retain_Link
          </button>
          <button
            onClick={onConfirm}
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
  );
}
