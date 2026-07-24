import React from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { cn } from "@/lib/utils";

/**
 * Transfer-ownership dialog: successor UUID + type-the-org-name
 * verification gate before the irreversible transfer.
 */
export function TransferOwnershipDialog({
  open,
  orgName,
  newOwnerId,
  confirmName,
  isPending,
  onNewOwnerIdChange,
  onConfirmNameChange,
  onClose,
  onSubmit,
}: {
  open: boolean;
  orgName: string | undefined;
  newOwnerId: string;
  confirmName: string;
  isPending: boolean;
  onNewOwnerIdChange: (id: string) => void;
  onConfirmNameChange: (name: string) => void;
  onClose: () => void;
  onSubmit: () => void;
}): React.ReactElement {
  const isTransferConfirmed = confirmName.trim() === orgName;

  return (
    <Dialog open={open} onClose={onClose} title="Identity_Shift">
      <div className="space-y-8">
        <div className="p-6 bg-destructive/10 border border-destructive/20 rounded-3xl flex items-start gap-5 relative overflow-hidden group">
          <div className="absolute inset-0 bg-destructive/5 blur-3xl animate-pulse opacity-20" />
          <AlertTriangle className="w-6 h-6 text-destructive shrink-0 mt-0.5 relative z-10" />
          <div className="space-y-2 relative z-10">
            <p className="text-xs font-black text-destructive uppercase tracking-widest">
              CRITICAL_GOVERNANCE_OVERRIDE
            </p>
            <p className="text-[11px] text-destructive/70 leading-relaxed font-medium">
              Transferring ownership grants{" "}
              <span className="text-destructive font-black underline decoration-2">
                FULL_SOVEREIGNTY
              </span>{" "}
              to another user. You will be demoted to Admin status immediately.
              This operation is irreversible without the new owner's consent.
            </p>
          </div>
        </div>

        <div className="space-y-6">
          <div className="space-y-2.5">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
              Successor_UUID
            </label>
            <Input
              placeholder="Target User UUID"
              value={newOwnerId}
              onChange={(e) => onNewOwnerIdChange(e.target.value)}
              className="h-14 bg-white/[0.03] border-white/10 focus:border-destructive/50 focus:ring-destructive/20 rounded-xl px-4 font-mono text-sm text-white placeholder:text-white/10 transition-premium"
            />
          </div>

          <div className="space-y-2.5">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
              Security_Verification
            </label>
            <div className="space-y-3">
              <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest ml-1">
                Type <span className="text-white">"{orgName}"</span> to confirm
                transfer
              </p>
              <Input
                placeholder="Verification Phrase"
                value={confirmName}
                onChange={(e) => onConfirmNameChange(e.target.value)}
                className={cn(
                  "h-14 bg-white/[0.03] border-white/10 rounded-xl px-4 text-sm transition-premium",
                  confirmName && !isTransferConfirmed
                    ? "border-destructive/50 focus:ring-destructive/20 text-destructive"
                    : "focus:border-primary/50 focus:ring-primary/20 text-white",
                )}
              />
            </div>
          </div>
        </div>

        <div className="flex gap-4 pt-4">
          <Button
            variant="outline"
            className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
            onClick={onClose}
          >
            CANCEL_TRANSFER
          </Button>
          <Button
            className="flex-1 h-14 rounded-xl bg-destructive hover:bg-destructive/90 text-white font-black uppercase text-[10px] tracking-widest shadow-2xl shadow-destructive/20"
            disabled={!newOwnerId.trim() || !isTransferConfirmed || isPending}
            onClick={onSubmit}
          >
            {isPending ? <LoadingSpinner /> : "EXECUTE_TRANSFER"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
