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
    <Dialog open={open} onClose={onClose} title="Transfer ownership">
      <div className="space-y-8">
        <div className="p-6 bg-destructive/10 border border-destructive/20 rounded-2xl flex items-start gap-5 relative overflow-hidden group">
          <AlertTriangle className="w-6 h-6 text-destructive shrink-0 mt-0.5 relative z-10" />
          <div className="space-y-2 relative z-10">
            <p className="text-xs font-semibold text-destructive">
              This cannot be undone
            </p>
            <p className="text-xs text-destructive/70 leading-relaxed font-medium">
              Transferring ownership grants{" "}
              <span className="text-destructive font-semibold underline decoration-2">
                full ownership
              </span>{" "}
              to another user. You will be demoted to Admin status immediately.
              This operation is irreversible without the new owner's consent.
            </p>
          </div>
        </div>

        <div className="space-y-6">
          <div className="space-y-2.5">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              New owner's user ID
            </label>
            <Input
              placeholder="User ID"
              value={newOwnerId}
              onChange={(e) => onNewOwnerIdChange(e.target.value)}
              className="h-14 bg-white/[0.03] border-white/10 focus:border-destructive/50 focus:ring-destructive/20 rounded-xl px-4 font-mono text-sm text-white placeholder:text-white/10 transition-ui"
            />
          </div>

          <div className="space-y-2.5">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Confirm
            </label>
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground/60 font-medium ml-1">
                Type <span className="text-white">"{orgName}"</span> to confirm
                transfer
              </p>
              <Input
                placeholder="Organization name"
                value={confirmName}
                onChange={(e) => onConfirmNameChange(e.target.value)}
                className={cn(
                  "h-14 bg-white/[0.03] border-white/10 rounded-xl px-4 text-sm transition-ui",
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
            className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-sm font-semibold"
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button
            className="flex-1 h-14 rounded-xl bg-destructive hover:bg-destructive/90 text-white font-semibold text-sm"
            disabled={!newOwnerId.trim() || !isTransferConfirmed || isPending}
            onClick={onSubmit}
          >
            {isPending ? <LoadingSpinner /> : "Transfer ownership"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
