import React from "react";
import { ArrowRightLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import type { Role } from "./graphql";

export interface RoleChangeTarget {
  userId: string;
  currentRole: string;
  newRole: Role;
}

/** Confirmation dialog for a member role change (current → proposed). */
export function RoleChangeDialog({
  target,
  isPending,
  onClose,
  onConfirm,
}: {
  target: RoleChangeTarget | null;
  isPending: boolean;
  onClose: () => void;
  onConfirm: () => void;
}): React.ReactElement {
  return (
    <Dialog open={!!target} onClose={onClose} title="Sync_Clearance">
      <div className="space-y-8">
        <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl">
          <p className="text-[11px] text-muted-foreground/60 leading-relaxed font-medium text-center">
            Awaiting confirmation to modify operative clearance levels. This
            change takes effect across all security perimeters immediately.
          </p>
        </div>

        <div className="flex items-center justify-center gap-12 py-4 relative">
          <div className="flex flex-col items-center gap-3">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted-foreground/30 mb-1">
              CURRENT
            </div>
            <div className="px-5 py-2 bg-white/5 border border-white/10 rounded-xl text-xs font-black uppercase text-muted-foreground/60">
              {target?.currentRole}
            </div>
          </div>

          <div className="flex items-center justify-center">
            <div className="w-10 h-10 bg-primary/10 rounded-full flex items-center justify-center border border-primary/20 shadow-[0_0_20px_hsla(var(--primary),0.2)]">
              <ArrowRightLeft className="w-4 h-4 text-primary animate-pulse" />
            </div>
          </div>

          <div className="flex flex-col items-center gap-3">
            <div className="text-[10px] font-black uppercase tracking-widest text-primary/40 mb-1">
              PROPOSED
            </div>
            <div className="px-5 py-2 bg-primary/20 border border-primary/40 rounded-xl text-xs font-black uppercase text-primary shadow-[0_0_20px_hsla(var(--primary),0.1)]">
              {target?.newRole}
            </div>
          </div>
        </div>

        <div className="flex gap-4 pt-4">
          <Button
            variant="outline"
            className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
            onClick={onClose}
          >
            ABORT_SYNC
          </Button>
          <Button
            variant="premium"
            className="flex-1 h-14 rounded-xl shadow-2xl"
            disabled={isPending}
            onClick={onConfirm}
          >
            {isPending ? <LoadingSpinner /> : "COMMIT_RESTRUCTURE"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
