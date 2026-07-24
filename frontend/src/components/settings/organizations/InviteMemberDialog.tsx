import React from "react";
import { UserPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { cn } from "@/lib/utils";
import type { Role } from "./graphql";
import { ROLE_OPTIONS } from "./graphql";

/** Invite-member dialog: target user UUID + role picker. */
export function InviteMemberDialog({
  open,
  orgName,
  userId,
  role,
  isPending,
  onUserIdChange,
  onRoleChange,
  onClose,
  onSubmit,
}: {
  open: boolean;
  orgName: string | undefined;
  userId: string;
  role: Role;
  isPending: boolean;
  onUserIdChange: (userId: string) => void;
  onRoleChange: (role: Role) => void;
  onClose: () => void;
  onSubmit: () => void;
}): React.ReactElement {
  return (
    <Dialog open={open} onClose={onClose} title="Protocol_Enrolment">
      <div className="space-y-8">
        <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-4">
          <UserPlus className="w-5 h-5 text-primary shrink-0 mt-0.5" />
          <p className="text-[11px] text-muted-foreground/60 leading-relaxed font-medium">
            Invite a new operative to the{" "}
            <span className="text-white font-black">{orgName}</span> syndicate.
            Access privileges are defined by the selected protocol role.
          </p>
        </div>

        <div className="space-y-6">
          <div className="space-y-2.5">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
              Operative_UUID
            </label>
            <Input
              placeholder="Target User Identifier"
              value={userId}
              onChange={(e) => onUserIdChange(e.target.value)}
              className="h-14 bg-white/[0.03] border-white/10 focus:border-primary/50 focus:ring-primary/20 rounded-xl px-4 font-mono text-sm text-white placeholder:text-white/10 transition-premium"
            />
          </div>

          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
              Protocol_Clearance_Level
            </label>
            <div className="flex gap-2 p-1.5 bg-black/40 border border-white/5 rounded-2xl">
              {ROLE_OPTIONS.map((r) => (
                <button
                  key={r}
                  onClick={() => onRoleChange(r)}
                  className={cn(
                    "flex-1 py-3 px-4 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-premium",
                    role === r
                      ? "bg-primary/20 border border-primary/40 text-primary shadow-[0_0_15px_hsla(var(--primary),0.2)]"
                      : "text-muted-foreground/20 hover:text-white hover:bg-white/5 border border-transparent",
                  )}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex gap-4 pt-4">
          <Button
            variant="outline"
            className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
            onClick={onClose}
          >
            ABORT_ENROLMENT
          </Button>
          <Button
            variant="premium"
            className="flex-1 h-14 rounded-xl shadow-2xl"
            disabled={!userId.trim() || isPending}
            onClick={onSubmit}
          >
            {isPending ? <LoadingSpinner /> : "DISPATCH_INVITE"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
