import React from "react";
import { Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { formatDate } from "@/lib/format";
import type { OrgMember, Role } from "./graphql";
import { ROLE_OPTIONS } from "./graphql";

/** One member row: identity, role pills (or owner badge), remove action. */
export function MemberRow({
  member,
  isCurrentUser,
  onRoleChange,
  onRemove,
}: {
  member: OrgMember;
  isCurrentUser: boolean;
  onRoleChange: (target: {
    userId: string;
    currentRole: string;
    newRole: Role;
  }) => void;
  onRemove: (userId: string) => void;
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between p-4 bg-white/[0.02] hover:bg-white/[0.04] border border-white/5 hover:border-white/10 rounded-2xl transition-premium group">
      <div className="flex items-center gap-4">
        <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-xs font-black text-white shadow-inner group-hover:scale-105 transition-premium">
          {member.userId.charAt(0).toUpperCase()}
        </div>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="text-sm font-black text-white tracking-tight uppercase font-outfit">
              OPERATIVE_
              {member.userId.split("-")[0].toUpperCase()}
            </span>
            {isCurrentUser && (
              <span className="text-[9px] font-black uppercase tracking-[0.3em] text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded-full shadow-[0_0_10px_hsla(var(--primary),0.2)]">
                SELF
              </span>
            )}
          </div>
          <div className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest">
            ENROLLED {formatDate(member.joinedAt)} &bull; ID:{" "}
            {member.userId.slice(0, 8)}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-6">
        {member.role === "owner" ? (
          <Badge
            variant="outline"
            className="text-[9px] uppercase font-black tracking-widest px-3 py-1 border-warning/30 text-warning bg-warning/5 rounded-full shadow-[0_0_10px_hsla(var(--warning),0.1)]"
          >
            {member.role}
          </Badge>
        ) : (
          <div className="flex items-center gap-1.5 p-1 bg-black/20 rounded-xl border border-white/5">
            {ROLE_OPTIONS.map((role) => (
              <button
                key={role}
                onClick={() =>
                  role !== member.role &&
                  onRoleChange({
                    userId: member.userId,
                    currentRole: member.role,
                    newRole: role,
                  })
                }
                className={cn(
                  "text-[9px] font-black uppercase tracking-wider px-3 py-1.5 rounded-lg transition-premium",
                  role === member.role
                    ? role === "admin"
                      ? "bg-success/20 border border-success/30 text-success shadow-[0_0_10px_hsla(var(--success),0.2)]"
                      : "bg-white/10 border border-white/10 text-white"
                    : "text-muted-foreground/30 hover:text-white hover:bg-white/5",
                )}
              >
                {role}
              </button>
            ))}
          </div>
        )}
        {member.role !== "owner" && !isCurrentUser && (
          <button
            type="button"
            aria-label={`Remove operative ${member.userId} from syndicate`}
            onClick={() => onRemove(member.userId)}
            className="p-2.5 text-muted-foreground/30 hover:text-destructive hover:bg-destructive/10 rounded-xl transition-premium opacity-0 group-hover:opacity-100 border border-transparent hover:border-destructive/20"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}
