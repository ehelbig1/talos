import React from "react";
import {
  ArrowRightLeft,
  Building2,
  Globe,
  Mail,
  ShieldCheck,
  UserPlus,
  Users,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import type { Org, OrgMember, Role } from "./graphql";
import { MemberRow } from "./MemberRow";

/**
 * Right column: the selected organization's member roster + governance
 * cards, or the "no organization selected" placeholder.
 */
export function OrgDetailsPanel({
  selectedOrg,
  members,
  isLoadingMembers,
  currentUserId,
  onShowTransfer,
  onShowInvite,
  onRoleChange,
  onRemoveMember,
}: {
  selectedOrg: Org | undefined;
  members: OrgMember[] | undefined;
  isLoadingMembers: boolean;
  currentUserId: string | undefined;
  onShowTransfer: () => void;
  onShowInvite: () => void;
  onRoleChange: (target: {
    userId: string;
    currentRole: string;
    newRole: Role;
  }) => void;
  onRemoveMember: (userId: string) => void;
}): React.ReactElement {
  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-right-4 duration-700">
      <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden group">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8 mb-10 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-white/5 border border-white/10 rounded-[1.5rem] flex items-center justify-center text-3xl font-black font-outfit text-white shadow-2xl">
              {selectedOrg?.name.charAt(0).toUpperCase()}
            </div>
            <div>
              <h3 className="text-2xl font-black text-white tracking-tight uppercase font-outfit mb-2">
                {selectedOrg?.name}
              </h3>
              <div className="flex flex-wrap items-center gap-6">
                <span className="flex items-center gap-2 text-[10px] text-muted-foreground/60 font-black uppercase tracking-[0.2em]">
                  <Globe className="w-3.5 h-3.5 text-primary" /> talos.sh/
                  {selectedOrg?.slug}
                </span>
                <span className="flex items-center gap-2 text-[10px] text-muted-foreground/60 font-black uppercase tracking-[0.2em]">
                  <Users className="w-3.5 h-3.5 text-primary" />{" "}
                  {members?.length || 0} SYNDICATE_MEMBERS
                </span>
              </div>
            </div>
          </div>
          <div className="flex gap-4 w-full md:w-auto">
            <Button
              variant="outline"
              className="flex-1 md:flex-none h-12 px-6 border-white/10 hover:bg-white/5 text-destructive/80 hover:text-destructive border-destructive/20 hover:border-destructive/40 rounded-xl font-black uppercase text-[10px] tracking-widest transition-premium"
              onClick={onShowTransfer}
            >
              <ArrowRightLeft className="w-4 h-4 mr-3" /> TRANSFER_OWNERSHIP
            </Button>
            <Button
              variant="premium"
              className="flex-1 md:flex-none h-12 px-8 rounded-xl"
              onClick={onShowInvite}
            >
              <UserPlus className="w-4 h-4 mr-3" /> INVITE_OPERATIVE
            </Button>
          </div>
        </div>

        <div className="space-y-2 relative z-10">
          <div className="px-1 py-4 text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground/20 border-b border-white/5 mb-4">
            Active_Operatives
          </div>
          {isLoadingMembers ? (
            <div className="py-12 flex justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="space-y-3">
              {members?.map((member) => (
                <MemberRow
                  key={member.id}
                  member={member}
                  isCurrentUser={member.userId === currentUserId}
                  onRoleChange={onRoleChange}
                  onRemove={onRemoveMember}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card className="bg-card/40 border-border/60 p-4 border">
          <div className="flex items-center gap-3 mb-3">
            <ShieldCheck className="w-4 h-4 text-primary" />
            <span className="text-xs font-bold uppercase tracking-wider text-foreground">
              Role Policies
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground leading-relaxed mb-3">
            Enforce strict RBAC policies for this organization. Admin roles can
            manage secrets and deployments.
          </p>
          <Button
            variant="ghost"
            className="p-0 h-auto text-[11px] text-primary hover:text-primary/90"
          >
            Configure Roles →
          </Button>
        </Card>
        <Card className="bg-card/40 border-border/60 p-4 border">
          <div className="flex items-center gap-3 mb-3">
            <Mail className="w-4 h-4 text-primary" />
            <span className="text-xs font-bold uppercase tracking-wider text-foreground">
              Pending Invites
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground leading-relaxed mb-3">
            You have no pending invitations for this organization. All team
            members have active accounts.
          </p>
          <Button
            variant="ghost"
            className="p-0 h-auto text-[11px] text-primary hover:text-primary/90"
          >
            View History →
          </Button>
        </Card>
      </div>
    </div>
  );
}

/** Placeholder shown when no organization is selected. */
export function NoOrgSelected(): React.ReactElement {
  return (
    <div className="h-full flex flex-col items-center justify-center p-12 border border-dashed border-white/5 rounded-[2.5rem] bg-white/[0.01]">
      <div className="w-16 h-16 bg-white/5 rounded-[1.5rem] flex items-center justify-center mb-6 border border-white/10">
        <Building2 className="w-8 h-8 text-muted-foreground/40" />
      </div>
      <h3 className="text-sm font-black text-white/40 uppercase tracking-widest mb-3 font-outfit">
        No Organization Selected
      </h3>
      <p className="text-[10px] text-muted-foreground/30 font-black uppercase tracking-widest text-center max-w-xs leading-relaxed">
        Select an organization from the left to manage members and settings.
      </p>
    </div>
  );
}
