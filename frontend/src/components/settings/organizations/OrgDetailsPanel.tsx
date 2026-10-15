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
    <div className="space-y-8">
      <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 relative overflow-hidden group">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8 mb-10 relative z-10">
          <div className="flex items-center gap-6">
            <div className="w-16 h-16 bg-white/5 border border-white/10 rounded-2xl flex items-center justify-center text-3xl font-semibold font-outfit text-white">
              {selectedOrg?.name.charAt(0).toUpperCase()}
            </div>
            <div>
              <h3 className="text-2xl font-semibold text-white tracking-tight font-outfit mb-2">
                {selectedOrg?.name}
              </h3>
              <div className="flex flex-wrap items-center gap-6">
                <span className="flex items-center gap-2 text-xs text-muted-foreground/60 font-semibold">
                  <Globe className="w-3.5 h-3.5 text-primary" /> talos.sh/
                  {selectedOrg?.slug}
                </span>
                <span className="flex items-center gap-2 text-xs text-muted-foreground/60 font-semibold">
                  <Users className="w-3.5 h-3.5 text-primary" />{" "}
                  {members?.length || 0} member
                  {(members?.length || 0) !== 1 ? "s" : ""}
                </span>
              </div>
            </div>
          </div>
          <div className="flex gap-4 w-full md:w-auto">
            <Button
              variant="outline"
              className="flex-1 md:flex-none h-12 px-6 border-white/10 hover:bg-white/5 text-destructive/80 hover:text-destructive border-destructive/20 hover:border-destructive/40 rounded-xl font-semibold text-sm transition-ui"
              onClick={onShowTransfer}
            >
              <ArrowRightLeft className="w-4 h-4 mr-3" /> Transfer ownership
            </Button>
            <Button
              variant="premium"
              className="flex-1 md:flex-none h-12 px-8 rounded-xl"
              onClick={onShowInvite}
            >
              <UserPlus className="w-4 h-4 mr-3" /> Invite member
            </Button>
          </div>
        </div>

        <div className="space-y-2 relative z-10">
          <div className="px-1 py-4 text-sm font-semibold text-muted-foreground/50 border-b border-white/5 mb-4">
            Members
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
            <span className="text-xs font-bold text-foreground">
              Role policies
            </span>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed mb-3">
            Enforce strict RBAC policies for this organization. Admin roles can
            manage secrets and deployments.
          </p>
          <Button
            variant="ghost"
            className="p-0 h-auto text-xs text-primary hover:text-primary/90"
          >
            Configure Roles →
          </Button>
        </Card>
        <Card className="bg-card/40 border-border/60 p-4 border">
          <div className="flex items-center gap-3 mb-3">
            <Mail className="w-4 h-4 text-primary" />
            <span className="text-xs font-bold text-foreground">
              Pending invites
            </span>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed mb-3">
            You have no pending invitations for this organization. All team
            members have active accounts.
          </p>
          <Button
            variant="ghost"
            className="p-0 h-auto text-xs text-primary hover:text-primary/90"
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
    <div className="h-full flex flex-col items-center justify-center p-12 border border-dashed border-white/5 rounded-2xl bg-white/[0.01]">
      <div className="w-16 h-16 bg-white/5 rounded-2xl flex items-center justify-center mb-6 border border-white/10">
        <Building2 className="w-8 h-8 text-muted-foreground/70" />
      </div>
      <h3 className="text-sm font-semibold text-white/70 mb-3 font-outfit">
        No organization selected
      </h3>
      <p className="text-xs text-muted-foreground/60 text-center max-w-xs leading-relaxed">
        Select an organization from the left to manage members and settings.
      </p>
    </div>
  );
}
