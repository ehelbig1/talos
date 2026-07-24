/**
 * Organizations settings surface: org list, member roster with role
 * management, and the create/invite/role-change/transfer dialogs.
 *
 * Decomposed (2026-07): GraphQL documents + shared types in
 * organizations/graphql.ts, presentational pieces in organizations/*.
 * All state + mutations stay here so the subcomponents are pure props.
 */

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useListOrgsQuery,
  useListOrgMembersQuery,
  useCreateOrgMutation,
  useRemoveMemberMutation,
  useInviteMemberMutation,
  useUpdateMemberRoleMutation,
  useTransferOwnershipMutation,
} from "@/generated/graphql";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { Building2, Plus } from "lucide-react";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { useAuth } from "@/contexts/AuthContext";
import type { Role } from "./organizations/graphql";
import { OrgListSidebar } from "./organizations/OrgListSidebar";
import {
  NoOrgSelected,
  OrgDetailsPanel,
} from "./organizations/OrgDetailsPanel";
import { CreateOrgDialog } from "./organizations/CreateOrgDialog";
import { InviteMemberDialog } from "./organizations/InviteMemberDialog";
import type { RoleChangeTarget } from "./organizations/RoleChangeDialog";
import { RoleChangeDialog } from "./organizations/RoleChangeDialog";
import { TransferOwnershipDialog } from "./organizations/TransferOwnershipDialog";

export default function OrganizationsManager() {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const [showCreate, setShowCreate] = useState(false);
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [newOrgName, setNewOrgName] = useState("");
  const [newOrgSlug, setNewOrgSlug] = useState("");

  // Invite member dialog state
  const [showInvite, setShowInvite] = useState(false);
  const [inviteUserId, setInviteUserId] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("member");

  // Update role confirmation state
  const [roleChangeTarget, setRoleChangeTarget] =
    useState<RoleChangeTarget | null>(null);

  // Transfer ownership dialog state
  const [showTransfer, setShowTransfer] = useState(false);
  const [transferNewOwnerId, setTransferNewOwnerId] = useState("");
  const [transferConfirmName, setTransferConfirmName] = useState("");

  // Load organizations
  const { data: orgData, isLoading: isLoadingOrgs } = useListOrgsQuery({});
  const organizations = orgData?.myOrganizations;

  // Load members for selected org
  const { data: memberData, isLoading: isLoadingMembers } =
    useListOrgMembersQuery(
      { orgId: selectedOrgId! },
      { enabled: !!selectedOrgId },
    );
  const members = memberData?.organizationMembers;

  const selectedOrg = organizations?.find((o) => o.id === selectedOrgId);

  const createOrgMutation = useCreateOrgMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ListOrgs"] });
      setShowCreate(false);
      setNewOrgName("");
      setNewOrgSlug("");
      toast.success("Organization created successfully");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to create organization"),
      );
    },
  });

  const removeMemberMutation = useRemoveMemberMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["ListOrgMembers", { orgId: selectedOrgId }],
      });
      toast.success("Member removed");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to remove member"),
      );
    },
  });

  const inviteMemberMutation = useInviteMemberMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["ListOrgMembers", { orgId: selectedOrgId }],
      });
      setShowInvite(false);
      setInviteUserId("");
      setInviteRole("member");
      toast.success("Member invited");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to invite member"),
      );
    },
  });

  const updateMemberRoleMutation = useUpdateMemberRoleMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["ListOrgMembers", { orgId: selectedOrgId }],
      });
      setRoleChangeTarget(null);
      toast.success("Role updated");
    },
    onError: (err: Error) => {
      toast.error(sanitizeErrorMessage(err.message || "Failed to update role"));
    },
  });

  const transferOwnershipMutation = useTransferOwnershipMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ListOrgs"] });
      setShowTransfer(false);
      setTransferNewOwnerId("");
      setTransferConfirmName("");
      toast.success("Ownership transferred");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to transfer ownership"),
      );
    },
  });

  const handleInvite = () => {
    if (!selectedOrgId || !inviteUserId.trim()) return;
    inviteMemberMutation.mutate({
      orgId: selectedOrgId,
      targetUserId: inviteUserId.trim(),
      role: inviteRole,
    });
  };

  const handleUpdateRole = () => {
    if (!selectedOrgId || !roleChangeTarget) return;
    updateMemberRoleMutation.mutate({
      orgId: selectedOrgId,
      targetUserId: roleChangeTarget.userId,
      role: roleChangeTarget.newRole,
    });
  };

  const handleTransferOwnership = () => {
    if (!selectedOrgId || !transferNewOwnerId.trim()) return;
    transferOwnershipMutation.mutate({
      orgId: selectedOrgId,
      newOwnerId: transferNewOwnerId.trim(),
    });
  };

  return (
    <div className="max-w-6xl mx-auto py-4 space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div className="flex items-center gap-6">
          <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[2rem] flex items-center justify-center text-primary shadow-[0_0_30px_hsla(var(--primary),0.1)] relative group">
            <div className="absolute inset-0 bg-primary/5 rounded-full blur-xl animate-pulse" />
            <Building2
              size={32}
              className="relative z-10 group-hover:scale-110 transition-premium"
            />
          </div>
          <div>
            <SectionHeader
              level="h2"
              className="text-2xl md:text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-1 leading-tight"
            >
              Organizations
            </SectionHeader>
            <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em]">
              Collaborative Workspaces & Team Governance
            </p>
          </div>
        </div>
        <Button
          onClick={() => setShowCreate(true)}
          variant="premium"
          className="h-14 px-8 rounded-2xl shadow-2xl flex items-center gap-3 w-full md:w-auto"
        >
          <Plus className="w-5 h-5" />
          NEW_ORGANIZATION
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-10">
        <OrgListSidebar
          organizations={organizations}
          isLoading={isLoadingOrgs}
          selectedOrgId={selectedOrgId}
          onSelect={setSelectedOrgId}
        />

        <div className="md:col-span-3">
          {selectedOrgId ? (
            <OrgDetailsPanel
              selectedOrg={selectedOrg}
              members={members}
              isLoadingMembers={isLoadingMembers}
              currentUserId={user?.id}
              onShowTransfer={() => setShowTransfer(true)}
              onShowInvite={() => setShowInvite(true)}
              onRoleChange={setRoleChangeTarget}
              onRemoveMember={(userId) =>
                removeMemberMutation.mutate({
                  orgId: selectedOrgId!,
                  userId,
                })
              }
            />
          ) : (
            <NoOrgSelected />
          )}
        </div>
      </div>

      <CreateOrgDialog
        open={showCreate}
        name={newOrgName}
        slug={newOrgSlug}
        isPending={createOrgMutation.isPending}
        onNameChange={(name, derivedSlug) => {
          setNewOrgName(name);
          if (derivedSlug !== undefined) setNewOrgSlug(derivedSlug);
        }}
        onSlugChange={setNewOrgSlug}
        onClose={() => {
          setShowCreate(false);
          setNewOrgName("");
          setNewOrgSlug("");
        }}
        onAbort={() => setShowCreate(false)}
        onSubmit={() =>
          createOrgMutation.mutate({
            name: newOrgName,
            slug: newOrgSlug,
          })
        }
      />

      <InviteMemberDialog
        open={showInvite}
        orgName={selectedOrg?.name}
        userId={inviteUserId}
        role={inviteRole}
        isPending={inviteMemberMutation.isPending}
        onUserIdChange={setInviteUserId}
        onRoleChange={setInviteRole}
        onClose={() => setShowInvite(false)}
        onSubmit={handleInvite}
      />

      <RoleChangeDialog
        target={roleChangeTarget}
        isPending={updateMemberRoleMutation.isPending}
        onClose={() => setRoleChangeTarget(null)}
        onConfirm={handleUpdateRole}
      />

      <TransferOwnershipDialog
        open={showTransfer}
        orgName={selectedOrg?.name}
        newOwnerId={transferNewOwnerId}
        confirmName={transferConfirmName}
        isPending={transferOwnershipMutation.isPending}
        onNewOwnerIdChange={setTransferNewOwnerId}
        onConfirmNameChange={setTransferConfirmName}
        onClose={() => setShowTransfer(false)}
        onSubmit={handleTransferOwnership}
      />
    </div>
  );
}
