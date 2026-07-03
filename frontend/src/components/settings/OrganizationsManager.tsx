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
import { gql } from "@/lib/graphqlClient";
import { Card } from "@/components/ui/card";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { Input } from "@/components/ui/input";
import {
  Building2,
  Plus,
  Users,
  UserPlus,
  Trash2,
  ShieldCheck,
  Globe,
  Mail,
  AlertTriangle,
  ArrowRightLeft,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDate } from "@/lib/format";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/contexts/AuthContext";

// GQL tags for codegen
const _LIST_ORGS = gql`
  query ListOrgs {
    myOrganizations {
      id
      name
      slug
      ownerId
      createdAt
      updatedAt
    }
  }
`;

const _LIST_ORG_MEMBERS = gql`
  query ListOrgMembers($orgId: UUID!) {
    organizationMembers(orgId: $orgId) {
      id
      orgId
      userId
      role
      invitedBy
      joinedAt
    }
  }
`;

const _CREATE_ORG = gql`
  mutation CreateOrg($name: String!, $slug: String!) {
    createOrganization(name: $name, slug: $slug) {
      id
      name
    }
  }
`;

const _REMOVE_MEMBER = gql`
  mutation RemoveMember($orgId: UUID!, $userId: UUID!) {
    removeMember(orgId: $orgId, targetUserId: $userId)
  }
`;

const _INVITE_MEMBER = gql`
  mutation InviteMember($orgId: UUID!, $targetUserId: UUID!, $role: String!) {
    inviteMember(orgId: $orgId, targetUserId: $targetUserId, role: $role) {
      id
      orgId
      userId
      role
      invitedBy
      joinedAt
    }
  }
`;

const _UPDATE_MEMBER_ROLE = gql`
  mutation UpdateMemberRole(
    $orgId: UUID!
    $targetUserId: UUID!
    $role: String!
  ) {
    updateMemberRole(orgId: $orgId, targetUserId: $targetUserId, role: $role) {
      id
      orgId
      userId
      role
      joinedAt
    }
  }
`;

const _TRANSFER_OWNERSHIP = gql`
  mutation TransferOwnership($orgId: UUID!, $newOwnerId: UUID!) {
    transferOwnership(orgId: $orgId, newOwnerId: $newOwnerId) {
      id
      name
      ownerId
    }
  }
`;

const ROLE_OPTIONS = ["viewer", "member", "admin"] as const;
type Role = (typeof ROLE_OPTIONS)[number];

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
  const [roleChangeTarget, setRoleChangeTarget] = useState<{
    userId: string;
    currentRole: string;
    newRole: Role;
  } | null>(null);

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

  const isTransferConfirmed = transferConfirmName.trim() === selectedOrg?.name;

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
        {/* Org List */}
        <div className="md:col-span-1 space-y-4">
          <div className="text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground/20 px-1 mb-2">
            Active_Protocols
          </div>
          {isLoadingOrgs ? (
            <div className="py-12 flex justify-center bg-white/[0.02] border border-white/5 rounded-[2rem]">
              <LoadingSpinner />
            </div>
          ) : organizations?.length === 0 ? (
            <div className="p-10 border border-dashed border-white/5 rounded-[2rem] text-center bg-white/[0.01]">
              <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest">
                No active organizations
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {organizations?.map((org) => (
                <button
                  type="button"
                  key={org.id}
                  onClick={() => setSelectedOrgId(org.id)}
                  className={cn(
                    "w-full flex items-center gap-4 p-4 rounded-[1.5rem] border transition-premium text-left relative overflow-hidden group",
                    selectedOrgId === org.id
                      ? "bg-primary/10 border-primary/40 shadow-[0_0_20px_hsla(var(--primary),0.1)]"
                      : "bg-white/[0.02] border-white/5 hover:bg-white/[0.04] hover:border-white/10",
                  )}
                >
                  <div
                    className={cn(
                      "w-12 h-12 rounded-xl flex items-center justify-center text-xl font-black font-outfit shadow-2xl transition-premium group-hover:scale-110",
                      selectedOrgId === org.id
                        ? "bg-primary text-white"
                        : "bg-white/5 text-muted-foreground/60",
                    )}
                  >
                    {org.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0 relative z-10">
                    <div
                      className={cn(
                        "text-sm font-black tracking-tight uppercase font-outfit truncate transition-premium",
                        selectedOrgId === org.id
                          ? "text-white"
                          : "text-muted-foreground/60 group-hover:text-white",
                      )}
                    >
                      {org.name}
                    </div>
                    <div className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest mt-1 truncate">
                      /{org.slug}
                    </div>
                  </div>
                  {selectedOrgId === org.id && (
                    <div className="absolute right-4 w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Selected Org Details */}
        <div className="md:col-span-3">
          {selectedOrgId ? (
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
                          <Globe className="w-3.5 h-3.5 text-primary" />{" "}
                          talos.sh/
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
                      onClick={() => setShowTransfer(true)}
                    >
                      <ArrowRightLeft className="w-4 h-4 mr-3" />{" "}
                      TRANSFER_OWNERSHIP
                    </Button>
                    <Button
                      variant="premium"
                      className="flex-1 md:flex-none h-12 px-8 rounded-xl"
                      onClick={() => setShowInvite(true)}
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
                      {members?.map((member) => {
                        const isCurrentUser = member.userId === user?.id;
                        return (
                          <div
                            key={member.id}
                            className="flex items-center justify-between p-4 bg-white/[0.02] hover:bg-white/[0.04] border border-white/5 hover:border-white/10 rounded-2xl transition-premium group"
                          >
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
                                  ENROLLED {formatDate(member.joinedAt)} &bull;
                                  ID: {member.userId.slice(0, 8)}
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
                                        setRoleChangeTarget({
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
                                  onClick={() =>
                                    removeMemberMutation.mutate({
                                      orgId: selectedOrgId!,
                                      userId: member.userId,
                                    })
                                  }
                                  className="p-2.5 text-muted-foreground/30 hover:text-destructive hover:bg-destructive/10 rounded-xl transition-premium opacity-0 group-hover:opacity-100 border border-transparent hover:border-destructive/20"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      })}
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
                    Enforce strict RBAC policies for this organization. Admin
                    roles can manage secrets and deployments.
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
                    You have no pending invitations for this organization. All
                    team members have active accounts.
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
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-12 border border-dashed border-white/5 rounded-[2.5rem] bg-white/[0.01]">
              <div className="w-16 h-16 bg-white/5 rounded-[1.5rem] flex items-center justify-center mb-6 border border-white/10">
                <Building2 className="w-8 h-8 text-muted-foreground/40" />
              </div>
              <h3 className="text-sm font-black text-white/40 uppercase tracking-widest mb-3 font-outfit">
                No Organization Selected
              </h3>
              <p className="text-[10px] text-muted-foreground/30 font-black uppercase tracking-widest text-center max-w-xs leading-relaxed">
                Select an organization from the left to manage members and
                settings.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Create Organization Dialog */}
      <Dialog
        open={showCreate}
        onClose={() => {
          setShowCreate(false);
          setNewOrgName("");
          setNewOrgSlug("");
        }}
        title="Establish Syndicate"
      >
        <div className="space-y-8">
          <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-4">
            <Building2 className="w-5 h-5 text-primary shrink-0 mt-0.5" />
            <p className="text-[11px] text-muted-foreground/60 leading-relaxed font-medium">
              Establish a new governing protocol. Organizations allow you to
              group multiple operatives and resources under a single
              administrative umbrella.
            </p>
          </div>

          <div className="space-y-6">
            <div className="space-y-2.5">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
                Organization_Identity
              </label>
              <div className="relative group">
                <Input
                  placeholder="e.g. TACTICAL_UNIT_ALPHA"
                  value={newOrgName}
                  onChange={(e) => {
                    setNewOrgName(e.target.value);
                    if (!newOrgSlug) {
                      setNewOrgSlug(
                        e.target.value
                          .toLowerCase()
                          .replace(/\s+/g, "-")
                          .replace(/[^a-z0-9-]/g, ""),
                      );
                    }
                  }}
                  className="h-14 bg-white/[0.03] border-white/10 focus:border-primary/50 focus:ring-primary/20 rounded-xl px-4 font-outfit text-white placeholder:text-white/10 transition-premium"
                />
              </div>
            </div>

            <div className="space-y-2.5">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
                Uplink_Identifier
              </label>
              <div className="relative flex items-center">
                <span className="absolute left-4 text-muted-foreground/30 font-outfit text-sm">
                  talos.sh/
                </span>
                <Input
                  placeholder="tactical-alpha"
                  value={newOrgSlug}
                  onChange={(e) =>
                    setNewOrgSlug(
                      e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""),
                    )
                  }
                  className="h-14 bg-white/[0.03] border-white/10 focus:border-primary/50 focus:ring-primary/20 rounded-xl pl-[4.5rem] font-mono text-sm text-white placeholder:text-white/10 transition-premium"
                />
              </div>
              <p className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-widest ml-1">
                LOWERCASE_ALPHANUMERIC_ONLY
              </p>
            </div>
          </div>

          <div className="flex gap-4 pt-4">
            <Button
              variant="outline"
              className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
              onClick={() => setShowCreate(false)}
            >
              ABORT_MISSION
            </Button>
            <Button
              variant="premium"
              className="flex-1 h-14 rounded-xl shadow-2xl"
              disabled={
                !newOrgName || !newOrgSlug || createOrgMutation.isPending
              }
              onClick={() =>
                createOrgMutation.mutate({
                  name: newOrgName,
                  slug: newOrgSlug,
                })
              }
            >
              {createOrgMutation.isPending ? (
                <LoadingSpinner />
              ) : (
                "ESTABLISH_UPLINK"
              )}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Invite Member Dialog */}
      <Dialog
        open={showInvite}
        onClose={() => setShowInvite(false)}
        title="Protocol_Enrolment"
      >
        <div className="space-y-8">
          <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-4">
            <UserPlus className="w-5 h-5 text-primary shrink-0 mt-0.5" />
            <p className="text-[11px] text-muted-foreground/60 leading-relaxed font-medium">
              Invite a new operative to the{" "}
              <span className="text-white font-black">{selectedOrg?.name}</span>{" "}
              syndicate. Access privileges are defined by the selected protocol
              role.
            </p>
          </div>

          <div className="space-y-6">
            <div className="space-y-2.5">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
                Operative_UUID
              </label>
              <Input
                placeholder="Target User Identifier"
                value={inviteUserId}
                onChange={(e) => setInviteUserId(e.target.value)}
                className="h-14 bg-white/[0.03] border-white/10 focus:border-primary/50 focus:ring-primary/20 rounded-xl px-4 font-mono text-sm text-white placeholder:text-white/10 transition-premium"
              />
            </div>

            <div className="space-y-3">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
                Protocol_Clearance_Level
              </label>
              <div className="flex gap-2 p-1.5 bg-black/40 border border-white/5 rounded-2xl">
                {ROLE_OPTIONS.map((role) => (
                  <button
                    key={role}
                    onClick={() => setInviteRole(role)}
                    className={cn(
                      "flex-1 py-3 px-4 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-premium",
                      inviteRole === role
                        ? "bg-primary/20 border border-primary/40 text-primary shadow-[0_0_15px_hsla(var(--primary),0.2)]"
                        : "text-muted-foreground/20 hover:text-white hover:bg-white/5 border border-transparent",
                    )}
                  >
                    {role}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="flex gap-4 pt-4">
            <Button
              variant="outline"
              className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
              onClick={() => setShowInvite(false)}
            >
              ABORT_ENROLMENT
            </Button>
            <Button
              variant="premium"
              className="flex-1 h-14 rounded-xl shadow-2xl"
              disabled={!inviteUserId.trim() || inviteMemberMutation.isPending}
              onClick={handleInvite}
            >
              {inviteMemberMutation.isPending ? (
                <LoadingSpinner />
              ) : (
                "DISPATCH_INVITE"
              )}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Update Role Confirmation Dialog */}
      <Dialog
        open={!!roleChangeTarget}
        onClose={() => setRoleChangeTarget(null)}
        title="Sync_Clearance"
      >
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
                {roleChangeTarget?.currentRole}
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
                {roleChangeTarget?.newRole}
              </div>
            </div>
          </div>

          <div className="flex gap-4 pt-4">
            <Button
              variant="outline"
              className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
              onClick={() => setRoleChangeTarget(null)}
            >
              ABORT_SYNC
            </Button>
            <Button
              variant="premium"
              className="flex-1 h-14 rounded-xl shadow-2xl"
              disabled={updateMemberRoleMutation.isPending}
              onClick={handleUpdateRole}
            >
              {updateMemberRoleMutation.isPending ? (
                <LoadingSpinner />
              ) : (
                "COMMIT_RESTRUCTURE"
              )}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Transfer Ownership Dialog */}
      <Dialog
        open={showTransfer}
        onClose={() => setShowTransfer(false)}
        title="Identity_Shift"
      >
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
                to another user. You will be demoted to Admin status
                immediately. This operation is irreversible without the new
                owner's consent.
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
                value={transferNewOwnerId}
                onChange={(e) => setTransferNewOwnerId(e.target.value)}
                className="h-14 bg-white/[0.03] border-white/10 focus:border-destructive/50 focus:ring-destructive/20 rounded-xl px-4 font-mono text-sm text-white placeholder:text-white/10 transition-premium"
              />
            </div>

            <div className="space-y-2.5">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
                Security_Verification
              </label>
              <div className="space-y-3">
                <p className="text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest ml-1">
                  Type <span className="text-white">"{selectedOrg?.name}"</span>{" "}
                  to confirm transfer
                </p>
                <Input
                  placeholder="Verification Phrase"
                  value={transferConfirmName}
                  onChange={(e) => setTransferConfirmName(e.target.value)}
                  className={cn(
                    "h-14 bg-white/[0.03] border-white/10 rounded-xl px-4 text-sm transition-premium",
                    transferConfirmName && !isTransferConfirmed
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
              onClick={() => setShowTransfer(false)}
            >
              CANCEL_TRANSFER
            </Button>
            <Button
              className="flex-1 h-14 rounded-xl bg-destructive hover:bg-destructive/90 text-white font-black uppercase text-[10px] tracking-widest shadow-2xl shadow-destructive/20"
              disabled={
                !transferNewOwnerId.trim() ||
                !isTransferConfirmed ||
                transferOwnershipMutation.isPending
              }
              onClick={handleTransferOwnership}
            >
              {transferOwnershipMutation.isPending ? (
                <LoadingSpinner />
              ) : (
                "EXECUTE_TRANSFER"
              )}
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
