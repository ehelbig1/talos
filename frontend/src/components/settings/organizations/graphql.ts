// GraphQL operation documents for the Organizations settings surface.
//
// These tagged templates exist for codegen discovery (the codegen
// `documents` glob over src plucks gql`...` templates); the typed hooks
// components actually call live in `@/generated/graphql`. Shared prop
// types for the decomposed subcomponents are derived from the generated
// query types below.

import { gql } from "@/lib/graphqlClient";
import type { ListOrgMembersQuery, ListOrgsQuery } from "@/generated/graphql";

export type Org = ListOrgsQuery["myOrganizations"][number];
export type OrgMember = ListOrgMembersQuery["organizationMembers"][number];

export const ROLE_OPTIONS = ["viewer", "member", "admin"] as const;
export type Role = (typeof ROLE_OPTIONS)[number];

// GQL tags for codegen
export const LIST_ORGS = gql`
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

export const LIST_ORG_MEMBERS = gql`
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

export const CREATE_ORG = gql`
  mutation CreateOrg($name: String!, $slug: String!) {
    createOrganization(name: $name, slug: $slug) {
      id
      name
    }
  }
`;

export const REMOVE_MEMBER = gql`
  mutation RemoveMember($orgId: UUID!, $userId: UUID!) {
    removeMember(orgId: $orgId, targetUserId: $userId)
  }
`;

export const INVITE_MEMBER = gql`
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

export const UPDATE_MEMBER_ROLE = gql`
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

export const TRANSFER_OWNERSHIP = gql`
  mutation TransferOwnership($orgId: UUID!, $newOwnerId: UUID!) {
    transferOwnership(orgId: $orgId, newOwnerId: $newOwnerId) {
      id
      name
      ownerId
    }
  }
`;
