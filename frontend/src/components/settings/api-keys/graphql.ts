/**
 * GraphQL operation documents for the API-keys settings panel.
 *
 * These are codegen source documents (picked up by the `src/**` documents
 * glob in codegen.yml) — the components consume the generated hooks from
 * `@/generated/graphql`, not these constants directly.
 */

import { gql } from "@/lib/graphqlClient";

const _LIST_API_KEYS = gql`
  query ListApiKeys($pagination: PaginationInput) {
    apiKeys(pagination: $pagination) {
      id
      name
      keyPrefix
      scopes
      createdAt
      expiresAt
      lastUsedAt
      isActive
      usageCount
    }
  }
`;

const _CREATE_API_KEY = gql`
  mutation CreateApiKey($input: CreateApiKeyInput!) {
    createApiKey(input: $input) {
      id
      name
      key
      scopes
      expiresAt
    }
  }
`;

const _REVOKE_API_KEY = gql`
  mutation RevokeApiKey($keyId: UUID!) {
    revokeApiKey(keyId: $keyId)
  }
`;

const _ROTATE_API_KEY = gql`
  mutation RotateApiKey($keyId: UUID!) {
    rotateApiKey(keyId: $keyId) {
      id
      name
      key
      scopes
      expiresAt
    }
  }
`;

const _DELETE_API_KEY = gql`
  mutation DeleteApiKey($keyId: UUID!) {
    deleteApiKey(keyId: $keyId)
  }
`;
