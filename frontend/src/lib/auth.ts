import { graphqlRequest } from "@/lib/graphqlClient";
import { refreshSession } from "@/lib/session";
import { useWorkflowStore } from "@/store/workflowStore";
import { useUIStore } from "@/store/uiStore";
import {
  useEphemeralExecutionStore,
  usePersistedExecutionStore,
} from "@/store/executionStore";

// MCP-933 (2026-05-15): removed the parallel `useAuthStore` Zustand
// store plus `StoredUserProfile`, `clearUserData()`,
// `getStoredUser()`, `setStoredUser()`, and the standalone
// `isAuthenticated()` helper. None had a production consumer —
// production auth state lives entirely in `AuthContext` (which is
// already consumed by App.tsx, AuthForm, OAuthCallback, etc. via
// `useAuth()`). The dead store was kept alive only by mutual
// reference: signup/login/verifyTwoFactor/fetchCurrentUser/
// refreshAccessToken each called `setStoredUser`, and the test
// file in __tests__/auth.test.ts asserted the dead store was
// mutated correctly. Same dead-API-surface class as MCP-931.
// Removing it eliminates the "two parallel user stores, only one
// matters" trap for future contributors and the test debt of
// validating writes to a store no UI reads from.

export interface User {
  id: string;
  email: string;
  name?: string;
  twoFactorEnabled: boolean;
  isTwoFactorVerified: boolean;
}

export interface AuthResponse {
  user: User;
}

// Auth API calls
export async function signup(
  email: string,
  password: string,
  name?: string,
): Promise<AuthResponse> {
  const mutation = `
    mutation Signup($input: SignupInput!) {
      signup(input: $input) {
        user {
          id
          email
          name
          twoFactorEnabled
          isTwoFactorVerified
        }
      }
    }
  `;

  const result = await graphqlRequest<{ signup: AuthResponse }>(mutation, {
    input: { email, password, name },
  });

  return result.signup;
}

export async function login(
  email: string,
  password: string,
): Promise<AuthResponse> {
  const mutation = `
    mutation Login($input: LoginInput!) {
      login(input: $input) {
        user {
          id
          email
          name
          twoFactorEnabled
          isTwoFactorVerified
        }
      }
    }
  `;

  const result = await graphqlRequest<{ login: AuthResponse }>(mutation, {
    input: { email, password },
  });

  return result.login;
}

// The documents in this file are bare template literals — no `gql` tag — so
// graphql-codegen never plucks or validates them. Until 2026-09-22 this one
// named its input `VerifyTwoFactorInput`; the schema has called it
// `Verify2FAInput` since at least 2026-05-18, so every 2FA login died at
// schema validation before the code reached the verifier (0 server-side
// attempts against 8 pending sessions on the first enrolled login). Every
// bare document in `src/` is now validated against `schema.graphql` by
// `__tests__/inline_documents.test.ts`.
export async function verifyTwoFactor(code: string): Promise<User> {
  const mutation = `
    mutation VerifyTwoFactor($input: Verify2FAInput!) {
      verifyTwoFactor(input: $input) {
        user {
          id
          email
          name
          twoFactorEnabled
          isTwoFactorVerified
        }
      }
    }
  `;

  const result = await graphqlRequest<{ verifyTwoFactor: AuthResponse }>(
    mutation,
    {
      input: { code },
    },
  );

  return result.verifyTwoFactor.user;
}

export async function fetchCurrentUser(): Promise<User> {
  const query = `
    query Me {
      me {
        id
        email
        name
        twoFactorEnabled
        isTwoFactorVerified
      }
    }
  `;

  const result = await graphqlRequest<{ me: User }>(query);
  return result.me;
}

/**
 * The 14-minute timer's refresh. Goes through `session.refreshSession`, the
 * ONE in-flight mutation every other refresh path shares — it used to issue
 * its own `refreshToken` through `graphqlRequest`, outside both wrappers'
 * dedupers, so a timer tick could race a 401-triggered refresh.
 */
export async function refreshAccessToken(): Promise<AuthResponse> {
  const outcome = await refreshSession();
  if (!outcome.refreshed) {
    throw new Error("Session refresh failed");
  }
  return { user: outcome.user };
}

export async function logout(): Promise<void> {
  try {
    const mutation = `
      mutation Logout {
        logout
      }
    `;

    await graphqlRequest<{ logout: boolean }>(mutation);
  } catch {
    // Continue with local cleanup even if backend logout fails
  }

  // Full resets: a partial one left the dirty flag, graph version and the
  // last user's run history (sessionStorage) behind for the next sign-in.
  useWorkflowStore.getState().clearWorkflow();
  useEphemeralExecutionStore.getState().resetNodeStatuses();
  useEphemeralExecutionStore.getState().clearEvents();
  useEphemeralExecutionStore.getState().clearCurrentExecution();
  usePersistedExecutionStore.setState({ workflowStatuses: {} });
  usePersistedExecutionStore.persist.clearStorage();
  useUIStore.setState({
    showToolbox: true,
    toolboxMode: "full",
    showInspector: false,
    terminalState: "collapsed",
    selectedNodeId: null,
    favoriteTemplates: [],
    recentTemplates: [],
  });
  useUIStore.persist.clearStorage();

  window.location.href = "/";
}
