import { graphqlRequest } from "@/lib/graphqlClient";
import { useWorkflowStore } from "@/store/workflowStore";
import { useUIStore } from "@/store/uiStore";

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

export async function verifyTwoFactor(code: string): Promise<User> {
  const mutation = `
    mutation VerifyTwoFactor($input: VerifyTwoFactorInput!) {
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

export async function refreshAccessToken(): Promise<AuthResponse> {
  const mutation = `
    mutation RefreshToken {
      refreshToken {
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

  const result = await graphqlRequest<{ refreshToken: AuthResponse }>(mutation);
  return result.refreshToken;
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

  useWorkflowStore.setState({
    nodes: [],
    edges: [],
    workflowId: null,
    workflowName: "Untitled Workflow",
  });
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
