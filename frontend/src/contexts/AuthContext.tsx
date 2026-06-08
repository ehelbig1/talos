import React, { createContext, useContext, useState, useEffect } from "react";
import type { ReactNode } from "react";
import { logout as authLogout, fetchCurrentUser } from "@/lib/auth";
import type { User } from "@/lib/auth";

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isTwoFactorVerified: boolean;
  isLoading: boolean;
  // MCP-931 (2026-05-14): `login` is now `(user: User) => void`. The
  // historic `verified?: boolean` second parameter was dead surface
  // — the implementation silently ignored it, no caller ever passed
  // it, and `isTwoFactorVerified` is derived from
  // `user.isTwoFactorVerified` via the useEffect below. Likewise
  // `setTwoFactorVerified` was exposed in this type but had no
  // external consumer (only AuthContext itself read it). Removing
  // both tightens the API so future contributors can't mistakenly
  // rely on a "knob" that doesn't actually do anything.
  login: (user: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // `isTwoFactorVerified` is PURELY derived from the current user — there
  // is no independent "verify" path that sets it without also updating
  // `user` (login re-fetches the user; logout nulls it). Deriving it
  // during render instead of mirroring it into state via an effect
  // removes the redundant double-render on every `setUser` and the
  // state-desync hazard the mirror created (react-hooks/set-state-in-effect).
  const isTwoFactorVerified = user?.isTwoFactorVerified ?? false;

  useEffect(() => {
    let mounted = true;
    async function initAuth() {
      try {
        const currentUser = await fetchCurrentUser();
        if (mounted) {
          setUser(currentUser);
        }
      } catch (err) {
        // Not logged in or token expired/invalid
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }
    initAuth();
    return () => {
      mounted = false;
    };
  }, []);

  const login = (newUser: User) => {
    setUser(newUser);
  };

  const logout = () => {
    // Nulling the user makes the derived `isTwoFactorVerified` false; no
    // separate setter needed.
    setUser(null);
    authLogout();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated:
          !!user && (!user.twoFactorEnabled || isTwoFactorVerified),
        isTwoFactorVerified,
        isLoading,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
