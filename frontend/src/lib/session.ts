/**
 * The session's ONE home for three things every authenticated request path
 * used to carry its own copy of (2026-09-22, package DP):
 *
 *   1. the CSRF-cookie seed (`GET /auth/csrf`, deduplicated in flight);
 *   2. the access-token refresh (`mutation RefreshToken`, deduplicated in
 *      flight);
 *   3. the "was that an auth failure?" string match that decides whether a
 *      failed request should try 2 and retry.
 *
 * Before this module `graphqlClient.ts` and `authedFetch.ts` each held their
 * own copy of 1 and 2 with their OWN in-flight promise, and the 14-minute
 * timer (`useTokenRefresh` → `auth.refreshAccessToken`) issued the mutation
 * through `graphqlRequest` with neither. Three refresh callers, two
 * dedupers, so a GraphQL 401, a REST 401 and the timer could refresh
 * CONCURRENTLY. Refresh tokens rotate, so the loser sends an already-rotated
 * token and the server's reuse detector answers `within_grace` (the arm that
 * exists for real multi-tab races), failing the losing request with an auth
 * error the user sees. Measured in `rotated_session_audit`: 95 rotation
 * pairs, 2 of them 0.4 s apart — the client racing itself after an idle
 * dashboard load. The two copies had also drifted once before: the REST
 * seed GET /graphql (a 405 in production) after the GraphQL one had moved to
 * /auth/csrf.
 *
 * 2026-09-22, package DS — the SECOND gap, measured on the first dashboard
 * load after DP deployed: two rotations 0.4 s apart, both successful,
 * `within_grace` 0. The in-flight promise covers callers whose failures
 * OVERLAP; it cannot cover a request that was already on the wire with the
 * stale cookie when the refresh settled — its 401 arrives AFTER
 * `activeRefresh` cleared, so it started a second, redundant refresh (one
 * wasted mutation and one extra rotation per load after idle). The refresh
 * EPOCH closes that gap: every caller captures `currentRefreshEpoch()` before
 * it sends, and on an auth failure asks `recoverSession(epochAtSend)`, which
 * answers "already fresh" without a network call when a refresh SUCCEEDED
 * after the request was sent, and otherwise joins or starts one. The epoch
 * advances on success only: a failed refresh must never make a later 401
 * assume the cookie is fresh.
 *
 * This module imports only `config` and `csrf` — never a request wrapper —
 * so it can never form a cycle with the callers it serves.
 */

import { config } from "@/config";
import { getCsrfToken } from "@/lib/csrf";

const API_URL = config.apiUrl || "";

/** The user the backend returns beside the rotated cookies. */
export interface RefreshedUser {
  id: string;
  email: string;
  name?: string;
  twoFactorEnabled: boolean;
  isTwoFactorVerified: boolean;
}

/**
 * One outcome for every caller. `refreshed: false` is the ONLY failure shape
 * — a network error, a non-JSON body, a GraphQL error and a missing payload
 * all collapse to it on purpose: every caller's next step is the same
 * ("do not retry; surface the original failure"), and the refresh token is
 * an HttpOnly cookie the client cannot inspect, so there is nothing more
 * specific the client could act on.
 */
export type RefreshOutcome =
  | { refreshed: true; user: RefreshedUser }
  | { refreshed: false };

/** ONE copy of the mutation text; selects every field any caller reads. */
export const REFRESH_TOKEN_MUTATION = `
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

let activeRefresh: Promise<RefreshOutcome> | null = null;
let activeSeed: Promise<void> | null = null;
/** Advances by one each time a refresh SUCCEEDS; never on failure. */
let refreshEpoch = 0;

async function doRefresh(): Promise<RefreshOutcome> {
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    // The refresh token itself travels in an HttpOnly cookie; the body
    // carries nothing secret.
    const resp = await fetch(`${API_URL}/graphql`, {
      method: "POST",
      headers,
      credentials: "include",
      cache: "no-store",
      body: JSON.stringify({ query: REFRESH_TOKEN_MUTATION }),
    });
    const text = await resp.text();
    let json: { data?: unknown; errors?: unknown[] };
    try {
      json = JSON.parse(text) as { data?: unknown; errors?: unknown[] };
    } catch {
      if (import.meta.env.DEV) console.error("Failed to parse response:", text);
      return { refreshed: false };
    }
    if (json.errors?.length) {
      return { refreshed: false };
    }
    const data = json.data as {
      refreshToken?: { user?: RefreshedUser };
    } | null;
    const user = data?.refreshToken?.user;
    if (!user || typeof user !== "object" || typeof user.id !== "string") {
      return { refreshed: false };
    }
    return { refreshed: true, user };
  } catch {
    return { refreshed: false };
  }
}

/**
 * Refresh the session's cookies. Every concurrent caller — a GraphQL request
 * that saw an auth error, a REST request that saw a 401, the WebSocket
 * reconnect, the 14-minute timer — shares ONE in-flight mutation; the next
 * call after it settles starts a new one.
 */
export function refreshSession(): Promise<RefreshOutcome> {
  if (activeRefresh) return activeRefresh;
  activeRefresh = doRefresh()
    .then((outcome) => {
      if (outcome.refreshed) refreshEpoch += 1;
      return outcome;
    })
    .finally(() => {
      activeRefresh = null;
    });
  return activeRefresh;
}

/**
 * The number of refreshes that have SUCCEEDED in this page's lifetime.
 * Capture it immediately before sending a request; hand it to
 * `recoverSession` if that request fails authentication.
 */
export function currentRefreshEpoch(): number {
  return refreshEpoch;
}

/**
 * The decision, kept pure so it can be pinned: a request sent at
 * `epochAtSend` already has a fresher cookie waiting if a refresh has
 * succeeded since — retrying is enough, refreshing again is a wasted
 * mutation and an extra rotation. Equality means nothing succeeded since
 * (a failed refresh does not advance the epoch), so a refresh is needed.
 */
export function refreshSucceededSince(
  epochAtSend: number,
  epochNow: number,
): boolean {
  return epochNow > epochAtSend;
}

/**
 * Recover a request that failed authentication: `true` means "retry now,
 * the cookie is fresh". No network call when a refresh already succeeded
 * after the request was sent; otherwise the shared in-flight refresh (or a
 * new one). The caller's `isRetry` guard still bounds this to ONE recovery
 * per request, so a cookie that is fresh and still refused surfaces the
 * original failure rather than looping.
 */
export async function recoverSession(epochAtSend: number): Promise<boolean> {
  if (refreshSucceededSince(epochAtSend, refreshEpoch)) return true;
  return attemptTokenRefresh();
}

/** `refreshSession()` collapsed to the boolean the retry paths branch on. */
export async function attemptTokenRefresh(): Promise<boolean> {
  return (await refreshSession()).refreshed;
}

/**
 * Seed the CSRF cookie by GET-ing `/auth/csrf` — the dedicated endpoint that
 * builds its Set-Cookie header by hand. `/graphql` is 405 in production and
 * `/health` has no CSRF middleware in its router branch; neither sets the
 * cookie. Concurrent callers on a fresh session share one GET.
 */
export function seedCsrfCookie(): Promise<void> {
  if (activeSeed) return activeSeed;
  activeSeed = (async () => {
    try {
      await fetch(`${API_URL}/auth/csrf`, {
        method: "GET",
        credentials: "include",
      });
    } catch {
      // Best-effort — if this fails the subsequent request surfaces a clear error.
    }
  })().finally(() => {
    activeSeed = null;
  });
  return activeSeed;
}

/** Seed only when the cookie is absent. */
export async function ensureCsrfCookie(): Promise<void> {
  if (!getCsrfToken()) {
    await seedCsrfCookie();
  }
}

/**
 * Does a server message mean "your session is not (or no longer) valid"?
 * The one place the three phrasings the backend uses are listed; a fourth
 * phrasing is added here, not at a call site.
 */
export function isAuthErrorMessage(message: unknown): boolean {
  const m = String(message ?? "");
  return (
    m.includes("Authentication required") ||
    m.includes("Not authenticated") ||
    m.includes("expired")
  );
}
