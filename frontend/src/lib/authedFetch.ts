/**
 * Shared utility for making authenticated REST API calls with CSRF protection.
 * All non-GraphQL fetch() calls to the Talos backend should use this helper
 * so that CSRF tokens and credentials are always included.
 */

import { getCsrfToken } from "@/lib/csrf";
import {
  currentRefreshEpoch,
  ensureCsrfCookie,
  isAuthErrorMessage,
  recoverSession,
} from "@/lib/session";
// Re-exported so thin fetch helpers keep their import path (`@/lib/authedFetch`).
export { ensureCsrfCookie };
import { sanitizeErrorMessage } from "@/lib/sanitize";

// The CSRF seed, the token refresh and the auth-error match live in ONE home
// (`session.ts`, 2026-09-22). This file's own copies had already drifted from
// `graphqlClient.ts`'s once (they seeded from `/graphql`, a 405 in production,
// after the GraphQL client had moved to `/auth/csrf`), and their separate
// in-flight promise let the two wrappers refresh concurrently.

/**
 * A fetch wrapper that handles CSRF, Auth cookies, 401 retries, and error sanitization.
 */
export async function authedFetch(
  url: string,
  options: RequestInit = {},
  isRetry = false,
): Promise<Response> {
  await ensureCsrfCookie();

  const csrfToken = getCsrfToken();
  const headers: Record<string, string> = {
    ...((options.headers as Record<string, string>) ?? {}),
  };

  if (csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  // Add distributed trace ID for request correlation
  const traceId =
    crypto.randomUUID?.() || Math.random().toString(36).substring(2);
  headers["X-Trace-ID"] = traceId;

  // Standardize with 15s timeout to prevent hanging requests
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);

  // Captured BEFORE the request leaves — see `session.recoverSession`.
  const epochAtSend = currentRefreshEpoch();

  let resp: Response;
  try {
    resp = await fetch(url, {
      ...options,
      credentials: "include",
      headers,
      signal: controller.signal,
    });
  } catch (e: unknown) {
    clearTimeout(timeout);
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error("Request timed out – please try again.", { cause: e });
    }
    throw e;
  } finally {
    clearTimeout(timeout);
  }

  // ONE recovery attempt per request. The 401 arm and the auth-message-body
  // arm below used to be independent, so a 401 whose body also read
  // "Not authenticated" refreshed TWICE when the first refresh failed —
  // a second mutation against a session already known to be dead
  // (found by the DS tests, 2026-09-22).
  let recoveryTried = false;
  if (resp.status === 401 && !isRetry) {
    recoveryTried = true;
    const recovered = await recoverSession(epochAtSend);
    if (recovered) {
      return authedFetch(url, options, true);
    }
  }

  if (!resp.ok) {
    const text = await resp.text();
    // A non-401 status whose body is the backend's auth-failure sentence
    // (the 403-shaped variants) gets the same single recovery attempt.
    if (!isRetry && !recoveryTried && isAuthErrorMessage(text)) {
      const recovered = await recoverSession(epochAtSend);
      if (recovered) {
        return authedFetch(url, options, true);
      }
    }
    throw new Error(sanitizeErrorMessage(text || `HTTP ${resp.status}`));
  }

  return resp;
}
