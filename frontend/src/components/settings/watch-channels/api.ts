/**
 * Shared plumbing for the watch-channel settings panels
 * (GoogleCalendarWatchChannels / GoogleCloudWatchChannels).
 *
 * These panels talk to the controller's REST integration endpoints
 * (not GraphQL), so they share a CSRF-aware fetch helper and the
 * ApiJson envelope shape.
 */

import { ensureCsrfCookie } from "@/lib/authedFetch";
import { getCsrfToken } from "@/lib/csrf";

/**
 * CSRF-aware fetch for the watch-channel panels.
 *
 * Deliberately NOT a re-export of `@/lib/authedFetch`: that helper throws on
 * any non-2xx response, while every caller here reads the ApiJson envelope
 * (`{ success, data, error }`) off the body — including 4xx bodies — and
 * renders `body.error` itself. What it DOES share is the CSRF seed: before
 * this change a fresh session's first watch-channel POST went out with no
 * X-CSRF-Token at all (the cookie is only minted by GET /auth/csrf, which
 * nothing on this path had called yet) and failed CSRF. `ensureCsrfCookie`
 * seeds through the one correct endpoint, then the token is attached.
 */
export async function authedFetch(
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  await ensureCsrfCookie();
  const csrf = getCsrfToken();
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (csrf) headers["X-CSRF-Token"] = csrf;
  return fetch(url, { ...init, credentials: "include", headers });
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Present iff the most recent renewal/push attempt failed. The
 * backend omits the field via serde's skip_serializing_if, so
 * undefined is the common case.
 */
export interface RecentFailure {
  error_message: string;
  failed_at: string;
  likely_oauth_failure: boolean;
}
