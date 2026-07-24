/**
 * Shared plumbing for the watch-channel settings panels
 * (GoogleCalendarWatchChannels / GoogleCloudWatchChannels).
 *
 * These panels talk to the controller's REST integration endpoints
 * (not GraphQL), so they share a CSRF-aware fetch helper and the
 * ApiJson envelope shape.
 */

import { getCsrfToken } from "@/lib/csrf";

export function authedFetch(
  url: string,
  init: RequestInit = {},
): Promise<Response> {
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
