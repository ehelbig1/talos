/**
 * Shared utility for making authenticated REST API calls with CSRF protection.
 * All non-GraphQL fetch() calls to the Talos backend should use this helper
 * so that CSRF tokens and credentials are always included.
 */

import { config } from "@/config";
import { getCsrfToken } from "@/lib/csrf";
import { sanitizeErrorMessage } from "@/lib/sanitize";

const API_URL = config.apiUrl || "";

let activeSeedPromise: Promise<void> | null = null;
let activeRefreshPromise: Promise<boolean> | null = null;

async function doTokenRefresh(): Promise<boolean> {
  try {
    const mutation = `
      mutation RefreshToken {
        refreshToken {
          user {
            id
          }
        }
      }
    `;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }

    const resp = await fetch(`${API_URL}/graphql`, {
      method: "POST",
      headers,
      credentials: "include",
      cache: "no-store",
      body: JSON.stringify({
        query: mutation,
      }),
    });

    const text = await resp.text();
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(text);
    } catch {
      return false;
    }
    const data = json.data;
    return (
      !json.errors &&
      typeof data === "object" &&
      data !== null &&
      "refreshToken" in data
    );
  } catch {
    return false;
  }
}

async function attemptTokenRefresh(): Promise<boolean> {
  if (activeRefreshPromise) return activeRefreshPromise;
  activeRefreshPromise = doTokenRefresh().finally(() => {
    activeRefreshPromise = null;
  });
  return activeRefreshPromise;
}

async function seedCsrfCookie(): Promise<void> {
  if (activeSeedPromise) return activeSeedPromise;
  activeSeedPromise = (async () => {
    try {
      await fetch(`${API_URL}/graphql`, {
        method: "GET",
        credentials: "include",
      });
    } catch {
      // Best-effort
    }
  })().finally(() => {
    activeSeedPromise = null;
  });
  return activeSeedPromise;
}

/**
 * A fetch wrapper that handles CSRF, Auth cookies, 401 retries, and error sanitization.
 */
export async function authedFetch(
  url: string,
  options: RequestInit = {},
  isRetry = false,
): Promise<Response> {
  if (!getCsrfToken()) {
    await seedCsrfCookie();
  }

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

  if (resp.status === 401 && !isRetry) {
    const refreshed = await attemptTokenRefresh();
    if (refreshed) {
      return authedFetch(url, options, true);
    }
  }

  if (!resp.ok) {
    const text = await resp.text();
    // Check if the response is actually an auth error message from the backend
    if (
      !isRetry &&
      (text.includes("Authentication required") ||
        text.includes("Not authenticated") ||
        text.includes("expired"))
    ) {
      const refreshed = await attemptTokenRefresh();
      if (refreshed) {
        return authedFetch(url, options, true);
      }
    }
    throw new Error(sanitizeErrorMessage(text || `HTTP ${resp.status}`));
  }

  return resp;
}
