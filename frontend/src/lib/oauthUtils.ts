/**
 * OAuth URL validation utility.
 * Guards against open-redirect attacks by validating that backend-supplied
 * OAuth authorization URLs point to known trusted OAuth providers.
 */

/** Static fallback used when the dynamic provider list has not loaded yet. */
const ALLOWED_OAUTH_HOSTS = [
  "accounts.google.com",
  "slack.com",
  "github.com",
  "oauth.slack.com",
  "app.slack.com",
  "auth.atlassian.com",
];

/**
 * Dynamically loaded OAuth hosts from the `/api/integrations/providers` endpoint.
 * `null` means the list has not been fetched yet; fall back to ALLOWED_OAUTH_HOSTS.
 */
export let cachedOAuthHosts: string[] | null = null;

/**
 * Fetches the integration providers list and caches the flattened set of
 * oauth_hosts so that `validateOAuthUrl` can use them.
 */
export async function loadOAuthHosts(): Promise<void> {
  try {
    const res = await fetch("/api/integrations/providers", {
      credentials: "include",
    });
    if (!res.ok) return;
    const providers: { oauth_hosts?: string[] }[] = await res.json();
    const hosts = providers.flatMap((p) => p.oauth_hosts ?? []);
    if (hosts.length > 0) {
      cachedOAuthHosts = hosts;
    }
  } catch {
    // Best-effort — the static fallback will be used.
  }
}

/**
 * Returns true if the URL is HTTPS and its hostname matches a known OAuth provider.
 * Prefers the dynamically loaded host list; falls back to the static allowlist.
 */
export function validateOAuthUrl(url: string): boolean {
  try {
    const { protocol, hostname } = new URL(url);
    const hosts = cachedOAuthHosts ?? ALLOWED_OAUTH_HOSTS;
    return (
      protocol === "https:" &&
      hosts.some((h) => hostname === h || hostname.endsWith("." + h))
    );
  } catch {
    return false;
  }
}
