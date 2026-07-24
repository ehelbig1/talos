/**
 * Data layer for IntegrationsManager: the service-integrations query, the
 * provider-metadata fetch, the GitHub App installations query, and the
 * OAuth-callback query-param handling (success/error toasts + refetch).
 */

import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { loadOAuthHosts } from "@/lib/oauthUtils";
import type { ServiceIntegration as GqlServiceIntegration } from "@/lib/graphqlApi";
import { listServiceIntegrations } from "@/lib/graphqlApi";
import { authedFetch } from "../watch-channels/api";
import type { ProviderInfo, GithubInstallation } from "./types";

export function useIntegrationsData() {
  // Service integrations are fetched via react-query so the loading/data
  // state is derived, not mirrored through a setState-in-effect. `refetch`
  // is used by the connect / disconnect / OAuth-callback paths.
  const {
    data: integrations = [],
    isLoading: loadingServices,
    isError: integrationsError,
    refetch: refetchIntegrations,
  } = useQuery<GqlServiceIntegration[]>({
    queryKey: ["serviceIntegrations"],
    queryFn: listServiceIntegrations,
  });
  const [providers, setProviders] = useState<ProviderInfo[]>([]);

  // Connected GitHub App installations (RFC 0008) — react-query owns the state
  // so the card can show the linked account without a setState-in-effect.
  const { data: githubInstallations = [], refetch: refetchGithub } = useQuery<
    GithubInstallation[]
  >({
    queryKey: ["githubInstallations"],
    queryFn: async () => {
      const res = await authedFetch("/api/github/installations");
      if (!res.ok) return [];
      const d = await res.json();
      return Array.isArray(d?.installations) ? d.installations : [];
    },
  });

  // Fetch provider metadata from the backend and warm the OAuth host cache.
  useEffect(() => {
    async function fetchProviders() {
      try {
        const res = await authedFetch("/api/integrations/providers");
        if (res.ok) {
          const data: ProviderInfo[] = await res.json();
          setProviders(data);
        }
      } catch {
        // Best-effort — the grid will simply be empty until retry.
        if (import.meta.env.DEV)
          console.error("Failed to fetch integration providers");
      }
    }
    fetchProviders();
    loadOAuthHosts();
  }, []);

  // Surface load failures as a toast (the fetch + retry is owned by
  // react-query above). No setState here, so this stays a pure
  // side-effect synchronization.
  useEffect(() => {
    if (integrationsError) toast.error("Failed to load integrations");
  }, [integrationsError]);

  // Handle OAuth callback query params for any provider (e.g. {provider.id}_connected / _error)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    let dirty = false;

    // Check every loaded provider for callback params
    for (const provider of providers) {
      const connectedKey = `${provider.id.replace(/-/g, "_")}_connected`;
      const errorKey = `${provider.id.replace(/-/g, "_")}_error`;

      const connectedVal = params.get(connectedKey);
      if (connectedVal) {
        toast.success(`${provider.display_name} connected: ${connectedVal}`);
        refetchIntegrations();
        params.delete(connectedKey);
        dirty = true;
      }

      const errorVal = params.get(errorKey);
      if (errorVal) {
        toast.error(
          sanitizeErrorMessage(
            `${provider.display_name} connection failed: ${errorVal}`,
          ),
        );
        params.delete(errorKey);
        dirty = true;
      }
    }

    // Also check legacy keys that the backend may emit before providers load
    const legacyKeys = [
      { param: "atlassian_connected", label: "Jira", isError: false },
      { param: "atlassian_error", label: "Jira", isError: true },
      { param: "gmail_connected", label: "Gmail", isError: false },
      { param: "gmail_error", label: "Gmail", isError: true },
      { param: "gcp_connected", label: "Google Cloud", isError: false },
      { param: "gcp_error", label: "Google Cloud", isError: true },
      { param: "github_connected", label: "GitHub", isError: false },
      { param: "github_error", label: "GitHub", isError: true },
    ];
    for (const { param, label, isError } of legacyKeys) {
      const val = params.get(param);
      if (val) {
        if (isError) {
          toast.error(
            sanitizeErrorMessage(`${label} connection failed: ${val}`),
          );
        } else {
          toast.success(`${label} connected: ${val}`);
          refetchIntegrations();
          if (param === "github_connected") refetchGithub();
        }
        params.delete(param);
        dirty = true;
      }
    }

    if (dirty) {
      window.history.replaceState(
        {},
        "",
        `${window.location.pathname}${params.toString() ? `?${params}` : ""}`,
      );
    }
  }, [providers, refetchIntegrations, refetchGithub]);

  return {
    integrations,
    loadingServices,
    refetchIntegrations,
    providers,
    githubInstallations,
    refetchGithub,
  };
}
