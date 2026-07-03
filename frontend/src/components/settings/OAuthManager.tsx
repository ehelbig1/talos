import React, { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import {
  Github,
  Chrome,
  Shield,
  Link as LinkIcon,
  Unlink,
  ExternalLink,
  Mail,
  User as UserIcon,
  Clock,
  Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { gql } from "@/lib/graphqlClient";
import { getOAuthLoginUrl } from "@/lib/graphqlApi";
import { validateOAuthUrl, loadOAuthHosts } from "@/lib/oauthUtils";
import type { ListLinkedAccountsQuery } from "@/generated/graphql";
import {
  useListLinkedAccountsQuery,
  useUnlinkOAuthMutation,
} from "@/generated/graphql";

const LIST_LINKED_ACCOUNTS = gql`
  query ListLinkedAccounts {
    linkedOauthAccounts {
      id
      provider
      email
      name
      pictureUrl
      linkedAt
      lastLoginAt
    }
  }
`;

const GET_OAUTH_URL = gql`
  query GetOAuthUrl($provider: String!) {
    oauthLoginUrl(provider: $provider) {
      authUrl
    }
  }
`;

const UNLINK_OAUTH = gql`
  mutation UnlinkOAuth($provider: String!) {
    unlinkOauthAccount(provider: $provider)
  }
`;

type OAuthAccount = ListLinkedAccountsQuery["linkedOauthAccounts"][number];

const PROVIDERS = [
  {
    id: "google",
    name: "Google",
    icon: Chrome,
    color: "text-info",
    bg: "bg-info/10",
    border: "border-info/20",
  },
  {
    id: "okta",
    name: "Okta",
    icon: Shield,
    color: "text-primary",
    bg: "bg-primary/10",
    border: "border-primary/20",
  },
  {
    id: "snyk",
    name: "Snyk",
    icon: Github, // Using Github icon for Snyk as generic dev icon
    color: "text-warning",
    bg: "bg-warning/10",
    border: "border-warning/20",
  },
];

export default function OAuthManager() {
  const queryClient = useQueryClient();
  const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
  const [providerToUnlink, setProviderToUnlink] = useState<string | null>(null);

  const { data, isLoading } = useListLinkedAccountsQuery();
  const accounts = data?.linkedOauthAccounts;

  // 2026-05-28 review (low): populate the dynamic OAuth-host allowlist so
  // validateOAuthUrl below accepts operator-configured providers (it falls
  // back to the static ALLOWED_OAUTH_HOSTS if this hasn't resolved yet).
  useEffect(() => {
    loadOAuthHosts();
  }, []);

  const unlinkMutation = useUnlinkOAuthMutation({
    onSuccess: () => {
      toast.success("Account unlinked successfully");
      queryClient.invalidateQueries({ queryKey: ["ListLinkedAccounts"] });
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to unlink account"),
      );
    },
  });

  const handleLink = async (providerId: string) => {
    // MCP-863 (2026-05-14): call graphqlRequest directly with the
    // freshly-passed providerId. The previous implementation used
    // `useGetOAuthUrlQuery({ provider: linkingProvider }, { enabled: false })`
    // + refetch, which captured linkingProvider in the queryFn closure
    // at render time. Because setLinkingProvider's state update doesn't
    // flush synchronously inside an event handler, fetchOAuthUrl ran
    // against the PREVIOUS render's `linkingProvider` — so the first
    // click sent `provider: ""` and subsequent clicks sent the
    // previously-linked provider's id.
    setLinkingProvider(providerId);
    try {
      const authUrl = await getOAuthLoginUrl(providerId);
      if (authUrl) {
        // 2026-05-28 review (low): gate the top-level navigation through the
        // same open-redirect guard the sibling redirect sites use
        // (IntegrationsManager, SlackAppSelector). Defends against a
        // backend-minted authUrl ever pointing off-allowlist.
        if (!validateOAuthUrl(authUrl)) {
          toast.error("Invalid OAuth authorization URL received from server");
          setLinkingProvider(null);
          return;
        }
        // eslint-disable-next-line react-hooks/immutability -- intentional browser navigation to the OAuth login URL in an async handler (not a render-time mutation of external state); the URL is validated above.
        window.location.href = authUrl;
      }
    } catch (err: unknown) {
      toast.error(
        sanitizeErrorMessage(
          err instanceof Error
            ? err.message
            : "Failed to start OAuth linking flow",
        ),
      );
      setLinkingProvider(null);
    }
  };

  const handleUnlink = (providerId: string) => {
    setProviderToUnlink(providerId);
  };

  if (isLoading) {
    return (
      <div className="py-12 flex flex-col items-center justify-center gap-4">
        <LoadingSpinner />
        <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest animate-pulse">
          Synchronizing connected accounts...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex items-center gap-6">
        <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-[2rem] flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)] group">
          <Shield className="w-8 h-8 text-primary group-hover:scale-110 transition-premium" />
        </div>
        <div>
          <SectionHeader
            level="h2"
            className="text-2xl md:text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-1"
          >
            Identity Protocols
          </SectionHeader>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-primary bg-primary/5 px-3 py-1 rounded-full border border-primary/20">
              Federated_Security
            </span>
            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40">
              OAuth_2.0_Standard
            </span>
          </div>
        </div>
      </div>

      <div className="grid gap-6">
        {PROVIDERS.map((provider) => {
          const linkedAccount = accounts?.find(
            (a) => a.provider.toLowerCase() === provider.id,
          );
          const isLinking = linkingProvider === provider.id;

          return (
            <div
              key={provider.id}
              className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 p-8 rounded-[2.5rem] group hover:border-white/10 hover:bg-surface-3/60 transition-premium relative overflow-hidden shadow-2xl"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

              <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 relative z-10">
                <div className="flex items-start gap-6">
                  <div
                    className={cn(
                      "w-16 h-16 rounded-2xl flex items-center justify-center border shadow-2xl shrink-0 transition-premium group-hover:scale-110 group-hover:rotate-3",
                      provider.bg,
                      provider.border,
                      linkedAccount
                        ? "shadow-primary/5"
                        : "grayscale opacity-20 group-hover:grayscale-0 group-hover:opacity-100",
                    )}
                  >
                    <provider.icon className={cn("w-8 h-8", provider.color)} />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-3">
                      <h5 className="text-xl font-black text-white tracking-tight uppercase font-outfit">
                        {provider.name}
                      </h5>
                      {linkedAccount && (
                        <div className="flex items-center gap-2 bg-success/10 px-3 py-1 rounded-full border border-success/20 shadow-[0_0_15px_hsla(var(--success),0.1)]">
                          <Check className="w-3 h-3 text-success" />
                          <span className="text-[9px] font-black text-success uppercase tracking-widest">
                            SYNCHRONIZED
                          </span>
                        </div>
                      )}
                    </div>
                    {linkedAccount ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-10 gap-y-2 text-[11px]">
                        <div className="flex items-center gap-3 text-white/60 font-bold uppercase tracking-widest">
                          <Mail className="w-3.5 h-3.5 text-primary/40" />
                          {linkedAccount.email}
                        </div>
                        {linkedAccount.name && (
                          <div className="flex items-center gap-3 text-white/60 font-bold uppercase tracking-widest">
                            <UserIcon className="w-3.5 h-3.5 text-primary/40" />
                            {linkedAccount.name}
                          </div>
                        )}
                        <div className="flex items-center gap-3 text-muted-foreground/30 font-black uppercase tracking-widest">
                          <Clock className="w-3.5 h-3.5" />
                          Linked_
                          {new Date(linkedAccount.linkedAt)
                            .toLocaleDateString(undefined, {
                              month: "short",
                              day: "numeric",
                              year: "numeric",
                            })
                            .toUpperCase()}
                        </div>
                      </div>
                    ) : (
                      <p className="text-[11px] text-muted-foreground/30 font-bold uppercase tracking-[0.2em]">
                        No active credential link for {provider.name}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-4 self-end md:self-center">
                  {linkedAccount ? (
                    <Button
                      variant="outline"
                      className="h-12 px-6 border-white/10 text-muted-foreground/60 hover:text-destructive hover:bg-destructive/10 hover:border-destructive/30 text-[10px] font-black uppercase tracking-widest rounded-xl transition-premium active:scale-95 shadow-xl"
                      onClick={() => handleUnlink(provider.id)}
                      disabled={unlinkMutation.isPending}
                    >
                      {unlinkMutation.isPending &&
                      unlinkMutation.variables?.provider === provider.id ? (
                        <LoadingSpinner className="py-0 mr-2" />
                      ) : (
                        <Unlink className="w-4 h-4 mr-3 opacity-40" />
                      )}
                      Disconnect_Protocol
                    </Button>
                  ) : (
                    <Button
                      variant="premium"
                      className="h-12 px-8 rounded-xl"
                      onClick={() => handleLink(provider.id)}
                      disabled={isLinking}
                    >
                      {isLinking ? (
                        <LoadingSpinner className="py-0 mr-2" />
                      ) : (
                        <LinkIcon className="w-4 h-4 mr-3" />
                      )}
                      ESTABLISH_LINK
                    </Button>
                  )}
                  {linkedAccount && (
                    <button
                      type="button"
                      className="h-12 w-12 flex items-center justify-center text-muted-foreground/20 hover:text-primary hover:bg-primary/10 rounded-xl transition-premium border border-white/5 hover:border-primary/20 shadow-xl"
                      title="Access provider dashboard"
                    >
                      <ExternalLink className="w-5 h-5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-primary/5 border border-white/5 rounded-[2.5rem] p-8 flex items-start gap-8 hover:border-white/10 transition-premium group relative overflow-hidden">
        <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-premium blur-3xl pointer-events-none" />
        <div className="w-16 h-16 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center shrink-0 group-hover:scale-105 transition-premium shadow-inner relative z-10">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <div className="space-y-2 relative z-10">
          <h4 className="text-lg font-black text-white uppercase tracking-tight font-outfit">
            Redundant_Authentication_Shield
          </h4>
          <p className="text-[11px] text-muted-foreground/40 font-bold uppercase tracking-widest leading-relaxed max-w-3xl">
            Linking multiple identity providers strengthens your account
            recovery perimeter. In the event of primary provider downtime, you
            can maintain operational continuity using any secondary verified
            protocol.
          </p>
        </div>
      </div>

      <ConfirmDialog
        open={providerToUnlink !== null}
        title="Sever Protocol Link?"
        message={`Are you sure you want to unlink your ${providerToUnlink} account? This will remove it as a fallback authentication method.`}
        confirmLabel="Sever Link"
        destructive
        onConfirm={() => {
          if (providerToUnlink)
            unlinkMutation.mutate({ provider: providerToUnlink });
          setProviderToUnlink(null);
        }}
        onCancel={() => setProviderToUnlink(null)}
      />
    </div>
  );
}
