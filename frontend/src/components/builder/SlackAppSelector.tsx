import React, { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui";
import { SlackAppCreator } from "./SlackAppCreator";
import { validateOAuthUrl } from "@/lib/oauthUtils";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { authedFetch } from "@/lib/authedFetch";
import { cn } from "@/lib/utils";
import {
  Hash,
  Plus,
  MessageSquare,
  Globe,
  Check,
  Loader2,
  AlertTriangle,
  Rocket,
  ArrowRight,
  Shield,
  Zap,
} from "lucide-react";

interface SlackIntegration {
  id: string;
  team_id: string;
  team_name: string;
  team_domain?: string;
  bot_user_id?: string;
  scope?: string;
  is_active: boolean;
  created_at?: string;
  last_used_at?: string;
}

interface SlackAppSelectorProps {
  onSelect: (config: Record<string, unknown>) => void;
  currentConfig?: Record<string, unknown>;
}

export function SlackAppSelector({
  onSelect,
  currentConfig,
}: SlackAppSelectorProps) {
  const [integrations, setIntegrations] = useState<SlackIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [showCreator, setShowCreator] = useState(false);
  const pollTimerRef = useRef<number | null>(null);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      const response = await authedFetch("/api/slack/integrations");
      const data = await response.json();

      if (data.success) {
        setIntegrations(data.data || []);
      } else {
        throw new Error(data.error || "Unknown error");
      }
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Unknown error",
        ),
      );
    } finally {
      setLoading(false);
    }
  };

  // Declared above this effect so the function exists before it is referenced
  // (react-hooks/immutability — no use-before-declaration).
  useEffect(() => {
    fetchIntegrations();
    return () => {
      if (pollTimerRef.current !== null) {
        clearInterval(pollTimerRef.current);
      }
    };
  }, []);

  const handleConnect = async () => {
    try {
      setConnecting(true);
      const response = await authedFetch("/api/slack/connect");
      const data = await response.json();

      if (data.success && data.data?.authorization_url) {
        if (!validateOAuthUrl(data.data.authorization_url)) {
          throw new Error(
            "Invalid OAuth authorization URL received from server",
          );
        }

        const width = 600;
        const height = 700;
        const left = window.screen.width / 2 - width / 2;
        const top = window.screen.height / 2 - height / 2;

        const popup = window.open(
          data.data.authorization_url,
          "Connect Slack",
          `width=${width},height=${height},left=${left},top=${top}`,
        );

        // MCP-891 (2026-05-14): same popup-watcher duration cap as the
        // IntegrationsManager sibling. Without it, abandoning the
        // popup leaves the 500ms poll firing indefinitely AND the
        // UI stuck in "connecting" state. 10-minute cap catches
        // legitimate Slack OAuth flows (typically <30s) while
        // bounding the abandoned-popup case.
        const POPUP_WATCH_MAX_MS = 10 * 60 * 1000;
        const watchStartedAt = Date.now();
        pollTimerRef.current = window.setInterval(() => {
          if (popup?.closed) {
            clearInterval(pollTimerRef.current!);
            pollTimerRef.current = null;
            fetchIntegrations();
            setConnecting(false);
            return;
          }
          if (Date.now() - watchStartedAt > POPUP_WATCH_MAX_MS) {
            clearInterval(pollTimerRef.current!);
            pollTimerRef.current = null;
            setConnecting(false);
          }
        }, 500);
      } else {
        throw new Error(data.error || "No authorization URL received");
      }
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Unknown error",
        ),
      );
      setConnecting(false);
    }
  };

  const handleSelect = (integration: SlackIntegration) => {
    setSelectedId(integration.id);
    onSelect({
      SLACK_INTEGRATION_ID: integration.id,
      SLACK_TEAM_NAME: integration.team_name,
      SLACK_TEAM_ID: integration.team_id,
      BOT_TOKEN: `{{integration:${integration.id}:bot_token}}`,
      VERIFICATION_TOKEN: `{{integration:${integration.id}:verification_token}}`,
    });
  };

  if (loading) {
    return (
      <div className="p-8 bg-surface-1/40 border border-white/5 rounded-2xl flex items-center justify-center gap-4 animate-pulse">
        <Loader2 className="h-5 w-5 animate-spin text-[#4A154B]" />
        <p className="m-0 text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40">
          Syncing Slack Grid Vectors...
        </p>
      </div>
    );
  }

  return (
    <div className="relative overflow-hidden p-8 bg-surface-2/40 border border-white/5 rounded-[2.5rem] space-y-8 shadow-2xl">
      <div className="absolute inset-0 bg-gradient-to-br from-[#4A154B]/5 via-transparent to-transparent opacity-50 pointer-events-none" />

      {showCreator && (
        <SlackAppCreator
          webhookUrl={(currentConfig?.WEBHOOK_URL as string) || ""}
          eventTypes={(currentConfig?.EVENT_TYPES as string[]) || []}
          onAppCreated={(credentials) => {
            onSelect({
              VERIFICATION_TOKEN: credentials.verificationToken,
              APP_ID: credentials.appId,
              CLIENT_ID: credentials.clientId,
              CLIENT_SECRET: credentials.clientSecret,
              SIGNING_SECRET: credentials.signingSecret,
              BOT_USER_ID: credentials.botUserId,
            });
            setShowCreator(false);
          }}
          onCancel={() => setShowCreator(false)}
        />
      )}

      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-[#4A154B]/10 border border-[#4A154B]/20">
            <MessageSquare className="h-5 w-5 text-[#4A154B]" />
          </div>
          <div>
            <h4 className="text-[11px] font-black text-white uppercase tracking-[0.2em]">
              Slack Workspace Integration
            </h4>
            <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-widest">
              Distributed Communication Vector
            </p>
          </div>
        </div>

        {integrations.length > 0 && (
          <div className="flex gap-2">
            <Button
              onClick={() => setShowCreator(true)}
              variant="outline"
              className="h-9 px-4 bg-purple-500/5 hover:bg-purple-500/10 text-purple-400 border-purple-500/20 text-[9px] font-black uppercase tracking-widest rounded-xl transition-premium"
            >
              <Rocket className="w-3.5 h-3.5 mr-2" /> Manifest App
            </Button>
            <Button
              onClick={handleConnect}
              disabled={connecting}
              variant="ghost"
              className="h-9 px-4 bg-surface-3 hover:bg-surface-4 text-white text-[9px] font-black uppercase tracking-widest rounded-xl border border-white/5 transition-premium"
            >
              {connecting ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin mr-2" />
              ) : (
                <Plus className="w-3.5 h-3.5 mr-2" />
              )}
              Bridge Workspace
            </Button>
          </div>
        )}
      </div>

      {error && (
        <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-2xl flex items-center gap-4 text-destructive animate-in shake duration-500">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <p className="m-0 text-[10px] font-black uppercase tracking-widest">
            {error}
          </p>
        </div>
      )}

      {integrations.length === 0 ? (
        <div className="p-10 bg-surface-4 border-2 border-dashed border-white/5 rounded-[2rem] text-center flex flex-col items-center animate-in fade-in duration-700">
          <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center mb-6 border border-white/10">
            <Hash className="h-8 w-8 text-muted-foreground/20" />
          </div>
          <h5 className="mb-2 text-sm font-black text-white uppercase tracking-tight font-outfit">
            No Slack Workspaces Bridged
          </h5>
          <p className="mb-8 text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest leading-relaxed max-w-xs mx-auto">
            Synchronize your Slack grid to enable distributed communication
            vectors for your automated workflows.
          </p>
          <Button
            onClick={handleConnect}
            disabled={connecting}
            className="h-11 px-8 bg-[#4A154B] hover:bg-[#4A154B]/90 text-white text-[10px] font-black uppercase tracking-widest rounded-xl shadow-xl shadow-[#4A154B]/20 active:scale-95 transition-premium"
          >
            {connecting ? (
              <div className="flex items-center gap-3">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Establishing Bridge...</span>
              </div>
            ) : (
              <>
                🔗 Initialize Connection{" "}
                <ArrowRight className="ml-2 w-3.5 h-3.5" />
              </>
            )}
          </Button>
        </div>
      ) : (
        <div className="space-y-6 relative z-10">
          <p className="px-1 text-[9px] font-black text-white/40 uppercase tracking-[0.3em]">
            ACTIVE COMMUNICATIONS GRID
          </p>
          <div className="grid gap-3">
            {integrations.map((integration) => {
              const isSelected = selectedId === integration.id;
              return (
                <button
                  key={integration.id}
                  onClick={() => handleSelect(integration)}
                  className={cn(
                    "group relative p-4 text-left rounded-2xl border transition-premium hover:scale-[1.01] active:scale-[0.98] overflow-hidden",
                    isSelected
                      ? "bg-[#4A154B]/10 border-[#4A154B] shadow-[0_0_20px_rgba(74,21,75,0.1)]"
                      : "bg-surface-3 border-white/5 hover:bg-surface-4 hover:border-white/20",
                  )}
                >
                  <div className="flex items-center gap-4 relative z-10">
                    <div
                      className={cn(
                        "w-10 h-10 rounded-xl flex items-center justify-center border transition-premium",
                        isSelected
                          ? "bg-[#4A154B] text-white border-[#4A154B]"
                          : "bg-white/5 text-muted-foreground/40 border-white/10",
                      )}
                    >
                      {isSelected ? (
                        <Check className="h-5 w-5" />
                      ) : (
                        <Hash className="h-5 w-5" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <span
                        className={cn(
                          "block text-xs font-black uppercase tracking-widest truncate transition-premium",
                          isSelected ? "text-white" : "text-white/60",
                        )}
                      >
                        {integration.team_name}
                      </span>
                      <span className="block text-[9px] font-black text-muted-foreground/20 uppercase tracking-tighter mt-0.5">
                        ID: {integration.team_id}{" "}
                        {integration.last_used_at &&
                          `• Active: ${new Date(integration.last_used_at).toLocaleDateString()}`}
                      </span>
                    </div>
                    {isSelected && (
                      <div className="animate-pulse">
                        <div className="w-2 h-2 rounded-full bg-[#4A154B]" />
                      </div>
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          <div className="p-6 bg-primary/5 border border-primary/10 rounded-[2rem] flex items-start gap-4">
            <div className="shrink-0 p-2 rounded-xl bg-primary/10 border border-primary/20">
              <Zap className="w-4 h-4 text-primary" />
            </div>
            <p className="text-[10px] text-primary/60 font-bold uppercase tracking-widest leading-relaxed">
              Strategic Insight: Use "Manifest App" to quickly synthesize a new
              Slack vector with pre-configured operational permissions.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
