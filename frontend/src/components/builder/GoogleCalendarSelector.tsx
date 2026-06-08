import React, { useState, useEffect } from "react";
import { getCsrfToken } from "@/lib/csrf";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  Calendar,
  AlertTriangle,
  Check,
  CheckCircle,
  Loader2,
  Settings,
  Shield,
  ArrowRight,
  Globe,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button, Badge } from "@/components/ui";

function authedFetch(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const csrfToken = getCsrfToken();
  const headers: Record<string, string> = {
    ...((options.headers as Record<string, string>) ?? {}),
  };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  return fetch(url, { ...options, credentials: "include", headers });
}

interface GoogleCalendarIntegration {
  id: string;
  oauth_account_id: string;
  email?: string;
  is_active: boolean;
  created_at: string;
}

interface CalendarData {
  id: string;
  summary: string;
  description?: string;
  time_zone?: string;
  access_role: string;
  primary?: boolean;
}

interface GoogleCalendarSelectorProps {
  onSelect: (config: Record<string, unknown>) => void;
  currentConfig?: Record<string, unknown>;
}

export function GoogleCalendarSelector({
  onSelect,
  currentConfig,
}: GoogleCalendarSelectorProps) {
  const [integrations, setIntegrations] = useState<GoogleCalendarIntegration[]>(
    [],
  );
  const [calendars, setCalendars] = useState<CalendarData[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingCalendars, setLoadingCalendars] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIntegrationId, setSelectedIntegrationId] = useState<
    string | null
  >(null);
  const [selectedCalendars, setSelectedCalendars] = useState<string[]>([]);
  const [setupComplete, setSetupComplete] = useState(false);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      const response = await authedFetch("/api/google-calendar/integrations");

      if (!response.ok) {
        throw new Error("Failed to fetch Google Calendar integrations");
      }

      const data = await response.json();

      if (data.success) {
        setIntegrations(data.data || []);
      } else {
        throw new Error("Failed to load integrations.");
      }
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Failed to load integrations",
        ),
      );
    } finally {
      setLoading(false);
    }
  };

  // Declared after fetchIntegrations so the function exists before this effect
  // references it (react-hooks/immutability — no use-before-declaration).
  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchCalendars = async (integrationId: string) => {
    try {
      setLoadingCalendars(true);
      const response = await authedFetch(
        `/api/google-calendar/integrations/${integrationId}/calendars`,
      );

      if (!response.ok) {
        throw new Error("Failed to fetch calendars");
      }

      const data = await response.json();

      if (data.success) {
        setCalendars(data.data || []);
      } else {
        throw new Error("Failed to load calendars.");
      }
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Failed to load calendars",
        ),
      );
    } finally {
      setLoadingCalendars(false);
    }
  };

  const handleSelectIntegration = async (integrationId: string) => {
    setSelectedIntegrationId(integrationId);
    setSelectedCalendars([]);
    await fetchCalendars(integrationId);
  };

  const handleToggleCalendar = (calendarId: string) => {
    setSelectedCalendars((prev) => {
      if (prev.includes(calendarId)) {
        return prev.filter((id) => id !== calendarId);
      } else {
        return [...prev, calendarId];
      }
    });
  };

  const handleConfirmSelection = () => {
    if (!selectedIntegrationId || selectedCalendars.length === 0) {
      setError("Please select at least one calendar");
      return;
    }

    setSetupComplete(true);
    onSelect({
      GOOGLE_CALENDAR_INTEGRATION_ID: selectedIntegrationId,
      CALENDAR_IDS: selectedCalendars,
    });
  };

  if (loading) {
    return (
      <div className="p-8 bg-surface-1/40 border border-white/5 rounded-2xl flex items-center justify-center gap-4 animate-pulse">
        <Loader2 className="h-5 w-5 animate-spin text-primary" />
        <p className="m-0 text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40">
          Syncing Google Auth Vectors...
        </p>
      </div>
    );
  }

  return (
    <div className="relative overflow-hidden p-8 bg-surface-2/40 border border-white/5 rounded-[2.5rem] space-y-8 shadow-2xl">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 pointer-events-none" />

      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20">
            <Calendar className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h4 className="text-[11px] font-black text-white uppercase tracking-[0.2em]">
              Google Calendar Integration
            </h4>
            <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-widest">
              Temporal Synchronization Vector
            </p>
          </div>
        </div>
        {setupComplete && (
          <Badge className="bg-success/10 text-success border-success/20 text-[8px] font-black px-2 py-1 uppercase tracking-widest animate-in zoom-in-95">
            <Check className="w-3 h-3 mr-1" /> Vector Locked
          </Badge>
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
            <Calendar className="h-8 w-8 text-muted-foreground/20" />
          </div>
          <h5 className="mb-2 text-sm font-black text-white uppercase tracking-tight font-outfit">
            No Google Matrix Connected
          </h5>
          <p className="mb-8 text-[11px] font-bold text-muted-foreground/40 uppercase tracking-widest leading-relaxed max-w-xs mx-auto">
            Establish a persistent auth tunnel in{" "}
            <strong>Command Settings</strong> to activate temporal monitoring.
          </p>
          <a
            href="/settings"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center rounded-xl font-black uppercase tracking-widest transition-premium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 disabled:opacity-30 disabled:pointer-events-none active:scale-95 select-none h-11 px-8 bg-primary hover:bg-primary/90 text-white text-[10px] shadow-xl shadow-primary/20 transition-premium"
          >
            Initialize Connection <ArrowRight className="ml-2 w-3.5 h-3.5" />
          </a>
        </div>
      ) : (
        <div className="space-y-8 relative z-10">
          <div className="space-y-4">
            <div className="flex items-center gap-2 px-1">
              <Shield className="w-3.5 h-3.5 text-primary/60" />
              <p className="m-0 text-[9px] font-black text-white/40 uppercase tracking-[0.3em]">
                PHASE 1: AUTHENTICATION TUNNEL
              </p>
            </div>
            <div className="grid gap-3">
              {integrations.map((integration) => {
                const isSelected = selectedIntegrationId === integration.id;
                return (
                  <button
                    key={integration.id}
                    onClick={() => handleSelectIntegration(integration.id)}
                    className={cn(
                      "group relative p-4 text-left rounded-2xl border transition-premium hover:scale-[1.01] active:scale-[0.98] overflow-hidden",
                      isSelected
                        ? "bg-primary/10 border-primary shadow-[0_0_20px_hsla(var(--primary),0.1)]"
                        : "bg-surface-3 border-white/5 hover:bg-surface-4 hover:border-white/20",
                    )}
                  >
                    <div className="flex items-center gap-4 relative z-10">
                      <div
                        className={cn(
                          "w-10 h-10 rounded-xl flex items-center justify-center border transition-premium",
                          isSelected
                            ? "bg-primary text-white border-primary"
                            : "bg-white/5 text-muted-foreground/40 border-white/10",
                        )}
                      >
                        {isSelected ? (
                          <Check className="h-5 w-5" />
                        ) : (
                          <Globe className="h-5 w-5" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <span
                          className={cn(
                            "block text-xs font-black uppercase tracking-widest truncate transition-premium",
                            isSelected ? "text-white" : "text-white/60",
                          )}
                        >
                          {integration.email || "Unified Google Vector"}
                        </span>
                        <span className="block text-[9px] font-black text-muted-foreground/20 uppercase tracking-tighter mt-0.5">
                          Established:{" "}
                          {new Date(
                            integration.created_at,
                          ).toLocaleDateString()}
                        </span>
                      </div>
                      {isSelected && (
                        <div className="animate-pulse">
                          <div className="w-2 h-2 rounded-full bg-primary" />
                        </div>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {selectedIntegrationId && (
            <div className="space-y-4 animate-in fade-in slide-in-from-top-4 duration-500">
              <div className="flex items-center gap-2 px-1">
                <Sparkles className="w-3.5 h-3.5 text-primary/60" />
                <p className="m-0 text-[9px] font-black text-white/40 uppercase tracking-[0.3em]">
                  PHASE 2: CALENDAR TELEMETRY
                </p>
              </div>
              {loadingCalendars ? (
                <div className="p-10 flex flex-col items-center justify-center gap-4 bg-surface-3 border border-white/5 rounded-2xl">
                  <Loader2 className="h-8 w-8 animate-spin text-primary" />
                  <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-widest">
                    Deciphering Calendars...
                  </p>
                </div>
              ) : calendars.length === 0 ? (
                <div className="p-6 bg-surface-3 border border-white/5 rounded-2xl text-center">
                  <p className="text-[10px] font-black text-destructive uppercase tracking-widest">
                    Null Calendars Returned
                  </p>
                </div>
              ) : (
                <div className="max-h-[320px] overflow-y-auto pr-2 custom-scrollbar space-y-2">
                  {calendars.map((calendar) => {
                    const isSelected = selectedCalendars.includes(calendar.id);
                    return (
                      <button
                        key={calendar.id}
                        onClick={() => handleToggleCalendar(calendar.id)}
                        className={cn(
                          "w-full group p-4 text-left rounded-xl border transition-premium hover:bg-surface-4",
                          isSelected
                            ? "bg-primary/5 border-primary/20"
                            : "bg-surface-3/60 border-white/5",
                        )}
                      >
                        <div className="flex items-start gap-4">
                          <div
                            className={cn(
                              "mt-1 w-5 h-5 rounded-md border flex items-center justify-center transition-premium",
                              isSelected
                                ? "bg-primary border-primary text-white"
                                : "bg-white/5 border-white/10 group-hover:border-white/30",
                            )}
                          >
                            {isSelected && <Check className="w-3 h-3" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-3 mb-1">
                              <span
                                className={cn(
                                  "text-[11px] font-black uppercase tracking-widest truncate transition-premium",
                                  isSelected ? "text-white" : "text-white/40",
                                )}
                              >
                                {calendar.summary}
                              </span>
                              {calendar.primary && (
                                <Badge className="bg-primary/10 text-primary border-primary/20 text-[7px] font-black px-1.5 py-0 uppercase tracking-widest">
                                  Primary
                                </Badge>
                              )}
                            </div>
                            {calendar.description && (
                              <p className="text-[9px] font-bold text-muted-foreground/20 line-clamp-1 uppercase tracking-tighter">
                                {calendar.description}
                              </p>
                            )}
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}

              {selectedCalendars.length > 0 && !setupComplete && (
                <Button
                  onClick={handleConfirmSelection}
                  className="w-full h-12 bg-primary hover:bg-primary/90 text-white text-[10px] font-black uppercase tracking-widest rounded-2xl shadow-2xl shadow-primary/20 active:scale-95 transition-premium mt-4"
                >
                  Confirm Temporal Locking ({selectedCalendars.length} VECTOR
                  {selectedCalendars.length > 1 ? "S" : ""})
                </Button>
              )}

              {setupComplete && (
                <div className="p-6 bg-emerald-500/5 border border-emerald-500/20 rounded-[2rem] mt-6 animate-in zoom-in-95 duration-500">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400">
                      <CheckCircle className="h-5 w-5" />
                    </div>
                    <span className="font-black text-[10px] text-white uppercase tracking-[0.2em]">
                      Uplink Validated
                    </span>
                  </div>
                  <p className="m-0 text-[11px] font-bold text-muted-foreground/40 leading-relaxed uppercase tracking-widest">
                    Selected {selectedCalendars.length} monitor cycle
                    {selectedCalendars.length > 1 ? "s" : ""}. Temporal watch
                    channels will initialize upon node synthesis. Real-time
                    telemetry will stream to the workflow core.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
