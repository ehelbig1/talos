import React, { useState } from "react";
import { Spinner } from "@/components/ui/spinner";
import { useQuery } from "@tanstack/react-query";
import { getCsrfToken } from "@/lib/csrf";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  Calendar,
  AlertTriangle,
  Check,
  CheckCircle,
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
}: GoogleCalendarSelectorProps) {
  // Integrations are fetched on mount via react-query so the loading/data
  // state is derived, not mirrored through a setState-in-effect.
  const {
    data: integrations = [],
    isLoading: loading,
    error: integrationsError,
  } = useQuery<GoogleCalendarIntegration[]>({
    queryKey: ["googleCalendarIntegrations"],
    queryFn: async () => {
      const response = await authedFetch("/api/google-calendar/integrations");
      if (!response.ok) {
        throw new Error("Failed to fetch Google Calendar integrations");
      }
      const data = await response.json();
      if (!data.success) {
        throw new Error("Failed to load integrations.");
      }
      return (data.data || []) as GoogleCalendarIntegration[];
    },
  });
  const [calendars, setCalendars] = useState<CalendarData[]>([]);
  const [loadingCalendars, setLoadingCalendars] = useState(false);
  // Local error for the calendar-fetch and confirm-validation paths
  // (event-driven). Integration-load failures come from the query above.
  const [error, setError] = useState<string | null>(null);
  const [selectedIntegrationId, setSelectedIntegrationId] = useState<
    string | null
  >(null);
  const [selectedCalendars, setSelectedCalendars] = useState<string[]>([]);
  const [setupComplete, setSetupComplete] = useState(false);

  // Combined error display: an event-driven local error (calendars /
  // validation) takes precedence, otherwise the integration-load error.
  const displayError =
    error ??
    (integrationsError
      ? sanitizeErrorMessage(
          integrationsError instanceof Error
            ? integrationsError.message
            : "Failed to load integrations",
        )
      : null);

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
      <div className="p-8 bg-surface-1/40 border border-white/5 rounded-2xl flex items-center justify-center gap-4">
        <Spinner className="h-5 w-5 text-primary" />
        <p className="m-0 text-xs font-semibold text-muted-foreground/70">
          Loading Google accounts…
        </p>
      </div>
    );
  }

  return (
    <div className="relative overflow-hidden p-8 bg-surface-2/40 border border-white/5 rounded-2xl space-y-8">
      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20">
            <Calendar className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-white">
              Google Calendar
            </h4>
            <p className="text-xs font-medium text-muted-foreground/50">
              Watch calendars for changes
            </p>
          </div>
        </div>
        {setupComplete && (
          <Badge className="bg-success/10 text-success border-success/20 text-2xs font-semibold px-2 py-1 uppercase tracking-wider">
            <Check className="w-3 h-3 mr-1" /> Configured
          </Badge>
        )}
      </div>

      {displayError && (
        <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-2xl flex items-center gap-4 text-destructive">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <p className="m-0 text-xs font-semibold">{displayError}</p>
        </div>
      )}

      {integrations.length === 0 ? (
        <div className="p-10 bg-surface-4 border-2 border-dashed border-white/5 rounded-2xl text-center flex flex-col items-center">
          <div className="w-14 h-14 rounded-full bg-white/5 flex items-center justify-center mb-6 border border-white/10">
            <Calendar className="h-8 w-8 text-muted-foreground/50" />
          </div>
          <h5 className="mb-2 text-sm font-semibold text-white tracking-tight font-outfit">
            No Google account connected
          </h5>
          <p className="mb-8 text-xs text-muted-foreground/70 leading-relaxed max-w-xs mx-auto">
            Connect a Google account in <strong>Settings</strong> to watch its
            calendars.
          </p>
          <a
            href="/settings"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center rounded-xl font-semibold transition-ui focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20 disabled:opacity-30 disabled:pointer-events-none select-none h-11 px-8 bg-primary hover:bg-primary/90 text-white text-sm transition-ui"
          >
            Initialize Connection <ArrowRight className="ml-2 w-3.5 h-3.5" />
          </a>
        </div>
      ) : (
        <div className="space-y-8 relative z-10">
          <div className="space-y-4">
            <div className="flex items-center gap-2 px-1">
              <Shield className="w-3.5 h-3.5 text-primary/60" />
              <p className="m-0 text-2xs font-semibold text-white/70 uppercase tracking-wider">
                Step 1: connect Google
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
                      "group relative p-4 text-left rounded-2xl border transition-ui overflow-hidden",
                      isSelected
                        ? "bg-primary/10 border-primary"
                        : "bg-surface-3 border-white/5 hover:bg-surface-4 hover:border-white/20",
                    )}
                  >
                    <div className="flex items-center gap-4 relative z-10">
                      <div
                        className={cn(
                          "w-10 h-10 rounded-xl flex items-center justify-center border transition-ui",
                          isSelected
                            ? "bg-primary text-white border-primary"
                            : "bg-white/5 text-muted-foreground/70 border-white/10",
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
                            "block text-xs font-semibold truncate transition-ui",
                            isSelected ? "text-white" : "text-white/60",
                          )}
                        >
                          {integration.email || "Google account"}
                        </span>
                        <span className="block text-xs font-medium text-muted-foreground/50 mt-0.5">
                          Established:{" "}
                          {new Date(
                            integration.created_at,
                          ).toLocaleDateString()}
                        </span>
                      </div>
                      {isSelected && (
                        <div>
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
            <div className="space-y-4">
              <div className="flex items-center gap-2 px-1">
                <Sparkles className="w-3.5 h-3.5 text-primary/60" />
                <p className="m-0 text-2xs font-semibold text-white/70 uppercase tracking-wider">
                  Step 2: choose calendars
                </p>
              </div>
              {loadingCalendars ? (
                <div className="p-10 flex flex-col items-center justify-center gap-4 bg-surface-3 border border-white/5 rounded-2xl">
                  <Spinner className="h-8 w-8 text-primary" />
                  <p className="text-xs font-medium text-muted-foreground/50">
                    Loading calendars…
                  </p>
                </div>
              ) : calendars.length === 0 ? (
                <div className="p-6 bg-surface-3 border border-white/5 rounded-2xl text-center">
                  <p className="text-xs font-semibold text-destructive">
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
                          "w-full group p-4 text-left rounded-xl border transition-ui hover:bg-surface-4",
                          isSelected
                            ? "bg-primary/5 border-primary/20"
                            : "bg-surface-3/60 border-white/5",
                        )}
                      >
                        <div className="flex items-start gap-4">
                          <div
                            className={cn(
                              "mt-1 w-5 h-5 rounded-md border flex items-center justify-center transition-ui",
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
                                  "text-xs font-semibold truncate transition-ui",
                                  isSelected ? "text-white" : "text-white/70",
                                )}
                              >
                                {calendar.summary}
                              </span>
                              {calendar.primary && (
                                <Badge className="bg-primary/10 text-primary border-primary/20 text-2xs font-semibold px-1.5 py-0">
                                  Primary
                                </Badge>
                              )}
                            </div>
                            {calendar.description && (
                              <p className="text-2xs font-medium text-muted-foreground/50 line-clamp-1">
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
                  className="w-full h-12 bg-primary hover:bg-primary/90 text-white text-sm font-semibold rounded-2xl transition-ui mt-4"
                >
                  Watch {selectedCalendars.length} calendar
                  {selectedCalendars.length > 1 ? "s" : ""}
                </Button>
              )}

              {setupComplete && (
                <div className="p-6 bg-success/5 border border-success/20 rounded-2xl mt-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-1.5 rounded-lg bg-success/10 text-success">
                      <CheckCircle className="h-5 w-5" />
                    </div>
                    <span className="font-semibold text-xs text-white">
                      Calendars selected
                    </span>
                  </div>
                  <p className="m-0 text-xs text-muted-foreground/70 leading-relaxed">
                    Watching {selectedCalendars.length} calendar
                    {selectedCalendars.length > 1 ? "s" : ""}. Watch channels
                    are created when the node is saved, and calendar changes
                    will start this workflow.
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
