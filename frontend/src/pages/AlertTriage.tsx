import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle,
  CheckCircle2,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { cn } from "@/lib/utils";
import { relativeTime } from "@/lib/formatTime";
import { ASSIGNABLE_SEVERITIES, severityStyle } from "@/lib/alertSeverity";
import {
  useOpsAlertsQuery,
  useOpsAlertsDigestQuery,
  useCorrectOpsAlertSeverityMutation,
  useAckOpsAlertMutation,
  useResolveOpsAlertMutation,
  type OpsAlertsQuery,
} from "@/generated/graphql";

type StatusFilter = "active" | "acked" | "resolved";

type AlertRow = OpsAlertsQuery["opsAlerts"][number];

// The `DateTime` GraphQL scalar isn't in codegen's scalar map (only UUID/JSON
// are), so it types as `unknown` even though the wire value is always an ISO
// 8601 string (async-graphql's DateTime<Utc> scalar). Narrow it once here
// rather than scattering `as string` casts through the JSX.
function asIsoString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

// "Active" is the server's default (no status arg = new+acked). The other
// two tabs pass an explicit status so the three views never overlap.
function statusArgFor(filter: StatusFilter): string | undefined {
  if (filter === "acked") return "acked";
  if (filter === "resolved") return "resolved";
  return undefined;
}

export default function AlertTriage() {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<StatusFilter>("active");
  const [pendingResolve, setPendingResolve] = useState<AlertRow | null>(null);

  const invalidateAlerts = () => {
    queryClient.invalidateQueries({ queryKey: ["OpsAlerts"] });
    queryClient.invalidateQueries({ queryKey: ["OpsAlertsDigest"] });
  };

  const { data: digestData, isLoading: digestLoading } =
    useOpsAlertsDigestQuery({}, { refetchOnWindowFocus: true });
  const digest = digestData?.opsAlertsDigest;

  const {
    data: alertsData,
    isLoading: alertsLoading,
    isError: alertsError,
    refetch: refetchAlerts,
  } = useOpsAlertsQuery(
    { status: statusArgFor(filter) },
    { refetchOnWindowFocus: true },
  );
  const alerts = alertsData?.opsAlerts ?? [];

  const correct = useCorrectOpsAlertSeverityMutation({
    onSuccess: (data) => {
      if (data.correctOpsAlertSeverity) {
        toast.success("Severity corrected");
        invalidateAlerts();
      } else {
        toast.error("Alert not found or already changed");
      }
    },
    onError: () => toast.error("Could not correct severity"),
  });

  const ack = useAckOpsAlertMutation({
    onSuccess: (data) => {
      if (data.ackOpsAlert) {
        toast.success("Acknowledged");
        invalidateAlerts();
      } else {
        toast.error("Could not acknowledge — already changed");
      }
    },
    onError: () => toast.error("Could not acknowledge alert"),
  });

  const resolve = useResolveOpsAlertMutation({
    onSuccess: (data) => {
      if (data.resolveOpsAlert) {
        toast.success("Resolved");
        invalidateAlerts();
      } else {
        toast.error("Could not resolve — already changed");
      }
      setPendingResolve(null);
    },
    onError: () => {
      toast.error("Could not resolve alert");
      setPendingResolve(null);
    },
  });

  const correctBusyId =
    correct.isPending && correct.variables ? correct.variables.alertId : null;
  const ackBusyId =
    ack.isPending && ack.variables ? ack.variables.alertId : null;

  return (
    <div className="flex flex-col h-full bg-background overflow-hidden">
      {/* Header */}
      <header className="px-10 pt-16 pb-8 shrink-0">
        <div className="flex items-center gap-5">
          <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)]">
            <AlertTriangle className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl md:text-3xl font-black text-white tracking-tight font-outfit uppercase leading-tight">
              Alerts
            </h1>
            <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.3em] mt-2">
              Ops alert triage · correct, acknowledge, resolve
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto custom-scrollbar px-10 pb-16">
        {/* Digest chips */}
        {digestLoading ? (
          <div className="flex gap-3 mb-8">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-8 w-28 bg-white/[0.02] border border-white/5 rounded-lg animate-pulse"
              />
            ))}
          </div>
        ) : digest ? (
          <div className="flex flex-wrap items-center gap-3 mb-8">
            {digest.activeBySeverity.map((sc) => (
              <span
                key={sc.severity}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border",
                  severityStyle(sc.severity),
                )}
              >
                {sc.count} {sc.severity}
              </span>
            ))}
            <span className="px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border text-primary bg-primary/5 border-primary/20">
              {digest.newLast24H} new in 24h
            </span>
            {digest.reopenedActive > 0 && (
              <span className="px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider border text-destructive bg-destructive/10 border-destructive/30">
                {digest.reopenedActive} reopened
              </span>
            )}
          </div>
        ) : null}

        {/* Filter row */}
        <div className="inline-flex h-10 items-center justify-center rounded-xl bg-white/5 p-1 text-muted-foreground border border-white/5 mb-8">
          {(["active", "acked", "resolved"] as StatusFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={cn(
                "inline-flex items-center justify-center whitespace-nowrap rounded-lg px-4 py-1.5 text-[10px] font-black uppercase tracking-widest transition-premium",
                filter === f
                  ? "bg-white/10 text-foreground shadow-sm border border-white/10"
                  : "text-muted-foreground/60 hover:text-foreground",
              )}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Alert list */}
        {alertsLoading ? (
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-32 bg-white/[0.02] border border-white/5 rounded-[2rem] animate-pulse"
              />
            ))}
          </div>
        ) : alertsError ? (
          <>
            <ErrorBanner message="Could not load alerts" />
            <div className="flex justify-center">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetchAlerts()}
              >
                Retry
              </Button>
            </div>
          </>
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={CheckCircle2}
            title="No active alerts — all quiet"
            description="Nothing is waiting on triage right now."
          />
        ) : (
          <div className="space-y-4">
            {alerts.map((a) => {
              const rowBusy = correctBusyId === a.id || ackBusyId === a.id;
              return (
                <Card
                  key={a.id}
                  className={cn(
                    "rounded-[2rem] p-6 relative overflow-hidden",
                    rowBusy && "opacity-50 pointer-events-none",
                  )}
                >
                  {/* Top row: title + badges */}
                  <div className="flex flex-wrap items-start gap-3 mb-4">
                    <span className="text-sm font-black text-white truncate max-w-xl font-outfit">
                      {a.title}
                    </span>
                    <Badge className="text-[9px]">{a.source}</Badge>
                    {a.occurrenceCount > 1 && (
                      <span className="text-[10px] font-bold text-muted-foreground/60">
                        ×{a.occurrenceCount}
                      </span>
                    )}
                    {asIsoString(a.reopenedAt) && (
                      <span className="px-2.5 py-0.5 rounded-lg text-[9px] font-bold uppercase tracking-wider inline-flex items-center border text-destructive bg-destructive/10 border-destructive/30">
                        <RotateCcw className="w-3 h-3 mr-1" />
                        reopened
                      </span>
                    )}
                    {a.correctedSeverity && (
                      <span className="px-2.5 py-0.5 rounded-lg text-[9px] font-bold uppercase tracking-wider inline-flex items-center border text-primary bg-primary/5 border-primary/20">
                        <ShieldCheck className="w-3 h-3 mr-1" />
                        corrected
                      </span>
                    )}
                    <span className="ml-auto text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest shrink-0">
                      {relativeTime(asIsoString(a.lastSeen))}
                    </span>
                  </div>

                  {a.resource && (
                    <p className="text-[11px] text-muted-foreground/50 font-medium mb-4 truncate">
                      {a.resource}
                    </p>
                  )}

                  {/* Severity chips */}
                  <div className="flex flex-wrap items-center gap-2 mb-4">
                    <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-widest mr-1">
                      Severity
                    </span>
                    {ASSIGNABLE_SEVERITIES.map((sev) => {
                      const isCurrent = sev === a.severity;
                      return (
                        <button
                          key={sev}
                          type="button"
                          disabled={isCurrent || correct.isPending}
                          onClick={() =>
                            correct.mutate({ alertId: a.id, severity: sev })
                          }
                          className={cn(
                            "h-8 px-3 rounded-lg text-[9px] font-black uppercase tracking-widest border transition-premium disabled:cursor-default",
                            isCurrent
                              ? severityStyle(sev)
                              : "bg-transparent text-muted-foreground/50 border-white/10 hover:bg-white/5 hover:text-foreground",
                          )}
                        >
                          {sev}
                        </button>
                      );
                    })}
                  </div>

                  {/* Row actions */}
                  <div className="flex items-center gap-2">
                    {a.status === "new" && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={ack.isPending}
                        onClick={() => ack.mutate({ alertId: a.id })}
                      >
                        Ack
                      </Button>
                    )}
                    {a.status !== "resolved" && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-muted-foreground/50 hover:text-destructive hover:bg-destructive/10"
                        onClick={() => setPendingResolve(a)}
                      >
                        Resolve
                      </Button>
                    )}
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={pendingResolve != null}
        title="Resolve alert"
        message={
          pendingResolve
            ? `Resolve "${pendingResolve.title}"? This suppresses it from the active digest until it re-fires.`
            : ""
        }
        confirmLabel="Resolve"
        isLoading={resolve.isPending}
        onConfirm={() => {
          if (pendingResolve) resolve.mutate({ alertId: pendingResolve.id });
        }}
        onCancel={() => setPendingResolve(null)}
      />
    </div>
  );
}
