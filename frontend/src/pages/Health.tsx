import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
// Data layer: generated react-query hooks (one per operation in
// src/graphql/*.graphql) — no direct graphqlRequest calls in pages.
import {
  useGetAllWorkflowStatsQuery,
  useGetSecretsQuery,
  useListActorSummariesQuery,
  useListWorkflowNamesQuery,
  useMySchedulesQuery,
  type GetAllWorkflowStatsQuery,
  type MySchedulesQuery,
} from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui";
import { futureTime, formatDurationSecs } from "@/lib/formatTime";
import {
  Activity,
  Bot,
  Calendar,
  CheckCircle2,
  Clock,
  Layers,
  Lock,
  XCircle,
  Zap,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type WorkflowStat = GetAllWorkflowStatsQuery["getAllWorkflowStats"][number];
type ScheduleItem = MySchedulesQuery["mySchedules"][number];

function successRate(stat: WorkflowStat): number {
  if (stat.total === 0) return 0;
  return Math.round((stat.succeeded / stat.total) * 100);
}

// ---------------------------------------------------------------------------
// Stat card
// ---------------------------------------------------------------------------

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ReactNode;
  accent?: string;
  loading?: boolean;
}

function StatCard({
  label,
  value,
  sub,
  icon,
  accent = "text-primary",
  loading,
}: StatCardProps) {
  const Icon = icon as React.ReactElement<{ size?: number }>;
  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-6 glass transition-premium hover-elevation relative overflow-hidden group">
      <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
        {React.cloneElement(Icon, { size: 48 })}
      </div>

      <div className="relative z-10 flex flex-col h-full">
        <div className="flex items-center gap-2 mb-4">
          <div
            className={cn(
              "w-8 h-8 rounded-xl flex items-center justify-center bg-surface-4/60 border border-white/5",
              accent,
            )}
          >
            {icon}
          </div>
          <span className="text-2xs font-semibold text-muted-foreground uppercase tracking-wider">
            {label}
          </span>
        </div>

        {loading ? (
          <div className="h-10 w-24 bg-white/5 rounded-xl animate-shimmer mt-auto" />
        ) : (
          <div className="mt-auto">
            <div
              className={cn(
                "text-3xl font-semibold tabular-nums tracking-tight",
                accent,
              )}
            >
              {value}
            </div>
            {sub && (
              <div className="text-xs text-muted-foreground mt-1">{sub}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Success rate bar
// ---------------------------------------------------------------------------

function RateBar({ rate }: { rate: number }) {
  const color =
    rate >= 95 ? "bg-success" : rate >= 80 ? "bg-warning" : "bg-destructive";
  const glow = rate >= 95 ? "" : rate >= 80 ? "" : "";

  return (
    <div className="flex items-center gap-3 min-w-0">
      <div className="flex-1 bg-white/5 rounded-full h-1.5 overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full transition-all duration-1000",
            color,
            glow,
          )}
          style={{ width: `${rate}%` }}
        />
      </div>
      <span
        className={cn(
          "text-xs font-semibold tabular-nums w-10 text-right shrink-0 tracking-wider",
          rate >= 95
            ? "text-success"
            : rate >= 80
              ? "text-warning"
              : "text-destructive",
        )}
      >
        {rate}%
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section header
// ---------------------------------------------------------------------------

function SectionHeader({
  icon,
  title,
  count,
}: {
  icon: React.ReactNode;
  title: string;
  count?: number;
}) {
  return (
    <div className="flex items-center justify-between mb-6">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-xl bg-surface-4/60 border border-white/5 flex items-center justify-center text-primary">
          {icon}
        </div>
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      {count !== undefined && (
        <span className="text-xs text-muted-foreground bg-white/5 px-2.5 py-1 rounded-full tabular-nums">
          {count} total
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Actor status breakdown
// ---------------------------------------------------------------------------

function ActorBreakdown() {
  const { data: actors = [], isLoading } = useListActorSummariesQuery(
    undefined,
    { staleTime: 30_000, select: (d) => d.actors },
  );
  const navigate = useNavigate();

  const counts = useMemo(
    () => ({
      active: actors.filter((a) => a.status === "active").length,
      suspended: actors.filter((a) => a.status === "suspended").length,
      terminated: actors.filter((a) => a.status === "terminated").length,
      archived: actors.filter((a) => a.status === "archived").length,
    }),
    [actors],
  );

  const rows = [
    {
      label: "Active",
      count: counts.active,
      dot: "bg-success",
      text: "text-success",
      bg: "bg-success/5 border-success/10",
    },
    {
      label: "Suspended",
      count: counts.suspended,
      dot: "bg-warning",
      text: "text-warning",
      bg: "bg-warning/5 border-warning/10",
    },
    {
      label: "Stopped",
      count: counts.terminated,
      dot: "bg-destructive",
      text: "text-destructive",
      bg: "bg-destructive/5 border-destructive/10",
    },
  ];

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-3xl p-8 glass h-full">
      <SectionHeader
        icon={<Bot size={16} />}
        title="Actors by status"
        count={actors.length}
      />
      {isLoading ? (
        <div className="space-y-4">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-12 bg-white/5 rounded-2xl animate-shimmer"
            />
          ))}
        </div>
      ) : actors.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Bot className="w-10 h-10 text-muted-foreground/30 mb-4" />
          <p className="text-sm text-muted-foreground">No actors yet</p>
        </div>
      ) : (
        <div className="space-y-3">
          {rows.map(
            (r) =>
              r.count > 0 && (
                <button
                  key={r.label}
                  onClick={() => navigate("/actors")}
                  className={cn(
                    "w-full flex items-center gap-4 p-4 rounded-2xl border transition-premium group active:scale-95",
                    r.bg,
                  )}
                >
                  <span
                    className={cn("w-2 h-2 rounded-full shrink-0", r.dot)}
                  />
                  <span className="text-sm text-muted-foreground flex-1 text-left group-hover:text-foreground transition-colors">
                    {r.label}
                  </span>
                  <span
                    className={cn("text-lg font-semibold tabular-nums", r.text)}
                  >
                    {r.count}
                  </span>
                </button>
              ),
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Upcoming schedules panel
// ---------------------------------------------------------------------------

type ScheduleWithWorkflow = ScheduleItem & {
  workflowName?: string;
};

function UpcomingSchedules() {
  const { data: schedules = [], isLoading } = useMySchedulesQuery(undefined, {
    staleTime: 60_000,
    select: (d) => d.mySchedules,
  });

  const workflowIds = useMemo(
    () => [...new Set(schedules.map((s) => s.workflowId))],
    [schedules],
  );

  const { data: workflowNames } = useListWorkflowNamesQuery(undefined, {
    enabled: workflowIds.length > 0,
    staleTime: 60_000,
    select: (d): Record<string, string> =>
      Object.fromEntries(d.workflows.map((w) => [w.id, w.name])),
  });

  // Wall-clock time for the "overdue" check, refreshed on an interval so a
  // schedule turns overdue as time passes without needing a refetch. Calling
  // Date.now() directly in render is impure (react-hooks/purity); a lazy
  // initializer + interval keeps render idempotent.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, []);

  const upcoming: ScheduleWithWorkflow[] = useMemo(() => {
    return schedules
      .filter((s) => s.isEnabled && s.nextTriggerAt)
      .sort(
        (a, b) =>
          new Date(a.nextTriggerAt!).getTime() -
          new Date(b.nextTriggerAt!).getTime(),
      )
      .slice(0, 8)
      .map((s) => ({ ...s, workflowName: workflowNames?.[s.workflowId] }));
  }, [schedules, workflowNames]);

  const enabledCount = schedules.filter((s) => s.isEnabled).length;

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-3xl p-8 glass h-full">
      <SectionHeader
        icon={<Calendar size={16} />}
        title="Upcoming schedules"
        count={enabledCount}
      />
      {isLoading ? (
        <div className="space-y-4">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-16 bg-white/5 rounded-2xl animate-shimmer"
            />
          ))}
        </div>
      ) : upcoming.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Calendar className="w-10 h-10 text-muted-foreground/30 mb-4" />
          <p className="text-sm text-muted-foreground">No schedules enabled</p>
        </div>
      ) : (
        <div className="space-y-2">
          {upcoming.map((s) => {
            const isOverdue =
              s.nextTriggerAt && new Date(s.nextTriggerAt).getTime() < now;
            return (
              <div
                key={s.id}
                className="flex items-center gap-4 p-4 bg-surface-4/40 border border-white/5 rounded-2xl transition-premium hover:bg-surface-4/60 group"
              >
                <div
                  className={cn(
                    "w-10 h-10 rounded-xl flex items-center justify-center bg-surface-3 border border-white/5",
                    isOverdue ? "text-destructive" : "text-primary",
                  )}
                >
                  <Clock size={18} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-white truncate">
                    {s.workflowName ?? s.workflowId.slice(0, 8) + "…"}
                  </div>
                  <div className="text-2xs font-semibold text-muted-foreground/70 uppercase tracking-wider mt-1">
                    {s.cronExpression}
                  </div>
                </div>
                <span
                  className={cn(
                    "text-xs font-semibold shrink-0",
                    isOverdue
                      ? "text-destructive animate-status-pulse"
                      : "text-primary",
                  )}
                >
                  {futureTime(s.nextTriggerAt)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Workflow execution health table
// ---------------------------------------------------------------------------

function WorkflowHealth() {
  const { data: stats = [], isLoading } = useGetAllWorkflowStatsQuery(
    { days: 7 },
    { staleTime: 60_000, select: (d) => d.getAllWorkflowStats },
  );

  const sorted = useMemo(
    () =>
      [...stats]
        .filter((s) => s.total > 0)
        .sort((a, b) => b.total - a.total)
        .slice(0, 15),
    [stats],
  );

  const totalExecs = useMemo(
    () => stats.reduce((sum, s) => sum + s.total, 0),
    [stats],
  );
  const totalFailed = useMemo(
    () => stats.reduce((sum, s) => sum + s.failed, 0),
    [stats],
  );

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-3xl p-8 glass relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30" />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-8">
          <SectionHeader
            icon={<Activity size={18} />}
            title="Workflow health"
            count={sorted.length}
          />
          <div className="flex items-center gap-4 text-xs font-semibold">
            <span className="flex items-center gap-2 bg-primary/10 text-primary px-3 py-1.5 rounded-full border border-primary/20">
              <Zap size={12} fill="currentColor" />
              {totalExecs} runs
            </span>
            {totalFailed > 0 && (
              <span className="flex items-center gap-2 bg-destructive/10 text-destructive px-3 py-1.5 rounded-full border border-destructive/20">
                <XCircle size={12} />
                {totalFailed} failed
              </span>
            )}
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-4">
            {[0, 1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="h-14 bg-white/5 rounded-2xl animate-shimmer"
              />
            ))}
          </div>
        ) : sorted.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <Activity className="w-16 h-16 text-muted-foreground/30 mb-6" />
            <p className="text-sm text-muted-foreground">
              No runs in the last 7 days
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/5">
                  <th className="text-left text-xs font-semibold text-muted-foreground/70 pb-4 pl-4">
                    Workflow
                  </th>
                  <th className="text-right text-xs font-semibold text-muted-foreground/70 pb-4 pr-6 w-24">
                    Runs
                  </th>
                  <th className="text-right text-xs font-semibold text-muted-foreground/70 pb-4 pr-6 w-24">
                    Failed
                  </th>
                  <th className="text-right text-xs font-semibold text-muted-foreground/70 pb-4 pr-6 w-24">
                    Latency
                  </th>
                  <th className="text-left text-xs font-semibold text-muted-foreground/70 pb-4 w-48">
                    Reliability
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {sorted.map((s) => {
                  const rate = successRate(s);
                  return (
                    <tr
                      key={s.id}
                      className="group/row hover:bg-white/5 transition-premium"
                    >
                      <td className="py-4 pl-4">
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "w-2 h-2 rounded-full",
                              s.failed > 0 ? "bg-destructive" : "bg-success",
                            )}
                          />
                          <span
                            className="text-sm font-semibold text-white truncate max-w-[240px] tracking-tight group-hover/row:text-primary transition-colors"
                            title={s.name}
                          >
                            {s.name}
                          </span>
                        </div>
                      </td>
                      <td className="py-4 pr-6 text-right tabular-nums text-foreground font-semibold text-xs">
                        {s.total}
                      </td>
                      <td className="py-4 pr-6 text-right tabular-nums">
                        <span
                          className={cn(
                            "text-xs font-semibold",
                            s.failed > 0
                              ? "text-destructive"
                              : "text-muted-foreground/50",
                          )}
                        >
                          {s.failed}
                        </span>
                      </td>
                      <td className="py-4 pr-6 text-right tabular-nums text-muted-foreground text-xs">
                        {formatDurationSecs(s.avgDurationSecs)}
                      </td>
                      <td className="py-4 pr-4">
                        <RateBar rate={rate} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Health() {
  const { data: actors = [], isLoading: actorsLoading } =
    useListActorSummariesQuery(undefined, {
      staleTime: 30_000,
      select: (d) => d.actors,
    });

  const { data: stats = [], isLoading: statsLoading } =
    useGetAllWorkflowStatsQuery(
      { days: 7 },
      { staleTime: 60_000, select: (d) => d.getAllWorkflowStats },
    );

  const { data: schedules = [], isLoading: schedulesLoading } =
    useMySchedulesQuery(undefined, {
      staleTime: 60_000,
      select: (d) => d.mySchedules,
    });

  const { data: secrets = [], isLoading: secretsLoading } = useGetSecretsQuery(
    undefined,
    { staleTime: 120_000, select: (d) => d.secrets },
  );

  const { data: workflows } = useListWorkflowNamesQuery(undefined, {
    staleTime: 60_000,
    select: (d) => d.workflows,
  });

  const activeActors = useMemo(
    () => actors.filter((a) => a.status === "active").length,
    [actors],
  );
  const totalExecsToday = useMemo(
    () => stats.reduce((s, w) => s + w.total, 0),
    [stats],
  );
  const failedToday = useMemo(
    () => stats.reduce((s, w) => s + w.failed, 0),
    [stats],
  );
  const enabledSchedules = useMemo(
    () => schedules.filter((s) => s.isEnabled).length,
    [schedules],
  );

  const overallHealthPct = useMemo(() => {
    const total = stats.reduce((s, w) => s + w.total, 0);
    const succeeded = stats.reduce((s, w) => s + w.succeeded, 0);
    return total === 0 ? 100 : Math.round((succeeded / total) * 100);
  }, [stats]);

  const healthColor =
    overallHealthPct >= 95
      ? "text-success"
      : overallHealthPct >= 80
        ? "text-warning"
        : "text-destructive";

  return (
    <div className="h-full overflow-y-auto bg-background custom-scrollbar relative">
      {/* Dynamic Glow Background */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-primary/5 via-background to-background opacity-50" />

      <div className="max-w-7xl mx-auto px-8 py-10 relative z-10">
        {/* Page header */}
        <PageHeader
          title="System health"
          description="Workflows, actors and runs over the last 7 days."
        />

        {/* Stat cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-12">
          <StatCard
            label="Workflows"
            value={workflows?.length ?? "—"}
            icon={<Layers size={18} />}
            accent="text-primary"
            loading={!workflows}
          />
          <StatCard
            label="Active actors"
            value={activeActors}
            sub={actors.length > 0 ? `${actors.length} in total` : undefined}
            icon={<Bot size={18} />}
            accent="text-success"
            loading={actorsLoading}
          />
          <StatCard
            label="Runs today"
            value={totalExecsToday}
            sub={failedToday > 0 ? `${failedToday} failed` : "None failed"}
            icon={<Activity size={18} />}
            accent={failedToday > 0 ? "text-warning" : "text-success"}
            loading={statsLoading}
          />
          <StatCard
            label="Success rate"
            value={`${overallHealthPct}%`}
            sub="Last 7 days"
            icon={<CheckCircle2 size={18} />}
            accent={healthColor}
            loading={statsLoading}
          />
          <StatCard
            label="Secrets"
            value={secrets.length}
            sub={
              enabledSchedules > 0
                ? `${enabledSchedules} active schedule${enabledSchedules === 1 ? "" : "s"}`
                : undefined
            }
            icon={<Lock size={18} />}
            accent="text-warning"
            loading={secretsLoading || schedulesLoading}
          />
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
          {/* Workflow health — spans 2 columns */}
          <div className="lg:col-span-2">
            <WorkflowHealth />
          </div>

          {/* Right column — actor status + upcoming schedules */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-1 gap-8">
            <ActorBreakdown />
            <UpcomingSchedules />
          </div>
        </div>

        {/* Footer note */}
        <footer className="pt-8 border-t border-white/5">
          <p className="text-xs text-muted-foreground/70 text-center leading-relaxed max-w-2xl mx-auto">
            Counts cover the last 7 days and refresh every minute.
          </p>
        </footer>
      </div>
    </div>
  );
}
