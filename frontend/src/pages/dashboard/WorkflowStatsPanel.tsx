import { useGetAllWorkflowStatsQuery } from "@/generated/graphql";
import { Zap, CheckCircle, XCircle, Clock } from "lucide-react";
import { cn } from "@/lib/utils";

function Stat({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Zap;
  label: string;
  value: string;
  tone: string;
}) {
  return (
    <div className="bg-surface-2/60 border border-white/5 rounded-xl p-4">
      <div className="flex items-center gap-2 mb-2 text-muted-foreground">
        <Icon className={cn("w-4 h-4", tone)} />
        <span className="text-xs">{label}</span>
      </div>
      <p className="text-2xl font-semibold text-white font-outfit tracking-tight tabular-nums">
        {value}
      </p>
    </div>
  );
}

/** Totals across every workflow for the last seven days. */
export default function WorkflowStatsPanel() {
  const { data, isLoading } = useGetAllWorkflowStatsQuery(
    { days: 7 },
    { staleTime: 60_000, refetchInterval: 60_000 },
  );
  const stats = data?.getAllWorkflowStats ?? [];

  if (isLoading) {
    return (
      <div className="h-full min-h-[160px] bg-surface-3/40 border border-white/5 rounded-2xl p-6 animate-shimmer" />
    );
  }
  if (stats.length === 0) return null;

  const totalRuns = stats.reduce((s, w) => s + w.total, 0);
  const totalSucceeded = stats.reduce((s, w) => s + w.succeeded, 0);
  const totalFailed = stats.reduce((s, w) => s + w.failed, 0);
  const successRate =
    totalRuns > 0 ? Math.round((totalSucceeded / totalRuns) * 100) : null;
  const statsWithDuration = stats.filter((w) => w.avgDurationSecs != null);
  const avgDuration =
    statsWithDuration.length > 0
      ? (
          statsWithDuration.reduce((s, w) => s + (w.avgDurationSecs ?? 0), 0) /
          statsWithDuration.length
        ).toFixed(1)
      : null;

  return (
    <section
      className="h-full bg-surface-3/60 border border-white/10 rounded-2xl p-6 flex flex-col gap-5"
      aria-label="Runs in the last 7 days"
    >
      <div>
        <h2 className="text-sm font-semibold text-white font-outfit">
          Last 7 days
        </h2>
        <p className="text-xs text-muted-foreground">
          Across {stats.length} workflow{stats.length === 1 ? "" : "s"}
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat
          icon={Zap}
          label="Runs"
          value={totalRuns.toLocaleString()}
          tone="text-primary"
        />
        <Stat
          icon={CheckCircle}
          label="Success rate"
          value={successRate !== null ? `${successRate}%` : "—"}
          tone="text-success"
        />
        <Stat
          icon={XCircle}
          label="Failed"
          value={totalFailed.toLocaleString()}
          tone={totalFailed > 0 ? "text-destructive" : "text-muted-foreground"}
        />
        <Stat
          icon={Clock}
          label="Average duration"
          value={avgDuration !== null ? `${avgDuration}s` : "—"}
          tone="text-muted-foreground"
        />
      </div>
    </section>
  );
}
