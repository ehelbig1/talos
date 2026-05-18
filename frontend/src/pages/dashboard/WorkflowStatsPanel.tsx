import {
  useGetAllWorkflowStatsQuery,
} from "@/generated/graphql";
import { SkeletonStatRow } from "@/components/ui";
import {
  Zap,
  TrendingUp,
  CheckCircle,
  XCircle,
  Clock,
} from "lucide-react";

export default function WorkflowStatsPanel() {
  const { data, isLoading } = useGetAllWorkflowStatsQuery(
    { days: 7 },
    { staleTime: 60_000, refetchInterval: 60_000 },
  );
  const stats = data?.getAllWorkflowStats ?? [];

  if (isLoading) {
    return (
      <div className="h-full min-h-[180px] bg-surface-3/40 border border-white/5 rounded-[2rem] p-6 glass backdrop-blur-xl animate-shimmer" />
    );
  }
  if (stats.length === 0) return null;

  const totalRuns = stats.reduce((s, w) => s + w.total, 0);
  const totalSucceeded = stats.reduce((s, w) => s + w.succeeded, 0);
  const totalFailed = stats.reduce((s, w) => s + w.failed, 0);
  const successRate = totalRuns > 0 ? Math.round((totalSucceeded / totalRuns) * 100) : null;
  const statsWithDuration = stats.filter((w) => w.avgDurationSecs != null);
  const avgDuration =
    statsWithDuration.length > 0
      ? (
          statsWithDuration.reduce((s, w) => s + (w.avgDurationSecs ?? 0), 0) /
          statsWithDuration.length
        ).toFixed(1)
      : null;

  return (
    <div 
      className="h-full bg-surface-3/40 border border-white/10 rounded-[2.5rem] p-8 glass backdrop-blur-3xl flex flex-col justify-between shadow-2xl gpu optimize-blur relative overflow-hidden"
      role="region"
      aria-label="Operational Telemetry Summary"
    >
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
      <div className="flex items-center justify-between mb-8 relative z-10">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_20px_hsla(var(--primary),0.1)]">
            <TrendingUp className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-sm font-black text-white tracking-tighter uppercase font-outfit">Operational Telemetry</h2>
            <p className="text-[10px] text-muted-foreground/40 font-black tracking-[0.3em] uppercase">Last 168 Hours</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 relative z-10">
        <div className="bg-surface-2/40 border border-white/5 rounded-[2rem] p-6 group hover:border-primary/30 transition-premium hover:scale-[1.02] active:scale-95 shadow-xl glass-light">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-1.5 rounded-lg bg-primary/5 border border-primary/10 group-hover:bg-primary/20 transition-premium">
                <Zap className="w-4 h-4 text-primary/60 group-hover:text-primary transition-colors" />
            </div>
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-widest group-hover:text-white/60 transition-colors">Throughput</span>
          </div>
          <p className="text-3xl font-black text-white font-outfit tracking-tight">{totalRuns.toLocaleString()}</p>
        </div>

        <div className="bg-surface-2/40 border border-white/5 rounded-[2rem] p-6 group hover:border-success/30 transition-premium hover:scale-[1.02] active:scale-95 shadow-xl glass-light">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-1.5 rounded-lg bg-success/5 border border-success/10 group-hover:bg-success/20 transition-premium">
                <CheckCircle className="w-4 h-4 text-success/60 group-hover:text-success transition-colors" />
            </div>
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-widest group-hover:text-white/60 transition-colors">Efficiency</span>
          </div>
          <p className="text-3xl font-black text-white group-hover:text-success transition-premium font-outfit tracking-tight">
            {successRate !== null ? `${successRate}%` : "\u2014"}
          </p>
        </div>

        <div className="bg-surface-2/40 border border-white/5 rounded-[2rem] p-6 group hover:border-destructive/30 transition-premium hover:scale-[1.02] active:scale-95 shadow-xl glass-light">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-1.5 rounded-lg bg-destructive/5 border border-destructive/10 group-hover:bg-destructive/20 transition-premium">
                <XCircle className="w-4 h-4 text-destructive/60 group-hover:text-destructive transition-colors" />
            </div>
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-widest group-hover:text-white/60 transition-colors">Anomalies</span>
          </div>
          <p className="text-3xl font-black text-white group-hover:text-destructive transition-premium font-outfit tracking-tight">{totalFailed.toLocaleString()}</p>
        </div>

        <div className="bg-surface-2/40 border border-white/5 rounded-[2rem] p-6 group hover:border-white/20 transition-premium hover:scale-[1.02] active:scale-95 shadow-xl glass-light">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-1.5 rounded-lg bg-white/5 border border-white/10 group-hover:bg-white/20 transition-premium">
                <Clock className="w-4 h-4 text-muted-foreground/60 group-hover:text-foreground transition-colors" />
            </div>
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-widest group-hover:text-white/60 transition-colors">Latency</span>
          </div>
          <p className="text-3xl font-black text-white font-outfit tracking-tight">
            {avgDuration !== null ? `${avgDuration}s` : "\u2014"}
          </p>
        </div>
      </div>
    </div>
  );
}
