import { useNavigate } from "react-router-dom";
import { useListActorsQuery, ListActorsQuery } from "@/generated/graphql";
import { Bot, Zap, ArrowRight } from "lucide-react";

export default function ActorsPanel() {
  const navigate = useNavigate();
  const { data: actors = [] } = useListActorsQuery(undefined, {
    staleTime: 30_000,
    refetchInterval: 30_000,
    select: (data: ListActorsQuery) => data.actors,
  });

  const active = actors.filter((a) => a.status === "active").length;
  const paused = actors.filter((a) => a.status === "suspended").length;
  const error = actors.filter((a) => a.status === "terminated").length;
  const totalExecs = actors.reduce((s, a) => s + (a.executionCount ?? 0), 0);

  if (actors.length === 0) return null;

  return (
    <div
      className="h-full bg-surface-3/40 border border-white/10 rounded-[2.5rem] p-8 glass backdrop-blur-3xl flex flex-col justify-between shadow-2xl gpu"
      role="region"
      aria-label="Actor Registry Status"
    >
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_20px_hsla(var(--primary),0.1)] relative overflow-hidden group/icon">
            <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover/icon:opacity-100 transition-premium" />
            <Bot className="w-6 h-6 text-primary relative z-10" />
          </div>
          <div>
            <h2 className="text-sm font-black text-white tracking-tighter uppercase font-outfit">
              Registry
            </h2>
            <p className="text-[10px] text-muted-foreground/30 font-black tracking-[0.2em] uppercase leading-none mt-1">
              {actors.length} Node{actors.length !== 1 ? "s" : ""}
            </p>
          </div>
        </div>
        <button
          onClick={() => navigate("/actors")}
          className="w-10 h-10 flex items-center justify-center text-muted-foreground/40 hover:text-primary hover:bg-primary/10 rounded-xl border border-transparent hover:border-primary/20 transition-premium active:scale-90"
          title="Manage All Actors"
        >
          <ArrowRight className="w-5 h-5" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-surface-4/40 border border-white/5 rounded-[1.5rem] p-4 group hover:border-success/30 transition-premium glass-light shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div className="w-2 h-2 rounded-full bg-success animate-status-pulse shadow-[0_0_10px_hsla(var(--success),0.6)]" />
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-[0.2em]">
              Active
            </span>
          </div>
          <p className="text-3xl font-black text-white font-outfit tracking-tighter transition-colors group-hover:text-success">
            {active}
          </p>
        </div>

        <div className="bg-surface-4/40 border border-white/5 rounded-[1.5rem] p-4 group hover:border-warning/30 transition-premium glass-light shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div className="w-2 h-2 rounded-full bg-warning shadow-[0_0_10px_hsla(var(--warning),0.3)]" />
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-[0.2em]">
              Paused
            </span>
          </div>
          <p className="text-3xl font-black text-white font-outfit tracking-tighter transition-colors group-hover:text-warning">
            {paused}
          </p>
        </div>

        <div className="bg-surface-4/40 border border-white/5 rounded-[1.5rem] p-4 group hover:border-destructive/30 transition-premium glass-light shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div className="w-2 h-2 rounded-full bg-destructive shadow-[0_0_10px_hsla(var(--destructive),0.3)]" />
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-[0.2em]">
              Failure
            </span>
          </div>
          <p className="text-3xl font-black text-white font-outfit tracking-tighter transition-colors group-hover:text-destructive">
            {error}
          </p>
        </div>

        <div className="bg-surface-4/40 border border-white/5 rounded-[1.5rem] p-4 group hover:border-primary/30 transition-premium glass-light shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <Zap className="w-4 h-4 text-primary/40 group-hover:text-primary transition-colors" />
            <span className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-[0.2em]">
              Loads
            </span>
          </div>
          <p className="text-2xl font-black text-white font-outfit tracking-tighter leading-none mt-1">
            {totalExecs >= 1000
              ? `${(totalExecs / 1000).toFixed(1)}k`
              : totalExecs}
          </p>
        </div>
      </div>
    </div>
  );
}
