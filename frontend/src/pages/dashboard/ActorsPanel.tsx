import { useNavigate } from "react-router";
import type { ListActorsQuery } from "@/generated/graphql";
import { useListActorsQuery } from "@/generated/graphql";
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
      className="lg:w-72 shrink-0 bg-surface-3/60 border border-white/10 rounded-2xl p-5 flex flex-col gap-4"
      role="region"
      aria-label="Actors"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="w-4 h-4 text-primary" />
          <div>
            <h2 className="text-sm font-semibold text-white font-outfit">
              Actors
            </h2>
            <p className="text-xs text-muted-foreground">
              {actors.length} actor{actors.length !== 1 ? "s" : ""}
            </p>
          </div>
        </div>
        <button
          onClick={() => navigate("/actors")}
          className="w-8 h-8 flex items-center justify-center text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-lg transition-premium"
          title="All actors"
          aria-label="All actors"
        >
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-surface-2/60 border border-white/5 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-success" />
            <span className="text-xs text-muted-foreground">Active</span>
          </div>
          <p className="text-2xl font-semibold text-white font-outfit tracking-tight tabular-nums">
            {active}
          </p>
        </div>

        <div className="bg-surface-2/60 border border-white/5 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-warning" />
            <span className="text-xs text-muted-foreground">Paused</span>
          </div>
          <p className="text-2xl font-semibold text-white font-outfit tracking-tight tabular-nums">
            {paused}
          </p>
        </div>

        <div className="bg-surface-2/60 border border-white/5 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-destructive" />
            <span className="text-xs text-muted-foreground">Stopped</span>
          </div>
          <p className="text-2xl font-semibold text-white font-outfit tracking-tight tabular-nums">
            {error}
          </p>
        </div>

        <div className="bg-surface-2/60 border border-white/5 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-3.5 h-3.5 text-primary" />
            <span className="text-xs text-muted-foreground">Runs</span>
          </div>
          <p className="text-2xl font-semibold text-white font-outfit tracking-tight tabular-nums">
            {totalExecs >= 1000
              ? `${(totalExecs / 1000).toFixed(1)}k`
              : totalExecs}
          </p>
        </div>
      </div>
    </div>
  );
}
