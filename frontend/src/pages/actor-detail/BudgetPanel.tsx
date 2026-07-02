import React from "react";
import { useQuery } from "@tanstack/react-query";
import { SkeletonStatRow } from "@/components/ui";
import {
  getActorExecutionsSummary,
  type ActorDetails,
  type ActorExecutionsSummary,
} from "@/lib/graphqlApi";
import { StatCard } from "./shared";

export function BudgetPanel({
  actorId,
  actor,
}: {
  actorId: string;
  actor: ActorDetails;
}) {
  const { data: summary, isLoading } = useQuery<ActorExecutionsSummary>({
    queryKey: ["actorExecutionsSummary", actorId],
    queryFn: () => getActorExecutionsSummary(actorId),
  });

  const successRate =
    summary && summary.totalExecutions > 0
      ? Math.round(
          (summary.successfulExecutions / summary.totalExecutions) * 100,
        )
      : null;

  return (
    <div className="space-y-6">
      {/* Execution summary */}
      <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
        <h2 className="text-white font-medium text-sm mb-4">
          Execution Summary
        </h2>
        {isLoading ? (
          <SkeletonStatRow className="mt-2" />
        ) : summary ? (
          <div className="space-y-4">
            {summary.totalExecutions > 0 && (
              <div className="w-full h-2 bg-background rounded-full overflow-hidden flex">
                <div
                  className="h-full bg-emerald-500 transition-premium"
                  style={{
                    width: `${(summary.successfulExecutions / summary.totalExecutions) * 100}%`,
                  }}
                />
                <div
                  className="h-full bg-red-500 transition-premium"
                  style={{
                    width: `${(summary.failedExecutions / summary.totalExecutions) * 100}%`,
                  }}
                />
                <div
                  className="h-full bg-sky-500 transition-premium"
                  style={{
                    width: `${(summary.activeExecutions / summary.totalExecutions) * 100}%`,
                  }}
                />
              </div>
            )}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <StatCard label="Total" value={summary.totalExecutions} />
              <StatCard
                label="Successful"
                value={summary.successfulExecutions}
                accent="text-emerald-400"
              />
              <StatCard
                label="Failed"
                value={summary.failedExecutions}
                accent="text-red-400"
              />
              <StatCard
                label="Active"
                value={summary.activeExecutions}
                accent="text-sky-400"
              />
            </div>
            {successRate !== null && (
              <p className="text-muted-foreground text-xs">
                Success rate:{" "}
                <span className="text-white font-semibold">{successRate}%</span>
              </p>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">
            No execution data available.
          </p>
        )}
      </div>

      {/* Rate limit */}
      <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
        <h2 className="text-white font-medium text-sm mb-3">Rate Limit</h2>
        <p className="text-2xl font-bold text-white tabular-nums">
          {actor.rateLimit != null ? `${actor.rateLimit}/min` : "Unlimited"}
        </p>
        <p className="text-muted-foreground/40 text-xs mt-2">
          Rate limits and budget policies are configured via MCP tools.
        </p>
      </div>

      {/* Budget cap */}
      <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
        <h2 className="text-white font-medium text-sm mb-3">Budget Cap</h2>
        <p className="text-2xl font-bold text-white tabular-nums">
          {actor.totalBudgetUsd != null
            ? `$${actor.totalBudgetUsd.toFixed(2)}`
            : "Unlimited"}
        </p>
        {actor.totalBudgetUsd != null && (
          <p className="text-muted-foreground text-xs mt-1">
            Spent:{" "}
            <span className="text-white font-semibold">
              ${actor.spentBudgetUsd.toFixed(2)}
            </span>
          </p>
        )}
      </div>
    </div>
  );
}
