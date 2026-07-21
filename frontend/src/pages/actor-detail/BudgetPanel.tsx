import React from "react";
import { useQuery } from "@tanstack/react-query";
import { SkeletonStatRow } from "@/components/ui";
import {
  getActorExecutionsSummary,
  type ActorDetails,
  type ActorExecutionsSummary,
} from "@/lib/graphqlApi";
import { useGetActorLlmUsageSummaryQuery } from "@/generated/graphql";
import { cn } from "@/lib/utils";
import { StatCard } from "./shared";

// R2 token ledger — trailing-window token count, abbreviated for the
// compact usage-bar label (e.g. "42.3K", "1.2M").
function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

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

  // R2 token ledger — read-only; the daily ceiling itself (max_llm_tokens_
  // per_day) is still configured via MCP tools, same as rate limit/budget
  // cap above.
  const { data: usageData, isLoading: usageLoading } =
    useGetActorLlmUsageSummaryQuery({ actorId, days: 7 });
  const usage = usageData?.llmUsageSummary;
  const tokenPct =
    usage && usage.maxLlmTokensPerDay
      ? Math.min(
          100,
          Math.round((usage.tokensLast24H / usage.maxLlmTokensPerDay) * 100),
        )
      : null;

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

      {/* LLM token spend (R2 token ledger) */}
      <div className="bg-surface-3/60 border border-white/5 rounded-2xl px-6 py-5">
        <h2 className="text-white font-medium text-sm mb-4">LLM Token Spend</h2>
        {usageLoading ? (
          <SkeletonStatRow className="mt-2" />
        ) : usage ? (
          <div className="space-y-5">
            <div>
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-muted-foreground">
                  Last 24h vs. daily ceiling
                </span>
                <span className="text-white font-semibold tabular-nums">
                  {formatTokens(usage.tokensLast24H)}
                  {usage.maxLlmTokensPerDay != null && (
                    <span className="text-muted-foreground font-normal">
                      {" "}
                      / {formatTokens(usage.maxLlmTokensPerDay)}
                    </span>
                  )}
                </span>
              </div>
              {tokenPct != null ? (
                <div className="w-full h-2 bg-background rounded-full overflow-hidden">
                  <div
                    className={cn(
                      "h-full transition-premium",
                      tokenPct >= 90
                        ? "bg-red-500"
                        : tokenPct >= 75
                          ? "bg-amber-500"
                          : "bg-emerald-500",
                    )}
                    style={{ width: `${tokenPct}%` }}
                  />
                </div>
              ) : (
                <p className="text-muted-foreground/40 text-xs">
                  No daily ceiling set — unlimited.
                </p>
              )}
            </div>

            {usage.byModel.length > 0 && (
              <div>
                <p className="text-muted-foreground/60 text-[11px] font-medium uppercase tracking-wide mb-2">
                  By provider/model · last 7 days
                </p>
                <div className="space-y-1.5">
                  {usage.byModel.map((row) => (
                    <div
                      key={`${row.provider}:${row.model}`}
                      className="flex items-center justify-between text-xs gap-3"
                    >
                      <span className="text-white/80 truncate">
                        {row.provider}/{row.model}
                      </span>
                      <span className="text-muted-foreground tabular-nums shrink-0">
                        {formatTokens(row.promptTokens + row.completionTokens)}{" "}
                        tok · {row.calls} calls
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">
            No usage data available.
          </p>
        )}
        <p className="text-muted-foreground/40 text-xs mt-3">
          The daily ceiling is configured via MCP tools.
        </p>
      </div>
    </div>
  );
}
