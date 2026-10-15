import React, { useCallback } from "react";
import {
  useGetCapabilityCeilingDetailQuery,
  useGetCapabilityWorldHierarchyQuery,
  useRevokeCapabilityCeilingMutation,
  useGetCurrentUserIdQuery,
} from "@/generated/graphql";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  Shield,
  ChevronRight,
  Crown,
  Info,
  RefreshCw,
  User,
  Zap,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────

interface CapabilityCeilingDetail {
  ceiling: string;
  source: string;
  grantedByEmail: string | null;
  grantedAt: string | null;
  notes: string | null;
}

interface CapabilityWorldInfo {
  name: string;
  rank: number;
  description: string;
}

// ── Tier color helpers ────────────────────────────────────────────────────

function tierColor(rank: number): string {
  if (rank <= 1) return "text-muted-foreground/60";
  if (rank <= 3) return "text-primary";
  if (rank <= 5) return "text-warning";
  return "text-destructive";
}

function tierBorder(rank: number): string {
  if (rank <= 1) return "border-white/5";
  if (rank <= 3) return "border-primary/20";
  if (rank <= 5) return "border-warning/20";
  return "border-destructive/20";
}

function tierBg(rank: number): string {
  if (rank <= 1) return "bg-white/5";
  if (rank <= 3) return "bg-primary/5";
  if (rank <= 5) return "bg-warning/5";
  return "bg-destructive/5";
}

function worldRank(
  worldName: string,
  hierarchy: CapabilityWorldInfo[],
): number {
  return hierarchy.find((w) => w.name === worldName)?.rank ?? -1;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CapabilityCeilingManager() {
  // Ceiling + world hierarchy are fetched via the generated react-query hooks
  // so the loading/data/error state is derived, not mirrored through a
  // setState-in-effect. Their refetchers back the manual refresh / retry
  // buttons and the post-revoke reload below.
  const detailQuery = useGetCapabilityCeilingDetailQuery();
  const hierarchyQuery = useGetCapabilityWorldHierarchyQuery();
  // Resolve the current user's id for the revoke mutation. Kept out of the
  // event handler (no imperative transport call) — react-query caches it.
  const currentUserQuery = useGetCurrentUserIdQuery();

  const ceiling: CapabilityCeilingDetail | null =
    detailQuery.data?.capabilityCeilingDetail ?? null;
  const hierarchy: CapabilityWorldInfo[] =
    hierarchyQuery.data?.capabilityWorldHierarchy ?? [];
  const loading = detailQuery.isLoading || hierarchyQuery.isLoading;
  const queryError = detailQuery.error ?? hierarchyQuery.error;
  const error = queryError
    ? sanitizeErrorMessage(
        queryError instanceof Error ? queryError.message : "Failed to load",
      )
    : null;
  // Wrap so onClick handlers don't pass the MouseEvent through as
  // react-query RefetchOptions.
  const loadData = useCallback(() => {
    detailQuery.refetch();
    hierarchyQuery.refetch();
  }, [detailQuery, hierarchyQuery]);

  const revokeMutation = useRevokeCapabilityCeilingMutation({
    onSuccess: () => {
      toast.success("Capability ceiling reverted to default (http-node)");
      loadData();
    },
    onError: (e: Error) => {
      toast.error(sanitizeErrorMessage(e.message || "Failed to revoke"));
    },
  });

  const handleRevoke = () => {
    if (!ceiling) return;
    const userId = currentUserQuery.data?.me?.id;
    if (!userId) {
      toast.error("Could not determine your user ID");
      return;
    }
    revokeMutation.mutate({ userId });
  };

  if (loading) {
    return (
      <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-10" />
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-24 bg-white/[0.02] border border-white/5 rounded-2xl"
            />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-destructive/5 border border-destructive/20 rounded-2xl p-10 text-center">
        <p className="text-sm text-destructive font-semibold mb-6">{error}</p>
        <button
          onClick={loadData}
          className="inline-flex items-center gap-3 px-6 py-3 bg-white/5 border border-white/10 rounded-2xl text-sm font-semibold text-white hover:bg-white/10 transition-ui"
        >
          <RefreshCw className="w-4 h-4" />
          Retry
        </button>
      </div>
    );
  }

  const currentRank = worldRank(ceiling?.ceiling ?? "http-node", hierarchy);

  const rankGroups = new Map<number, CapabilityWorldInfo[]>();
  for (const w of hierarchy) {
    const existing = rankGroups.get(w.rank) || [];
    existing.push(w);
    rankGroups.set(w.rank, existing);
  }
  const sortedRanks = [...rankGroups.entries()].sort(([a], [b]) => a - b);

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 relative overflow-hidden group">
      {/* Header */}
      <div className="flex items-center justify-between mb-10 relative z-10">
        <div className="flex items-center gap-5">
          <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center transition-ui">
            <Shield className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h3 className="text-2xl md:text-3xl font-semibold text-white tracking-tight font-outfit leading-tight">
              Capability ceiling
            </h3>
            <p className="text-xs text-muted-foreground/70 font-bold mt-2">
              The most permissive module world you may use
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-2xs font-semibold text-muted-foreground hover:text-white transition-ui"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Synchronize
        </button>
      </div>

      {/* Current ceiling card */}
      <div className="mb-10 relative z-10">
        <div
          className={cn(
            "bg-black/40 border-2 rounded-2xl p-8 relative overflow-hidden transition-ui",
            tierBorder(currentRank),
          )}
        >
          <div className="flex items-center justify-between relative z-10">
            <div className="flex items-center gap-6">
              <div
                className={cn(
                  "w-16 h-16 rounded-2xl border-2 flex items-center justify-center transition-ui",
                  tierBorder(currentRank),
                  tierBg(currentRank),
                )}
              >
                <Crown className={cn("w-8 h-8", tierColor(currentRank))} />
              </div>
              <div>
                <p className="text-xs font-semibold text-muted-foreground/70 mb-1">
                  Active Access Threshold
                </p>
                <p
                  className={cn(
                    "text-3xl font-semibold tracking-tight font-outfit",
                    tierColor(currentRank),
                  )}
                >
                  {ceiling?.ceiling ?? "http-node"}
                </p>
              </div>
            </div>
            <div className="text-right">
              <span
                className={cn(
                  "inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold border shadow-sm",
                  ceiling?.source === "grant"
                    ? "bg-primary/10 text-primary border-primary/20"
                    : "bg-white/5 text-muted-foreground/70 border-white/10",
                )}
              >
                {ceiling?.source === "grant" ? (
                  <>
                    <Zap className="w-3 h-3" />
                    Granted
                  </>
                ) : (
                  "Default"
                )}
              </span>
            </div>
          </div>

          {ceiling?.source === "grant" && (
            <div className="mt-8 pt-6 border-t border-white/5 flex flex-wrap items-center gap-8 text-xs text-muted-foreground/70 font-semibold relative z-10">
              {ceiling.grantedByEmail && (
                <span className="flex items-center gap-2">
                  <User className="w-3.5 h-3.5 opacity-40" />
                  Granted by {ceiling.grantedByEmail}
                </span>
              )}
              {ceiling.grantedAt && (
                <span>
                  Issued {new Date(ceiling.grantedAt).toLocaleDateString()}
                </span>
              )}
              {ceiling.notes && (
                <span className="flex items-center gap-2 text-muted-foreground/50 italic truncate max-w-xs">
                  <Info className="w-3.5 h-3.5 shrink-0 opacity-40" />
                  {ceiling.notes}
                </span>
              )}
              <button
                onClick={handleRevoke}
                className="ml-auto text-destructive/40 hover:text-destructive transition-ui font-semibold tracking-wider"
              >
                Revoke grant
              </button>
            </div>
          )}
        </div>
      </div>

      {/* World hierarchy */}
      <div className="relative z-10">
        <p className="text-xs font-semibold text-muted-foreground/50 mb-6 pl-1">
          Capability Privilege Tiering
        </p>

        <div className="space-y-3">
          {sortedRanks.map(([rank, worlds]) => (
            <div key={rank} className="flex items-stretch gap-4">
              {/* Rank badge */}
              <div className="w-10 shrink-0 flex items-center justify-center">
                <span
                  className={cn(
                    "text-xs font-semibold tabular-nums tracking-wider",
                    tierColor(rank),
                  )}
                >
                  T{rank}
                </span>
              </div>

              {/* Worlds at this rank */}
              <div className="flex-1 flex flex-wrap gap-3">
                {worlds.map((w) => {
                  const isCurrent = w.name === ceiling?.ceiling;
                  const isAccessible = rank <= currentRank;
                  return (
                    <div
                      key={w.name}
                      className={cn(
                        "flex-1 min-w-[240px] flex items-center gap-4 px-6 py-5 rounded-2xl border transition-ui group/world relative overflow-hidden",
                        isCurrent
                          ? cn("border-2", tierBg(rank), tierBorder(rank))
                          : isAccessible
                            ? "bg-white/[0.02] border-white/5 hover:border-white/10 hover:bg-white/[0.04]"
                            : "bg-black/20 border-white/[0.02] opacity-30 cursor-not-allowed",
                      )}
                    >
                      <div className="flex-1 min-w-0 relative z-10">
                        <div className="flex items-center gap-3">
                          <span
                            className={cn(
                              "text-sm font-semibold tracking-tight font-outfit whitespace-nowrap",
                              isCurrent
                                ? tierColor(rank)
                                : isAccessible
                                  ? "text-white"
                                  : "text-muted-foreground/70",
                            )}
                          >
                            {w.name}
                          </span>
                          {isCurrent && (
                            <span className="px-2 py-0.5 bg-primary/10 text-primary text-2xs font-semibold uppercase tracking-wider rounded-full border border-primary/20 shadow-sm">
                              Current
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground/70 mt-1.5 leading-relaxed">
                          {w.description}
                        </p>
                      </div>
                      {isAccessible && !isCurrent && (
                        <ChevronRight className="w-4 h-4 text-muted-foreground/50 shrink-0 transition-ui" />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Footer hint */}
      <div className="mt-10 pt-6 border-t border-white/5 relative z-10">
        <p className="text-xs text-muted-foreground/50 leading-relaxed">
          The ceiling restricts the maximum WIT world privileges assignable to
          nodes. Worlds above this threshold are locked to prevent unauthorized
          capability escalation.
        </p>
      </div>
    </div>
  );
}
