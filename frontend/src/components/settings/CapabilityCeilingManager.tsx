import React, { useState, useEffect, useCallback } from "react";
import { graphqlRequest } from "@/lib/graphqlClient";
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

// ── GraphQL queries ───────────────────────────────────────────────────────

async function fetchCeilingDetail(): Promise<CapabilityCeilingDetail> {
  const data = await graphqlRequest<{
    capabilityCeilingDetail: CapabilityCeilingDetail;
  }>(
    `query { capabilityCeilingDetail { ceiling source grantedByEmail grantedAt notes } }`,
  );
  return data.capabilityCeilingDetail;
}

async function fetchWorldHierarchy(): Promise<CapabilityWorldInfo[]> {
  const data = await graphqlRequest<{
    capabilityWorldHierarchy: CapabilityWorldInfo[];
  }>(`query { capabilityWorldHierarchy { name rank description } }`);
  return data.capabilityWorldHierarchy;
}

async function revokeCeiling(userId: string): Promise<boolean> {
  const data = await graphqlRequest<{ revokeCapabilityCeiling: boolean }>(
    `mutation RevokeCeiling($userId: UUID!) {
      revokeCapabilityCeiling(userId: $userId)
    }`,
    { userId },
  );
  return data.revokeCapabilityCeiling;
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
  const [ceiling, setCeiling] = useState<CapabilityCeilingDetail | null>(null);
  const [hierarchy, setHierarchy] = useState<CapabilityWorldInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [detail, worlds] = await Promise.all([
        fetchCeilingDetail(),
        fetchWorldHierarchy(),
      ]);
      setCeiling(detail);
      setHierarchy(worlds);
    } catch (e) {
      setError(
        sanitizeErrorMessage(e instanceof Error ? e.message : "Failed to load"),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRevoke = async () => {
    if (!ceiling) return;
    try {
      const data = await graphqlRequest<{ currentUser: { id: string } }>(
        `query { currentUser { id } }`,
      ).catch(() => null);
      if (!data?.currentUser?.id) {
        toast.error("Could not determine your user ID");
        return;
      }
      await revokeCeiling(data.currentUser.id);
      toast.success("Capability ceiling reverted to default (http-node)");
      loadData();
    } catch (e) {
      toast.error(
        sanitizeErrorMessage(
          e instanceof Error ? e.message : "Failed to revoke",
        ),
      );
    }
  };

  if (loading) {
    return (
      <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-10" />
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-24 bg-white/[0.02] border border-white/5 rounded-[2rem]"
            />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-destructive/5 border border-destructive/20 rounded-[2.5rem] p-10 text-center">
        <p className="text-sm text-destructive font-black uppercase tracking-widest mb-6">
          {error}
        </p>
        <button
          onClick={loadData}
          className="inline-flex items-center gap-3 px-6 py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-black uppercase tracking-widest text-white hover:bg-white/10 transition-premium"
        >
          <RefreshCw className="w-4 h-4" />
          Reconnect Protocol
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
    <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

      {/* Header */}
      <div className="flex items-center justify-between mb-10 relative z-10">
        <div className="flex items-center gap-5">
          <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)] group-hover:scale-105 transition-premium">
            <Shield className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h3 className="text-2xl md:text-3xl font-black text-white tracking-tighter font-outfit uppercase leading-tight">
              Capability Ceiling
            </h3>
            <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.3em] mt-2">
              WIT World Access Governance
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-[9px] font-black uppercase tracking-widest text-muted-foreground hover:text-white transition-premium"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Synchronize
        </button>
      </div>

      {/* Current ceiling card */}
      <div className="mb-10 relative z-10">
        <div
          className={cn(
            "bg-black/40 border-2 rounded-[2rem] p-8 relative overflow-hidden transition-premium",
            tierBorder(currentRank),
          )}
        >
          <div
            className={cn(
              "absolute inset-0 opacity-20 blur-[100px] pointer-events-none",
              tierBg(currentRank),
            )}
          />
          <div className="flex items-center justify-between relative z-10">
            <div className="flex items-center gap-6">
              <div
                className={cn(
                  "w-16 h-16 rounded-2xl border-2 flex items-center justify-center shadow-2xl transition-premium group-hover:scale-110",
                  tierBorder(currentRank),
                  tierBg(currentRank),
                )}
              >
                <Crown className={cn("w-8 h-8", tierColor(currentRank))} />
              </div>
              <div>
                <p className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 mb-1">
                  Active Access Threshold
                </p>
                <p
                  className={cn(
                    "text-3xl font-black tracking-tighter uppercase font-outfit",
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
                  "inline-flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border shadow-sm",
                  ceiling?.source === "grant"
                    ? "bg-primary/10 text-primary border-primary/20"
                    : "bg-white/5 text-muted-foreground/40 border-white/10",
                )}
              >
                {ceiling?.source === "grant" ? (
                  <>
                    <Zap className="w-3 h-3" />
                    Protocol_Granted
                  </>
                ) : (
                  "Baseline_Default"
                )}
              </span>
            </div>
          </div>

          {ceiling?.source === "grant" && (
            <div className="mt-8 pt-6 border-t border-white/5 flex flex-wrap items-center gap-8 text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest relative z-10">
              {ceiling.grantedByEmail && (
                <span className="flex items-center gap-2">
                  <User className="w-3.5 h-3.5 opacity-40" />
                  AUTH_BY: {ceiling.grantedByEmail}
                </span>
              )}
              {ceiling.grantedAt && (
                <span>
                  ISSUED: {new Date(ceiling.grantedAt).toLocaleDateString()}
                </span>
              )}
              {ceiling.notes && (
                <span className="flex items-center gap-2 text-muted-foreground/20 italic truncate max-w-xs">
                  <Info className="w-3.5 h-3.5 shrink-0 opacity-40" />
                  {ceiling.notes}
                </span>
              )}
              <button
                onClick={handleRevoke}
                className="ml-auto text-destructive/40 hover:text-destructive transition-premium font-black tracking-widest"
              >
                REVOKE_OVERRIDE
              </button>
            </div>
          )}
        </div>
      </div>

      {/* World hierarchy */}
      <div className="relative z-10">
        <p className="text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground/20 mb-6 pl-1">
          Capability Privilege Tiering
        </p>

        <div className="space-y-3">
          {sortedRanks.map(([rank, worlds]) => (
            <div key={rank} className="flex items-stretch gap-4">
              {/* Rank badge */}
              <div className="w-10 shrink-0 flex items-center justify-center">
                <span
                  className={cn(
                    "text-xs font-black tabular-nums tracking-widest",
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
                        "flex-1 min-w-[240px] flex items-center gap-4 px-6 py-5 rounded-[1.5rem] border transition-premium group/world relative overflow-hidden",
                        isCurrent
                          ? cn(
                              "border-2",
                              tierBg(rank),
                              tierBorder(rank),
                              "shadow-xl",
                            )
                          : isAccessible
                            ? "bg-white/[0.02] border-white/5 hover:border-white/10 hover:bg-white/[0.04]"
                            : "bg-black/20 border-white/[0.02] opacity-30 cursor-not-allowed",
                      )}
                    >
                      {isCurrent && (
                        <div
                          className={cn(
                            "absolute inset-0 opacity-10 blur-2xl pointer-events-none",
                            tierBg(rank),
                          )}
                        />
                      )}

                      <div className="flex-1 min-w-0 relative z-10">
                        <div className="flex items-center gap-3">
                          <span
                            className={cn(
                              "text-sm font-black uppercase tracking-tight font-outfit whitespace-nowrap",
                              isCurrent
                                ? tierColor(rank)
                                : isAccessible
                                  ? "text-white"
                                  : "text-muted-foreground/40",
                            )}
                          >
                            {w.name}
                          </span>
                          {isCurrent && (
                            <span className="px-2 py-0.5 bg-primary/10 text-primary text-[8px] font-black uppercase tracking-[0.2em] rounded-full border border-primary/20 shadow-sm">
                              ACTIVE_TIER
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-muted-foreground/40 mt-1.5 leading-relaxed font-bold uppercase tracking-wider">
                          {w.description}
                        </p>
                      </div>
                      {isAccessible && !isCurrent && (
                        <ChevronRight className="w-4 h-4 text-muted-foreground/20 shrink-0 group-hover/world:translate-x-1 transition-premium" />
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
        <p className="text-[10px] text-muted-foreground/20 leading-relaxed font-black uppercase tracking-widest">
          The ceiling restricts the maximum WIT world privileges assignable to
          nodes. Worlds above this threshold are locked to prevent unauthorized
          capability escalation.
        </p>
      </div>
    </div>
  );
}
