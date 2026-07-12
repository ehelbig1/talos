import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  BrainCircuit,
  CheckCircle2,
  Sparkles,
  ShieldCheck,
  X,
  Bot,
  Cpu,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  useMlModelsQuery,
  useMlModelDisagreementsQuery,
  useResolveMlDisagreementMutation,
} from "@/generated/graphql";

// Lifecycle state → badge palette. shadow = learning (amber), hybrid =
// partly serving (primary), fast_primary = model-led (success).
const LIFECYCLE_STYLE: Record<string, string> = {
  llm_only: "text-muted-foreground/60 bg-white/5 border-white/10",
  shadow: "text-warning bg-warning/5 border-warning/20",
  hybrid: "text-primary bg-primary/5 border-primary/20",
  fast_primary: "text-success bg-success/5 border-success/20",
};

function pct(v: number | null | undefined): string {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}

export default function ModelReview() {
  const queryClient = useQueryClient();
  const [picked, setPicked] = useState<string | null>(null);

  const { data: modelsData, isLoading: modelsLoading } = useMlModelsQuery(
    {},
    { refetchOnWindowFocus: true },
  );
  const models = modelsData?.mlModels ?? [];

  // Default to the model with the most pending review, else the first.
  const activeName =
    picked ??
    models.find((m) => m.pendingDisagreements > 0)?.name ??
    models[0]?.name ??
    null;

  const { data: feedData, isLoading: feedLoading } =
    useMlModelDisagreementsQuery(
      { modelName: activeName ?? "", limit: 50 },
      { enabled: !!activeName, refetchOnWindowFocus: true },
    );
  const feed = feedData?.mlModelDisagreements;
  const pending = feed?.pending ?? [];

  const resolve = useResolveMlDisagreementMutation({
    onSuccess: (data) => {
      const r = data.resolveMlDisagreement;
      toast.success(
        r.correctionAppended
          ? "Correction saved — counts toward promotion"
          : "Dismissed",
      );
      // Refresh both the queue and the per-model pending counts.
      queryClient.invalidateQueries({ queryKey: ["MlModelDisagreements"] });
      queryClient.invalidateQueries({ queryKey: ["MlModels"] });
    },
    onError: () => toast.error("Could not resolve disagreement"),
  });

  // The model's label vocabulary, derived from the candidate labels in the
  // feed (no hardcoded bucket set — works for any classifier). The LLM's
  // label is the usual "correct" answer, so it's visually emphasized.
  const labelOptions = useMemo(() => {
    const s = new Set<string>();
    // Depend on the cached array reference (feed?.pending), not the
    // per-render `?? []` fallback, so this only recomputes on real change.
    for (const d of feed?.pending ?? []) {
      if (d.fastLabel) s.add(d.fastLabel);
      s.add(d.llmLabel);
    }
    return [...s].sort();
  }, [feed?.pending]);

  const busyId =
    resolve.isPending && resolve.variables
      ? resolve.variables.disagreementId
      : null;

  return (
    <div className="flex flex-col h-full bg-background overflow-hidden">
      {/* Header */}
      <header className="px-10 pt-16 pb-8 shrink-0">
        <div className="flex items-center gap-5">
          <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center shadow-[0_0_30px_hsla(var(--primary),0.1)]">
            <BrainCircuit className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl md:text-3xl font-black text-white tracking-tight font-outfit uppercase leading-tight">
              Model Review
            </h1>
            <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.3em] mt-2">
              Human-in-the-loop distillation · teach the small model
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto custom-scrollbar px-10 pb-16">
        {/* Model picker row */}
        {modelsLoading ? (
          <div className="flex gap-4">
            {[1, 2].map((i) => (
              <div
                key={i}
                className="h-28 w-72 bg-white/[0.02] border border-white/5 rounded-[2rem] animate-pulse"
              />
            ))}
          </div>
        ) : models.length === 0 ? (
          <div className="text-center py-24 bg-white/[0.01] border border-dashed border-white/5 rounded-[2.5rem]">
            <BrainCircuit className="w-16 h-16 text-muted-foreground/10 mb-6 mx-auto" />
            <p className="text-sm text-muted-foreground/50 font-black uppercase tracking-[0.2em]">
              No models yet
            </p>
            <p className="text-[10px] text-muted-foreground/30 font-bold uppercase tracking-widest mt-2">
              Distilled classifiers appear here as they start learning.
            </p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-4">
            {models.map((m) => {
              const isActive = m.name === activeName;
              return (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setPicked(m.name)}
                  className={cn(
                    "text-left w-72 rounded-[2rem] p-6 border transition-premium relative overflow-hidden group",
                    isActive
                      ? "bg-primary/[0.06] border-primary/30 shadow-xl"
                      : "bg-white/[0.02] border-white/5 hover:bg-white/[0.04] hover:border-white/10",
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-sm font-black text-white truncate font-outfit">
                      {m.name}
                    </span>
                    {m.pendingDisagreements > 0 && (
                      <span className="shrink-0 bg-warning text-black text-[10px] font-black rounded-full px-2.5 py-1 min-w-[1.6rem] text-center shadow-[0_0_10px_hsla(var(--warning),0.5)]">
                        {m.pendingDisagreements}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-4">
                    <span
                      className={cn(
                        "text-[9px] font-black uppercase tracking-widest px-2.5 py-1 rounded-lg border",
                        LIFECYCLE_STYLE[m.lifecycleState] ??
                          LIFECYCLE_STYLE.llm_only,
                      )}
                    >
                      {m.lifecycleState.replace("_", " ")}
                    </span>
                    <span className="text-[9px] text-muted-foreground/40 font-bold uppercase tracking-widest">
                      acc {pct(m.promotedAccuracy)}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        )}

        {/* Selected model status + disagreement queue */}
        {activeName && (
          <div className="mt-10">
            {/* Status strip */}
            {feed && (
              <div className="flex flex-wrap items-center gap-x-8 gap-y-3 mb-8 px-6 py-5 bg-white/[0.02] border border-white/5 rounded-[2rem]">
                <Stat
                  label="Lifecycle"
                  value={feed.lifecycleState.replace("_", " ")}
                />
                <Stat
                  label="Shadow agreement"
                  value={pct(feed.shadowAgreement)}
                  hint={`${feed.shadowObservations} obs`}
                />
                <Stat label="Pending review" value={String(pending.length)} />
                <div className="ml-auto flex items-center gap-2 text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.25em]">
                  <Sparkles className="w-3.5 h-3.5 text-primary/40" />
                  Corrections train the model toward promotion
                </div>
              </div>
            )}

            {feedLoading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className="h-40 bg-white/[0.02] border border-white/5 rounded-[2rem] animate-pulse"
                  />
                ))}
              </div>
            ) : pending.length === 0 ? (
              <div className="text-center py-24 bg-white/[0.01] border border-dashed border-white/5 rounded-[2.5rem] group">
                <CheckCircle2 className="w-16 h-16 text-success/25 mb-6 mx-auto group-hover:text-success/50 transition-premium" />
                <p className="text-sm text-muted-foreground font-black uppercase tracking-[0.2em]">
                  All caught up
                </p>
                <p className="text-[10px] text-muted-foreground/30 font-bold uppercase tracking-widest mt-2">
                  No disagreements waiting on your review.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {pending.map((d) => {
                  const rowBusy = busyId === d.id;
                  return (
                    <div
                      key={d.id}
                      className={cn(
                        "bg-white/[0.02] border border-white/5 rounded-[2rem] p-6 transition-premium relative overflow-hidden",
                        rowBusy && "opacity-50 pointer-events-none",
                      )}
                    >
                      {/* Candidate labels */}
                      <div className="flex flex-wrap items-center gap-3 mb-4">
                        <span
                          className={cn(
                            "text-[9px] font-black uppercase tracking-widest px-2.5 py-1 rounded-lg border",
                            d.kind === "divergence"
                              ? "text-warning bg-warning/5 border-warning/20"
                              : "text-muted-foreground/60 bg-white/5 border-white/10",
                          )}
                        >
                          {d.kind === "divergence"
                            ? "Model disagreed"
                            : "Model abstained"}
                        </span>
                        <span className="flex items-center gap-1.5 text-[10px] font-bold text-muted-foreground/60">
                          <Cpu className="w-3.5 h-3.5 text-warning/70" />
                          model:{" "}
                          <span className="font-black text-white/80">
                            {d.fastLabel ?? "—"}
                          </span>
                          {d.fastConfidence != null && (
                            <span className="text-muted-foreground/40">
                              ({pct(d.fastConfidence)})
                            </span>
                          )}
                        </span>
                        <span className="flex items-center gap-1.5 text-[10px] font-bold text-muted-foreground/60">
                          <Bot className="w-3.5 h-3.5 text-primary/70" />
                          llm:{" "}
                          <span className="font-black text-white/80">
                            {d.llmLabel}
                          </span>
                        </span>
                        <span className="ml-auto text-[9px] text-muted-foreground/30 font-black uppercase tracking-widest">
                          {new Date(d.createdAt).toLocaleString()}
                        </span>
                      </div>

                      {/* Email-derived features */}
                      <pre className="text-[12px] leading-relaxed text-muted-foreground/80 whitespace-pre-wrap font-sans bg-black/20 border border-white/5 rounded-2xl p-4 mb-5 max-h-40 overflow-auto custom-scrollbar">
                        {d.featuresText}
                      </pre>

                      {/* Correct-label actions + dismiss */}
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-widest mr-1">
                          Correct label
                        </span>
                        {labelOptions.map((label) => {
                          const suggested = label === d.llmLabel;
                          return (
                            <Button
                              key={label}
                              size="sm"
                              onClick={() =>
                                resolve.mutate({
                                  disagreementId: d.id,
                                  correctLabel: label,
                                })
                              }
                              className={cn(
                                "h-9 rounded-xl font-black text-[10px] uppercase tracking-widest border transition-premium",
                                suggested
                                  ? "bg-primary/10 hover:bg-primary text-primary hover:text-black border-primary/30"
                                  : "bg-white/[0.03] hover:bg-white/10 text-white/80 border-white/10",
                              )}
                            >
                              {suggested && (
                                <ShieldCheck className="w-3.5 h-3.5 mr-1.5" />
                              )}
                              {label}
                            </Button>
                          );
                        })}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            resolve.mutate({ disagreementId: d.id })
                          }
                          className="h-9 rounded-xl font-black text-[10px] uppercase tracking-widest text-muted-foreground/50 hover:text-destructive hover:bg-destructive/10 border border-transparent hover:border-destructive/20 ml-auto"
                        >
                          <X className="w-3.5 h-3.5 mr-1.5" />
                          Dismiss
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="flex flex-col">
      <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.25em]">
        {label}
      </span>
      <span className="text-lg font-black text-white leading-tight mt-1 capitalize">
        {value}
        {hint && (
          <span className="text-[10px] text-muted-foreground/40 font-bold lowercase ml-2">
            {hint}
          </span>
        )}
      </span>
    </div>
  );
}
