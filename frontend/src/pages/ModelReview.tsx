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
  GraduationCap,
  AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  useMlModelsQuery,
  useMlModelDisagreementsQuery,
  useResolveMlDisagreementMutation,
} from "@/generated/graphql";
import { LIFECYCLE_STYLE, lifecycleLabel } from "@/lib/mlLifecycle";

function pct(v: number | null | undefined): string {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}

// ── RFC 0011 R3 teacher-vs-gold audit ───────────────────────────────────────
// `teacherAudit` is a raw JSON passthrough of `ml_models.teacher_audit`
// (talos-ml::teacher_audit) — polymorphic on `status`. Mirrors the shape
// documented in talos-ml/src/teacher_audit.rs exactly; see that module for
// the authoritative contract.

interface TeacherAuditPerClass {
  n: number;
  agree: number;
}

interface TeacherAuditMismatch {
  example_key?: string | null;
  human: string;
  teacher: string;
}

interface TeacherAuditRunning {
  status: "running";
  started_at?: string;
  done?: number;
  gold_rows: number;
  skipped_few_shot_anchors?: number;
}

interface TeacherAuditFailed {
  status: "failed";
  error: string;
  failed_at: string;
}

interface TeacherAuditComplete {
  status: "complete";
  audited_at: string;
  total: number;
  compared: number;
  agree: number;
  parse_failed: number;
  accuracy: number | null;
  per_class: Record<string, TeacherAuditPerClass>;
  mismatches: TeacherAuditMismatch[];
  teacher: { provider: string; model: string; few_shot_used: number };
}

type TeacherAudit =
  | TeacherAuditRunning
  | TeacherAuditFailed
  | TeacherAuditComplete;

function isTeacherAudit(value: unknown): value is TeacherAudit {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    typeof (value as { status: unknown }).status === "string"
  );
}

/** "Teacher ceiling" card — the LLM teacher's accuracy against human-corrected
 * gold rows. Distilled fast models can never beat this number, so it's the
 * ceiling on how good the classifier can get. Handles the three
 * `teacher_audit` states (running/failed/complete) plus "never audited". */
function TeacherCeilingCard({ audit }: { audit: unknown }) {
  if (!isTeacherAudit(audit)) {
    return (
      <div className="px-6 py-5 bg-white/[0.02] border border-white/5 rounded-[2rem]">
        <div className="flex items-center gap-2 mb-1">
          <GraduationCap className="w-4 h-4 text-muted-foreground/40" />
          <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.25em]">
            Teacher ceiling
          </span>
        </div>
        <p className="text-[10px] text-muted-foreground/30 font-bold uppercase tracking-widest mt-2">
          Not audited yet — run ml_teacher_audit to measure the teacher's
          accuracy against gold corrections.
        </p>
      </div>
    );
  }

  if (audit.status === "running") {
    const done = audit.done ?? 0;
    const total = Math.max(audit.gold_rows, 1);
    const progressPct = Math.min(100, Math.round((done / total) * 100));
    return (
      <div className="px-6 py-5 bg-white/[0.02] border border-primary/20 rounded-[2rem]">
        <div className="flex items-center gap-2 mb-3">
          <GraduationCap className="w-4 h-4 text-primary animate-pulse" />
          <span className="text-[9px] text-primary/80 font-black uppercase tracking-[0.25em]">
            Teacher ceiling — auditing
          </span>
          <span className="ml-auto text-[10px] text-muted-foreground/50 font-bold">
            {done}/{audit.gold_rows}
          </span>
        </div>
        <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div
            className="h-full bg-primary shadow-[0_0_10px_hsla(var(--primary),0.6)] transition-all duration-500 ease-premium-out"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>
    );
  }

  if (audit.status === "failed") {
    return (
      <div className="px-6 py-5 bg-white/[0.02] border border-destructive/20 rounded-[2rem]">
        <div className="flex items-center gap-2 mb-1">
          <AlertTriangle className="w-4 h-4 text-destructive/70" />
          <span className="text-[9px] text-destructive/70 font-black uppercase tracking-[0.25em]">
            Teacher ceiling — audit failed
          </span>
        </div>
        <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-widest mt-2">
          {audit.error}
        </p>
      </div>
    );
  }

  // complete
  const perClassEntries = Object.entries(audit.per_class);
  return (
    <div className="px-6 py-5 bg-white/[0.02] border border-white/5 rounded-[2rem]">
      <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
        <div className="flex items-center gap-2">
          <GraduationCap className="w-4 h-4 text-primary/70" />
          <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-[0.25em]">
            Teacher ceiling
          </span>
        </div>
        <Stat
          label="Accuracy"
          value={pct(audit.accuracy)}
          hint={`${audit.agree}/${audit.compared} agree`}
        />
        <Stat label="Parse failed" value={String(audit.parse_failed)} />
        <span className="ml-auto text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.25em]">
          {new Date(audit.audited_at).toLocaleString()} · teacher:{" "}
          {audit.teacher.model}
        </span>
      </div>
      {perClassEntries.length > 0 && (
        <div className="mt-4 space-y-2">
          {perClassEntries.map(([label, { n, agree }]) => {
            const classPct = n > 0 ? (agree / n) * 100 : 0;
            return (
              <div key={label} className="flex items-center gap-3">
                <span className="w-28 shrink-0 text-[10px] text-muted-foreground/60 font-bold truncate capitalize">
                  {label}
                </span>
                <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary/70 transition-all duration-500 ease-premium-out"
                    style={{ width: `${classPct}%` }}
                  />
                </div>
                <span className="w-16 shrink-0 text-[10px] text-muted-foreground/40 font-bold text-right tabular-nums">
                  {agree}/{n}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
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

  const {
    data: feedData,
    isLoading: feedLoading,
    isError: feedError,
    refetch: refetchFeed,
  } = useMlModelDisagreementsQuery(
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
                      {lifecycleLabel(m.lifecycleState)}
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
                  value={lifecycleLabel(feed.lifecycleState)}
                />
                <Stat
                  label="Shadow agreement"
                  value={pct(feed.shadowAgreement)}
                  hint={`${feed.shadowObservations} obs · era ${feed.shadowEpoch}`}
                />
                <Stat label="Pending review" value={String(pending.length)} />
                <div className="ml-auto flex items-center gap-2 text-[9px] text-muted-foreground/30 font-black uppercase tracking-[0.25em]">
                  <Sparkles className="w-3.5 h-3.5 text-primary/40" />
                  Corrections train the model toward promotion
                </div>
              </div>
            )}

            {/* Teacher ceiling — the LLM teacher's accuracy on gold rows,
                the distilled model's accuracy ceiling. */}
            {feed && (
              <div className="mb-8">
                <TeacherCeilingCard audit={feed.teacherAudit} />
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
            ) : feedError ? (
              // A failed queue load must NEVER masquerade as "all caught
              // up" — with pending items still counted in the model list,
              // that silently hides work (found live 2026-07-14: a
              // schema/query version skew errored the feed while the
              // badge showed 10 pending).
              <div className="text-center py-24 bg-white/[0.01] border border-dashed border-destructive/20 rounded-[2.5rem]">
                <p className="text-sm text-destructive/80 font-black uppercase tracking-[0.2em]">
                  Could not load the review queue
                </p>
                <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-widest mt-2">
                  The pending count in the model list is still accurate.
                </p>
                <button
                  onClick={() => refetchFeed()}
                  className="mt-6 px-5 py-2 text-[10px] font-black uppercase tracking-[0.2em] text-foreground/80 bg-white/[0.04] border border-white/10 rounded-full hover:bg-white/[0.08] transition-premium"
                >
                  Retry
                </button>
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
