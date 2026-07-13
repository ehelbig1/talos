// Shared presentation for RFC 0011 model lifecycle states. Single source so
// the ModelReview page and the Smart Classifier node badge never drift.
//
// llm_only    — no distilled model yet; the LLM does all the work.
// shadow      — model predicts in the background for agreement measurement.
// hybrid      — model serves when confident, LLM covers the rest.
// fast_primary— model leads; LLM is the rare fallback.

export const LIFECYCLE_STYLE: Record<string, string> = {
  llm_only: "text-muted-foreground/60 bg-white/5 border-white/10",
  shadow: "text-warning bg-warning/5 border-warning/20",
  hybrid: "text-primary bg-primary/5 border-primary/20",
  fast_primary: "text-success bg-success/5 border-success/20",
};

// Short human labels for the lifecycle states (badge text).
export const LIFECYCLE_LABEL: Record<string, string> = {
  llm_only: "LLM only",
  shadow: "Learning",
  hybrid: "Hybrid",
  fast_primary: "Model-led",
};

export function lifecycleStyle(state: string | null | undefined): string {
  return (state && LIFECYCLE_STYLE[state]) || LIFECYCLE_STYLE.llm_only;
}

export function lifecycleLabel(state: string | null | undefined): string {
  return (state && LIFECYCLE_LABEL[state]) || state || "LLM only";
}
