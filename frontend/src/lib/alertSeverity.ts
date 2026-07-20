// Shared presentation for ops-alert severities. Single source so the alert
// triage page and any future badge (e.g. digest emails' web counterpart)
// never drift. Mirrors the mlLifecycle.ts convention.
//
// critical/high — urgent, needs attention now (destructive/warning family).
// medium         — worth a look, not on fire.
// low/info       — informational, muted.
// noise          — actively suppressed from attention, faint.
// unclassified   — no triage signal yet; appears on ROWS but is not
//                   assignable via a human correction (there's nothing to
//                   "correct to unclassified").

export const SEVERITY_STYLE: Record<string, string> = {
  critical: "text-destructive bg-destructive/5 border-destructive/20",
  high: "text-warning bg-warning/5 border-warning/20",
  medium: "text-warning/80 bg-warning/5 border-warning/10",
  low: "text-muted-foreground/60 bg-white/5 border-white/10",
  info: "text-muted-foreground/50 bg-white/5 border-white/10",
  noise: "text-muted-foreground/30 bg-white/[0.02] border-white/5",
  unclassified:
    "text-muted-foreground/40 bg-transparent border-dashed border-white/10",
};

// The six human-assignable severities. `unclassified` is a valid severity
// VALUE on a row (nothing has triaged it yet) but is deliberately excluded
// here — a human correction always resolves to a real severity, never back
// to "unclassified".
export const ASSIGNABLE_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "noise",
] as const;

export function severityStyle(sev: string | null | undefined): string {
  return (sev && SEVERITY_STYLE[sev]) || SEVERITY_STYLE.unclassified;
}
