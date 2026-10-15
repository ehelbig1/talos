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
  noise: "text-muted-foreground/60 bg-white/[0.02] border-white/5",
  unclassified:
    "text-muted-foreground/70 bg-transparent border-dashed border-white/10",
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

/** Severities a count in the nav should include: everything active except
 *  noise, which is suppressed from attention by definition. */
const COUNTED_IN_NAV = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unclassified",
]);

/** Severities from most to least urgent, for picking a badge's colour. */
const URGENCY = ["critical", "high", "medium", "low", "info", "unclassified"];

export interface SeverityCount {
  severity: string;
  count: number;
}

/** Active alerts the nav badge counts, and the most urgent severity among
 *  them (null when there is nothing to show). */
export function navAlertSummary(active: ReadonlyArray<SeverityCount>): {
  count: number;
  worst: string | null;
} {
  let count = 0;
  let worst: string | null = null;
  for (const { severity, count: n } of active) {
    if (n <= 0 || !COUNTED_IN_NAV.has(severity)) continue;
    count += n;
    const rank = URGENCY.indexOf(severity);
    const worstRank = worst === null ? Infinity : URGENCY.indexOf(worst);
    if (rank !== -1 && rank < worstRank) worst = severity;
  }
  return { count, worst };
}
