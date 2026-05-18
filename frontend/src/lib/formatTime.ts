/**
 * Shared time formatting utilities.
 * Extracted from ActorDetail, Actors, and Dashboard to eliminate duplication.
 */

/**
 * Format a timestamp as a human-readable relative time string.
 * Examples: "just now", "5m ago", "2h ago", "3d ago", "2025-01-15"
 */
export function relativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "—";
  const date = new Date(dateStr);
  const now = Date.now();
  const diffMs = now - date.getTime();

  if (diffMs < 0) return "just now"; // future timestamps
  if (diffMs < 60_000) return "just now";
  if (diffMs < 3_600_000) return `${Math.floor(diffMs / 60_000)}m ago`;
  if (diffMs < 86_400_000) return `${Math.floor(diffMs / 3_600_000)}h ago`;
  if (diffMs < 604_800_000) return `${Math.floor(diffMs / 86_400_000)}d ago`;

  // Over 7 days — show date
  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/**
 * Format a duration in milliseconds as a compact human-readable string.
 * Examples: "0ms", "150ms", "2.3s", "1m 15s", "2h 30m"
 */
export function formatDurationCompact(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60_000);
  const secs = Math.floor((ms % 60_000) / 1000);
  if (ms < 3_600_000) return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  const hrs = Math.floor(ms / 3_600_000);
  const remainMins = Math.floor((ms % 3_600_000) / 60_000);
  return remainMins > 0 ? `${hrs}h ${remainMins}m` : `${hrs}h`;
}

/**
 * Calculate the age of a date in days.
 */
export function ageDays(dateStr: string | null | undefined): number {
  if (!dateStr) return 0;
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86_400_000);
}

/**
 * Format a future timestamp as a human-readable time-until string.
 * Examples: "overdue", "in 30s", "in 5m", "in 2h", "in 3d"
 */
export function futureTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const diff = new Date(isoString).getTime() - Date.now();
  if (diff < 0) return "overdue";
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `in ${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `in ${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `in ${hours}h`;
  return `in ${Math.floor(hours / 24)}d`;
}

/**
 * Format a duration in seconds as a compact human-readable string.
 * Examples: "—", "450ms", "1.5s", "2m 30s"
 */
export function formatDurationSecs(secs: number | null | undefined): string {
  if (secs == null) return "—";
  if (secs < 1) return `${Math.round(secs * 1000)}ms`;
  if (secs < 60) return `${secs.toFixed(1)}s`;
  return `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s`;
}
