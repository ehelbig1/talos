/**
 * Common formatting helpers used across the UI.
 * Keeping these in a single module improves readability and guarantees
 * consistent output (e.g., for file sizes and dates).
 */

/** Convert a byte count to a human‑readable string. */
export const formatSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

/** Format an ISO date string into a locale date‑time string. */
export const formatDate = (dateStr?: string): string => {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return "";
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
};
