// In production builds (import.meta.env.PROD) use a strict whitelist: any message
// that doesn't match a known safe pattern is replaced with a generic string.
// This is defence-in-depth — the backend already returns generic error messages at
// API boundaries — but the frontend is the last line of defence if any internal
// detail slips through (e.g. from an unexpected GraphQL error shape).
//
// In development builds the heuristic redaction path is used so developers still
// see meaningful error context while working locally.

const SAFE_PATTERNS: RegExp[] = [
  /network error/i,
  /permission denied/i,
  /access denied/i,
  /not found/i,
  /session expired/i,
  /invalid (request|input|parameter)/i,
  /server error/i,
  /unauthorized/i,
  /forbidden/i,
  /rate limit/i,
  /too many requests/i,
  /timeout/i,
  /service unavailable/i,
  /bad gateway/i,
  /csrf/i,
  /authentication (failed|required)/i,
];

const GENERIC_ERROR = "An error occurred. Please try again.";

export function sanitizeErrorMessage(message: string): string {
  if (!message) return "";

  if (import.meta.env.PROD) {
    // Whitelist mode: only surface messages that match a known safe pattern.
    // Return a canonical form of the matched phrase rather than the raw message
    // to avoid leaking incidental internal detail in messages that happen to match
    // (e.g. "Not found: SELECT * FROM users" would emit "Not found" only).
    for (const pattern of SAFE_PATTERNS) {
      if (pattern.test(message)) {
        const match = message.match(pattern);
        if (match) {
          const phrase = match[0];
          return phrase.charAt(0).toUpperCase() + phrase.slice(1);
        }
      }
    }
    return GENERIC_ERROR;
  }

  // Development: heuristic redaction preserves debugging context.

  // Remove file paths (e.g., /Users/..., /app/src/..., C:\...)
  let sanitized = message.replace(
    /(?:\/[a-zA-Z0-9_.-]+){2,}/g,
    "[PATH REDACTED]",
  );
  sanitized = sanitized.replace(
    /[a-zA-Z]:\\[a-zA-Z0-9_.-]+\\/g,
    "[PATH REDACTED]\\",
  );

  // Remove possible SQL queries. Previous regex was case-insensitive
  // and matched any English verb like "create" or "update" that
  // happens to appear in an error message, chopping everything after
  // it. That was a dev-UX disaster (real errors got truncated to
  // "Failed to [DB QUERY REDACTED]"). Tightened heuristic:
  //
  //   - ALL-CAPS only — Postgres dumps queries in the casing the
  //     client wrote, which in this codebase is always upper-case.
  //     English-text errors (e.g. "Failed to create channel") use
  //     lower-case and are left alone.
  //   - Require at least one of SELECT/UPDATE/INSERT/DELETE to be
  //     followed by FROM, SET, INTO, or a star — the grammatical
  //     shape of a real query.
  //   - Match only to end-of-statement (semicolon) or end-of-line,
  //     so we don't swallow the error's explanation that precedes
  //     the query fragment.
  const sqlStatementPattern =
    /\b(SELECT\s+[\s\S]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[a-zA-Z_][\w.]*\s+SET\b|DELETE\s+FROM\b|CREATE\s+(?:TABLE|INDEX|SCHEMA|VIEW|FUNCTION|TRIGGER)\b|DROP\s+(?:TABLE|INDEX|SCHEMA|VIEW|FUNCTION|TRIGGER)\b|ALTER\s+(?:TABLE|INDEX|SCHEMA|VIEW)\b|TRUNCATE\s+(?:TABLE\s+)?[a-zA-Z_])[\s\S]*?(?:;|$)/g;
  sanitized = sanitized.replace(sqlStatementPattern, "[DB QUERY REDACTED]");

  // Redact database constraint names (often appear in Postgres errors as "violation of constraint '...'")
  sanitized = sanitized.replace(
    /\b[a-z0-9_]+_(?:key|pkey|fkey|check|excl)\b/g,
    "[CONSTRAINT REDACTED]",
  );

  // Strip HTML tags and dangerous URL schemes (defence-in-depth for non-JSX contexts)
  sanitized = sanitized.replace(/<[^>]*>/g, "");
  sanitized = sanitized.replace(/javascript:/gi, "");

  // Truncate to 500 chars to avoid UI flooding
  if (sanitized.length > 500) {
    sanitized = sanitized.slice(0, 500) + "…";
  }

  return sanitized;
}
