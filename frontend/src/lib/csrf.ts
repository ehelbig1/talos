/**
 * Shared CSRF token utility.
 * Reads the `talos_csrf_token` cookie set by the backend.
 */
export function getCsrfToken(): string | null {
  return readCookie("talos_csrf_token");
}

/** The one cookie reader: the value of `name` from `document.cookie`, or
 *  null. Only NON-HttpOnly cookies are visible here by construction — the
 *  auth cookies never are; the CSRF token and the session marker are. */
export function readCookie(name: string): string | null {
  for (const raw of document.cookie.split(";")) {
    const s = raw.trim();
    const eq = s.indexOf("=");
    if (eq === -1) continue;
    if (s.slice(0, eq) === name) {
      return decodeURIComponent(s.slice(eq + 1));
    }
  }
  return null;
}
