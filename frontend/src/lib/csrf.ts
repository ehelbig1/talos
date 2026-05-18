/**
 * Shared CSRF token utility.
 * Reads the `talos_csrf_token` cookie set by the backend.
 */
export function getCsrfToken(): string | null {
  for (const raw of document.cookie.split(";")) {
    const s = raw.trim();
    const eq = s.indexOf("=");
    if (eq === -1) continue;
    const name = s.slice(0, eq);
    const value = s.slice(eq + 1);
    if (name === "talos_csrf_token") {
      return decodeURIComponent(value);
    }
  }
  return null;
}
