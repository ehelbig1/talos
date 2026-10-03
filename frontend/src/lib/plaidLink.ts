/**
 * Plaid Link: Plaid's own bank sign-in window.
 *
 * Plaid requires the script to be loaded from its CDN — never bundled or
 * self-hosted — so it is injected on first use rather than imported. The bank
 * password goes to Plaid and the bank; this page only ever sees the
 * short-lived `public_token`, which it hands to the server.
 */

export const PLAID_LINK_SCRIPT =
  "https://cdn.plaid.com/link/v2/stable/link-initialize.js";

export interface PlaidInstitution {
  name?: string | null;
  institution_id?: string | null;
}

export interface PlaidSuccessMetadata {
  institution?: PlaidInstitution | null;
}

export interface PlaidExitError {
  error_code?: string;
  display_message?: string | null;
}

interface PlaidHandler {
  open: () => void;
  destroy: () => void;
}

interface PlaidGlobal {
  create: (config: {
    token: string;
    onSuccess: (publicToken: string, metadata: PlaidSuccessMetadata) => void;
    onExit?: (err: PlaidExitError | null) => void;
  }) => PlaidHandler;
}

declare global {
  interface Window {
    Plaid?: PlaidGlobal;
  }
}

let loading: Promise<PlaidGlobal> | null = null;

/** Load the Link script once; later calls reuse it. */
export function loadPlaidLink(): Promise<PlaidGlobal> {
  if (window.Plaid) return Promise.resolve(window.Plaid);
  if (loading) return loading;
  loading = new Promise<PlaidGlobal>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = PLAID_LINK_SCRIPT;
    script.async = true;
    script.onload = () =>
      window.Plaid
        ? resolve(window.Plaid)
        : reject(new Error("Plaid Link did not load"));
    script.onerror = () => {
      loading = null;
      script.remove();
      reject(new Error("Plaid Link could not be loaded"));
    };
    document.head.appendChild(script);
  });
  return loading;
}

/** True while a Link window is open (or being opened). */
let open = false;

/** Whether a bank sign-in window is currently open. */
export function plaidLinkIsOpen(): boolean {
  return open;
}

export interface LinkOutcome {
  publicToken: string;
  institution: PlaidInstitution | null;
}

/**
 * Open Plaid Link with a server-minted `linkToken`. Resolves with the
 * `public_token` on success, `null` when the person closes the window.
 *
 * Only ONE window at a time. The script and the first window take a moment
 * to appear, and a second click in that moment used to open a second window
 * stacked on the first; a call made while one is open is refused instead.
 */
export async function openPlaidLink(
  linkToken: string,
): Promise<LinkOutcome | null> {
  if (open) {
    throw new Error("A bank sign-in window is already open");
  }
  open = true;
  try {
    const plaid = await loadPlaidLink();
    return await new Promise<LinkOutcome | null>((resolve, reject) => {
      let settled = false;
      const handler = plaid.create({
        token: linkToken,
        onSuccess: (publicToken, metadata) => {
          settled = true;
          handler.destroy();
          resolve({ publicToken, institution: metadata.institution ?? null });
        },
        onExit: (err) => {
          if (settled) return;
          settled = true;
          handler.destroy();
          if (err && err.error_code) {
            reject(
              new Error(
                err.display_message || "The bank sign-in did not finish",
              ),
            );
          } else {
            resolve(null);
          }
        },
      });
      handler.open();
    });
  } finally {
    open = false;
  }
}
