/**
 * "Reconnect your account" banner shared by the watch-channel panels.
 *
 * Shown when ANY channel has an OAuth-shaped recent failure. Channels
 * with non-OAuth failures get the per-row badge only; the banner is
 * specifically for the "refresh token died, reconnect to recover" case.
 *
 * We don't programmatically launch the OAuth flow because the existing
 * provider-card path handles state-token CSRF + redirect sequencing —
 * the button scrolls to the provider card instead.
 */

import React from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";

export function OAuthReconnectBanner({
  title,
  description,
  providerId,
  buttonLabel,
}: {
  title: string;
  description: React.ReactNode;
  /** Value of the target card's `data-provider-id` attribute. */
  providerId: string;
  buttonLabel: string;
}): React.ReactElement {
  return (
    <div className="mb-4 p-4 bg-destructive/5 border border-destructive/20 rounded-2xl flex items-start gap-4">
      <div className="w-10 h-10 bg-destructive/10 border border-destructive/20 rounded-lg flex items-center justify-center text-destructive shrink-0">
        <KeyRound size={18} />
      </div>
      <div className="flex-1">
        <p className="text-sm font-semibold text-foreground mb-1">{title}</p>
        <p className="text-xs text-muted-foreground leading-relaxed mb-3">
          {description}
        </p>
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            const el = document.querySelector(
              `[data-provider-id="${providerId}"]`,
            );
            if (el instanceof HTMLElement) {
              el.scrollIntoView({ behavior: "smooth", block: "center" });
            } else {
              window.scrollTo({ top: 0, behavior: "smooth" });
            }
          }}
          className="h-8 px-3 text-xs font-bold"
        >
          {buttonLabel}
        </Button>
      </div>
    </div>
  );
}
