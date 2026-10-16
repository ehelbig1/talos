/**
 * The new-key form for ApiKeysManager: name, lifetime and the scope picker.
 * Presentational — the parent owns the form state and the create mutation.
 */

import React from "react";
import { Spinner } from "@/components/ui/spinner";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Plus } from "lucide-react";
import { cn } from "@/lib/utils";

const availableScopes = [
  {
    value: "workflows:read",
    label: "Read Workflows",
    desc: "View workflows and history",
  },
  {
    value: "workflows:write",
    label: "Write Workflows",
    desc: "Create and edit workflows",
  },
  {
    value: "secrets:read",
    label: "Read Secrets",
    desc: "Access encrypted secrets",
  },
  {
    value: "secrets:write",
    label: "Write Secrets",
    desc: "Update secrets and keys",
  },
  {
    value: "webhooks:access",
    label: "Webhooks Access",
    desc: "Trigger internal webhooks",
  },
  {
    value: "admin",
    label: "Admin access",
    desc: "Full control over all resources",
  },
];

export function CreateKeyDialog({
  name,
  expiresIn,
  selectedScopes,
  isPending,
  onNameChange,
  onExpiresInChange,
  onToggleScope,
  onClose,
  onCreate,
}: {
  name: string;
  expiresIn: string;
  selectedScopes: string[];
  isPending: boolean;
  onNameChange: (value: string) => void;
  onExpiresInChange: (value: string) => void;
  onToggleScope: (value: string) => void;
  onClose: () => void;
  onCreate: () => void;
}) {
  return (
    <Dialog open onClose={onClose} title="New key" className="max-w-lg">
      <div className="space-y-6">
        <div className="space-y-2">
          <label
            htmlFor="api-key-name"
            className="text-xs font-semibold text-muted-foreground"
          >
            Key name
          </label>
          <Input
            id="api-key-name"
            placeholder="e.g. GitHub Actions Runner"
            value={name}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              onNameChange(e.target.value)
            }
          />
        </div>

        <div className="space-y-2">
          <label
            htmlFor="api-key-expires"
            className="text-xs font-semibold text-muted-foreground"
          >
            Expires after (days)
          </label>
          <Input
            id="api-key-expires"
            type="number"
            min={1}
            placeholder="Leave empty for no expiry"
            value={expiresIn}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              onExpiresInChange(e.target.value)
            }
          />
        </div>

        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground">Scopes</p>
          <div className="grid grid-cols-2 gap-3">
            {availableScopes.map((s) => {
              const selected = selectedScopes.includes(s.value);
              return (
                <button
                  key={s.value}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => onToggleScope(s.value)}
                  className={cn(
                    "flex flex-col items-start p-4 rounded-xl border transition-ui text-left",
                    selected
                      ? "bg-primary/10 border-primary/40 text-primary"
                      : "bg-surface-3/40 border-white/5 text-muted-foreground hover:border-white/10 hover:bg-white/[0.02]",
                  )}
                >
                  <div className="flex items-center justify-between w-full mb-1.5">
                    <span className="text-2xs font-medium text-muted-foreground">
                      {s.value.split(":")[0]}
                    </span>
                    <span
                      aria-hidden
                      className={cn(
                        "w-4 h-4 rounded-full border transition-ui flex items-center justify-center",
                        selected
                          ? "bg-primary border-primary"
                          : "bg-surface-3/60 border-white/10",
                      )}
                    >
                      <Plus
                        className={cn(
                          "w-2.5 h-2.5 text-white transition-transform",
                          selected && "rotate-45",
                        )}
                      />
                    </span>
                  </div>
                  <div
                    className={cn(
                      "text-xs font-semibold leading-tight mb-1",
                      selected ? "text-primary" : "text-foreground",
                    )}
                  >
                    {s.label}
                  </div>
                  <div className="text-xs text-muted-foreground leading-tight">
                    {s.desc}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <Button variant="outline" onClick={onClose} disabled={isPending}>
            Cancel
          </Button>
          <Button
            onClick={onCreate}
            disabled={isPending || !name.trim() || selectedScopes.length === 0}
          >
            {isPending ? (
              <>
                <Spinner className="w-4 h-4" />
                Creating…
              </>
            ) : (
              "Create key"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
