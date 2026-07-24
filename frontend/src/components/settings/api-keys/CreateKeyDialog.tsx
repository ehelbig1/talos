/**
 * Create-key dialog for ApiKeysManager: name + expiry inputs and the
 * scope-picker grid. Strictly presentational — the parent owns the form
 * state and the create mutation.
 */

import React from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { Input } from "@/components/ui/input";
import { Plus, Calendar, X, Key, Fingerprint } from "lucide-react";
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
    <Dialog open={true} onClose={onClose}>
      <div
        className="bg-surface-3/90 border border-white/5 shadow-[0_0_50px_rgba(0,0,0,0.5)] rounded-2xl overflow-hidden w-[520px] animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-indigo-500/10 rounded-xl flex items-center justify-center border border-indigo-500/20 text-indigo-400">
              <Key size={20} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-foreground tracking-tight">
                Create API Key
              </h3>
              <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest leading-none mt-1">
                New access credential
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-white/5 text-muted-foreground hover:text-white transition-premium"
          >
            <X size={20} />
          </button>
        </div>

        <div className="p-8 space-y-8">
          <div className="space-y-3">
            <label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground ml-1">
              Key Identity
            </label>
            <div className="relative group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-muted-foreground group-focus-within:text-indigo-400 transition-premium">
                <Fingerprint size={18} />
              </div>
              <Input
                placeholder="e.g. GitHub Actions Runner"
                value={name}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  onNameChange(e.target.value)
                }
                className="pl-12 bg-surface-4/60 border-white/5 focus:border-indigo-500 focus:ring-indigo-500/10 transition-premium h-12 text-sm font-medium rounded-xl shadow-inner"
              />
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground ml-1">
              Expiration Policy
            </label>
            <div className="relative group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-muted-foreground group-focus-within:text-indigo-400 transition-premium">
                <Calendar size={18} />
              </div>
              <Input
                type="number"
                placeholder="Lifetime in days (optional)"
                value={expiresIn}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  onExpiresInChange(e.target.value)
                }
                className="pl-12 bg-surface-4/60 border-white/5 focus:border-indigo-500 focus:ring-indigo-500/10 transition-premium h-12 text-sm font-medium rounded-xl shadow-inner"
              />
            </div>
          </div>

          <div className="space-y-4">
            <label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground ml-1">
              Scope configuration
            </label>
            <div className="grid grid-cols-2 gap-3">
              {availableScopes.map((s) => (
                <button
                  key={s.value}
                  onClick={() => onToggleScope(s.value)}
                  className={cn(
                    "flex flex-col items-start p-4 rounded-xl border transition-premium text-left group/scope",
                    selectedScopes.includes(s.value)
                      ? "bg-indigo-500/10 border-indigo-500/40 text-indigo-100 shadow-[0_4px_12px_rgba(99,102,241,0.1)]"
                      : "bg-surface-4/60 border-white/5 text-muted-foreground hover:border-white/10 hover:bg-white/[0.02]",
                  )}
                >
                  <div className="flex items-center justify-between w-full mb-1.5">
                    <span
                      className={cn(
                        "text-[9px] font-bold uppercase tracking-widest",
                        selectedScopes.includes(s.value)
                          ? "text-indigo-400"
                          : "text-muted-foreground",
                      )}
                    >
                      {s.value.split(":")[0]}
                    </span>
                    <div
                      className={cn(
                        "w-4 h-4 rounded-full border transition-premium flex items-center justify-center",
                        selectedScopes.includes(s.value)
                          ? "bg-indigo-500 border-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.4)]"
                          : "bg-surface-3/60 border-white/5",
                      )}
                    >
                      <Plus
                        className={cn(
                          "w-2.5 h-2.5 text-white transition-transform",
                          selectedScopes.includes(s.value) && "rotate-45",
                        )}
                      />
                    </div>
                  </div>
                  <div className="text-xs font-bold leading-tight mb-1">
                    {s.label}
                  </div>
                  <div className="text-[10px] text-muted-foreground font-medium leading-tight group-hover/scope:text-muted-foreground transition-premium">
                    {s.desc}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex justify-end gap-3">
          <Button
            variant="ghost"
            onClick={onClose}
            disabled={isPending}
            className="text-muted-foreground hover:text-white hover:bg-white/5 font-bold"
          >
            Discard
          </Button>
          <Button
            onClick={onCreate}
            disabled={isPending || !name || selectedScopes.length === 0}
            className="bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/20 px-8 h-11 rounded-xl font-bold transition-premium"
          >
            {isPending ? (
              <div className="flex items-center gap-2">
                <LoadingSpinner className="w-4 h-4" />
                <span>Processing...</span>
              </div>
            ) : (
              "Generate Key"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
