/**
 * Confirmation dialogs for the destructive API-key actions (revoke,
 * rotate, delete). Strictly presentational — the parent owns the
 * target-key state and the mutations.
 */

import React from "react";
import { Spinner } from "@/components/ui/spinner";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Shield, Trash2, Info, RefreshCw } from "lucide-react";

export function RevokeKeyDialog({
  isPending,
  onCancel,
  onConfirm,
}: {
  isPending: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog open={true} onClose={onCancel}>
      <div
        className="bg-surface-3/90 border border-warning/20 rounded-2xl overflow-hidden w-[400px]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-8 text-center space-y-4">
          <div className="w-14 h-14 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center text-warning mx-auto">
            <Shield size={28} />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white tracking-tight">
              Revoke API Key?
            </h3>
            <p className="text-sm text-muted-foreground font-medium mt-2 leading-relaxed">
              Any automation or script using this key will immediately lose
              access. The key will remain in the list as inactive. This action
              cannot be undone.
            </p>
          </div>
        </div>

        <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex items-center justify-center gap-3">
          <Button
            variant="ghost"
            onClick={onCancel}
            className="flex-1 text-muted-foreground hover:text-white hover:bg-white/5 font-bold h-12 rounded-xl"
          >
            Cancel
          </Button>
          <Button
            onClick={onConfirm}
            disabled={isPending}
            className="flex-1 bg-warning hover:bg-warning/90 text-warning-foreground shadow-warning/20 font-bold h-12 rounded-xl transition-ui"
          >
            {isPending ? "Revoking..." : "Revoke Key"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function RotateKeyDialog({
  isPending,
  onCancel,
  onConfirm,
}: {
  isPending: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog open={true} onClose={onCancel}>
      <div
        className="bg-surface-3/90 border border-primary/20 rounded-2xl overflow-hidden w-[460px]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-8 text-center space-y-4">
          <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center text-primary mx-auto">
            <RefreshCw size={28} />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white tracking-tight">
              Rotate API Key?
            </h3>
            <p className="text-sm text-muted-foreground font-medium mt-2 leading-relaxed">
              Rotating creates a new key with the same permissions. The old key
              is immediately invalidated. You'll need to update any systems
              using this key.
            </p>
          </div>
          <div className="p-4 bg-primary/5 border border-primary/15 rounded-xl text-left">
            <div className="flex items-start gap-2.5">
              <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
              <p className="text-xs text-muted-foreground leading-relaxed">
                The new secret will be shown once after rotation. Make sure you
                have a place to save it before proceeding.
              </p>
            </div>
          </div>
        </div>

        <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex items-center justify-center gap-3">
          <Button
            variant="ghost"
            onClick={onCancel}
            className="flex-1 text-muted-foreground hover:text-white hover:bg-white/5 font-bold h-12 rounded-xl"
          >
            Cancel
          </Button>
          <Button
            onClick={onConfirm}
            disabled={isPending}
            className="flex-1 bg-primary hover:bg-primary/90 text-white shadow-primary/20 font-bold h-12 rounded-xl transition-ui"
          >
            {isPending ? (
              <div className="flex items-center gap-2">
                <Spinner className="w-4 h-4" />
                <span>Rotating...</span>
              </div>
            ) : (
              "Rotate Key"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function DeleteKeyDialog({
  isPending,
  onCancel,
  onConfirm,
}: {
  isPending: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog open={true} onClose={onCancel}>
      <div
        className="bg-surface-3/90 border border-destructive/20 rounded-2xl overflow-hidden w-[400px]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-8 text-center space-y-4">
          <div className="w-14 h-14 bg-destructive/10 border border-destructive/20 rounded-2xl flex items-center justify-center text-destructive mx-auto">
            <Trash2 size={28} />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white tracking-tight">
              Delete API Key?
            </h3>
            <p className="text-sm text-muted-foreground font-medium mt-2 leading-relaxed">
              This permanently removes the key from your account. Any automation
              or script using this key will immediately lose access. This action
              cannot be undone.
            </p>
          </div>
        </div>

        <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex items-center justify-center gap-3">
          <Button
            variant="ghost"
            onClick={onCancel}
            className="flex-1 text-muted-foreground hover:text-white hover:bg-white/5 font-bold h-12 rounded-xl"
          >
            Cancel
          </Button>
          <Button
            onClick={onConfirm}
            disabled={isPending}
            className="flex-1 bg-destructive hover:bg-destructive/90 text-white shadow-destructive/20 font-bold h-12 rounded-xl transition-ui"
          >
            {isPending ? "Deleting..." : "Delete Key"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
