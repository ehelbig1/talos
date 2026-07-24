/**
 * Confirmation dialogs for the destructive API-key actions (revoke,
 * rotate, delete). Strictly presentational — the parent owns the
 * target-key state and the mutations.
 */

import React from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { LoadingSpinner } from "@/components/LoadingSpinner";
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
        className="bg-surface-3/90 border border-amber-500/20 shadow-2xl rounded-2xl overflow-hidden w-[400px] animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-8 text-center space-y-4">
          <div className="w-16 h-16 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex items-center justify-center text-amber-500 mx-auto shadow-inner">
            <Shield size={32} />
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
            className="flex-1 bg-amber-600 hover:bg-amber-500 text-white shadow-xl shadow-amber-900/20 font-bold h-12 rounded-xl transition-premium"
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
        className="bg-surface-3/90 border border-indigo-500/20 shadow-2xl rounded-2xl overflow-hidden w-[460px] animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-8 text-center space-y-4">
          <div className="w-16 h-16 bg-indigo-500/10 border border-indigo-500/20 rounded-2xl flex items-center justify-center text-indigo-400 mx-auto shadow-inner">
            <RefreshCw size={32} />
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
          <div className="p-4 bg-indigo-500/5 border border-indigo-500/15 rounded-xl text-left">
            <div className="flex items-start gap-2.5">
              <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
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
            className="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white shadow-xl shadow-indigo-900/20 font-bold h-12 rounded-xl transition-premium"
          >
            {isPending ? (
              <div className="flex items-center gap-2">
                <LoadingSpinner className="w-4 h-4" />
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
        className="bg-surface-3/90 border border-red-500/20 shadow-2xl rounded-2xl overflow-hidden w-[400px] animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-8 text-center space-y-4">
          <div className="w-16 h-16 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center justify-center text-red-500 mx-auto shadow-inner">
            <Trash2 size={32} />
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
            className="flex-1 bg-red-600 hover:bg-red-500 text-white shadow-xl shadow-red-900/20 font-bold h-12 rounded-xl transition-premium"
          >
            {isPending ? "Deleting..." : "Delete Key"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
