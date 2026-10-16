/**
 * One-time display dialog for a newly created or rotated API key.
 * Strictly presentational — the parent owns the newKey state.
 */

import React from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Shield, Copy, Info } from "lucide-react";
import { toast } from "sonner";

export function NewKeyDialog({
  newKey,
  onClose,
}: {
  newKey: string;
  onClose: () => void;
}) {
  return (
    <Dialog open={true} onClose={onClose}>
      <div
        className="bg-surface-3/90 border border-warning/20 rounded-2xl overflow-hidden w-[520px]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-8 py-6 border-b border-warning/10 flex items-center justify-between bg-warning/[0.03]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-warning/10 rounded-xl flex items-center justify-center border border-warning/20 text-warning">
              <Shield size={20} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-warning tracking-tight">
                Key Generated
              </h3>
              <p className="text-xs text-warning font-bold leading-none mt-1">
                One-time security display
              </p>
            </div>
          </div>
        </div>

        <div className="p-8 space-y-6">
          <div className="p-5 bg-warning/[0.02] border border-warning/10 rounded-2xl">
            <div className="flex items-start gap-3 mb-4">
              <Info className="w-5 h-5 text-warning shrink-0 mt-0.5" />
              <p className="text-xs text-warning/60 leading-relaxed font-medium">
                This secret key will{" "}
                <span className="text-warning font-bold italic px-1">
                  never be shown again
                </span>
                . If you lose it, you must revoke this key and create a new one.
              </p>
            </div>
            <div className="relative group">
              <div className="absolute top-3 left-4 text-2xs font-bold uppercase tracking-wider text-muted-foreground pointer-events-none">
                API key
              </div>
              <pre className="bg-black border border-white/5 text-warning p-6 pt-10 rounded-xl text-[14px] font-mono break-all whitespace-pre-wrap leading-relaxed">
                {newKey}
              </pre>
              <Button
                size="sm"
                className="absolute top-3 right-3 h-8 px-3 bg-warning hover:bg-warning/90 text-warning-foreground font-bold text-xs rounded-lg transition-transform"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(newKey);
                    toast.success("Key copied to clipboard");
                  } catch {
                    toast.error(
                      "Failed to copy — clipboard unavailable (requires HTTPS)",
                    );
                  }
                }}
              >
                <Copy className="w-3.5 h-3.5 mr-1.5" />
                Copy Key
              </Button>
            </div>
          </div>
        </div>

        <div className="px-8 py-6 bg-white/[0.02] border-t border-white/5 flex justify-end">
          <Button
            onClick={onClose}
            className="bg-white/10 hover:bg-white/10 text-foreground border border-white/10 px-8 h-11 rounded-xl font-bold transition-ui"
          >
            I've Saved It
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
