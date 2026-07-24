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
        className="bg-surface-3/90 border border-amber-500/20 shadow-[0_0_100px_rgba(245,158,11,0.1)] rounded-2xl overflow-hidden w-[520px] animate-in zoom-in-95 duration-300"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-8 py-6 border-b border-amber-500/10 flex items-center justify-between bg-amber-500/[0.03]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-amber-500/10 rounded-xl flex items-center justify-center border border-amber-500/20 text-amber-500">
              <Shield size={20} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-amber-500 tracking-tight">
                Key Generated
              </h3>
              <p className="text-[10px] text-amber-600 font-bold uppercase tracking-widest leading-none mt-1">
                One-time security display
              </p>
            </div>
          </div>
        </div>

        <div className="p-8 space-y-6">
          <div className="p-5 bg-amber-500/[0.02] border border-amber-500/10 rounded-2xl">
            <div className="flex items-start gap-3 mb-4">
              <Info className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
              <p className="text-xs text-amber-200/60 leading-relaxed font-medium">
                This secret key will{" "}
                <span className="text-amber-400 font-bold uppercase italic px-1">
                  never be shown again
                </span>
                . If you lose it, you must revoke this key and create a new one.
              </p>
            </div>
            <div className="relative group">
              <div className="absolute top-3 left-4 text-[9px] font-bold uppercase tracking-[0.2em] text-muted-foreground pointer-events-none">
                Talos Secret Credential
              </div>
              <pre className="bg-black border border-white/5 text-amber-500 p-6 pt-10 rounded-xl text-[14px] font-mono break-all whitespace-pre-wrap leading-relaxed shadow-inner">
                {newKey}
              </pre>
              <Button
                size="sm"
                className="absolute top-3 right-3 h-8 px-3 bg-amber-500 hover:bg-amber-400 text-black font-bold text-xs rounded-lg transition-transform hover:scale-105 active:scale-95"
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
            className="bg-white/10 hover:bg-white/10 text-foreground border border-white/10 px-8 h-11 rounded-xl font-bold transition-premium"
          >
            I've Saved It
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
