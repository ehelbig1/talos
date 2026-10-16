/**
 * The one-time reveal of a created or rotated API key.
 * Presentational — the parent owns the newKey state.
 */

import React from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Copy } from "lucide-react";
import { toast } from "sonner";

export function NewKeyDialog({
  newKey,
  onClose,
}: {
  newKey: string;
  onClose: () => void;
}) {
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(newKey);
      toast.success("Key copied");
    } catch {
      toast.error("Could not copy. The clipboard needs a secure (HTTPS) page.");
    }
  };

  return (
    <Dialog open onClose={onClose} title="Your new key" className="max-w-lg">
      <div className="space-y-6">
        <p className="text-sm text-muted-foreground">
          Copy it now. It is shown once; if you lose it, revoke this key and
          create another.
        </p>

        <div className="relative">
          <pre className="bg-black border border-white/10 text-warning p-5 pr-28 rounded-xl text-sm font-mono break-all whitespace-pre-wrap leading-relaxed">
            {newKey}
          </pre>
          <Button
            size="sm"
            variant="outline"
            className="absolute top-3 right-3"
            onClick={copy}
          >
            <Copy className="w-3.5 h-3.5" />
            Copy
          </Button>
        </div>

        <div className="flex justify-end">
          <Button onClick={onClose}>I've saved it</Button>
        </div>
      </div>
    </Dialog>
  );
}
