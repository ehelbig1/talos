import React from "react";
import { Building2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { LoadingSpinner } from "@/components/LoadingSpinner";

/** Create-organization dialog. Slug auto-derives from the name until
 *  the user edits it explicitly.
 *
 *  `onClose` (dialog dismiss) resets the fields; `onAbort` (the ABORT
 *  button) only hides the dialog — preserving the pre-decomposition
 *  behavior where the two paths differed. */
export function CreateOrgDialog({
  open,
  name,
  slug,
  isPending,
  onNameChange,
  onSlugChange,
  onClose,
  onAbort,
  onSubmit,
}: {
  open: boolean;
  name: string;
  slug: string;
  isPending: boolean;
  onNameChange: (name: string, derivedSlug?: string) => void;
  onSlugChange: (slug: string) => void;
  onClose: () => void;
  onAbort: () => void;
  onSubmit: () => void;
}): React.ReactElement {
  return (
    <Dialog open={open} onClose={onClose} title="Establish Syndicate">
      <div className="space-y-8">
        <div className="p-6 bg-primary/5 border border-primary/10 rounded-2xl flex items-start gap-4">
          <Building2 className="w-5 h-5 text-primary shrink-0 mt-0.5" />
          <p className="text-[11px] text-muted-foreground/60 leading-relaxed font-medium">
            Establish a new governing protocol. Organizations allow you to group
            multiple operatives and resources under a single administrative
            umbrella.
          </p>
        </div>

        <div className="space-y-6">
          <div className="space-y-2.5">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
              Organization_Identity
            </label>
            <div className="relative group">
              <Input
                placeholder="e.g. TACTICAL_UNIT_ALPHA"
                value={name}
                onChange={(e) => {
                  const value = e.target.value;
                  onNameChange(
                    value,
                    slug
                      ? undefined
                      : value
                          .toLowerCase()
                          .replace(/\s+/g, "-")
                          .replace(/[^a-z0-9-]/g, ""),
                  );
                }}
                className="h-14 bg-white/[0.03] border-white/10 focus:border-primary/50 focus:ring-primary/20 rounded-xl px-4 font-outfit text-white placeholder:text-white/10 transition-premium"
              />
            </div>
          </div>

          <div className="space-y-2.5">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/40 ml-1">
              Uplink_Identifier
            </label>
            <div className="relative flex items-center">
              <span className="absolute left-4 text-muted-foreground/30 font-outfit text-sm">
                talos.sh/
              </span>
              <Input
                placeholder="tactical-alpha"
                value={slug}
                onChange={(e) =>
                  onSlugChange(
                    e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""),
                  )
                }
                className="h-14 bg-white/[0.03] border-white/10 focus:border-primary/50 focus:ring-primary/20 rounded-xl pl-[4.5rem] font-mono text-sm text-white placeholder:text-white/10 transition-premium"
              />
            </div>
            <p className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-widest ml-1">
              LOWERCASE_ALPHANUMERIC_ONLY
            </p>
          </div>
        </div>

        <div className="flex gap-4 pt-4">
          <Button
            variant="outline"
            className="flex-1 h-14 rounded-xl border-white/10 hover:bg-white/5 text-[10px] font-black uppercase tracking-widest"
            onClick={onAbort}
          >
            ABORT_MISSION
          </Button>
          <Button
            variant="premium"
            className="flex-1 h-14 rounded-xl shadow-2xl"
            disabled={!name || !slug || isPending}
            onClick={onSubmit}
          >
            {isPending ? <LoadingSpinner /> : "ESTABLISH_UPLINK"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
