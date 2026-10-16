import * as React from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface DialogProps {
  open: boolean;
  /** Called when the close button, the backdrop or Escape dismisses the dialog. */
  onClose: () => void;
  /** The heading. Without one the dialog is still named for assistive technology. */
  title?: string;
  /** Applied to the panel: use it for the width (`max-w-md`). */
  className?: string;
  children: React.ReactNode;
}

/**
 * The one dialog. Radix supplies the portal, the focus trap, the scroll lock,
 * the Escape and backdrop dismissal and the aria wiring; this file supplies
 * the one panel every dialog shares.
 */
export const Dialog: React.FC<DialogProps> = ({
  open,
  onClose,
  title,
  className,
  children,
}) => {
  return (
    <RadixDialog.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="fixed inset-0 z-[9999] bg-black/60 backdrop-blur-sm animate-fade-in" />
        <RadixDialog.Content
          aria-describedby={undefined}
          className={cn(
            "fixed left-1/2 top-1/2 z-[9999] w-[calc(100%-2rem)] max-w-3xl max-h-[calc(100vh-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto custom-scrollbar rounded-2xl border border-white/10 bg-surface-2 p-6 shadow-2xl outline-none nodrag nopan",
            className,
          )}
        >
          <div className="mb-6 flex items-start justify-between gap-4">
            <RadixDialog.Title
              className={cn(
                "text-xl font-semibold text-white tracking-tight font-outfit",
                !title && "sr-only",
              )}
            >
              {title ?? "Dialog"}
            </RadixDialog.Title>
            <RadixDialog.Close asChild>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Close"
                className="ml-auto -mr-2 -mt-2 h-8 w-8 shrink-0"
              >
                <X className="w-4 h-4" />
              </Button>
            </RadixDialog.Close>
          </div>
          {children}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
};
