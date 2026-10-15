import * as React from "react";
import { X } from "lucide-react";
import { DialogWrapper } from "@/components/ui/DialogWrapper";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Simple reusable dialog wrapper used across the UI.
 * It mirrors the styling previously duplicated in several components
 * (CreateSecretDialog, CreateModuleDialog, etc.).
 *
 * Props:
 *   - `open`: control visibility of the dialog.
 *   - `onClose`: callback when the backdrop is clicked or Escape is pressed.
 *   - `title`: optional heading displayed at the top.
 *   - `children`: dialog body.
 */
export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  className?: string;
  children: React.ReactNode;
}

import { createPortal } from "react-dom";

export const Dialog: React.FC<DialogProps> = ({
  open,
  onClose,
  title,
  className,
  children,
}) => {
  const contentRef = React.useRef<HTMLDivElement>(null);
  const triggerRef = React.useRef<Element | null>(null);

  // Capture the element that had focus before the dialog opened so we can
  // restore it when the dialog closes.  Also auto-focus the first focusable
  // element inside the dialog content.
  React.useEffect(() => {
    if (open) {
      triggerRef.current = document.activeElement;
      // Defer focus until the dialog DOM has painted.
      const id = requestAnimationFrame(() => {
        const first =
          contentRef.current?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
        first?.focus();
      });
      return () => cancelAnimationFrame(id);
    } else if (triggerRef.current instanceof HTMLElement) {
      triggerRef.current.focus();
      triggerRef.current = null;
    }
  }, [open]);

  const handleKey = React.useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }

      // Focus trap: keep Tab / Shift+Tab within the dialog content.
      if (e.key === "Tab") {
        const focusable = Array.from(
          contentRef.current?.querySelectorAll<HTMLElement>(
            FOCUSABLE_SELECTOR,
          ) ?? [],
        );
        if (focusable.length === 0) return;

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    },
    [onClose],
  );

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[9999] animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-labelledby={title ? "dialog-title" : undefined}
      onClick={onClose}
      onKeyDown={handleKey}
    >
      <div
        ref={contentRef}
        className="w-full flex justify-center px-4 animate-in fade-in zoom-in-95 duration-200"
      >
        <DialogWrapper
          className={className}
          onClick={(e: React.MouseEvent) => e.stopPropagation()}
        >
          <div className="flex justify-between items-start gap-4 mb-6">
            {title && (
              <h2
                id="dialog-title"
                className="text-xl font-semibold text-white tracking-tight font-outfit"
              >
                {title}
              </h2>
            )}
            <button
              onClick={onClose}
              className="ml-auto p-2 bg-white/5 border border-white/10 hover:bg-white/10 rounded-lg transition-premium text-muted-foreground hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
              title="Close"
              aria-label="Close"
            >
              <X size={18} />
            </button>
          </div>
          {children}
        </DialogWrapper>
      </div>
    </div>,
    document.body,
  );
};
