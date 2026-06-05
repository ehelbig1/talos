import * as React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { DialogWrapper } from "@/components/ui/DialogWrapper";
import { IconButton } from "@/components/ui/IconButton";

/**
 * Simple reusable modal using Radix UI Dialog.
 * Props mirror the previous `DialogBase` component but expose the `open`
 * state to allow controlled usage.
 */
export interface ModalProps {
  title: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

export const Modal: React.FC<ModalProps> = ({
  title,
  open,
  onOpenChange,
  children,
}) => {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 animate-fade-in z-50 overflow-y-auto" />
        <Dialog.Content
          className="fixed inset-0 flex items-center justify-center z-[60] animate-slide-up outline-none"
          onOpenAutoFocus={(e) => e.preventDefault()}
          aria-describedby={undefined}
        >
          {/* Accessible title — Radix requires Dialog.Title as a descendant of Dialog.Content */}
          <Dialog.Title className="sr-only">{title}</Dialog.Title>
          {/* Dark-theme modal container */}
          <DialogWrapper className="m-4">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-semibold">{title}</h2>
              <Dialog.Close asChild>
                <IconButton aria-label="Close dialog">
                  <X className="h-4 w-4" />
                </IconButton>
              </Dialog.Close>
            </div>
            {children}
          </DialogWrapper>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
};
