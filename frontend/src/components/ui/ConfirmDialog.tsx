import * as React from "react";
import { Button } from "./button";
import { Dialog } from "./dialog";

export interface ConfirmDialogProps {
  open: boolean;
  /** Dialog heading */
  title?: string;
  /** Body message shown to the user */
  message: string;
  /** Label for the confirm button (default: "Confirm") */
  confirmLabel?: string;
  /** Label for the cancel button (default: "Cancel") */
  cancelLabel?: string;
  /** When true the confirm button uses the destructive (red) variant */
  destructive?: boolean;
  /** When true, disables the confirm button to prevent double-submission */
  isLoading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Accessible confirmation dialog built on our standard Dialog component.
 * Replaces window.confirm() calls throughout the app.
 */
export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title = "Confirm",
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive = false,
  isLoading = false,
  onConfirm,
  onCancel,
}) => {
  return (
    <Dialog open={open} onClose={onCancel} title={title}>
      <div
        id="confirm-dialog-message"
        className="text-sm text-muted-foreground mb-6"
      >
        {message}
      </div>
      <div className="flex justify-end gap-3">
        {/* Auto-focus Cancel so Escape / Enter both dismiss safely */}
        <Button
          variant="outline"
          onClick={onCancel}
          disabled={isLoading}
          autoFocus
        >
          {cancelLabel}
        </Button>
        <Button
          variant={destructive ? "destructive" : "default"}
          onClick={onConfirm}
          disabled={isLoading}
        >
          {isLoading ? "Loading…" : confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
};
