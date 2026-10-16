import React from "react";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import type { Role } from "./graphql";

export interface RoleChangeTarget {
  userId: string;
  currentRole: string;
  newRole: Role;
}

/** Confirmation for a member role change (current → proposed). */
export function RoleChangeDialog({
  target,
  isPending,
  onClose,
  onConfirm,
}: {
  target: RoleChangeTarget | null;
  isPending: boolean;
  onClose: () => void;
  onConfirm: () => void;
}): React.ReactElement {
  return (
    <ConfirmDialog
      open={!!target}
      title="Change role?"
      message={
        <>
          This member goes from{" "}
          <span className="text-white">{target?.currentRole}</span> to{" "}
          <span className="text-white">{target?.newRole}</span>. It takes effect
          immediately.
        </>
      }
      confirmLabel="Change role"
      isLoading={isPending}
      onCancel={onClose}
      onConfirm={onConfirm}
    />
  );
}
