/**
 * Keeps unsaved editor changes from being lost by leaving the page: a
 * `beforeunload` prompt for reloads / tab closes, and an in-app navigation
 * blocker while the workflow store is dirty.
 */
import React, { useContext, useEffect } from "react";
import { UNSAFE_DataRouterContext, useBlocker } from "react-router";
import { ConfirmDialog } from "@/components/ui";
import { useWorkflowStore } from "@/store/workflowStore";

/**
 * Should leaving `currentPath` for `nextPath` ask first? Only while dirty,
 * and not when the editor merely gains the URL of the workflow it already
 * shows (`/editor` → `/editor/<its id>`).
 */
export function shouldBlockNavigation(
  isDirty: boolean,
  workflowId: string | null,
  currentPath: string,
  nextPath: string,
): boolean {
  if (!isDirty || currentPath === nextPath) return false;
  return !(workflowId !== null && nextPath === `/editor/${workflowId}`);
}

function NavigationBlocker() {
  const blocker = useBlocker(({ currentLocation, nextLocation }) => {
    const { isDirty, workflowId } = useWorkflowStore.getState();
    return shouldBlockNavigation(
      isDirty,
      workflowId,
      currentLocation.pathname,
      nextLocation.pathname,
    );
  });
  return (
    <ConfirmDialog
      open={blocker.state === "blocked"}
      title="Unsaved Changes"
      message="This workflow has unsaved changes. Leave and discard them?"
      confirmLabel="Discard"
      destructive
      onConfirm={() => {
        // Discarded by choice: a later visit loads the saved version.
        useWorkflowStore.getState().markClean();
        blocker.proceed?.();
      }}
      onCancel={() => blocker.reset?.()}
    />
  );
}

export function UnsavedChangesGuard() {
  const isDirty = useWorkflowStore((s) => s.isDirty);
  useEffect(() => {
    if (!isDirty) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [isDirty]);
  // `useBlocker` needs a data router; without one (tests rendering under a
  // MemoryRouter) only the unload prompt applies.
  const dataRouter = useContext(UNSAFE_DataRouterContext);
  return dataRouter ? <NavigationBlocker /> : null;
}
