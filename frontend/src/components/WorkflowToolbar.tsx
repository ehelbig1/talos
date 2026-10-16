import {
  Save,
  Settings2,
  PlusCircle,
  FolderPlus,
  Zap,
  Loader2,
  Trash2,
  Play,
  Tag,
} from "lucide-react";
import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  memo,
  lazy,
  Suspense,
} from "react";
import { ConfirmDialog, Dialog, Button, Input } from "@/components/ui";
import { useShallow } from "zustand/react/shallow";
import {
  usePersistedExecutionStore,
  type PersistedSlice,
} from "@/store/executionStore";
import { LoadingSpinner } from "./LoadingSpinner";
import { useWorkflowStore } from "@/store/workflowStore";
import { useUIStore } from "@/store/uiStore";
import { useQueryClient } from "@tanstack/react-query";
import { useWorkflowSave } from "@/hooks/useWorkflowSave";
import {
  useDeleteWorkflowMutation,
  usePublishWorkflowVersionMutation,
} from "@/generated/graphql";
import { ControlFlowMenu } from "@/components/builder/ControlFlowMenu";
import { toast } from "sonner";
import { userFacingErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";

// Sub-components
import { WorkflowStatus } from "./toolbar/WorkflowStatus";

const CreateModuleDialog = lazy(() => import("./CreateModuleDialog"));
const AddExistingNodeDialog = lazy(() => import("./AddExistingNodeDialog"));
const TestWorkflowModal = lazy(() =>
  import("./TestWorkflowModal").then((m) => ({ default: m.TestWorkflowModal })),
);

/** A toolbar action: icon always, label from 2xl up, name for assistive tech always. */
function ToolbarButton({
  label,
  icon: Icon,
  iconClassName,
  variant = "outline",
  ...rest
}: {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  iconClassName?: string;
  variant?: "outline" | "default";
} & Pick<React.ComponentProps<typeof Button>, "onClick" | "disabled">) {
  return (
    <Button
      variant={variant}
      size="sm"
      aria-label={label}
      title={label}
      className="h-8 px-2.5 2xl:px-3 rounded-lg"
      {...rest}
    >
      <Icon className={cn("w-3.5 h-3.5", iconClassName)} />
      <span className="hidden 2xl:inline">{label}</span>
    </Button>
  );
}

const Divider = () => <div className="w-px h-6 bg-white/10 mx-1" aria-hidden />;

type ToolbarModalState =
  | { kind: "none" }
  | { kind: "create" }
  | { kind: "addExisting" }
  | { kind: "confirmClear" }
  | { kind: "name"; pendingName: string }
  | { kind: "confirmDelete" }
  | { kind: "test" }
  | { kind: "publish"; desc: string };

export const WorkflowToolbar = memo(function WorkflowToolbar() {
  const [localModal, setModal] = useState<ToolbarModalState>({
    kind: "none",
  });
  // A request from elsewhere (the empty canvas) is read from the store and
  // cleared on close, so no effect has to copy it into local state.
  const toolbarModalRequest = useUIStore((s) => s.toolbarModal);
  const modal: ToolbarModalState = toolbarModalRequest
    ? { kind: toolbarModalRequest }
    : localModal;
  const closeModal = useCallback(() => {
    setModal({ kind: "none" });
    useUIStore.getState().setToolbarModal(null);
  }, []);

  const nameInputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  // Workflow Store
  const {
    nodeCount,
    edgeCount,
    workflowName,
    workflowId,
    isDirty,
    setWorkflowMeta,
    clearWorkflow,
    addNode,
  } = useWorkflowStore(
    useShallow((s) => ({
      nodeCount: s.nodes.length,
      edgeCount: s.edges.length,
      workflowName: s.workflowName,
      workflowId: s.workflowId,
      isDirty: s.isDirty,
      setWorkflowMeta: s.setWorkflowMeta,
      clearWorkflow: s.clearWorkflow,
      addNode: s.addNode,
    })),
  );

  // UI Store
  const { showInspector, setShowInspector } = useUIStore(
    useShallow((s) => ({
      showInspector: s.showInspector,
      setShowInspector: s.setShowInspector,
    })),
  );

  // Execution Store
  const runStatus = usePersistedExecutionStore((s: PersistedSlice) =>
    workflowId ? s.workflowStatuses[workflowId] : undefined,
  );

  // Mutations
  const publishVersionMutation = usePublishWorkflowVersionMutation({
    onSuccess: () => {
      toast.success("Version published");
      closeModal();
    },
    onError: () => toast.error("Failed to publish version"),
  });

  const deleteWorkflowMutation = useDeleteWorkflowMutation({
    onSuccess: () => {
      toast.success("Workflow deleted");
      clearWorkflow();
      queryClient.invalidateQueries({ queryKey: ["Workflows"] });
      window.dispatchEvent(new CustomEvent("workflowDeleted"));
    },
    onError: (err) =>
      toast.error(userFacingErrorMessage(err, "Failed to delete workflow")),
  });

  useEffect(() => {
    const handleWorkflowDeleted = () => clearWorkflow();
    window.addEventListener("workflowDeleted", handleWorkflowDeleted);
    return () =>
      window.removeEventListener("workflowDeleted", handleWorkflowDeleted);
  }, [clearWorkflow]);

  useEffect(() => {
    if (modal.kind === "name") {
      setTimeout(() => nameInputRef.current?.focus(), 50);
    }
  }, [modal.kind]);

  const { handleSave, isSaving } = useWorkflowSave({
    workflowId,
    workflowName,
  });

  const handleNew = useCallback(() => {
    if (nodeCount === 0) {
      clearWorkflow();
    } else {
      setModal({ kind: "confirmClear" });
    }
  }, [nodeCount, clearWorkflow]);

  const handleModuleCreated = useCallback(
    (
      moduleId: string,
      moduleName: string,
      config?: Record<string, unknown>,
      category?: string,
    ) => {
      addNode(
        moduleId,
        moduleName,
        { x: 250, y: 250 },
        config || {},
        undefined,
        undefined,
        category,
      );
    },
    [addNode],
  );

  const handleExistingNodeAdded = useCallback(
    (
      moduleId: string,
      moduleName: string,
      config: Record<string, unknown>,
      capabilityWorld?: string,
      capabilityDescription?: string,
      category?: string,
      importedInterfaces?: string[],
    ) => {
      addNode(
        moduleId,
        moduleName,
        { x: 250, y: 250 },
        config,
        capabilityWorld,
        capabilityDescription,
        category,
        importedInterfaces,
      );
    },
    [addNode],
  );

  const handleSaveWithName = useCallback(async () => {
    if (!workflowId) {
      setModal({ kind: "name", pendingName: workflowName });
    } else {
      await handleSave();
    }
  }, [workflowId, workflowName, handleSave]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "s") {
        e.preventDefault();
        const currentNodeCount = useWorkflowStore.getState().nodes.length;
        if (currentNodeCount > 0 && !isSaving) {
          handleSaveWithName();
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isSaving, handleSaveWithName]);

  const handleNameDialogConfirm = async () => {
    if (modal.kind !== "name") return;
    const name = modal.pendingName.trim();
    if (!name) return;
    closeModal();
    setWorkflowMeta(null, name);
    await handleSave(name);
  };

  return (
    <div
      className="flex items-center gap-2 flex-wrap"
      role="toolbar"
      aria-label="Workflow tools"
    >
      {/* Dialogs */}
      <ConfirmDialog
        open={modal.kind === "confirmClear"}
        title="New workflow?"
        message="Clear the current workflow? Unsaved changes will be lost."
        confirmLabel="Clear"
        destructive
        onConfirm={() => {
          closeModal();
          clearWorkflow();
        }}
        onCancel={closeModal}
      />

      <ConfirmDialog
        open={modal.kind === "confirmDelete"}
        title="Delete workflow?"
        message={`“${workflowName}” and its run history will be deleted. This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={() => {
          closeModal();
          if (workflowId) deleteWorkflowMutation.mutate({ id: workflowId });
        }}
        onCancel={closeModal}
      />

      <Dialog
        title="Rename workflow"
        open={modal.kind === "name"}
        onClose={closeModal}
      >
        <div className="space-y-6">
          <p className="text-xs text-muted-foreground/60 leading-relaxed">
            Give this workflow a name.
          </p>
          <div className="relative group">
            <Input
              ref={nameInputRef}
              type="text"
              value={modal.kind === "name" ? modal.pendingName : ""}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setModal({ kind: "name", pendingName: e.target.value })
              }
              onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) => {
                if (e.key === "Enter") handleNameDialogConfirm();
                if (e.key === "Escape") closeModal();
              }}
              placeholder="Workflow name"
              className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-sm font-semibold rounded-2xl relative z-10"
            />
          </div>
          <div className="flex justify-end gap-3 pt-4 relative z-10">
            <Button
              variant="ghost"
              onClick={closeModal}
              className="h-12 px-8 text-sm font-semibold text-muted-foreground/70 hover:text-white transition-ui bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5"
            >
              Cancel
            </Button>
            <Button
              onClick={handleNameDialogConfirm}
              disabled={modal.kind === "name" && !modal.pendingName.trim()}
              className="h-12 px-10"
            >
              Save name
            </Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        title="Publish version"
        open={modal.kind === "publish"}
        onClose={closeModal}
      >
        <div className="space-y-6">
          <p className="text-xs text-muted-foreground/60 leading-relaxed">
            Publish the current graph as a version so you can roll back to it
            later.
          </p>
          <div className="relative group">
            <Input
              type="text"
              value={modal.kind === "publish" ? modal.desc : ""}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setModal({ kind: "publish", desc: e.target.value })
              }
              onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) => {
                if (
                  e.key === "Enter" &&
                  workflowId &&
                  modal.kind === "publish"
                ) {
                  publishVersionMutation.mutate({
                    workflowId,
                    description: modal.desc || undefined,
                  });
                }
                if (e.key === "Escape") closeModal();
              }}
              placeholder="What changed? (optional)"
              className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-sm font-semibold rounded-2xl relative z-10"
            />
          </div>
          <div className="flex justify-end gap-3 pt-4 relative z-10">
            <Button
              variant="ghost"
              onClick={closeModal}
              className="h-12 px-8 text-sm font-semibold text-muted-foreground/70 hover:text-white transition-ui bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5"
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (workflowId && modal.kind === "publish")
                  publishVersionMutation.mutate({
                    workflowId,
                    description: modal.desc || undefined,
                  });
              }}
              disabled={publishVersionMutation.isPending}
              className="h-12 px-10"
            >
              {publishVersionMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin mr-2" />
              ) : (
                <Tag className="w-4 h-4 mr-2" />
              )}
              Publish version
            </Button>
          </div>
        </div>
      </Dialog>

      <WorkflowStatus isDirty={isDirty} runStatus={runStatus} />

      <ToolbarButton label="New" icon={PlusCircle} onClick={handleNew} />
      <ToolbarButton
        label="Add from library"
        icon={FolderPlus}
        onClick={() => setModal({ kind: "addExisting" })}
      />
      <ToolbarButton
        label="New module"
        icon={Zap}
        onClick={() => setModal({ kind: "create" })}
      />
      <ControlFlowMenu onClose={closeModal} />

      <Divider />

      <ToolbarButton
        label={isSaving ? "Saving…" : "Save"}
        icon={isSaving ? Loader2 : Save}
        iconClassName={isSaving ? "animate-spin" : undefined}
        variant={isDirty && nodeCount > 0 && !isSaving ? "default" : "outline"}
        onClick={handleSaveWithName}
        disabled={isSaving || nodeCount === 0}
      />
      {workflowId && !isDirty && (
        <ToolbarButton
          label="Publish version"
          icon={Tag}
          onClick={() => setModal({ kind: "publish", desc: "" })}
        />
      )}
      {workflowId && (
        <ToolbarButton
          label="Test"
          icon={Play}
          onClick={() => setModal({ kind: "test" })}
        />
      )}
      {workflowId && (
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setModal({ kind: "confirmDelete" })}
          className="h-8 w-8 rounded-lg text-muted-foreground/70 hover:text-destructive hover:bg-destructive/10"
          aria-label="Delete workflow"
          title="Delete workflow"
        >
          <Trash2 className="w-4 h-4" />
        </Button>
      )}

      <Divider />

      <Button
        variant={showInspector ? "secondary" : "ghost"}
        size="icon"
        onClick={() => setShowInspector(!showInspector)}
        aria-label="Inspector"
        title="Inspector"
        aria-pressed={showInspector}
        className={cn(
          "h-8 w-8 rounded-lg",
          showInspector
            ? "bg-white/5 text-white border border-white/10"
            : "text-muted-foreground/70 hover:text-white",
        )}
      >
        <Settings2 className="w-4 h-4" />
      </Button>
      <span className="hidden 2xl:inline text-xs text-muted-foreground tabular-nums whitespace-nowrap pl-1">
        {nodeCount} node{nodeCount === 1 ? "" : "s"} · {edgeCount} edge
        {edgeCount === 1 ? "" : "s"}
      </span>

      {/* Dialog Rendering */}
      {modal.kind === "create" && (
        <Suspense fallback={<LoadingSpinner />}>
          <CreateModuleDialog
            onModuleCreated={handleModuleCreated}
            onClose={closeModal}
          />
        </Suspense>
      )}

      {modal.kind === "addExisting" && (
        <Suspense fallback={<LoadingSpinner />}>
          <AddExistingNodeDialog
            onNodeAdded={handleExistingNodeAdded}
            onClose={closeModal}
          />
        </Suspense>
      )}

      {modal.kind === "test" && workflowId && (
        <Suspense fallback={<LoadingSpinner />}>
          <TestWorkflowModal
            workflowId={workflowId}
            workflowName={workflowName}
            onClose={closeModal}
          />
        </Suspense>
      )}
    </div>
  );
});
