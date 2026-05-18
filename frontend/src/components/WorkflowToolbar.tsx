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
import React, { useState, useEffect, useRef, useCallback, memo, lazy, Suspense } from "react";
import {
  ConfirmDialog,
  Dialog,
  Button,
  Input,
} from "@/components/ui";
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
import { useDeleteWorkflowMutation, usePublishWorkflowVersionMutation } from "@/generated/graphql";
import { ControlFlowMenu } from "@/components/builder/ControlFlowMenu";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// Sub-components
import { ToolbarGroup } from "./toolbar/ToolbarGroup";
import { WorkflowStatus } from "./toolbar/WorkflowStatus";
import { ResourceStats } from "./toolbar/ResourceStats";

const CreateModuleDialog = lazy(() => import("./CreateModuleDialog"));
const AddExistingNodeDialog = lazy(() => import("./AddExistingNodeDialog"));
const TestWorkflowModal = lazy(() =>
  import("./TestWorkflowModal").then((m) => ({ default: m.TestWorkflowModal })),
);

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
  const [modal, setModal] = useState<ToolbarModalState>({ kind: "none" });
  const closeModal = useCallback(() => setModal({ kind: "none" }), []);

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
    addNode 
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
  const { showInspector, setShowInspector, toolbarModalRequest } = useUIStore(
    useShallow((s) => ({
      showInspector: s.showInspector,
      setShowInspector: s.setShowInspector,
      toolbarModalRequest: s.toolbarModal,
    })),
  );

  // Execution Store
  const runStatus = usePersistedExecutionStore(
    (s: PersistedSlice) => workflowId ? s.workflowStatuses[workflowId] : undefined,
  );

  // External triggers for modals (from Workspace empty state)
  useEffect(() => {
    if (toolbarModalRequest === "addExisting") {
      setModal({ kind: "addExisting" });
      useUIStore.getState().setToolbarModal(null);
    } else if (toolbarModalRequest === "create") {
      setModal({ kind: "create" });
      useUIStore.getState().setToolbarModal(null);
    }
  }, [toolbarModalRequest]);

  // Mutations
  const publishVersionMutation = usePublishWorkflowVersionMutation({
    onSuccess: () => {
      toast.success("Version snapshot published");
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
    onError: () => toast.error("Failed to delete workflow"),
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

  const { handleSave, isSaving } = useWorkflowSave({ workflowId, workflowName });

  const handleNew = useCallback(() => {
    if (nodeCount === 0) {
      clearWorkflow();
    } else {
      setModal({ kind: "confirmClear" });
    }
  }, [nodeCount, clearWorkflow]);

  const handleModuleCreated = useCallback((
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
  }, [addNode]);

  const handleExistingNodeAdded = useCallback((
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
  }, [addNode]);

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
      className="bg-surface-1/60 backdrop-blur-xl border-b border-white/5 px-6 py-3 flex items-center gap-8 shrink-0 sticky top-0 z-40 shadow-2xl relative group"
      role="toolbar"
      aria-label="Workflow Construction Tools"
    >
      <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent opacity-50" />

      {/* Dialogs */}
      <ConfirmDialog
        open={modal.kind === "confirmClear"}
        title="New Workflow"
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
        title="Delete Workflow"
        message={`Permanently delete "${workflowName}"? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={() => {
          closeModal();
          if (workflowId) deleteWorkflowMutation.mutate({ id: workflowId });
        }}
        onCancel={closeModal}
      />

      <Dialog
        title="Identity Assignment"
        open={modal.kind === "name"}
        onClose={closeModal}
      >
        <div className="space-y-6">
          <p className="text-[11px] text-muted-foreground/60 font-bold uppercase tracking-widest leading-relaxed">
            Assign a unique operational identifier to this workflow sequence.
          </p>
          <div className="relative group">
            <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition-premium" />
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
              placeholder="Workflow Identifier..."
              className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-xs font-black uppercase tracking-widest rounded-2xl relative z-10 shadow-inner"
            />
          </div>
          <div className="flex justify-end gap-3 pt-4 relative z-10">
            <Button 
                variant="ghost" 
                onClick={closeModal}
                className="h-12 px-8 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5 active:scale-95"
            >
              Abort
            </Button>
            <Button
              variant="premium"
              onClick={handleNameDialogConfirm}
              disabled={modal.kind === "name" && !modal.pendingName.trim()}
              className="h-12 px-10"
            >
              Commit Identity
            </Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        title="Version Snapshot"
        open={modal.kind === "publish"}
        onClose={closeModal}
      >
        <div className="space-y-6">
          <p className="text-[11px] text-muted-foreground/60 font-bold uppercase tracking-widest leading-relaxed">
            Create a named protocol snapshot. This allows for rapid rollback and audit tracking across the deployment pipeline.
          </p>
          <div className="relative group">
            <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within:opacity-100 transition-premium" />
            <Input
              type="text"
              value={modal.kind === "publish" ? modal.desc : ""}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setModal({ kind: "publish", desc: e.target.value })
              }
              onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) => {
                if (e.key === "Enter" && workflowId && modal.kind === "publish") {
                  publishVersionMutation.mutate({ workflowId, description: modal.desc || undefined });
                }
                if (e.key === "Escape") closeModal();
              }}
              placeholder="Snapshot details (e.g. Protocol optimization v2)..."
              className="h-14 bg-surface-2/40 border-white/5 focus:border-primary/40 focus:ring-1 focus:ring-primary/40 text-xs font-black uppercase tracking-widest rounded-2xl relative z-10 shadow-inner"
            />
          </div>
          <div className="flex justify-end gap-3 pt-4 relative z-10">
            <Button 
                variant="ghost" 
                onClick={closeModal}
                className="h-12 px-8 text-[10px] font-black uppercase tracking-widest text-muted-foreground/40 hover:text-white transition-premium bg-surface-2 hover:bg-surface-3 rounded-2xl border border-white/5 active:scale-95"
            >
              Cancel
            </Button>
            <Button
              variant="premium"
              onClick={() => {
                if (workflowId && modal.kind === "publish") publishVersionMutation.mutate({ workflowId, description: modal.desc || undefined });
              }}
              disabled={publishVersionMutation.isPending}
              className="h-12 px-10"
            >
              {publishVersionMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin mr-2" />
              ) : (
                <Tag className="w-4 h-4 mr-2" />
              )}
              Publish Snapshot
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Build tools */}
      <ToolbarGroup label="Protocol">
        <Button
          variant="outline"
          size="sm"
          onClick={handleNew}
          className="bg-surface-4 border-white/5"
        >
          <PlusCircle className="w-3.5 h-3.5 mr-2" />
          New
        </Button>

        <Button
          variant="secondary"
          size="sm"
          onClick={() => setModal({ kind: "addExisting" })}
          className="bg-indigo-500/5 text-indigo-300 border-indigo-500/20 hover:bg-indigo-500/15"
        >
          <FolderPlus className="w-3.5 h-3.5 mr-2" />
          Library
        </Button>

        <Button
          variant="secondary"
          size="sm"
          onClick={() => setModal({ kind: "create" })}
          className="bg-emerald-500/5 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/15"
        >
          <Zap className="w-3.5 h-3.5 mr-2" />
          Modules
        </Button>

        <div className="pt-0.5">
          <ControlFlowMenu onClose={closeModal} />
        </div>
      </ToolbarGroup>

      <div className="w-[1px] h-8 bg-white/5 mx-2" />

      {/* Deployment tools */}
      <ToolbarGroup label="Deployment">
        <Button
          variant={isSaving || nodeCount === 0 ? "outline" : "premium"}
          size="sm"
          onClick={handleSaveWithName}
          disabled={isSaving || nodeCount === 0}
        >
          {isSaving ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin mr-2" />
          ) : (
            <Save className="w-3.5 h-3.5 mr-2" />
          )}
          {isSaving ? "Syncing..." : "Save"}
        </Button>

        {workflowId && !isDirty && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setModal({ kind: "publish", desc: "" })}
            className="bg-violet-500/5 text-violet-400 border-violet-500/20 hover:bg-violet-500/15"
          >
            <Tag className="w-3.5 h-3.5 mr-2" />
            Snapshot
          </Button>
        )}

        {workflowId && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setModal({ kind: "test" })}
            className="bg-emerald-500/5 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/15"
          >
            <Play className="w-3.5 h-3.5 mr-2" />
            Validate
          </Button>
        )}

        {workflowId && (
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setModal({ kind: "confirmDelete" })}
            className="text-muted-foreground/40 hover:text-destructive hover:bg-destructive/10"
            aria-label="Decommission Workflow"
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        )}
      </ToolbarGroup>

      {/* Global state & Telemetry */}
      <div className="ml-auto flex items-center gap-6">
        <WorkflowStatus 
          name={workflowName} 
          isDirty={isDirty} 
          runStatus={runStatus} 
        />

        <div className="w-[1px] h-10 bg-white/5" />

        <div className="flex items-center gap-3">
          <Button
            variant={showInspector ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setShowInspector(!showInspector)}
            className={cn(
              "px-4",
              showInspector ? "bg-white/5 text-white border-white/10" : "text-muted-foreground/40 hover:text-white"
            )}
          >
            <Settings2 className="w-4 h-4 mr-2" />
            <span className="hidden sm:inline">Diagnostics</span>
          </Button>

          <ResourceStats 
            nodeCount={nodeCount} 
            edgeCount={edgeCount} 
          />
        </div>
      </div>

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

