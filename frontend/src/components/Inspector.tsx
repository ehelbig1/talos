import React, { useEffect, useCallback, useState } from "react";
import { useWorkflowStore, type WorkflowState } from "@/store/workflowStore";
import { useUIStore, type UIState } from "@/store/uiStore";
import {
  useEphemeralExecutionStore,
  type EphemeralSlice,
} from "@/store/executionStore";
import { NodeInspector } from "./inspector/NodeInspector";
import { EdgeInspector } from "./inspector/EdgeInspector";
import { WorkflowInspector } from "./inspector/WorkflowInspector";
import { DebugPanel } from "./debug/DebugPanel";
import { ConfirmDialog } from "./ui/ConfirmDialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui";

import { useShallow } from "zustand/react/shallow";

function Inspector() {
  const selectedNode = useWorkflowStore((state: WorkflowState) =>
    state.nodes.find((n) => n.selected),
  );
  const selectedEdge = useWorkflowStore((state: WorkflowState) =>
    state.edges.find((e) => e.selected),
  );

  const {
    updateNodeData,
    updateEdgeData,
    deleteNode,
    nodeCount,
    edgeCount,
    workflowId,
    workflowName,
  } = useWorkflowStore(
    useShallow((state: WorkflowState) => ({
      updateNodeData: state.updateNodeData,
      updateEdgeData: state.updateEdgeData,
      deleteNode: state.deleteNode,
      nodeCount: state.nodes.length,
      edgeCount: state.edges.length,
      workflowId: state.workflowId,
      workflowName: state.workflowName,
    })),
  );

  const { setShowInspector, setSelectedNodeId, debugNodeId, setDebugNodeId } =
    useUIStore(
      useShallow((state: UIState) => ({
        setShowInspector: state.setShowInspector,
        setSelectedNodeId: state.setSelectedNodeId,
        debugNodeId: state.debugNodeId,
        setDebugNodeId: state.setDebugNodeId,
      })),
    );

  const hasExecution = useEphemeralExecutionStore(
    (state: EphemeralSlice) =>
      state.isRunning || state.currentExecutionId != null,
  );

  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  useEffect(() => {
    if (selectedNode) {
      setSelectedNodeId(selectedNode.id);
    }
  }, [selectedNode, setSelectedNodeId]);

  const handleClose = useCallback(() => {
    setShowInspector(false);
  }, [setShowInspector]);

  const handleDeleteNode = useCallback((id: string) => {
    setDeleteConfirmId(id);
  }, []);

  const confirmDelete = useCallback(() => {
    if (deleteConfirmId) {
      deleteNode(deleteConfirmId);
      setDeleteConfirmId(null);
      setShowInspector(false);
    }
  }, [deleteConfirmId, deleteNode, setShowInspector]);

  // Render the appropriate inspector based on selection
  let content;
  if (selectedNode) {
    content = (
      <NodeInspector
        node={selectedNode}
        updateNodeData={updateNodeData}
        deleteNode={handleDeleteNode}
        onClose={handleClose}
      />
    );
  } else if (selectedEdge) {
    content = (
      <EdgeInspector
        edge={selectedEdge}
        updateEdgeData={updateEdgeData}
        onClose={handleClose}
      />
    );
  } else {
    content = (
      <WorkflowInspector
        workflowName={workflowName}
        workflowId={workflowId}
        nodeCount={nodeCount}
        edgeCount={edgeCount}
        onClose={handleClose}
      />
    );
  }

  // Determine the active tab: if debugNodeId is set and execution data exists, default to debug
  const showDebugTab = hasExecution && debugNodeId != null;

  // The tab strip only renders while `debugNodeId != null` (see
  // `showDebugTab`), and switching to "inspector" clears `debugNodeId`
  // — which removes the strip entirely. So the active tab is fully
  // derivable from `debugNodeId` and needs no mirrored state or sync
  // effect (react-hooks/set-state-in-effect).
  const activeTab = debugNodeId != null ? "debug" : "inspector";

  // Clear debugNodeId when switching away from the debug tab
  const handleTabChange = useCallback(
    (value: string) => {
      if (value !== "debug") {
        setDebugNodeId(null);
      }
    },
    [setDebugNodeId],
  );

  return (
    <>
      {showDebugTab ? (
        <Tabs
          value={activeTab}
          onValueChange={handleTabChange}
          className="flex flex-col h-full bg-surface-1/60 backdrop-blur-3xl relative"
        >
          <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />

          <TabsList className="w-full justify-start rounded-none border-b border-white/5 bg-surface-2/40 px-4 gap-2 shrink-0 relative z-10">
            <TabsTrigger
              value="inspector"
              className="text-[10px] font-black uppercase tracking-[0.2em] data-[state=active]:text-primary data-[state=active]:bg-primary/5 text-muted-foreground/40 rounded-xl py-2 px-6 transition-premium"
            >
              Inspector
            </TabsTrigger>
            <TabsTrigger
              value="debug"
              className="text-[10px] font-black uppercase tracking-[0.2em] data-[state=active]:text-warning data-[state=active]:bg-warning/5 text-muted-foreground/40 rounded-xl py-2 px-6 transition-premium"
            >
              Debug
            </TabsTrigger>
          </TabsList>

          <TabsContent
            value="inspector"
            className="flex-1 min-h-0 overflow-hidden relative z-10"
          >
            {content}
          </TabsContent>

          <TabsContent
            value="debug"
            className="flex-1 min-h-0 overflow-hidden relative z-10"
          >
            <DebugPanel nodeId={debugNodeId} />
          </TabsContent>
        </Tabs>
      ) : (
        <div className="flex flex-col h-full bg-surface-1/60 backdrop-blur-3xl relative">
          <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent opacity-30 pointer-events-none" />
          {/* min-h-0 so the inspector's inner scroll area (overflow-auto) is
              bounded and scrolls instead of overflowing the sidebar. */}
          <div className="flex-1 min-h-0 relative z-10">{content}</div>
        </div>
      )}
      <ConfirmDialog
        open={!!deleteConfirmId}
        title="Terminate & Remove Node"
        message={`Are you sure you want to terminate and remove node "${selectedNode?.data.label || "this node"}"?`}
        confirmLabel="Terminate & Remove"
        destructive={true}
        onConfirm={confirmDelete}
        onCancel={() => setDeleteConfirmId(null)}
      />
    </>
  );
}

export default React.memo(Inspector);
