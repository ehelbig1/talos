import { create } from "zustand";
import { useShallow } from "zustand/react/shallow";
import type {
  Node as RFNode,
  Edge as RFEdge,
  OnNodesChange,
  OnEdgesChange,
  Connection,
} from "@xyflow/react";
import { applyNodeChanges, applyEdgeChanges } from "@xyflow/react";

export interface RetryPolicy {
  maxRetries: number;
  backoffMs?: number;
  retryCondition?: string; // Rhai expression returning bool
  retryDelayExpression?: string; // Rhai expression returning int (ms)
}

export interface WorkflowNodeData {
  [key: string]: unknown;
  label: string;
  moduleId: string;
  moduleName: string;
  config?: Record<string, unknown>;
  category?: string;
  executionStatus?: string;
  capabilityWorld?: string;
  capabilityDescription?: string;
  importedInterfaces?: string[];
  // System node type (for engine-handled nodes)
  systemNodeKind?:
    | "ForEach"
    | "FanIn"
    | "WhileLoop"
    | "RepeatLoop"
    | "Loop"
    | "Collect"
    | "DynamicDispatch"
    | "CapabilityDispatch"
    | "SubWorkflow"
    | "ErrorHandler"
    | "Wait";
  // FanIn config
  joinMode?: "All" | "Any" | "Majority" | "N";
  joinN?: number;
  aggregationExpr?: string;
  // WhileLoop / Loop config
  loopCondition?: string;
  maxIterations?: number;
  // RepeatLoop config
  repeatCount?: number;
  // SubWorkflow config
  subWorkflowId?: string;
  // DynamicDispatch config
  dispatchExpression?: string;
  // CapabilityDispatch config
  requiredCapabilities?: string[];
  // Shared dispatch config
  // ... extra timeout placeholder removed ...
  // ErrorHandler config
  errorPattern?: string;
  // Execution configuration
  skipCondition?: string;
  continueOnError?: boolean;
  timeoutSecs?: number;
  // Retry configuration
  retryPolicy?: RetryPolicy;
  // Additional dynamic properties
  properties?: Record<string, unknown>;
}

export type WorkflowNode = RFNode<WorkflowNodeData>;

export interface EdgeData {
  [key: string]: unknown;
  edgeType?: "default" | "error" | "conditional" | "OnFailure";
  condition?: string;
  mapping?: string;
}

export type WorkflowEdge = RFEdge<EdgeData>;

export interface WorkflowState {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  workflowId: string | null;
  workflowName: string;
  maxConcurrentExecutions: number;
  priority: "high" | "normal" | "low";
  intent: Record<string, unknown>;
  isDirty: boolean;
  onNodesChange: OnNodesChange;
  onEdgesChange: OnEdgesChange;
  connectNodes: (connection: Connection, edgeType?: string) => void;
  updateEdgeData: (edgeId: string, data: Partial<EdgeData>) => void;
  addNode: (
    moduleId: string,
    moduleName: string,
    position: { x: number; y: number },
    config?: Record<string, unknown>,
    capabilityWorld?: string,
    capabilityDescription?: string,
    category?: string,
    importedInterfaces?: string[],
  ) => void;
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => void;
  deleteNode: (id: string) => void;
  duplicateNode: (nodeId: string) => void;
  clearWorkflow: () => void;
  loadWorkflow: (workflow: {
    nodes: WorkflowNode[];
    edges: WorkflowEdge[];
  }) => void;
  setWorkflowMeta: (id: string | null, name: string) => void;
  setMaxConcurrentExecutions: (count: number) => void;
  setPriority: (priority: "high" | "normal" | "low") => void;
  setIntent: (intent: Record<string, unknown>) => void;
  markClean: () => void;
}

export const useWorkflowStore = create<WorkflowState>((set, get) => ({
  nodes: [],
  edges: [],
  workflowId: null,
  workflowName: "Untitled Workflow",
  maxConcurrentExecutions: 1,
  priority: "normal",
  intent: {},
  isDirty: false,
  onNodesChange: (changes) => {
    const nextNodes = applyNodeChanges(changes, get().nodes) as WorkflowNode[];
    const hasSignificantChange = changes.some((c) => c.type !== "select");
    set({
      nodes: nextNodes,
      isDirty: get().isDirty || hasSignificantChange,
    });
  },
  onEdgesChange: (changes) => {
    const nextEdges = applyEdgeChanges(changes, get().edges) as WorkflowEdge[];
    const hasSignificantChange = changes.some((c) => c.type !== "select");
    set({
      edges: nextEdges,
      isDirty: get().isDirty || hasSignificantChange,
    });
  },
  connectNodes: (connection, edgeType?) => {
    if (!connection.source || !connection.target) return;

    // Prevent duplicate edges
    const exists = get().edges.some(
      (e) =>
        e.source === connection.source &&
        e.target === connection.target &&
        e.sourceHandle === connection.sourceHandle &&
        e.targetHandle === connection.targetHandle,
    );

    if (exists) return;

    const newEdge: WorkflowEdge = {
      source: connection.source,
      target: connection.target,
      sourceHandle: connection.sourceHandle,
      targetHandle: connection.targetHandle,
      id: `e-${connection.source}-${connection.sourceHandle || "default"}-${connection.target}-${connection.targetHandle || "default"}`,
      type: "conditionEdge",
      data: { edgeType: (edgeType as EdgeData["edgeType"]) || "default" },
    };
    set({ edges: [...get().edges, newEdge], isDirty: true });
  },
  updateEdgeData: (edgeId, data) => {
    set({
      edges: get().edges.map((e) =>
        e.id === edgeId ? { ...e, data: { ...(e.data || {}), ...data } } : e,
      ),
      isDirty: true,
    });
  },
  addNode: (
    moduleId,
    moduleName,
    position,
    config = {},
    capabilityWorld,
    capabilityDescription,
    category,
    importedInterfaces,
  ) => {
    const newNode: WorkflowNode = {
      id: crypto.randomUUID(), // UI‑only ID for React Flow
      type: "talosNode",
      position,
      data: {
        label: moduleName,
        moduleId,
        moduleName,
        config,
        capabilityWorld,
        category,
        capabilityDescription,
        importedInterfaces,
      },
    };
    set({ nodes: [...get().nodes, newNode], isDirty: true });
  },
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => {
    set({
      nodes: get().nodes.map((n) =>
        n.id === id ? { ...n, data: { ...n.data, ...data } } : n,
      ),
      isDirty: true,
    });
  },
  deleteNode: (id) => {
    set({
      nodes: get().nodes.filter((n) => n.id !== id),
      edges: get().edges.filter((e) => e.source !== id && e.target !== id),
      isDirty: true,
    });
  },
  duplicateNode: (nodeId) => {
    const node = get().nodes.find((n) => n.id === nodeId);
    if (!node) return;
    const clone: WorkflowNode = {
      ...node,
      id: crypto.randomUUID(),
      position: {
        x: node.position.x + 40,
        y: node.position.y + 40,
      },
      selected: false,
    };
    set({ nodes: [...get().nodes, clone], isDirty: true });
  },
  clearWorkflow: () => {
    set({
      nodes: [],
      edges: [],
      workflowId: null,
      workflowName: "Untitled Workflow",
      maxConcurrentExecutions: 1,
      priority: "normal",
      intent: {},
      isDirty: false,
    });
  },
  loadWorkflow: (workflow) => {
    set({ nodes: workflow.nodes, edges: workflow.edges, isDirty: false });
  },
  setWorkflowMeta: (id, name) => {
    set({ workflowId: id, workflowName: name });
  },
  setMaxConcurrentExecutions: (count) => {
    set({ maxConcurrentExecutions: count, isDirty: true });
  },
  setPriority: (priority) => {
    set({ priority, isDirty: true });
  },
  setIntent: (intent) => {
    set({ intent, isDirty: true });
  },
  markClean: () => {
    set({ isDirty: false });
  },
}));

// ============================================================================
// Selector hooks for optimized re-renders
// Use these instead of useWorkflowStore for better performance
// ============================================================================

/** Hook to get only the nodes - optimized for minimal re-renders */
export const useWorkflowNodes = () => useWorkflowStore((state) => state.nodes);

/** Hook to get only the edges - optimized for minimal re-renders */
export const useWorkflowEdges = () => useWorkflowStore((state) => state.edges);

/** Hook to get only the workflow metadata - optimized for minimal re-renders */
export const useWorkflowMeta = () =>
  useWorkflowStore(
    useShallow((state) => ({
      workflowId: state.workflowId,
      workflowName: state.workflowName,
      isDirty: state.isDirty,
    })),
  );

/** Hook to get only the execution settings */
export const useWorkflowSettings = () =>
  useWorkflowStore(
    useShallow((state) => ({
      maxConcurrentExecutions: state.maxConcurrentExecutions,
      priority: state.priority,
      intent: state.intent,
    })),
  );

/** Hook to get node/edge change handlers (stable references) */
export const useWorkflowCallbacks = () =>
  useWorkflowStore(
    useShallow((state) => ({
      onNodesChange: state.onNodesChange,
      onEdgesChange: state.onEdgesChange,
      connectNodes: state.connectNodes,
      addNode: state.addNode,
      updateNodeData: state.updateNodeData,
      deleteNode: state.deleteNode,
      duplicateNode: state.duplicateNode,
      updateEdgeData: state.updateEdgeData,
      loadWorkflow: state.loadWorkflow,
      clearWorkflow: state.clearWorkflow,
      setWorkflowMeta: state.setWorkflowMeta,
      setMaxConcurrentExecutions: state.setMaxConcurrentExecutions,
      setPriority: state.setPriority,
      setIntent: state.setIntent,
      markClean: state.markClean,
    })),
  );
