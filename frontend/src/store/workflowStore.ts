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
  // Absent = the graph declares no count, so the engine's method-aware
  // default applies. NOT the same as 0 (an explicit "never retry").
  maxRetries?: number;
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
  // The module's declared config contract (talos.json config_schema),
  // hydrated at load time. Used as a rename-stable module identity.
  configSchema?: Record<string, unknown>;
  // Origin catalog template slug (stable identity; undefined for
  // sandbox/extracted modules).
  catalogSlug?: string;
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
  // Top-level keys of the STORED node the editor does not model (`kind`,
  // `description`, …). Carried verbatim through load → save; never shown,
  // never written into `data`. See `lib/graphDocument.ts`.
  storedNodeExtras?: Record<string, unknown>;
}

export type WorkflowNode = RFNode<WorkflowNodeData>;

export interface EdgeData {
  [key: string]: unknown;
  edgeType?: "default" | "error" | "conditional" | "OnFailure";
  condition?: string;
  mapping?: string;
  // Top-level keys of the STORED edge the editor does not model (`id`,
  // `logic`, …), carried verbatim and written back at the edge's top level.
  storedEdgeExtras?: Record<string, unknown>;
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
  // The `graphVersion` the loaded graph was read at (null for a workflow this
  // editor has not loaded or saved). Sent as `expectedGraphVersion` so a save
  // cannot silently overwrite an edit made elsewhere since the load.
  graphVersion: number | null;
  // Top-level keys of the stored graph the editor does not model
  // (`execution_timeout_secs`, …), carried verbatim through load → save.
  graphExtras: Record<string, unknown>;
  isDirty: boolean;
  // Advances on every edit. A save captures it when it reads the graph and
  // clears `isDirty` only if nothing changed while the request was in flight.
  editGeneration: number;
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
  setGraphDocument: (doc: {
    graphVersion: number | null;
    graphExtras: Record<string, unknown>;
  }) => void;
  setGraphVersion: (graphVersion: number | null) => void;
  /** Clear `isDirty`. With a generation, only if no edit happened since it
   *  was read; returns whether the store is now clean. */
  markClean: (generation?: number) => boolean;
}

/** The patch every editing action applies alongside its change. */
function dirtied(s: Pick<WorkflowState, "editGeneration">) {
  return { isDirty: true, editGeneration: s.editGeneration + 1 };
}

export const useWorkflowStore = create<WorkflowState>((set, get) => ({
  nodes: [],
  edges: [],
  workflowId: null,
  workflowName: "Untitled Workflow",
  maxConcurrentExecutions: 1,
  priority: "normal",
  intent: {},
  graphVersion: null,
  graphExtras: {},
  isDirty: false,
  editGeneration: 0,
  onNodesChange: (changes) => {
    const nextNodes = applyNodeChanges(changes, get().nodes) as WorkflowNode[];
    const hasSignificantChange = changes.some((c) => c.type !== "select");
    set({
      nodes: nextNodes,
      ...(hasSignificantChange ? dirtied(get()) : {}),
    });
  },
  onEdgesChange: (changes) => {
    const nextEdges = applyEdgeChanges(changes, get().edges) as WorkflowEdge[];
    const hasSignificantChange = changes.some((c) => c.type !== "select");
    set({
      edges: nextEdges,
      ...(hasSignificantChange ? dirtied(get()) : {}),
    });
  },
  connectNodes: (connection, edgeType?) => {
    if (!connection.source || !connection.target) return;

    // A node may not connect to itself. React Flow lets you drag an output
    // handle back onto the same node's input by default; that self-edge is a
    // 1-node cycle and the engine rejects the whole graph with "workflow graph
    // contains a cycle". Drop it silently instead of poisoning the workflow.
    if (connection.source === connection.target) return;

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
    set({ edges: [...get().edges, newEdge], ...dirtied(get()) });
  },
  updateEdgeData: (edgeId, data) => {
    set({
      edges: get().edges.map((e) =>
        e.id === edgeId ? { ...e, data: { ...(e.data || {}), ...data } } : e,
      ),
      ...dirtied(get()),
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
    set({ nodes: [...get().nodes, newNode], ...dirtied(get()) });
  },
  updateNodeData: (id: string, data: Partial<WorkflowNodeData>) => {
    set({
      nodes: get().nodes.map((n) =>
        n.id === id ? { ...n, data: { ...n.data, ...data } } : n,
      ),
      ...dirtied(get()),
    });
  },
  deleteNode: (id) => {
    set({
      nodes: get().nodes.filter((n) => n.id !== id),
      edges: get().edges.filter((e) => e.source !== id && e.target !== id),
      ...dirtied(get()),
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
    set({ nodes: [...get().nodes, clone], ...dirtied(get()) });
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
      graphVersion: null,
      graphExtras: {},
      isDirty: false,
    });
  },
  loadWorkflow: (workflow) => {
    set({ nodes: workflow.nodes, edges: workflow.edges, isDirty: false });
  },
  setWorkflowMeta: (id, name) => {
    // A version belongs to the workflow it was read from: switching identity
    // drops it, so a save to a different workflow never carries it.
    set((s) =>
      id === s.workflowId
        ? { workflowId: id, workflowName: name }
        : { workflowId: id, workflowName: name, graphVersion: null },
    );
  },
  setMaxConcurrentExecutions: (count) => {
    set({ maxConcurrentExecutions: count, ...dirtied(get()) });
  },
  setPriority: (priority) => {
    set({ priority, ...dirtied(get()) });
  },
  setIntent: (intent) => {
    set({ intent, ...dirtied(get()) });
  },
  setGraphDocument: ({ graphVersion, graphExtras }) => {
    set({ graphVersion, graphExtras });
  },
  setGraphVersion: (graphVersion) => {
    set({ graphVersion });
  },
  markClean: (generation) => {
    if (generation !== undefined && generation !== get().editGeneration) {
      return false;
    }
    set({ isDirty: false });
    return true;
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
