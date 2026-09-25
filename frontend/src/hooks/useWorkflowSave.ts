/**
 * Encapsulates the workflow save/update GraphQL mutation and surrounding state.
 * Extracted from WorkflowToolbar to keep the toolbar focused on rendering.
 */
import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { useShallow } from "zustand/react/shallow";
import {
  GRAPH_VERSION_CONFLICT_CODE,
  GraphQLCodedError,
  graphqlRequest,
} from "@/lib/graphqlClient";
import { engineControlKeys } from "@/lib/graphDocument";
import { useWorkflowStore } from "@/store/workflowStore";
import type {
  WorkflowEdge,
  WorkflowNode,
  WorkflowState,
} from "@/store/workflowStore";

interface SaveResult {
  id: string;
  name: string;
  graphVersion: number;
}

interface UseWorkflowSaveOptions {
  workflowId: string | null;
  workflowName: string;
  onSuccess?: (saved: SaveResult) => void;
}

/**
 * Serialize one canvas node into the stored graph shape.
 *
 * ENGINE CONTRACT (engine.rs node_configs): a MODULE node's stored `data`
 * IS its config — flat, exactly as every MCP writer (add_node_to_workflow,
 * update_node_config) stores it. The editor used to persist the whole
 * WorkflowNodeData here, which buried the real config under `data.config`
 * (the module saw MODEL_NAME/SYSTEM_PROMPT/… one level too deep and every
 * editor-saved module node failed at run time with "Missing … config") and
 * shipped UI metadata — including full module sourceCode — inside every
 * dispatched envelope. UI metadata (label/moduleName/configSchema/…) is
 * re-derived from the module row by workflowLoader at load, so nothing is
 * lost by not persisting it.
 *
 * System nodes keep the legacy full-data shape: their runtime params live
 * in top-level data fields the engine already reads, and narrowing them is
 * a separate (riskier) change from this fix.
 *
 * Engine controls (skip / continue-on-error / timeout / retry) are written
 * ONLY when set (see `lib/graphDocument.ts`): spreading them unconditionally
 * wrote explicit `undefined`s that overwrote the same keys in the config and
 * were then dropped by `JSON.stringify`, deleting every MCP-authored control
 * on the first editor save. Top-level keys of the stored node the editor does
 * not model (`storedNodeExtras`: `kind`, `description`, …) are written back
 * verbatim underneath the ones it does.
 *
 * Exported for unit tests (repo convention: tests exercise the real code).
 */
export function serializeNode(n: WorkflowNode) {
  let kind = n.data.systemNodeKind?.toLowerCase();
  if (kind === "whileloop" || kind === "repeatloop") kind = "loop";
  if (kind === "errorhandler") kind = "error_handler";
  if (kind === "fanin") kind = "collect";
  if (kind === "dynamicdispatch") kind = "dynamic_dispatch";
  if (kind === "capabilitydispatch") kind = "capability_dispatch";

  const controls = engineControlKeys({
    skipCondition: n.data.skipCondition,
    continueOnError: n.data.continueOnError,
    timeoutSecs: n.data.timeoutSecs,
    retryPolicy: n.data.retryPolicy,
  });
  // `storedNodeExtras` is editor bookkeeping, never part of `data`.
  const { storedNodeExtras, ...nodeData } = n.data;
  const data = n.data.systemNodeKind
    ? { ...nodeData, config: n.data.config || {}, ...controls }
    : { ...(n.data.config || {}), ...controls };

  return {
    ...(storedNodeExtras ?? {}),
    id: n.id,
    type: n.data.moduleId || "unknown",
    // Only a node created in the editor has a `systemNodeKind`; a loaded
    // node's stored `kind` rides in `storedNodeExtras` and must not be
    // overwritten by `undefined`.
    ...(kind !== undefined ? { kind } : {}),
    position: n.position,
    data,
    // The same controls at the node's top level too — where MCP writes the
    // `retry_*` family and where the engine reads them first.
    ...controls,
  };
}

/** Serialize one canvas edge. Top-level keys of the stored edge the editor
 *  does not model (`storedEdgeExtras`: `id`, `logic`, …) are written back. */
export function serializeEdge(e: WorkflowEdge) {
  const { storedEdgeExtras, ...data } = e.data ?? {};
  return {
    ...(storedEdgeExtras ?? {}),
    source: e.source,
    target: e.target,
    sourceHandle: e.sourceHandle,
    targetHandle: e.targetHandle,
    condition: e.data?.condition,
    edge_type: e.data?.edgeType || "default",
    data,
  };
}

/**
 * The full stored graph document for the editor's current state: the
 * graph-level keys the editor does not model (`execution_timeout_secs`, …)
 * first, then the ones it does. Exported for the load → save round-trip test.
 */
export function buildGraphDocument(
  state: Pick<WorkflowState, "nodes" | "edges" | "priority" | "graphExtras">,
) {
  return {
    ...state.graphExtras,
    priority: state.priority,
    nodes: state.nodes.map(serializeNode),
    edges: state.edges.map(serializeEdge),
  };
}

export function useWorkflowSave({
  workflowId,
  workflowName,
  onSuccess,
}: UseWorkflowSaveOptions) {
  const [isSaving, setIsSaving] = useState(false);
  const { markClean, setWorkflowMeta, setGraphVersion } = useWorkflowStore(
    useShallow((s) => ({
      markClean: s.markClean,
      setWorkflowMeta: s.setWorkflowMeta,
      setGraphVersion: s.setGraphVersion,
    })),
  );

  const saveMutation = useMutation({
    mutationFn: async ({ customName }: { customName?: string }) => {
      const state = useWorkflowStore.getState();
      const { maxConcurrentExecutions, intent } = state;
      const nameToSave = customName || workflowName;

      const graphJson = JSON.stringify(buildGraphDocument(state));

      const mutation = workflowId
        ? `mutation UpdateWorkflow($id: UUID!, $input: CreateWorkflowInput!, $expectedGraphVersion: Int) {
            updateWorkflow(id: $id, input: $input, expectedGraphVersion: $expectedGraphVersion) { id name intent graphVersion }
          }`
        : `mutation CreateWorkflow($input: CreateWorkflowInput!) {
            createWorkflow(input: $input) { id name intent graphVersion }
          }`;

      const variables = workflowId
        ? {
            id: workflowId,
            // The version the editor's graph was loaded (or last saved) at:
            // the server refuses the save if anything changed the graph since,
            // instead of silently overwriting that change. Null only for a
            // workflow this editor never read a version for.
            expectedGraphVersion:
              state.workflowId === workflowId ? state.graphVersion : null,
            input: {
              name: nameToSave,
              graphJson,
              maxConcurrentExecutions,
              intent,
            },
          }
        : {
            input: {
              name: nameToSave,
              graphJson,
              maxConcurrentExecutions,
              intent,
            },
          };

      const result = await graphqlRequest<{
        updateWorkflow?: SaveResult;
        createWorkflow?: SaveResult;
      }>(mutation, variables);

      const saved = result.updateWorkflow || result.createWorkflow;
      if (!saved) throw new Error("Failed to save workflow: no data returned");
      return {
        id: saved.id,
        name: saved.name,
        graphVersion: saved.graphVersion,
      } as SaveResult;
    },
    onSuccess: (saved) => {
      setWorkflowMeta(saved.id, saved.name);
      // AFTER setWorkflowMeta, which drops a version from another workflow.
      setGraphVersion(saved.graphVersion);
      markClean();
      toast.success("Workflow saved");
      window.dispatchEvent(new CustomEvent("workflowSaved"));
      onSuccess?.(saved);
    },
    onError: (error) => {
      if (
        error instanceof GraphQLCodedError &&
        error.code === GRAPH_VERSION_CONFLICT_CODE
      ) {
        // Nothing was written. The editor stays dirty so the user's changes
        // are not lost from the canvas either.
        toast.error(
          "Not saved: this workflow was changed elsewhere (e.g. by an MCP tool) since you opened it. Reload it to get the latest version, then re-apply your edit.",
        );
        return;
      }
      toast.error("Failed to save workflow");
    },
  });

  const handleSave = useCallback(
    async (customName?: string) => {
      setIsSaving(true);
      try {
        await saveMutation.mutateAsync({ customName });
      } finally {
        setIsSaving(false);
      }
    },
    [saveMutation],
  );

  return { handleSave, isSaving };
}
