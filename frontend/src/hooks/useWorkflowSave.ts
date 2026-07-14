/**
 * Encapsulates the workflow save/update GraphQL mutation and surrounding state.
 * Extracted from WorkflowToolbar to keep the toolbar focused on rendering.
 */
import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { useShallow } from "zustand/react/shallow";
import { graphqlRequest } from "@/lib/graphqlClient";
import { useWorkflowStore } from "@/store/workflowStore";
import type { WorkflowNode } from "@/store/workflowStore";

interface SaveResult {
  id: string;
  name: string;
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
 * Exported for unit tests (repo convention: tests exercise the real code).
 */
export function serializeNode(n: WorkflowNode) {
  let kind = n.data.systemNodeKind?.toLowerCase();
  if (kind === "whileloop" || kind === "repeatloop") kind = "loop";
  if (kind === "errorhandler") kind = "error_handler";
  if (kind === "fanin") kind = "collect";
  if (kind === "dynamicdispatch") kind = "dynamic_dispatch";
  if (kind === "capabilitydispatch") kind = "capability_dispatch";

  const engineExtras = {
    skip_condition: n.data.skipCondition,
    continue_on_error: n.data.continueOnError,
    timeout_secs: n.data.timeoutSecs,
    retry_count: n.data.retryPolicy?.maxRetries,
    retry_backoff_ms: n.data.retryPolicy?.backoffMs,
    retry_condition: n.data.retryPolicy?.retryCondition,
    retry_delay_expression: n.data.retryPolicy?.retryDelayExpression,
  };
  const data = n.data.systemNodeKind
    ? { ...n.data, config: n.data.config || {}, ...engineExtras }
    : { ...(n.data.config || {}), ...engineExtras };

  return {
    id: n.id,
    type: n.data.moduleId || "unknown",
    kind,
    position: n.position,
    data,
    skip_condition: n.data.skipCondition,
    continue_on_error: n.data.continueOnError,
    retry_count: n.data.retryPolicy?.maxRetries,
    retry_backoff_ms: n.data.retryPolicy?.backoffMs,
    timeout_secs: n.data.timeoutSecs,
  };
}

export function useWorkflowSave({
  workflowId,
  workflowName,
  onSuccess,
}: UseWorkflowSaveOptions) {
  const [isSaving, setIsSaving] = useState(false);
  const { markClean, setWorkflowMeta } = useWorkflowStore(
    useShallow((s) => ({
      markClean: s.markClean,
      setWorkflowMeta: s.setWorkflowMeta,
    })),
  );

  const saveMutation = useMutation({
    mutationFn: async ({ customName }: { customName?: string }) => {
      const { nodes, edges, maxConcurrentExecutions, priority, intent } =
        useWorkflowStore.getState();
      const nameToSave = customName || workflowName;

      const graphJson = JSON.stringify({
        priority,
        nodes: nodes.map(serializeNode),
        edges: edges.map((e) => ({
          source: e.source,
          target: e.target,
          sourceHandle: e.sourceHandle,
          targetHandle: e.targetHandle,
          condition: e.data?.condition,
          edge_type: e.data?.edgeType || "default",
          data: e.data,
        })),
      });

      const mutation = workflowId
        ? `mutation UpdateWorkflow($id: UUID!, $input: CreateWorkflowInput!) {
            updateWorkflow(id: $id, input: $input) { id name intent }
          }`
        : `mutation CreateWorkflow($input: CreateWorkflowInput!) {
            createWorkflow(input: $input) { id name intent }
          }`;

      const variables = workflowId
        ? {
            id: workflowId,
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
        updateWorkflow?: { id: string; name: string };
        createWorkflow?: { id: string; name: string };
      }>(mutation, variables);

      const saved = result.updateWorkflow || result.createWorkflow;
      if (!saved) throw new Error("Failed to save workflow: no data returned");
      return { id: saved.id, name: saved.name } as SaveResult;
    },
    onSuccess: (saved) => {
      setWorkflowMeta(saved.id, saved.name);
      markClean();
      toast.success("Workflow saved");
      window.dispatchEvent(new CustomEvent("workflowSaved"));
      onSuccess?.(saved);
    },
    onError: () => {
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
