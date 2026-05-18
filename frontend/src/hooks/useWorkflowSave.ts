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

interface SaveResult {
  id: string;
  name: string;
}

interface UseWorkflowSaveOptions {
  workflowId: string | null;
  workflowName: string;
  onSuccess?: (saved: SaveResult) => void;
}

export function useWorkflowSave({ workflowId, workflowName, onSuccess }: UseWorkflowSaveOptions) {
  const [isSaving, setIsSaving] = useState(false);
  const { markClean, setWorkflowMeta } = useWorkflowStore(
    useShallow((s) => ({ markClean: s.markClean, setWorkflowMeta: s.setWorkflowMeta })),
  );

  const saveMutation = useMutation({
    mutationFn: async ({ customName }: { customName?: string }) => {
      const { nodes, edges, maxConcurrentExecutions, priority, intent } =
        useWorkflowStore.getState();
      const nameToSave = customName || workflowName;

      const graphJson = JSON.stringify({
        priority,
        nodes: nodes.map((n) => {
          let kind = n.data.systemNodeKind?.toLowerCase();
          if (kind === "whileloop" || kind === "repeatloop") kind = "loop";
          if (kind === "errorhandler") kind = "error_handler";
          if (kind === "fanin") kind = "collect";
          if (kind === "dynamicdispatch") kind = "dynamic_dispatch";
          if (kind === "capabilitydispatch") kind = "capability_dispatch";

          return {
            id: n.id,
            type: n.data.moduleId || "unknown",
            kind,
            position: n.position,
            data: {
              ...n.data,
              config: n.data.config || {},
              skip_condition: n.data.skipCondition,
              continue_on_error: n.data.continueOnError,
              timeout_secs: n.data.timeoutSecs,
              retry_count: n.data.retryPolicy?.maxRetries,
              retry_backoff_ms: n.data.retryPolicy?.backoffMs,
              retry_condition: n.data.retryPolicy?.retryCondition,
              retry_delay_expression: n.data.retryPolicy?.retryDelayExpression,
            },
            skip_condition: n.data.skipCondition,
            continue_on_error: n.data.continueOnError,
            retry_count: n.data.retryPolicy?.maxRetries,
            retry_backoff_ms: n.data.retryPolicy?.backoffMs,
            timeout_secs: n.data.timeoutSecs,
          };
        }),
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
        ? { id: workflowId, input: { name: nameToSave, graphJson, maxConcurrentExecutions, intent } }
        : { input: { name: nameToSave, graphJson, maxConcurrentExecutions, intent } };

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
