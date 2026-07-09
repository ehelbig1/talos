import { graphqlRequest, gql } from "./graphqlClient";
import type {
  GetWorkflowLoaderQuery,
  GetModulesLoaderQuery,
} from "@/generated/graphql";
import {
  GetWorkflowLoaderDocument,
  GetModulesLoaderDocument,
} from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { toast } from "sonner";
// Node/Edge types imported via workflowStore

// Define queries for codegen to pick up
const _GET_WORKFLOW_LOADER = gql`
  query GetWorkflowLoader($id: UUID!) {
    workflow(id: $id) {
      id
      name
      graphJson
      actorId
      maxConcurrentExecutions
      intent
    }
  }
`;

const _GET_MODULES_LOADER = gql`
  query GetModulesLoader($ids: [UUID!]!) {
    wasmModules(ids: $ids) {
      id
      name
      config
      sourceCode
      capabilityWorld
      importedInterfaces
    }
  }
`;

interface GraphNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data?: Record<string, unknown>;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

interface GraphJson {
  nodes: GraphNode[];
  edges: GraphEdge[];
  priority?: "high" | "normal" | "low";
}

/**
 * Load a workflow from the backend by ID and populate the editor
 */
export async function loadWorkflowById(workflowId: string): Promise<void> {
  try {
    // Fetch workflow from backend
    const data = await graphqlRequest<GetWorkflowLoaderQuery>(
      GetWorkflowLoaderDocument,
      { id: workflowId },
    );

    const workflow = data.workflow;
    if (!workflow) {
      toast.error("Workflow not found");
      return;
    }

    // Guard against excessively large graphJson payloads (>2 MiB) before parsing.
    // JSON.parse on a very large string can cause UI stalls or OOM in the browser.
    const MAX_GRAPH_JSON_BYTES = 2 * 1024 * 1024; // 2 MiB

    // Size guard BEFORE the parse try/catch: keep it outside the block so its
    // specific "exceeds the 2 MiB size limit" message reaches the caller. When
    // it lived inside the try, the catch below rewrapped it into the generic
    // "invalid graph data" message, masking the real (size) reason.
    if (workflow.graphJson.length > MAX_GRAPH_JSON_BYTES) {
      throw new Error(
        `Workflow "${workflow.name}" graph data exceeds the 2 MiB size limit and cannot be loaded.`,
      );
    }

    // Parse the graph JSON — wrap in try/catch so a corrupt graphJson in the
    // database doesn't crash the editor with an unhandled exception.
    let graph: GraphJson;
    try {
      graph = JSON.parse(workflow.graphJson);
    } catch (err) {
      throw new Error(
        `Workflow "${workflow.name}" has invalid graph data and cannot be loaded.`,
        { cause: err },
      );
    }

    // Validate that node types look like UUIDs before sending them to the server.
    // This prevents prototype-pollution or injection via maliciously crafted graph JSON.
    const UUID_RE =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const invalidNodes = (graph.nodes ?? []).filter((n: GraphNode) => {
      const isSystemNode =
        typeof n.type === "string" && n.type.startsWith("system:");
      const invalid =
        typeof n.type !== "string" || (!isSystemNode && !UUID_RE.test(n.type));
      if (invalid) {
        if (import.meta.env.DEV) console.error("Invalid node:", n);
      }
      return invalid;
    });
    if (invalidNodes.length > 0) {
      throw new Error(
        `Workflow "${workflow.name}" contains nodes with invalid module IDs and cannot be loaded.`,
      );
    }

    // Extract unique module IDs from nodes. Structural/system nodes
    // (collect, loop, sub_workflow, capability_dispatch, …) carry a
    // "system:<kind>" sentinel in `type`, NOT a module UUID — they must be
    // EXCLUDED here, otherwise the "system:collect" string is sent to
    // wasmModules(ids: [UUID!]!) and the server rejects the whole query with
    // a "Failed to parse UUID" error, making any workflow with a fan-in /
    // loop node unopenable in the editor.
    const moduleIds = Array.from(
      new Set(
        graph.nodes
          .map((n: GraphNode) => n.type)
          .filter((t) => typeof t === "string" && !t.startsWith("system:")),
      ),
    );

    // Fetch module metadata (names and configs) for all modules in this workflow
    let moduleMap: Map<
      string,
      {
        name: string;
        config: Record<string, unknown>;
        capabilityWorld?: string | null;
        sourceCode?: string | null;
        category?: string | null;
        capabilityDescription?: string | null;
        importedInterfaces?: string[] | null;
      }
    > = new Map();
    if (moduleIds.length > 0) {
      const modulesData = await graphqlRequest<GetModulesLoaderQuery>(
        GetModulesLoaderDocument,
        { ids: moduleIds },
      );

      // Build a map of moduleId -> { name, config, capabilityWorld, importedInterfaces }
      modulesData.wasmModules.forEach((m) => {
        let parsedConfig: Record<string, unknown> = {};
        try {
          parsedConfig = JSON.parse(m.config);
        } catch {
          // if (import.meta.env.DEV) console.warn(`Failed to parse config for module ${m.id}`, e);
        }
        moduleMap.set(m.id, {
          name: m.name,
          config: parsedConfig,
          sourceCode: m.sourceCode,
          capabilityWorld: m.capabilityWorld,
          importedInterfaces: m.importedInterfaces,
        });
      });
    }

    // Convert backend format to React Flow format
    const nodes = graph.nodes.map((n: GraphNode) => {
      const isSystemNode =
        typeof n.type === "string" && n.type.startsWith("system:");
      const moduleData = moduleMap.get(n.type);
      // System/structural nodes have no module row — label them by kind
      // (e.g. "system:collect" → "Collect") instead of the raw sentinel.
      const moduleName = isSystemNode
        ? n.type.slice("system:".length).replace(/^\w/, (c) => c.toUpperCase())
        : moduleData?.name || n.type;

      // Workflow config takes precedence over module default config
      const config = n.data || moduleData?.config || {};

      return {
        id: n.id, // Use backend ID for consistency
        type: "talosNode", // React Flow node type
        position: n.position || { x: 100, y: 100 },
        data: {
          label: moduleName, // Use module name as label
          moduleId: n.type, // Module UUID (for execution)
          moduleName: moduleName, // Human-readable name
          config: config, // Node configuration (workflow override or module default)
          capabilityWorld: moduleData?.capabilityWorld ?? undefined,
          sourceCode: moduleData?.sourceCode ?? undefined,
          category: moduleData?.category ?? undefined,
          importedInterfaces: moduleData?.importedInterfaces ?? undefined,
        },
      };
    });

    const edges = graph.edges.map((e: GraphEdge) => {
      const { source, target, id, data, ...rest } = e;
      return {
        id: id || `${source}-${target}`,
        source,
        target,
        data: data || (rest as Record<string, unknown>),
      };
    });

    // Update the workflow store
    const store = useWorkflowStore.getState();
    if (import.meta.env.DEV)
      console.log(
        `Loaded workflow: ${workflow.name} (${workflow.id}) with ${nodes.length} nodes`,
      );
    store.setWorkflowMeta(workflow.id, workflow.name);
    store.setMaxConcurrentExecutions(workflow.maxConcurrentExecutions ?? 1);
    store.setPriority(graph.priority ?? "normal");
    store.setIntent(
      (workflow.intent as Record<string, unknown> | null | undefined) ?? {},
    );
    store.loadWorkflow({ nodes, edges });
  } catch (error) {
    if (import.meta.env.DEV) console.error("Failed to load workflow:", error);
    // Notify the user so they know what failed
    toast.error(
      "Failed to load workflow: " +
        sanitizeErrorMessage((error as Error).message ?? String(error)),
    );
    throw error;
  }
}
