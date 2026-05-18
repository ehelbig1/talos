import { useState, useEffect, useCallback, useRef } from "react";
import { graphqlRequest } from "@/lib/graphqlClient";

export interface WasmModule {
  id: string;
  name: string;
  sizeBytes: number;
  contentHash: string;
  compiledAt: string;
  config: string; // JSON string
  capabilityWorld?: string;

  capabilityDescription?: string;
  importedInterfaces?: string[];
}

/**
 * Hook encapsulating the fetching and selection logic for the AddExistingNodeDialog.
 * Returns state and helper callbacks that the UI component can consume.
 */
export function useAddExistingNode() {
  const [modules, setModules] = useState<WasmModule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedModuleId, setSelectedModuleId] = useState<string>("");

  const fetchModules = useCallback(async () => {
    try {
      setLoading(true);
      const data = await graphqlRequest<{ myModules: WasmModule[] }>(
        `query { myModules { id name sizeBytes contentHash compiledAt config capabilityWorld capabilityDescription importedInterfaces } }`,
        {},
      );
      setModules(data.myModules);
    } catch (e: unknown) {
      setModules([]);
      setError(e instanceof Error ? e.message : "Failed to fetch modules");
    } finally {
      setLoading(false);
    }
  }, []);

  const hasFetchedRef = useRef(false);

  useEffect(() => {
    if (!hasFetchedRef.current) {
      hasFetchedRef.current = true;
      fetchModules();
    }
  }, [fetchModules]);

  const getSelectedModule = () =>
    modules.find((m) => m.id === selectedModuleId);

  const parseConfig = (module: WasmModule): Record<string, unknown> => {
    try {
      return JSON.parse(module.config);
    } catch {
      if (import.meta.env.DEV)
        console.warn("Failed to parse module config, using empty object");
      return {};
    }
  };

  return {
    modules,
    loading,
    error,
    selectedModuleId,
    setSelectedModuleId,
    fetchModules,
    getSelectedModule,
    parseConfig,
  } as const;
}
