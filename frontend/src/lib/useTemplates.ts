import { useState, useEffect, useRef } from "react";
import { graphqlRequest } from "./graphqlClient";

export interface NodeTemplate {
  id: string;
  name: string;
  category: string;
  description: string | null;
  configSchema: string;
  icon: string | null;
  allowedHosts: string[];
}

export function useTemplates() {
  const [templates, setTemplates] = useState<NodeTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const hasFetchedRef = useRef(false);

  useEffect(() => {
    if (!hasFetchedRef.current) {
      hasFetchedRef.current = true;
      fetchTemplates();
    }
  }, []);

  async function fetchTemplates() {
    try {
      setLoading(true);
      const data = await graphqlRequest<{ nodeTemplates: NodeTemplate[] }>(
        `query {
          nodeTemplates {
            id
            name
            category
            description
            configSchema
            icon
            allowedHosts
          }
        }`,
        {},
      );
      if (data?.nodeTemplates) {
        setTemplates(data.nodeTemplates);
      } else {
        setTemplates([]);
      }
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch modules");
      // if (import.meta.env.DEV) console.error("Failed to fetch templates:", e);
    } finally {
      setLoading(false);
    }
  }

  return { templates, loading, error, refetch: fetchTemplates };
}
