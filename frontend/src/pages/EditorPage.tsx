import React, { Suspense, lazy, useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import ErrorBoundary from "@/components/ErrorBoundary";
import { loadWorkflowById } from "@/lib/workflowLoader";
import { useGetModulesLoaderQuery } from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";

const ExecutionPanel = lazy(() => import("@/components/ExecutionPanel"));
const Workspace = lazy(() => import("@/components/Workspace"));

function ModulePreloader({ moduleId }: { moduleId: string }) {
  const addNode = useWorkflowStore((s) => s.addNode);
  const added = React.useRef(false);

  const { data } = useGetModulesLoaderQuery(
    { ids: [moduleId] },
    { staleTime: 60_000, refetchOnWindowFocus: false },
  );

  useEffect(() => {
    if (!data?.wasmModules?.[0] || added.current) return;
    added.current = true;
    const mod = data.wasmModules[0];
    let config: Record<string, unknown> = {};
    try {
      config = JSON.parse(mod.config);
    } catch {
      /* empty config */
    }
    addNode(
      mod.id,
      mod.name,
      { x: 200, y: 200 },
      config,
      mod.capabilityWorld ?? undefined,
      undefined,
      undefined,
      mod.importedInterfaces ?? undefined,
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  return null;
}

function EditorPage() {
  const { id } = useParams<{ id?: string }>();
  const [searchParams] = useSearchParams();
  const moduleId = searchParams.get("moduleId");

  useEffect(() => {
    if (id) {
      loadWorkflowById(id).catch((err) => {
        if (import.meta.env.DEV)
          console.error("Failed to deep-link workflow:", err);
      });
    }
  }, [id]);

  return (
    <div className="flex flex-col h-screen bg-background overflow-hidden">
      <ErrorBoundary
        fallback={
          <div className="p-4 text-red-400">Failed to load editor.</div>
        }
      >
        <Suspense
          fallback={
            <div className="flex-1 flex items-center justify-center text-muted-foreground">
              <div className="flex flex-col items-center gap-3">
                <div className="w-8 h-8 border-2 border-violet-500/20 border-t-violet-500 rounded-full animate-spin" />
                <span className="text-sm font-medium animate-pulse">
                  Initializing Talos Engine...
                </span>
              </div>
            </div>
          }
        >
          {moduleId && <ModulePreloader moduleId={moduleId} />}

          {/* Execution Monitoring Top Bar / Header */}
          <div className="shrink-0 border-b border-white/5 bg-background relative z-40">
            <ExecutionPanel />
          </div>

          {/* Main Editor Surface */}
          <div className="flex-1 min-h-0 relative">
            <Workspace />
          </div>
        </Suspense>
      </ErrorBoundary>
    </div>
  );
}

export default EditorPage;
