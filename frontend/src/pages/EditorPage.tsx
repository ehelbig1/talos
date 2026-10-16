import React, { Suspense, lazy, useEffect } from "react";
import { LoadingState } from "@/components/ui/spinner";
import { useParams, useSearchParams } from "react-router";
import ErrorBoundary from "@/components/ErrorBoundary";
import { loadWorkflowById } from "@/lib/workflowLoader";
import { useGetModulesLoaderQuery } from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";
import { UnsavedChangesGuard } from "@/components/UnsavedChangesGuard";

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
    // `addNode` is a stable store action; `added` makes this run once.
  }, [data, addNode]);

  return null;
}

function EditorPage() {
  const { id } = useParams<{ id?: string }>();
  const [searchParams] = useSearchParams();
  const moduleId = searchParams.get("moduleId");

  useEffect(() => {
    if (!id) return;
    // Unsaved edits to THIS workflow (e.g. `/editor` gaining its id after a
    // first save, or a remount) are kept rather than overwritten.
    const { isDirty, workflowId } = useWorkflowStore.getState();
    if (isDirty && workflowId === id) return;
    let current = true;
    loadWorkflowById(id, { isCurrent: () => current }).catch((err) => {
      if (import.meta.env.DEV)
        console.error("Failed to deep-link workflow:", err);
    });
    return () => {
      current = false;
    };
  }, [id]);

  // h-full, not h-screen: the shell's <main> is the screen minus the nav, and
  // a taller child makes <main> scroll its first 56 px (the toolbar row) out
  // of view the moment anything lower takes focus, while clipping the console
  // drawer at the bottom.
  return (
    <div className="flex flex-col h-full bg-background overflow-hidden">
      <ErrorBoundary
        fallback={
          <div className="p-4 text-destructive">Failed to load editor.</div>
        }
      >
        <Suspense
          fallback={<LoadingState label="Loading editor…" className="flex-1" />}
        >
          <UnsavedChangesGuard />
          {moduleId && <ModulePreloader moduleId={moduleId} />}

          {/* Header row: workflow, tools, run */}
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
