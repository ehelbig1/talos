import React, {
  useCallback,
  Suspense,
  useMemo,
  useSyncExternalStore,
} from "react";
import { useNavigate } from "react-router";
import { LoadingState } from "@/components/ui/spinner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import ErrorBoundary from "@/components/ErrorBoundary";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  Panel,
} from "@xyflow/react";
import type { Connection } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { TalosNode } from "@/components/TalosNode";
import { ConditionEdge } from "@/components/ConditionEdge";
import { useWorkflowStore } from "@/store/workflowStore";
import { useShallow } from "zustand/react/shallow";
import { useUIStore } from "@/store/uiStore";
const Inspector = React.lazy(() => import("@/components/Inspector"));
const Terminal = React.lazy(() => import("@/components/Terminal"));
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { cn } from "@/lib/utils";
import { useKeyboardShortcuts, SHORTCUTS } from "@/hooks/useKeyboardShortcuts";
import { Zap, FolderPlus, BookOpen, Plus } from "lucide-react";
import { Button } from "@/components/ui";

const proOptions = { hideAttribution: true };
const nodeTypes = { talosNode: TalosNode };
const edgeTypes = { conditionEdge: ConditionEdge };

// Module-level so `useSyncExternalStore` sees a stable subscribe function
// (an inline one re-subscribes on every render).
function subscribeToResize(onChange: () => void) {
  window.addEventListener("resize", onChange);
  return () => window.removeEventListener("resize", onChange);
}
const readWindowHeight = () => window.innerHeight;

function Workspace() {
  const navigate = useNavigate();
  const nodes = useWorkflowStore(useShallow((s) => s.nodes));
  const edges = useWorkflowStore(useShallow((s) => s.edges));
  const onNodesChange = useWorkflowStore((s) => s.onNodesChange);
  const onEdgesChange = useWorkflowStore((s) => s.onEdgesChange);
  const connectNodes = useWorkflowStore((s) => s.connectNodes);
  const deleteNode = useWorkflowStore((s) => s.deleteNode);
  const nodeCount = nodes.length;

  const { showInspector, terminalState, setShowInspector, setTerminalState } =
    useUIStore(
      useShallow((s) => ({
        showInspector: s.showInspector,
        terminalState: s.terminalState,
        setShowInspector: s.setShowInspector,
        setTerminalState: s.setTerminalState,
      })),
    );

  const onConnect = useCallback(
    (connection: Connection) => {
      connectNodes(connection);
    },
    [connectNodes],
  );

  const handleDeleteSelected = useCallback(() => {
    const activeElement = document.activeElement as HTMLElement;
    const isInput =
      activeElement &&
      (activeElement.tagName === "INPUT" ||
        activeElement.tagName === "TEXTAREA" ||
        activeElement.isContentEditable ||
        activeElement.closest(".monaco-editor"));

    if (isInput) return;

    const selectedNode = useWorkflowStore
      .getState()
      .nodes.find((n) => n.selected);
    if (selectedNode) {
      deleteNode(selectedNode.id);
      setShowInspector(false);
    }
  }, [deleteNode, setShowInspector]);

  const keyboardShortcuts = useMemo(
    () => [
      {
        ...SHORTCUTS.TOGGLE_INSPECTOR,
        handler: () => setShowInspector(!showInspector),
      },
      {
        ...SHORTCUTS.TOGGLE_TERMINAL,
        handler: () => {
          if (terminalState === "collapsed") setTerminalState("compact");
          else if (terminalState === "compact") setTerminalState("full");
          else setTerminalState("collapsed");
        },
      },
      {
        key: "Delete",
        handler: handleDeleteSelected,
        description: "Delete node",
      },
      {
        key: "Backspace",
        handler: handleDeleteSelected,
        description: "Delete node",
      },
    ],
    [
      showInspector,
      terminalState,
      handleDeleteSelected,
      setShowInspector,
      setTerminalState,
    ],
  );
  useKeyboardShortcuts(keyboardShortcuts);

  // Subscribe to window resize for terminal height calculation
  const windowHeight = useSyncExternalStore(
    subscribeToResize,
    readWindowHeight,
  );

  const terminalHeight =
    terminalState === "collapsed"
      ? 24
      : terminalState === "compact"
        ? 240
        : windowHeight * 0.45;

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-background relative overflow-hidden h-full">
      <div className="flex flex-1 overflow-hidden relative z-10">
        <div className="flex-1 relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            nodeOrigin={[0.5, 0.5]}
            snapToGrid
            snapGrid={[15, 15]}
            onlyRenderVisibleElements
            nodeDragThreshold={1}
            defaultEdgeOptions={{
              style: { strokeWidth: 3, stroke: "hsla(var(--primary), 0.5)" },
              animated: false,
            }}
            proOptions={proOptions}
            className="bg-transparent"
          >
            <Background
              color="hsla(var(--white), 0.05)"
              gap={40}
              size={1}
              variant={BackgroundVariant.Lines}
              className="opacity-50"
            />

            <div className="absolute bottom-8 left-8 z-20">
              <Controls
                showInteractive={false}
                className="!m-0 !bg-surface-3/40 !backdrop-blur-2xl !border-white/5 !rounded-2xl overflow-hidden [&>button]:!bg-transparent [&>button]:!border-white/10 [&>button]:!text-muted-foreground [&>button:hover]:!text-foreground [&>button:hover]:!bg-white/5 [&>button]:!transition-ui"
              />
            </div>

            <Panel position="bottom-right" className="!m-8 z-20">
              <MiniMap
                className="!bg-surface-3/40 !backdrop-blur-2xl !border-white/5 !rounded-2xl overflow-hidden"
                maskColor="hsla(var(--background), 0.8)"
                nodeColor={(n) => {
                  if (n.data?.category === "control-flow")
                    return "hsl(var(--info))";
                  return "hsl(var(--primary))";
                }}
                nodeStrokeWidth={4}
                zoomable
                pannable
              />
            </Panel>
          </ReactFlow>

          {nodeCount === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-30 px-6">
              <div className="text-center pointer-events-auto bg-surface-3/40 border border-white/10 p-10 rounded-2xl max-w-md w-full">
                <div className="w-14 h-14 mx-auto mb-5 rounded-2xl bg-surface-4/60 border border-white/10 flex items-center justify-center">
                  <Zap className="w-6 h-6 text-primary fill-primary/10" />
                </div>

                <h2 className="text-xl font-semibold text-white tracking-tight mb-2 font-outfit">
                  An empty canvas
                </h2>
                <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
                  A workflow is made of modules. Create one from a template, or
                  add one you already have.
                </p>

                <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Button
                    onClick={() =>
                      useUIStore.getState().setToolbarModal("create")
                    }
                  >
                    <Plus className="w-4 h-4" />
                    New module
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() =>
                      useUIStore.getState().setToolbarModal("addExisting")
                    }
                  >
                    <FolderPlus className="w-4 h-4" />
                    Add existing module
                  </Button>
                </div>
                <button
                  onClick={() => navigate("/library#templates")}
                  className="mt-5 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-white transition-ui"
                >
                  <BookOpen className="w-3.5 h-3.5" />
                  Browse templates
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Inspector - Slide in/out */}
        <div
          className={cn(
            "border-l border-white/5 bg-surface-1/60 backdrop-blur-3xl transition-[width] duration-200 z-20 overflow-hidden",
          )}
          style={{ width: showInspector ? "min(420px, 100vw)" : "0px" }}
        >
          <ErrorBoundary
            fallback={(e) => (
              <div className="p-4 text-destructive overflow-auto break-words text-xs font-mono">
                Failed to load inspector: {sanitizeErrorMessage(e.message)}
              </div>
            )}
          >
            <Suspense fallback={<LoadingState />}>
              <Inspector />
            </Suspense>
          </ErrorBoundary>
        </div>
      </div>

      {/* Bottom Terminal - Drawer */}
      <div
        className={cn(
          "border-t border-white/5 bg-surface-1/60 backdrop-blur-3xl text-foreground z-30",
        )}
        style={{ height: `${terminalHeight}px` }}
      >
        <ErrorBoundary
          fallback={
            <div className="p-4 text-xs text-destructive">
              Failed to load terminal.
            </div>
          }
        >
          <Suspense fallback={<LoadingState />}>
            <Terminal />
          </Suspense>
        </ErrorBoundary>
      </div>

      <KeyboardShortcutsHelp />
    </div>
  );
}

export default Workspace;
